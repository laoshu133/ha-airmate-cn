"""Push state and confirmed commands using Home Assistant's MQTT client."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components import mqtt
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    COMMAND_TIMEOUT,
    CONF_DEVICE_ID,
    CONF_PRODUCT_ID,
    CONF_STALE_TIMEOUT,
    DEFAULT_STALE_TIMEOUT,
    DOMAIN,
)
from .protocol import LIMITS, Protocol

_LOGGER = logging.getLogger(__name__)
SPEED_PREPARE_DELAY = 1.0


class Coordinator(DataUpdateCoordinator[dict[str, int]]):
    """One device, one subscription; cached values never acknowledge a write."""

    def __init__(self, hass, entry) -> None:
        super().__init__(hass, _LOGGER, name=DOMAIN, config_entry=entry)
        self.protocol = Protocol(
            entry.data[CONF_PRODUCT_ID], entry.data[CONF_DEVICE_ID]
        )
        self.device_name = entry.title
        self.stale_timeout = entry.options.get(
            CONF_STALE_TIMEOUT, DEFAULT_STALE_TIMEOUT
        )
        self.data = {}
        self.firmware: str | None = None
        self.online = False
        self._connected = False
        self._closed = False
        self._unsubs = []
        self._expiry = None
        self._lock = asyncio.Lock()
        self._pending: tuple[dict[str, int], dict[str, int], asyncio.Future] | None = (
            None
        )
        self._epoch = 0
        self._state_store = Store(
            hass, 1, f"{DOMAIN}.{entry.entry_id}", private=True
        )

    async def async_start(self) -> None:
        """Restore the last report, then register listeners before entities are added."""
        await self._async_restore_state()
        self._connected = mqtt.is_connected(self.hass)
        self._unsubs.append(
            mqtt.async_subscribe_connection_status(self.hass, self._connection_changed)
        )
        try:
            self._unsubs.append(
                await mqtt.async_subscribe(
                    self.hass,
                    self.protocol.up_topic,
                    self._receive,
                    qos=0,
                )
            )
        except BaseException:
            self.async_close()
            raise

    async def _async_restore_state(self) -> None:
        """Restore validated properties for display until a fresh report arrives."""
        try:
            stored = await self._state_store.async_load()
        except Exception as err:  # pragma: no cover - defensive storage handling
            _LOGGER.warning("Unable to restore AirMate state: %s", err)
            return
        if not isinstance(stored, dict):
            return
        if (
            stored.get("product_id") != self.protocol.product_id
            or stored.get("device_id") != self.protocol.device_id
        ):
            return
        properties = stored.get("properties")
        if isinstance(properties, dict):
            self.data = {
                key: value
                for key, value in properties.items()
                if key in LIMITS
                and type(value) is int
                and LIMITS[key][0] <= value <= LIMITS[key][1]
            }
        firmware = stored.get("firmware")
        if isinstance(firmware, str) and 0 < len(firmware) <= 64:
            self.firmware = firmware

    def _async_save_state(self) -> None:
        """Persist the latest validated report without blocking MQTT callbacks."""
        self._state_store.async_delay_save(
            lambda: {
                "product_id": self.protocol.product_id,
                "device_id": self.protocol.device_id,
                "properties": dict(self.data),
                "firmware": self.firmware,
            },
            delay=0.1,
        )

    @callback
    def _receive(self, message) -> None:
        if self._closed or not self._connected:
            return
        report = self.protocol.decode(
            message.topic, message.payload, retained=message.retain
        )
        if report is None:
            return
        self.online = True
        if report.firmware is not None:
            self.firmware = report.firmware
        if self._expiry is not None:
            self._expiry.cancel()
        self._expiry = self.hass.loop.call_later(self.stale_timeout, self._expire)
        self.async_set_updated_data({**self.data, **report.properties})
        self._async_save_state()
        if self._pending is not None:
            expected, seen, future = self._pending
            seen.update(report.properties)
            if (
                all(seen.get(key) == value for key, value in expected.items())
                and not future.done()
            ):
                future.set_result(None)

    @callback
    def _fail_pending(self, reason: str) -> None:
        if self._pending is not None and not self._pending[2].done():
            self._pending[2].set_exception(HomeAssistantError(reason))

    @callback
    def _expire(self) -> None:
        self._expiry = None
        self._epoch += 1
        self.online = False
        # Keep the last known values for display; commands still require online=True.
        self.async_set_updated_data(dict(self.data))
        self._fail_pending("AirMate device stopped reporting")

    @callback
    def _connection_changed(self, connected: bool) -> None:
        if self._closed:
            return
        self._connected = connected
        if self._expiry is not None:
            self._expiry.cancel()
            self._expiry = None
        self._expire()

    async def async_set_power(self, power: int) -> None:
        await self._async_command({"power_switch": power}, {"power_switch": power})

    async def async_set_speed(self, speed: int) -> None:
        await self._async_command(
            {"power_switch": 1, "mode": 0, "downshift": speed},
            {"downshift": speed},
            prelude={"downshift": speed},
        )

    async def async_set_horizontal(self, value: int) -> None:
        await self._async_command(
            {"horizontal_swing": value}, {"horizontal_swing": value}
        )

    async def async_set_vertical(self, value: int) -> None:
        await self._async_command({"vertical_swing": value}, {"vertical_swing": value})

    def _check_available(self, epoch=None) -> None:
        if (
            self._closed
            or not self._connected
            or not self.online
            or (epoch is not None and epoch != self._epoch)
        ):
            raise HomeAssistantError(
                "AirMate device is unavailable; wait for a fresh report"
            )

    async def _async_command(self, data, required, *, prelude=None) -> None:
        """Serialize the complete transaction and confirm new matching properties.

        This firmware needs a speed preparation message before the full legacy
        command. That is a protocol step, not a timeout retry. No stage is repeated.
        """
        async with self._lock:
            self.protocol.validate_properties(data)  # Validate even a no-op.
            self._check_available()
            if all(self.data.get(key) == value for key, value in data.items()):
                return
            epoch = self._epoch
            expected = dict(required)
            expected.update(
                {
                    key: value
                    for key, value in data.items()
                    if key in self.data and self.data[key] != value
                }
            )
            future = self.hass.loop.create_future()
            try:
                async with asyncio.timeout(COMMAND_TIMEOUT):
                    if prelude is not None:
                        await mqtt.async_publish(
                            self.hass,
                            self.protocol.down_topic,
                            self.protocol.encode_properties(prelude),
                            qos=0,
                            retain=False,
                        )
                        await asyncio.sleep(SPEED_PREPARE_DELAY)
                        self._check_available(epoch)
                    # Reports during preparation cannot confirm the final command.
                    self._pending = (expected, {}, future)
                    # Generate this ID after the preparation message, in wire order.
                    payload = self.protocol.encode_properties(data)
                    await mqtt.async_publish(
                        self.hass,
                        self.protocol.down_topic,
                        payload,
                        qos=0,
                        retain=False,
                    )
                    await future
            except TimeoutError as exc:
                raise HomeAssistantError(
                    "No matching AirMate property report within 15 seconds; command was not retried"
                ) from exc
            except HomeAssistantError:
                raise
            except Exception as exc:
                raise HomeAssistantError("Unable to publish AirMate command") from exc
            finally:
                self._pending = None
                if not future.done():
                    future.cancel()
                elif not future.cancelled():
                    future.exception()

    @callback
    def async_close(self) -> None:
        """Idempotently release subscriptions, timer and in-flight commands."""
        self._closed = True
        self._connected = False
        if self._expiry is not None:
            self._expiry.cancel()
            self._expiry = None
        for unsubscribe in self._unsubs:
            unsubscribe()
        self._unsubs.clear()
        self.online = False
        self._fail_pending("AirMate integration was unloaded")
