"""Shared identity and availability for local entities."""

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Coordinator


class BaseEntity(CoordinatorEntity[Coordinator]):
    _attr_has_entity_name = True
    _airmate_state_keys: frozenset[str] = frozenset()

    def __init__(
        self,
        coordinator: Coordinator,
        key: str | None = None,
        state_keys: set[str] | None = None,
    ) -> None:
        super().__init__(coordinator)
        self._airmate_state_keys = frozenset(
            self._airmate_state_keys if state_keys is None else state_keys
        )
        device_id = coordinator.protocol.device_id
        # Preserve the legacy primary fan unique ID and device identifier.
        suffix = f"_{key}" if key else ""
        self._attr_unique_id = f"{DOMAIN}_fan{suffix}_{device_id}"
        self._attr_name = None

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.coordinator.protocol.device_id)},
            manufacturer="AirMate",
            name=self.coordinator.device_name,
            model="Local MQTT fan",
            sw_version=self.coordinator.firmware,
        )

    @property
    def available(self) -> bool:
        # Keep the last validated values visible while MQTT is offline. Commands
        # still require a live report and are rejected by the coordinator.
        return self.coordinator.online or self._has_cached_state

    @property
    def _has_cached_state(self) -> bool:
        if not self._airmate_state_keys:
            return bool(self.coordinator.data)
        return any(key in self.coordinator.data for key in self._airmate_state_keys)

    @property
    def extra_state_attributes(self) -> dict[str, str] | None:
        if self._has_cached_state and not self.coordinator.online:
            return {"state_source": "last_known"}
        return None
