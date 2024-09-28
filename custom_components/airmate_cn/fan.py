"""Platform for AirMate Fan integration."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING

from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.core import HomeAssistant, callback
from homeassistant.util.percentage import (
    percentage_to_ranged_value,
    ranged_value_to_percentage,
)

from .dao import DeviceModel
from .entity import BaseEntity, BaseEntityDesc

if TYPE_CHECKING:
    from .coordinator import Coordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry, async_add_entities):
    """Perform the setup for AirMate Fan devices."""
    coordinator = config_entry.coordinator

    # Main entity has no description
    desc = None

    entities = [
        AirMateFan(coordinator, device, desc)
        for device in coordinator.account.devices
        if device.type == "fan"
    ]

    async_add_entities(entities)


# mode: 0-标准风, 1-婴儿风, 2-暴风
ORDERED_NAMED_MODES = ["normal", "low", "high"]

# downshift: 1-32
SPEED_RANGE = (1, 32)


class AirMateFan(BaseEntity, FanEntity):
    """A AirMate Fan."""

    def __init__(
        self, coordinator: Coordinator, model: DeviceModel, desc: BaseEntityDesc | None
    ) -> None:
        """Initialize the Fan."""
        super().__init__(coordinator, model, desc)

        self._attr_supported_features = (
            FanEntityFeature.OSCILLATE
            | FanEntityFeature.PRESET_MODE
            | FanEntityFeature.SET_SPEED
            | FanEntityFeature.TURN_OFF
            | FanEntityFeature.TURN_ON
        )

        self._attr_preset_modes = ORDERED_NAMED_MODES[1:]
        self._attr_preset_mode = None

        self._attr_oscillating = False
        self._attr_percentage = 0

    def index_to_mode(self, index=0) -> str:
        """Get mode by index."""

        return (
            ORDERED_NAMED_MODES[index]
            if 0 <= index < len(ORDERED_NAMED_MODES)
            else ORDERED_NAMED_MODES[0]
        )

    def mode_to_index(self, mode: str) -> int:
        """Get index by mode."""

        return ORDERED_NAMED_MODES.index(mode) if mode in ORDERED_NAMED_MODES else 0

    def percentage_to_speed(self, percentage: int) -> int:
        """Get speed by percentage."""
        return math.ceil(percentage_to_ranged_value(SPEED_RANGE, percentage))

    def speed_to_percentage(self, speed: int) -> int:
        """Get percentage by speed."""
        return ranged_value_to_percentage(SPEED_RANGE, speed)

    def get_last_percentage(self) -> int:
        """Get last speed."""
        dp_status = self.model.get("dp_status", {})

        return self.speed_to_percentage(dp_status.get("downshift", 1))

    async def async_turn_on(
        self, percentage: int | None = None, preset_mode: str | None = None, **kwargs
    ) -> None:
        """Turn on the fan."""

        # power_switch: 0, 1
        # mode: 0-标准风, 1-婴儿风, 2-暴风
        # downshift: 1-32
        data = {
            "power_switch": 1,
            "mode": self.mode_to_index("normal"),
            "downshift": self.get_last_percentage(),
        }

        if percentage is not None and percentage > 0:
            data["downshift"] = self.percentage_to_speed(percentage)

        if preset_mode is not None:
            data["mode"] = self.mode_to_index(preset_mode)

        # Turn off if speed is 0
        if data["downshift"] <= 0:
            await self.async_turn_off()
            return

        await self.account.push_entity_state(self, data)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn on the fan."""
        await self.account.push_entity_state(self, {"power_switch": 0})

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set the preset mode of the fan."""
        await self.async_turn_on(preset_mode=preset_mode)

    async def async_set_percentage(self, percentage: int) -> None:
        """Set the speed percentage of the fan."""
        await self.async_turn_on(percentage=percentage)

    async def async_oscillate(self, oscillating: bool) -> None:
        """Oscillate the fan."""

        _LOGGER.info("Oscillate: %s", oscillating)

        # horizontal_swing: 0-关摆头, 1-开摆头, 2-30°摆头, 3-60°摆头, 4-90°摆头
        await self.account.push_entity_state(
            self, {"horizontal_swing": 3 if oscillating else 0}
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""

        dp_status: dict = self.model.get("dp_status", {})

        is_on = dp_status.get("power_switch", 0) == 1
        mode = self.index_to_mode(dp_status.get("mode", 0))
        percentage = self.speed_to_percentage(dp_status.get("downshift", 1))

        # _LOGGER.info("Updating model of %s: %s", self.model.name, dp_status)

        # Update state
        self._attr_percentage = percentage if is_on else 0
        self._attr_preset_mode = mode if mode != "normal" else None
        self._attr_oscillating = dp_status.get("horizontal_swing", 0) != 0

        # self.async_write_ha_state()
        super()._handle_coordinator_update()
