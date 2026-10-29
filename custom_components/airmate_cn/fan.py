"""Verified power, staged speed, mode and horizontal oscillation control."""

import math

from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util.percentage import (
    percentage_to_ranged_value,
    ranged_value_to_percentage,
)

from .entity import BaseEntity
from .protocol import MODE_OPTIONS

SPEED_RANGE = (1, 32)


def percentage_to_speed(percentage: int) -> int:
    if type(percentage) is not int or not 1 <= percentage <= 100:
        raise ValueError("Speed percentage must be 1 to 100")
    return math.ceil(percentage_to_ranged_value(SPEED_RANGE, percentage))


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([AirMateFan(entry.runtime_data)])


class AirMateFan(BaseEntity, FanEntity):
    _airmate_state_keys = frozenset(
        {"power_switch", "downshift", "horizontal_swing"}
    )
    _attr_supported_features = (
        FanEntityFeature.TURN_ON
        | FanEntityFeature.TURN_OFF
        | FanEntityFeature.SET_SPEED
        | FanEntityFeature.OSCILLATE
        | FanEntityFeature.PRESET_MODE
    )
    _attr_speed_count = 32
    _attr_preset_modes = list(MODE_OPTIONS.values())

    @property
    def is_on(self) -> bool | None:
        power = self.coordinator.data.get("power_switch")
        return None if power is None else power == 1

    @property
    def percentage(self) -> int | None:
        if self.is_on is False:
            return 0
        speed = self.coordinator.data.get("downshift")
        return None if speed is None else ranged_value_to_percentage(SPEED_RANGE, speed)

    @property
    def oscillating(self) -> bool | None:
        value = self.coordinator.data.get("horizontal_swing")
        return None if value is None else value != 0

    @property
    def preset_mode(self) -> str | None:
        return MODE_OPTIONS.get(self.coordinator.data.get("mode"))

    async def async_turn_on(self, percentage=None, preset_mode=None, **kwargs) -> None:
        if preset_mode is not None:
            try:
                mode = next(
                    value for value, label in MODE_OPTIONS.items() if label == preset_mode
                )
            except StopIteration as err:
                raise HomeAssistantError("Unsupported AirMate preset mode") from err
            await self.coordinator.async_set_mode(mode)
            return
        if percentage is not None:
            await self.async_set_percentage(percentage)
            return
        await self.coordinator.async_set_power(1)

    async def async_turn_off(self, **kwargs) -> None:
        await self.coordinator.async_set_power(0)

    async def async_set_percentage(self, percentage: int) -> None:
        if percentage == 0 and type(percentage) is int:
            await self.async_turn_off()
            return
        await self.coordinator.async_set_speed(percentage_to_speed(percentage))

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        await self.async_turn_on(preset_mode=preset_mode)

    async def async_oscillate(self, oscillating: bool) -> None:
        await self.coordinator.async_set_horizontal(3 if oscillating else 0)
