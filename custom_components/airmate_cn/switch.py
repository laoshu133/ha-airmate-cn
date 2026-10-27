"""Verified vertical swing control."""

from homeassistant.components.switch import SwitchEntity

from .entity import BaseEntity


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([AirMateVerticalSwing(entry.runtime_data)])


class AirMateVerticalSwing(BaseEntity, SwitchEntity):
    _attr_translation_key = "vertical_swing"

    def __init__(self, coordinator):
        super().__init__(coordinator, "vertical_swing")
        del self._attr_name

    @property
    def is_on(self) -> bool | None:
        value = self.coordinator.data.get("vertical_swing")
        return None if value is None else value == 1

    async def async_turn_on(self, **kwargs) -> None:
        await self.coordinator.async_set_vertical(1)

    async def async_turn_off(self, **kwargs) -> None:
        await self.coordinator.async_set_vertical(0)
