"""Verified horizontal swing angles; generic value 1 remains read-only."""

from homeassistant.components.select import SelectEntity

from .entity import BaseEntity
from .protocol import HORIZONTAL_CONTROL_OPTIONS


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([AirMateHorizontalSwing(entry.runtime_data)])


class AirMateHorizontalSwing(BaseEntity, SelectEntity):
    _attr_translation_key = "horizontal_swing"
    _attr_options = list(HORIZONTAL_CONTROL_OPTIONS.values())

    def __init__(self, coordinator):
        super().__init__(coordinator, "horizontal_swing")
        del self._attr_name

    @property
    def current_option(self) -> str | None:
        return HORIZONTAL_CONTROL_OPTIONS.get(
            self.coordinator.data.get("horizontal_swing")
        )

    async def async_select_option(self, option: str) -> None:
        value = {label: code for code, label in HORIZONTAL_CONTROL_OPTIONS.items()}[
            option
        ]
        await self.coordinator.async_set_horizontal(value)
