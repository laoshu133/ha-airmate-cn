"""Platform for AirMate Fan integration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant, callback

from .dao import DeviceModel
from .entity import BaseEntity

if TYPE_CHECKING:
    from .coordinator import Coordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry, async_add_entities):
    """Perform the setup for AirMate Fan devices."""
    coordinator = config_entry.coordinator

    entities = [
        AirMateSelect(coordinator, device)
        for device in coordinator.account.devices
        if device.type == "fan"
    ]

    async_add_entities(entities)


class AirMateSelect(BaseEntity, SelectEntity):
    """A select for AirMate Fan."""

    def __init__(self, coordinator: Coordinator, model: DeviceModel) -> None:
        """Initialize the horizontal_swing for Fan."""
        super().__init__(coordinator, model)

        # horizontal_swing: 0-关摆头, 1-开摆头, 2-30°摆头, 3-60°摆头, 4-90°摆头, 5-120°摆头
        self._attr_options = ["Off", "30°", "60°", "90°", "120°"]
        self._attr_current_option = "Off"

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        index = self._attr_options.index(option)

        # 修正缺失选项 「1-开摆头」
        if index > 0:
            index += 1

        await self.account.push_entity_state(self, {"horizontal_swing": index})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""

        dp_status: dict = self.model.get("dp_status", {})

        # Update state
        self._attr_current_option = dp_status.get("horizontal_swing", 0) == 1

        # self.async_write_ha_state()
        super()._handle_coordinator_update()
