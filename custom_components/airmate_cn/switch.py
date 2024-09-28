"""Platform for AirMate Fan integration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant, callback

from .dao import DeviceModel
from .entity import BaseEntity, BaseEntityDesc

if TYPE_CHECKING:
    from .coordinator import Coordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry, async_add_entities):
    """Perform the setup for AirMate Fan devices."""
    coordinator = config_entry.coordinator

    # Vertical Swing switch
    desc = BaseEntityDesc(
        key="vertical_swing",
        name="Vertical Swing",
    )

    entities = [
        AirMateSwitch(coordinator, device, desc)
        for device in coordinator.account.devices
        if device.type == "fan"
    ]

    async_add_entities(entities)


class AirMateSwitch(BaseEntity, SwitchEntity):
    """A switch for AirMate Fan."""

    def __init__(
        self, coordinator: Coordinator, model: DeviceModel, desc: BaseEntityDesc
    ) -> None:
        """Initialize the vertical_swing for Fan."""
        super().__init__(coordinator, model, desc)

        self._attr_is_on = False

    async def async_turn_on(self) -> None:
        """Turn the vertical_swing on."""
        await self.account.push_entity_state(self, {"vertical_swing": 1})

    async def async_turn_off(self) -> None:
        """Turn the vertical_swing off."""
        await self.account.push_entity_state(self, {"vertical_swing": 0})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""

        dp_status: dict = self.model.get("dp_status", {})

        # Update state
        self._attr_is_on = dp_status.get("vertical_swing", 0) == 1

        # self.async_write_ha_state()
        super()._handle_coordinator_update()
