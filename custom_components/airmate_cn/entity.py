"""Base for all entities."""

from __future__ import annotations

import logging

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Coordinator
from .dao import DeviceModel

_LOGGER = logging.getLogger(__name__)


class BaseEntity(CoordinatorEntity[Coordinator]):
    """Common base for all entities."""

    _attr_has_entity_name = True

    model: DeviceModel

    def __init__(
        self,
        coordinator: Coordinator,
        model: DeviceModel,
    ) -> None:
        """Initialize entity."""
        super().__init__(coordinator)

        self.model = model

        self._attr_name = model.name
        self._attr_unique_id = f"{DOMAIN}_{model.type}_{model.id}"

        self._attr_device_info = DeviceInfo(
            serial_number=model.serial_number,
            manufacturer=model.brand_name,
            identifiers={(DOMAIN, model.id)},
            model=f"{DOMAIN}.{model.type}",
            name=model.name,
        )

        _LOGGER.info(
            "Entity.setup_device: %s - %s", self._attr_unique_id, self._attr_device_info
        )

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    @property
    def account(self):
        """Return account."""
        return self.coordinator.account
