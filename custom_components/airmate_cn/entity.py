"""Base for all entities."""

from __future__ import annotations

import logging

from attr import dataclass

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Coordinator
from .dao import DeviceModel

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class BaseEntityDesc(EntityDescription):
    """Class describing for Entity."""

    device_class: BaseEntity | str | None = None


class BaseEntity(CoordinatorEntity[Coordinator]):
    """Common base for all entities."""

    _attr_has_entity_name = True

    model: DeviceModel

    def __init__(
        self,
        coordinator: Coordinator,
        model: DeviceModel,
        desc: BaseEntityDesc | None = None,
    ) -> None:
        """Initialize entity."""
        super().__init__(coordinator)

        self.model = model

        # Add entity description if provided
        if desc:
            self.entity_description = desc

        # Main entity
        if not hasattr(self, "entity_description"):
            # Reset name if no description
            self._attr_name = ""

        self._attr_unique_id = f"{DOMAIN}_{self.full_type.replace(".", "_")}_{model.id}"

        self._attr_device_info = DeviceInfo(
            serial_number=model.serial_number,
            manufacturer=model.brand_name,
            identifiers={(DOMAIN, model.id)},
            model=f"{DOMAIN}.{self.full_type}",
            name=model.name,
        )

        # _LOGGER.info(
        #     "Entity.setup_entity: %s - %s", self._attr_unique_id, self._attr_device_info
        # )

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    @property
    def type(self):
        """Return type of entity."""
        return self.model.type

    @property
    def full_type(self):
        """Return full type of entity."""

        sub_type = (
            self.entity_description.key if hasattr(self, "entity_description") else ""
        )

        return f"{self.type}.{sub_type}" if sub_type else self.type

    @property
    def account(self):
        """Return account."""
        return self.coordinator.account
