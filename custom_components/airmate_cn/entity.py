"""Shared identity and availability for local entities."""

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Coordinator


class BaseEntity(CoordinatorEntity[Coordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: Coordinator, key: str | None = None) -> None:
        super().__init__(coordinator)
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
        return self.coordinator.online or bool(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, bool] | None:
        if self.coordinator.data and not self.coordinator.online:
            return {"state_source": "last_known"}
        return None
