"""Read-only properties; receiving a property does not prove it is writable."""

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
)

from .entity import BaseEntity
from .protocol import HORIZONTAL_OPTIONS, MODE_OPTIONS

ENUMS = {
    "horizontal_swing": HORIZONTAL_OPTIONS,
    "mode": MODE_OPTIONS,
    "vertical_swing": {0: "off", 1: "on"},
    "light": {0: "off", 1: "on"},
    "mute": {0: "off", 1: "on"},
}
DESCRIPTIONS = (
    SensorEntityDescription(
        key="downshift", translation_key="downshift", icon="mdi:fan"
    ),
    *(
        SensorEntityDescription(
            key=key,
            translation_key=key,
            device_class=SensorDeviceClass.ENUM,
            options=list(values.values()),
        )
        for key, values in ENUMS.items()
    ),
)


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities(
        [AirMateSensor(entry.runtime_data, description) for description in DESCRIPTIONS]
    )


class AirMateSensor(BaseEntity, SensorEntity):
    def __init__(self, coordinator, description) -> None:
        super().__init__(
            coordinator,
            f"reported_{description.key}",
            state_keys={description.key},
        )
        self.entity_description = description
        # Use the translated description name instead of the main entity name.
        del self._attr_name

    @property
    def native_value(self):
        key = self.entity_description.key
        value = self.coordinator.data.get(key)
        return ENUMS[key].get(value) if key in ENUMS else value
