"""Local MQTT integration for AirMate fans."""

from __future__ import annotations

import logging

from homeassistant.components import mqtt
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.exceptions import ConfigEntryNotReady

from .coordinator import Coordinator

PLATFORMS = [Platform.FAN, Platform.SENSOR, Platform.SELECT, Platform.SWITCH]
_LOGGER = logging.getLogger(__name__)
type AirMateConfigEntry = ConfigEntry[Coordinator]


async def async_setup_entry(hass, entry: AirMateConfigEntry) -> bool:
    if not await mqtt.async_wait_for_mqtt_client(hass):
        raise ConfigEntryNotReady("Configure the Home Assistant MQTT integration first")
    coordinator = entry.runtime_data = Coordinator(hass, entry)
    await coordinator.async_start()
    entry.async_on_unload(coordinator.async_close)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except BaseException:
        coordinator.async_close()
        raise
    return True


async def _async_update_listener(hass, entry: AirMateConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass, entry: AirMateConfigEntry) -> bool:
    if await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        entry.runtime_data.async_close()
        return True
    return False


async def async_migrate_entry(hass, entry: AirMateConfigEntry) -> bool:
    if entry.version < 2:
        _LOGGER.error(
            "The legacy cloud account cannot be migrated automatically. Remove the old "
            "AirMate entry and add one local MQTT entry per device; see README migration steps"
        )
        return False
    return entry.version == 2
