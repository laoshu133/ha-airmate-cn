"""Diagnostics without credentials, identifiers, topics, IPs or raw messages."""


async def async_get_config_entry_diagnostics(hass, entry):
    coordinator = entry.runtime_data
    return {
        "transport": "mqtt",
        "online": coordinator.online,
        "reported_properties": dict(coordinator.data),
        "stale_timeout": coordinator.stale_timeout,
        "verified_controls": [
            "power_switch",
            "downshift",
            "horizontal_swing",
            "vertical_swing",
        ],
    }
