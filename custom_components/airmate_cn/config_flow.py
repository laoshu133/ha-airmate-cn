"""One local device per entry, with credentials owned by HA's MQTT integration."""

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow
from homeassistant.const import CONF_NAME

from .const import CONF_DEVICE_ID, CONF_PRODUCT_ID, DOMAIN
from .protocol import valid_identifier

SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, default="AirMate"): vol.All(
            str, vol.Length(min=1, max=64)
        ),
        vol.Required(CONF_PRODUCT_ID): str,
        vol.Required(CONF_DEVICE_ID): str,
    }
)


class AirMateConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 2

    async def async_step_user(self, user_input=None):
        if not any(
            entry.disabled_by is None
            for entry in self.hass.config_entries.async_entries("mqtt")
        ):
            return self.async_abort(reason="mqtt_required")
        errors = {}
        if user_input is not None:
            if not all(
                valid_identifier(user_input[key])
                for key in (CONF_PRODUCT_ID, CONF_DEVICE_ID)
            ):
                errors["base"] = "invalid_identifier"
            elif (
                not isinstance(user_input[CONF_NAME], str)
                or not user_input[CONF_NAME].strip()
            ):
                errors[CONF_NAME] = "invalid_name"
            else:
                await self.async_set_unique_id(
                    f"{user_input[CONF_PRODUCT_ID]}/{user_input[CONF_DEVICE_ID]}"
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_NAME].strip(),
                    data={
                        CONF_PRODUCT_ID: user_input[CONF_PRODUCT_ID],
                        CONF_DEVICE_ID: user_input[CONF_DEVICE_ID],
                    },
                )
        return self.async_show_form(step_id="user", data_schema=SCHEMA, errors=errors)
