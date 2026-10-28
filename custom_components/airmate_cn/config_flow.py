"""One local device per entry, with credentials owned by HA's MQTT integration."""

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlowWithConfigEntry
from homeassistant.const import CONF_NAME

from .const import CONF_DEVICE_ID, CONF_PRODUCT_ID, DOMAIN
from .protocol import valid_identifier

SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, default="循环扇"): vol.All(
            str, vol.Length(min=1, max=64)
        ),
        vol.Required(CONF_PRODUCT_ID): str,
        vol.Required(CONF_DEVICE_ID): str,
    }
)


class AirMateConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 2

    @staticmethod
    def async_get_options_flow(config_entry):
        return AirMateOptionsFlow(config_entry)

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


class AirMateOptionsFlow(OptionsFlowWithConfigEntry):
    """Allow an existing device entry to be renamed or retargeted."""

    async def async_step_init(self, user_input=None):
        errors = {}
        if user_input is not None:
            name = user_input[CONF_NAME].strip()
            product_id = user_input[CONF_PRODUCT_ID].strip()
            device_id = user_input[CONF_DEVICE_ID].strip()
            if not valid_identifier(product_id) or not valid_identifier(device_id):
                errors["base"] = "invalid_identifier"
            elif not name:
                errors[CONF_NAME] = "invalid_name"
            else:
                unique_id = f"{product_id}/{device_id}"
                duplicate = any(
                    entry.entry_id != self.config_entry.entry_id
                    and entry.unique_id == unique_id
                    for entry in self.hass.config_entries.async_entries(DOMAIN)
                )
                if duplicate:
                    errors["base"] = "already_configured"
                else:
                    self.hass.config_entries.async_update_entry(
                        self.config_entry,
                        title=name,
                        data={
                            CONF_PRODUCT_ID: product_id,
                            CONF_DEVICE_ID: device_id,
                        },
                        unique_id=unique_id,
                    )
                    return self.async_create_entry(title="", data={})

        current = self.config_entry.data
        schema = vol.Schema(
            {
                vol.Required(CONF_NAME, default=self.config_entry.title): vol.All(
                    str, vol.Length(min=1, max=64)
                ),
                vol.Required(
                    CONF_PRODUCT_ID, default=current.get(CONF_PRODUCT_ID, "")
                ): str,
                vol.Required(
                    CONF_DEVICE_ID, default=current.get(CONF_DEVICE_ID, "")
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
