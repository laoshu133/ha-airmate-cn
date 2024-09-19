"""Config flow for AirMate integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

# from homeassistant.core import HomeAssistant
from .account import Account
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME, "Phone Number"): str,
        vol.Required(CONF_PASSWORD, "Password"): str,
    }
)


class ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for AirMate."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                account = Account(user_input)
                house = await account.api.get_default_house()

                # Add init tokens
                user_input["init_tokens"] = await account.api.get_tokens()
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                username = user_input[CONF_USERNAME]
                title = "AirMate CN - " + house.villageName

                await self.async_set_unique_id(username)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(title=title, data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )
