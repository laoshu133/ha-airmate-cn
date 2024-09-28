"""Coordinator base on API."""

from __future__ import annotations

import logging

from httpx import RequestError

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .account import Account
from .api_utils import APIError, AuthError
from .const import AUTH_VALID_OFFSET, DOMAIN

_LOGGER = logging.getLogger(__name__)


class Coordinator(DataUpdateCoordinator[None]):
    """Class to manage fetching data."""

    account: Account

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize a data updater."""

        self.config_entry = entry

        # Init account
        entry_data = entry.data.copy()
        self.account = Account(config=entry_data)

        # Remove init token from entry data
        _LOGGER.debug("Coordinator.update_config: %s", entry_data)
        hass.config_entries.async_update_entry(self.config_entry, data=entry_data)

        # Force update data when init
        hass.config_entries.async_update_entry(self.config_entry, data=entry.data)

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}.{entry.entry_id}",
            update_interval=AUTH_VALID_OFFSET * 2,
        )

        # Default to false on init so _async_update_data logic works
        self.last_update_success = False

    async def _async_update_data(self) -> None:
        """Fetch devices state from API."""
        try:
            await self.account.fetch_devices_state()
        except AuthError as err:
            raise ConfigEntryAuthFailed(err) from err
        except (APIError, RequestError) as err:
            raise UpdateFailed(err) from err
