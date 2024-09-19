"""Access to a Account."""

from base64 import b64decode
import json
import logging

from .api import API, APIAuth
from .const import API_BASE_CFG
from .dao import DeviceModel

_LOGGER = logging.getLogger(__name__)


class Account:
    """Create a new connection to the service."""

    devices: list[DeviceModel] = []

    def __init__(self, config: dict) -> None:
        """Initialize the account."""

        _LOGGER.info("Account.init: %s", config)

        # Get init tokens from config and remove it
        init_tokens: dict = config.get("init_tokens") or {}
        config.pop("init_token")

        # Read config from .const with base64 and json decode
        api_config: dict[str, str] = json.loads(b64decode(API_BASE_CFG).decode())

        # Only for debugging
        api_config.update(
            {
                "all_proxy_url": "http://172.16.3.33:8888",
                "ssl_verify_pem": "/workspaces/proxyman-ca.pem",
            }
        )

        self.api = API(
            **api_config,
            auth=APIAuth(api_config=api_config, **config, **init_tokens),
        )

        self.devices = []
        self.fetched_at = None

    async def get_devices(self, force_init: bool = False) -> list[DeviceModel]:
        """Retrieve device data from services."""

        # Only support 1 house
        if len(self.devices) == 0 or force_init:
            self.devices = [
                DeviceModel(device) for device in await self.api.get_devices()
            ]

        return self.devices

    async def fetch_devices_state(self) -> None:
        """Fetch devices state from API."""
        devices = await self.get_devices()
        params = [
            {"device_id": device.id, "product_key": device.get("product_key")}
            for device in devices
        ]

        # Fetch states
        states = await self.api.fetch_devices_state(params)

        # Update devices state
        if len(states) > 0:
            devices_map = {device.id: device for device in devices}

            for state in states:
                device_id = state["device_id"]
                if device_id in devices_map:
                    devices_map[device_id].update(
                        {
                            "online_status": state["online_status"],
                            "dp_status": state["dp_status"],
                            "base_info": state["base_info"],
                        }
                    )
