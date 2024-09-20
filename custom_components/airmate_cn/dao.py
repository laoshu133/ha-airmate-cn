"""Data Models."""

# import asyncio
from dataclasses import dataclass
import logging

# from .api_utils import AuthError
# from .utils import get_now

_LOGGER = logging.getLogger(__name__)


@dataclass
class DeviceModel:
    """Device Model."""

    data: dict

    def __init__(self, data: dict) -> None:
        """Initialize model."""
        self.data = {}

        self.update(data)

    @property
    def id(self) -> str:
        """Get id of the model."""
        return self.data.get("id", self.data.get("device_id", ""))

    @property
    def type(self) -> str:
        """Get type of the model."""
        return self.data.get("type", "")

    @property
    def name(self) -> str:
        """Get name of the model."""
        return self.data.get("name", "")

    @property
    def brand_name(self) -> str:
        """Get brand_name of the model."""
        return self.data.get("brand_name", "")

    @property
    def serial_number(self) -> str:
        """Get serial_number of the model."""
        return self.data.get("serial_number", self.id)

    def get(self, key: str, default_val="", base_key: str | None = None):
        """Get value by key."""

        data = self.data if not base_key else self.data.get(base_key, {})
        return data.get(key, default_val)

    def update(self, data: dict, base_key: str | None = None) -> None:
        """Update the state."""

        dist = self.data if not base_key else self.data.setdefault(base_key, {})
        dist.update(data)
