"""Observed AirMate MQTT protocol, independent of Home Assistant.

Power, staged speed, mode and selected swing writes are verified; light and
mute remain read-only until their device behavior is confirmed.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime

IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
LIMITS = {
    "power_switch": (0, 1),
    "downshift": (1, 32),
    "mode": (0, 2),
    "horizontal_swing": (0, 4),
    "vertical_swing": (0, 1),
    "mute": (0, 1),
    "light": (0, 1),
}
HORIZONTAL_OPTIONS = {0: "off", 1: "on", 2: "30°", 3: "60°", 4: "90°"}
HORIZONTAL_CONTROL_OPTIONS = {0: "off", 2: "30°", 3: "60°", 4: "90°"}
MODE_OPTIONS = {0: "normal", 1: "baby", 2: "strong"}


def valid_identifier(value: object) -> bool:
    """Reject MQTT wildcards, slashes, whitespace and empty identifiers."""
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


@dataclass(frozen=True)
class Report:
    properties: dict[str, int]
    firmware: str | None = None


class Protocol:
    """Validate reports and encode only experimentally verified commands."""

    def __init__(self, product_id: str, device_id: str) -> None:
        if not valid_identifier(product_id) or not valid_identifier(device_id):
            raise ValueError("Invalid product or device identifier")
        self.product_id = product_id
        self.device_id = device_id
        self.up_topic = f"{product_id}/{device_id}/data"
        self.down_topic = f"{product_id}/{device_id}/rrpc"
        self._last_timestamp = 0

    def decode(
        self, topic: str, payload: str | bytes, *, retained: bool = False
    ) -> Report | None:
        """Ignore stale, malformed, cross-device and unsupported messages."""
        if retained or topic != self.up_topic or len(payload) > 16384:
            return None
        try:
            message = json.loads(payload)
        except (ValueError, UnicodeError, RecursionError):
            return None
        if not isinstance(message, dict):
            return None
        if (
            type(message.get("command")) is not int
            or message["command"] != 300014
            or message.get("product_id") != self.product_id
            or message.get("device_id") != self.device_id
        ):
            return None
        data = message.get("data")
        if not isinstance(data, dict):
            return None
        method = message.get("method")
        if method == "thing.base.status":
            firmware = data.get("firmware_version")
            if isinstance(firmware, str) and 0 < len(firmware) <= 64:
                return Report({}, firmware)
            return None
        if method == "thing.time":
            return Report({}) if isinstance(data.get("countdown_time"), list) else None
        if method not in (None, ""):
            return None
        properties = {
            key: value
            for key, value in data.items()
            if key in LIMITS
            and type(value) is int
            and LIMITS[key][0] <= value <= LIMITS[key][1]
        }
        return Report(properties) if properties else None

    def encode_power(self, power: int) -> str:
        return self.encode_properties({"power_switch": power})

    @staticmethod
    def validate_properties(data: dict[str, int]) -> None:
        """Allow only verified property shapes, including speed preparation."""
        allowed = (
            {"power_switch"},
            {"downshift"},
            {"horizontal_swing"},
            {"vertical_swing"},
            {"power_switch", "mode", "downshift"},
        )
        if set(data) not in allowed:
            raise ValueError("Unsupported command properties")
        if any(
            type(value) is not int or not LIMITS[key][0] <= value <= LIMITS[key][1]
            for key, value in data.items()
        ):
            raise ValueError("Invalid property value")
        if (
            "horizontal_swing" in data
            and data["horizontal_swing"] not in HORIZONTAL_CONTROL_OPTIONS
        ):
            raise ValueError("Generic swing value 1 is not verified")
        if "mode" in data and data["power_switch"] != 1:
            raise ValueError("Mode control requires power on")

    def encode_properties(self, data: dict[str, int]) -> str:
        """Create a compact command with an ID in publication order."""
        self.validate_properties(data)
        timestamp = max(int(time.time() * 1000), self._last_timestamp + 1)
        self._last_timestamp = timestamp
        return json.dumps(
            {
                "command": 300013,
                "method": "thing.property.update",
                "device_id": self.device_id,
                "timestamp": str(timestamp),
                "msg_id": f"{timestamp}ez9u{datetime.now().hour}",
                "data": dict(data),
            },
            separators=(",", ":"),
        )
