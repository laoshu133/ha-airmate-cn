#!/usr/bin/env python3
"""Discover AirMate product/device IDs from one temporary MQTT observation.

The observer account must temporarily have read access to ``#``. The script
prints only the topic and IDs, never the MQTT payload or credentials. Remove
the wildcard ACL after discovery and configure the integration with the two
reported IDs.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import select
import socket
import struct
import time

IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def mqtt_string(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("!H", len(encoded)) + encoded


def frame(kind: int, body: bytes) -> bytes:
    length = len(body)
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (0x80 if length else 0))
        if not length:
            return bytes([kind]) + encoded + body


def read_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise ConnectionError("MQTT connection closed")
        result.extend(chunk)
    return bytes(result)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    kind = read_exact(sock, 1)[0]
    length = 0
    multiplier = 1
    for _ in range(4):
        digit = read_exact(sock, 1)[0]
        length += (digit & 127) * multiplier
        if not digit & 128:
            return kind, read_exact(sock, length)
        multiplier *= 128
    raise ValueError("Invalid MQTT remaining length")


def discover(args: argparse.Namespace) -> dict[str, str]:
    password = args.password or getpass.getpass("MQTT observer password: ")
    client_id = f"airmate-discover-{int(time.time())}"
    body = mqtt_string("MQTT") + bytes([4, 0xC2]) + b"\x00\x3c"
    body += mqtt_string(client_id) + mqtt_string(args.username) + mqtt_string(password)
    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(frame(0x10, body))
        if read_frame(sock) != (0x20, b"\x00\x00"):
            raise RuntimeError("MQTT observer authentication was rejected")
        sock.sendall(frame(0x82, b"\x00\x01" + mqtt_string("#") + b"\x00"))
        if read_frame(sock) != (0x90, b"\x00\x01\x00"):
            raise RuntimeError("MQTT wildcard subscription was rejected")
        deadline = time.monotonic() + args.seconds
        last_ping = time.monotonic()
        while time.monotonic() < deadline:
            wait = min(1.0, max(0.0, deadline - time.monotonic()))
            if not select.select([sock], [], [], wait)[0]:
                if time.monotonic() - last_ping >= 20:
                    sock.sendall(b"\xc0\x00")
                    last_ping = time.monotonic()
                continue
            kind, payload = read_frame(sock)
            if kind == 0xD0:
                continue
            if kind >> 4 != 3 or (kind >> 1) & 3:
                continue
            topic_size = int.from_bytes(payload[:2], "big")
            topic = payload[2 : 2 + topic_size].decode("utf-8", errors="replace")
            if not topic.endswith("/data") or kind & 1:
                continue
            try:
                message = json.loads(payload[2 + topic_size :])
            except (ValueError, UnicodeError):
                continue
            product_id = message.get("product_id")
            device_id = message.get("device_id")
            parts = topic.split("/")
            if (
                message.get("command") == 300014
                and isinstance(product_id, str)
                and isinstance(device_id, str)
                and IDENTIFIER.fullmatch(product_id)
                and IDENTIFIER.fullmatch(device_id)
                and parts[-3:-1] == [product_id, device_id]
            ):
                return {"topic": topic, "product_id": product_id, "device_id": device_id}
        raise TimeoutError("No valid AirMate data message observed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="MQTT broker host")
    parser.add_argument("--port", type=int, default=3866)
    parser.add_argument("--username", required=True, help="Temporary read-only observer account")
    parser.add_argument("--password", help="Prefer an interactive prompt when omitted")
    parser.add_argument("--seconds", type=int, default=90)
    args = parser.parse_args()
    result = discover(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
