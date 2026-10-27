"""Synthetic protocol fixtures only; no captured identities or credentials."""

import json
import unittest

from custom_components.airmate_cn.protocol import Protocol


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.protocol = Protocol("testproduct", "testdevice")

    def payload(self, data, **extra):
        return json.dumps(
            dict(
                command=300014,
                product_id="testproduct",
                device_id="testdevice",
                data=data,
            )
            | extra
        )

    def test_partial_report_without_method(self):
        report = self.protocol.decode(
            self.protocol.up_topic, self.payload({"downshift": 11})
        )
        self.assertEqual(report.properties, {"downshift": 11})
        self.assertNotIn("power_switch", report.properties)

    def test_ranges_and_types(self):
        report = self.protocol.decode(
            self.protocol.up_topic,
            self.payload(
                {
                    "power_switch": True,
                    "downshift": 33,
                    "horizontal_swing": 1,
                    "mode": "0",
                    "light": -1,
                }
            ),
        )
        self.assertEqual(report.properties, {"horizontal_swing": 1})
        for key, value in (("downshift", 0), ("mode", 3), ("vertical_swing", 2)):
            self.assertIsNone(
                self.protocol.decode(self.protocol.up_topic, self.payload({key: value}))
            )

    def test_reject_bad_envelopes(self):
        good = self.payload({"power_switch": 1})
        for payload in [
            "{",
            "[]",
            "null",
            "x" * 16385,
            b"\xff",
            self.payload([], method=""),
            self.payload({"power_switch": 1}, device_id="other"),
            self.payload({"power_switch": 1}, product_id="other"),
            self.payload({"power_switch": 1}, command=300013),
            self.payload({"power_switch": 1}, command=300014.0),
            self.payload({"power_switch": 1}, method="unsupported"),
        ]:
            with self.subTest(payload=str(payload)[:80]):
                self.assertIsNone(self.protocol.decode(self.protocol.up_topic, payload))
        self.assertIsNone(
            self.protocol.decode(self.protocol.up_topic, good, retained=True)
        )
        self.assertIsNone(self.protocol.decode("other/topic", good))

    def test_base_and_time_not_properties(self):
        report = self.protocol.decode(
            self.protocol.up_topic,
            self.payload(
                {"firmware_version": "1.0.4", "power_switch": 1},
                method="thing.base.status",
            ),
        )
        self.assertEqual(report.firmware, "1.0.4")
        self.assertEqual(report.properties, {})
        self.assertIsNotNone(
            self.protocol.decode(
                self.protocol.up_topic,
                self.payload({"countdown_time": []}, method="thing.time"),
            )
        )

    def test_identifier_validation(self):
        for value in ["", "#", "+", "a/b", " a", "a\n", "x" * 65, None]:
            with self.assertRaises(ValueError):
                Protocol(value, "device")

    def test_power_command_and_unique_ids(self):
        first = json.loads(self.protocol.encode_power(0))
        second = json.loads(self.protocol.encode_power(1))
        self.assertEqual(first["data"], {"power_switch": 0})
        self.assertEqual(first["command"], 300013)
        self.assertEqual(first["method"], "thing.property.update")
        self.assertEqual(first["device_id"], "testdevice")
        self.assertNotIn("product_id", first)
        self.assertNotEqual(first["msg_id"], second["msg_id"])
        for invalid in [True, -1, 2, "1"]:
            with self.assertRaises(ValueError):
                self.protocol.encode_power(invalid)

    def test_only_verified_property_shapes_and_values(self):
        for data in [
            {"mode": 1},
            {"mute": 1},
            {"horizontal_swing": 1},
            {"downshift": 33},
            {"vertical_swing": 2},
            {"power_switch": 0, "mode": 0, "downshift": 10},
            {"power_switch": 1, "mode": 1, "downshift": 10},
        ]:
            with self.assertRaises(ValueError):
                self.protocol.encode_properties(data)
        for data in [
            {"downshift": 10},
            {"power_switch": 1, "mode": 0, "downshift": 10},
            {"horizontal_swing": 4},
            {"vertical_swing": 1},
        ]:
            self.assertEqual(
                json.loads(self.protocol.encode_properties(data))["data"], data
            )
