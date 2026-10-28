"""Run against the actual Home Assistant image, mocking only MQTT transport."""

import asyncio
import json
import tempfile
import unittest
from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import AbortFlow
from homeassistant.exceptions import HomeAssistantError

from custom_components.airmate_cn import (
    async_migrate_entry,
    async_setup_entry,
    async_unload_entry,
)
from custom_components.airmate_cn.config_flow import (
    AirMateConfigFlow,
    AirMateOptionsFlow,
)
from custom_components.airmate_cn.coordinator import Coordinator
from custom_components.airmate_cn.diagnostics import async_get_config_entry_diagnostics
from custom_components.airmate_cn.fan import AirMateFan
from custom_components.airmate_cn.sensor import DESCRIPTIONS, AirMateSensor


def make_entry(domain="airmate_cn", data=None, **extra):
    return ConfigEntry(
        domain=domain,
        title="Test fan",
        data=data or {"product_id": "testproduct", "device_id": "testdevice"},
        version=2,
        minor_version=1,
        source="user",
        unique_id="testproduct/testdevice",
        options={},
        discovery_keys=MappingProxyType({}),
        subentries_data=None,
        **extra,
    )


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.hass = HomeAssistant(self.directory.name)
        self.hass.config_entries = ConfigEntries(self.hass, {})
        self.entry = make_entry()
        self.hass.config_entries._entries[self.entry.entry_id] = self.entry
        self.coordinator = Coordinator(self.hass, self.entry)
        self.entry.runtime_data = self.coordinator
        self.publish = AsyncMock()
        self.unsubscribe = Mock()
        self.unsubscribe_connection = Mock()
        self.patches = [
            patch(
                "custom_components.airmate_cn.coordinator.mqtt.is_connected",
                return_value=True,
            ),
            patch(
                "custom_components.airmate_cn.coordinator.mqtt.async_subscribe",
                AsyncMock(return_value=self.unsubscribe),
            ),
            patch(
                "custom_components.airmate_cn.coordinator.mqtt.async_subscribe_connection_status",
                return_value=self.unsubscribe_connection,
            ),
            patch(
                "custom_components.airmate_cn.coordinator.mqtt.async_publish",
                self.publish,
            ),
            patch(
                "custom_components.airmate_cn.coordinator.SPEED_COALESCE_DELAY",
                0,
            ),
        ]
        for item in self.patches:
            item.start()
        await self.coordinator.async_start()

    async def asyncTearDown(self):
        self.coordinator.async_close()
        for item in reversed(self.patches):
            item.stop()
        await self.hass.async_stop(force=True)
        self.directory.cleanup()

    def report(self, data, retain=False, **extra):
        self.coordinator._receive(
            SimpleNamespace(
                topic=self.coordinator.protocol.up_topic,
                retain=retain,
                payload=json.dumps(
                    dict(
                        command=300014,
                        product_id="testproduct",
                        device_id="testdevice",
                        data=data,
                    )
                    | extra
                ),
            )
        )

    async def tick(self):
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    async def test_unknown_partial_merge_and_retained(self):
        fan = AirMateFan(self.coordinator)
        self.assertFalse(fan.available)
        self.assertIsNone(fan.is_on)
        self.report({"downshift": 11})
        self.assertTrue(fan.available)
        self.assertIsNone(fan.is_on)
        self.report({"power_switch": 1})
        self.assertEqual(self.coordinator.data, {"downshift": 11, "power_switch": 1})
        self.report({"downshift": 20}, retain=True)
        self.assertEqual(self.coordinator.data["downshift"], 11)

        horizontal = AirMateSensor(
            self.coordinator,
            next(d for d in DESCRIPTIONS if d.key == "horizontal_swing"),
        )
        self.coordinator._expire()
        self.assertFalse(horizontal.available)

    async def test_last_known_state_is_restored(self):
        self.report(
            {
                "power_switch": 1,
                "downshift": 11,
                "horizontal_swing": 3,
                "vertical_swing": 1,
            }
        )
        await asyncio.sleep(0.2)
        await self.hass.async_block_till_done()
        self.coordinator.async_close()

        restored = Coordinator(self.hass, self.entry)
        self.entry.runtime_data = restored
        await restored.async_start()
        self.assertFalse(restored.online)
        self.assertEqual(
            restored.data,
            {
                "power_switch": 1,
                "downshift": 11,
                "horizontal_swing": 3,
                "vertical_swing": 1,
            },
        )
        restored_fan = AirMateFan(restored)
        self.assertTrue(restored_fan.available)
        self.assertEqual(
            restored_fan.extra_state_attributes, {"state_source": "last_known"}
        )
        restored.async_close()
        self.coordinator = restored

    async def test_publish_and_new_report_required(self):
        self.report({"power_switch": 0, "downshift": 11})
        task = asyncio.create_task(self.coordinator.async_set_power(1))
        await self.tick()
        args, kwargs = self.publish.call_args
        self.assertEqual(args[1], "testproduct/testdevice/rrpc")
        self.assertEqual(json.loads(args[2])["data"], {"power_switch": 1})
        self.assertEqual(kwargs, {"qos": 0, "retain": False})
        self.assertEqual(self.coordinator.data["power_switch"], 0)
        self.report({"power_switch": 1}, retain=True)
        self.report({"downshift": 11})
        await self.tick()
        self.assertFalse(task.done())
        self.report({"power_switch": 1})
        await task

    async def test_noop_does_not_publish(self):
        self.report({"power_switch": 1})
        await self.coordinator.async_set_power(1)
        self.publish.assert_not_called()

    async def test_timeout_does_not_mutate_state_or_retry(self):
        self.report({"power_switch": 0})
        with patch("custom_components.airmate_cn.coordinator.COMMAND_TIMEOUT", 0.01):
            with self.assertRaisesRegex(HomeAssistantError, "No matching"):
                await self.coordinator.async_set_power(1)
        self.assertEqual(self.coordinator.data, {"power_switch": 0})
        self.assertEqual(self.publish.await_count, 1)
        self.assertIsNone(self.coordinator._pending)

    async def test_publish_failure(self):
        self.report({"power_switch": 0})
        self.publish.side_effect = OSError("transport failed")
        with self.assertRaisesRegex(HomeAssistantError, "Unable to publish"):
            await self.coordinator.async_set_power(1)
        self.assertEqual(self.coordinator.data["power_switch"], 0)
        self.assertIsNone(self.coordinator._pending)

    async def test_commands_serialized(self):
        self.report({"power_switch": 0})
        first = asyncio.create_task(self.coordinator.async_set_power(1))
        second = asyncio.create_task(self.coordinator.async_set_power(0))
        await self.tick()
        self.assertEqual(self.publish.await_count, 1)
        self.report({"power_switch": 1})
        await first
        await self.tick()
        self.assertEqual(self.publish.await_count, 2)
        self.report({"power_switch": 0})
        await second

    async def test_disconnect_keeps_cached_fields_and_fails_pending(self):
        self.report({"power_switch": 0, "downshift": 11})
        task = asyncio.create_task(self.coordinator.async_set_power(1))
        await self.tick()
        self.coordinator._connection_changed(False)
        with self.assertRaises(HomeAssistantError):
            await task
        self.assertFalse(self.coordinator.online)
        self.coordinator._connection_changed(True)
        self.assertFalse(self.coordinator.online)
        self.report({"downshift": 11})
        self.assertTrue(self.coordinator.online)
        self.assertEqual(self.coordinator.data["power_switch"], 0)

    async def test_stale_then_partial_recovery(self):
        self.coordinator.stale_timeout = 0.01
        self.report({"power_switch": 1})
        await asyncio.sleep(0.02)
        self.assertFalse(self.coordinator.online)
        self.assertEqual(self.coordinator.data, {"power_switch": 1})
        self.report({"downshift": 11})
        self.assertTrue(self.coordinator.online)
        self.assertEqual(self.coordinator.data["power_switch"], 1)

    async def test_close_cancels_waiters_and_unsubscribes_once(self):
        self.report({"power_switch": 0})
        first = asyncio.create_task(self.coordinator.async_set_power(1))
        second = asyncio.create_task(self.coordinator.async_set_power(1))
        await self.tick()
        self.coordinator.async_close()
        self.coordinator.async_close()
        results = await asyncio.gather(first, second, return_exceptions=True)
        self.assertTrue(all(isinstance(error, HomeAssistantError) for error in results))
        self.assertEqual(self.publish.await_count, 1)
        self.unsubscribe.assert_called_once()
        self.unsubscribe_connection.assert_called_once()
        self.assertIsNone(self.coordinator._expiry)

    async def test_cancellation_releases_command_lock(self):
        self.report({"power_switch": 0})
        task = asyncio.create_task(self.coordinator.async_set_power(1))
        await self.tick()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNone(self.coordinator._pending)
        self.assertFalse(self.coordinator._lock.locked())

    async def test_entity_contracts_and_readonly_mappings(self):
        fan = AirMateFan(self.coordinator)
        self.assertEqual(fan.unique_id, "airmate_cn_fan_testdevice")
        self.report({"power_switch": 1, "horizontal_swing": 1})
        with patch.object(
            self.coordinator, "async_set_power", AsyncMock()
        ) as set_power:
            await fan.async_turn_on(percentage=0)
            set_power.assert_awaited_once_with(0)
            with self.assertRaises(HomeAssistantError):
                await fan.async_turn_on(preset_mode="baby")
        sensors = {d.key: AirMateSensor(self.coordinator, d) for d in DESCRIPTIONS}
        self.assertEqual(sensors["horizontal_swing"].native_value, "on")
        for value, expected in [(0, "off"), (2, "30°"), (3, "60°"), (4, "90°")]:
            self.report({"horizontal_swing": value})
            self.assertEqual(sensors["horizontal_swing"].native_value, expected)
        self.assertIsNone(sensors["mode"].native_value)

    async def test_diagnostics_redaction(self):
        self.report({"power_switch": 1})
        result = await async_get_config_entry_diagnostics(self.hass, self.entry)
        self.assertNotIn("testdevice", json.dumps(result))
        self.assertNotIn("testproduct", json.dumps(result))
        self.assertNotIn("password", json.dumps(result))

    async def test_setup_and_unload(self):
        self.coordinator.async_close()
        with (
            patch(
                "custom_components.airmate_cn.mqtt.async_wait_for_mqtt_client",
                AsyncMock(return_value=True),
            ),
            patch.object(
                self.hass.config_entries, "async_forward_entry_setups", AsyncMock()
            ),
            patch.object(
                self.hass.config_entries,
                "async_unload_platforms",
                AsyncMock(return_value=True),
            ),
        ):
            self.assertTrue(await async_setup_entry(self.hass, self.entry))
            self.coordinator = self.entry.runtime_data
            self.assertTrue(await async_unload_entry(self.hass, self.entry))
            self.assertTrue(self.coordinator._closed)

    async def test_legacy_migration_is_explicit(self):
        old = SimpleNamespace(version=1)
        self.assertFalse(await async_migrate_entry(self.hass, old))

    async def test_subscription_failure_releases_connection_listener(self):
        coordinator = Coordinator(self.hass, self.entry)
        unsubscribe = Mock()
        with (
            patch(
                "custom_components.airmate_cn.coordinator.mqtt.async_subscribe",
                AsyncMock(side_effect=OSError("subscription failed")),
            ),
            patch(
                "custom_components.airmate_cn.coordinator.mqtt.async_subscribe_connection_status",
                return_value=unsubscribe,
            ),
        ):
            with self.assertRaises(OSError):
                await coordinator.async_start()
        unsubscribe.assert_called_once()
        self.assertTrue(coordinator._closed)

    async def test_failed_platform_setup_closes_transport(self):
        self.coordinator.async_close()
        with (
            patch(
                "custom_components.airmate_cn.mqtt.async_wait_for_mqtt_client",
                AsyncMock(return_value=True),
            ),
            patch.object(
                self.hass.config_entries,
                "async_forward_entry_setups",
                AsyncMock(side_effect=RuntimeError("platform failed")),
            ),
        ):
            with self.assertRaises(RuntimeError):
                await async_setup_entry(self.hass, self.entry)
        self.coordinator = self.entry.runtime_data
        self.assertTrue(self.coordinator._closed)
        self.assertFalse(self.coordinator._unsubs)

    async def test_failed_unload_keeps_transport(self):
        with patch.object(
            self.hass.config_entries,
            "async_unload_platforms",
            AsyncMock(return_value=False),
        ):
            self.assertFalse(await async_unload_entry(self.hass, self.entry))
        self.assertFalse(self.coordinator._closed)

    async def test_retained_or_invalid_report_cannot_mark_online(self):
        self.report({"power_switch": 1}, retain=True)
        self.report({"downshift": 33})
        self.assertFalse(self.coordinator.online)
        self.assertIsNone(self.coordinator._expiry)

    async def test_config_flow_requires_mqtt_and_validates_ids(self):
        flow = AirMateConfigFlow()
        flow.hass = self.hass
        flow.handler = "airmate_cn"
        flow.context = {"source": "user"}
        result = await flow.async_step_user()
        self.assertEqual(result["reason"], "mqtt_required")
        mqtt_entry = make_entry("mqtt", {"broker": "localhost"})
        self.hass.config_entries._entries[mqtt_entry.entry_id] = mqtt_entry
        result = await flow.async_step_user(
            {"name": "Fan", "product_id": "#", "device_id": "test"}
        )
        self.assertEqual(result["errors"]["base"], "invalid_identifier")
        result = await flow.async_step_user(
            {"name": "Fan", "product_id": "testproduct", "device_id": "different"}
        )
        self.assertEqual(result["type"], "create_entry")
        with self.assertRaises(AbortFlow):
            await flow.async_step_user(
                {
                    "name": "Duplicate",
                    "product_id": "testproduct",
                    "device_id": "testdevice",
                }
            )

    async def test_options_flow_updates_name_and_identity(self):
        with patch("homeassistant.config_entries.report_usage"):
            options = AirMateOptionsFlow(self.entry)
        options.hass = self.hass
        options.handler = self.entry.entry_id
        result = await options.async_step_init()
        self.assertEqual(result["type"], "form")
        result = await options.async_step_init(
            {
                "name": "循环扇",
                "product_id": "newproduct",
                "device_id": "newdevice",
            }
        )
        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(self.entry.title, "循环扇")
        self.assertEqual(
            self.entry.data,
            {"product_id": "newproduct", "device_id": "newdevice"},
        )
        self.assertEqual(self.entry.unique_id, "newproduct/newdevice")

    async def test_speed_preparation_then_fresh_confirmation(self):
        self.report({"power_switch": 1, "mode": 0, "downshift": 11})
        with patch(
            "custom_components.airmate_cn.coordinator.SPEED_PREPARE_DELAY", 0.01
        ):
            task = asyncio.create_task(self.coordinator.async_set_speed(10))
            await self.tick()
            self.assertEqual(self.publish.await_count, 1)
            self.assertEqual(
                json.loads(self.publish.call_args.args[2])["data"], {"downshift": 10}
            )
            self.assertEqual(self.coordinator.data["downshift"], 11)
            self.report(
                {"downshift": 10}
            )  # Before final publish, not its confirmation.
            await asyncio.sleep(0.02)
            self.assertEqual(self.publish.await_count, 2)
            self.assertTrue(task.done())
            task.result()
            worker = self.coordinator._speed_task
            first, final = [
                json.loads(call.args[2]) for call in self.publish.call_args_list
            ]
            self.assertEqual(
                final["data"], {"power_switch": 1, "mode": 0, "downshift": 10}
            )
            self.assertGreater(int(final["timestamp"]), int(first["timestamp"]))
            self.assertEqual(self.coordinator.data["downshift"], 10)
            self.report({"downshift": 10})
            await worker
        self.assertTrue(
            all(
                call.kwargs == {"qos": 0, "retain": False}
                for call in self.publish.call_args_list
            )
        )

    async def test_speed_requests_coalesce_to_latest(self):
        self.report({"power_switch": 1, "mode": 0, "downshift": 11})
        with (
            patch(
                "custom_components.airmate_cn.coordinator.SPEED_COALESCE_DELAY", 0.05
            ),
            patch("custom_components.airmate_cn.coordinator.SPEED_PREPARE_DELAY", 0),
        ):
            first = asyncio.create_task(self.coordinator.async_set_speed(10))
            await self.tick()
            second = asyncio.create_task(self.coordinator.async_set_speed(20))
            await first
            await asyncio.sleep(0.06)
            self.assertEqual(self.publish.await_count, 2)
            first_payload, final_payload = [
                json.loads(call.args[2]) for call in self.publish.call_args_list
            ]
            self.assertEqual(first_payload["data"], {"downshift": 20})
            self.assertEqual(
                final_payload["data"],
                {"power_switch": 1, "mode": 0, "downshift": 20},
            )
            self.report({"downshift": 20})
            await second

    async def test_speed_requires_all_known_changed_fields(self):
        self.report({"power_switch": 0, "mode": 1, "downshift": 11})
        with patch("custom_components.airmate_cn.coordinator.SPEED_PREPARE_DELAY", 0):
            task = asyncio.create_task(self.coordinator.async_set_speed(10))
            await self.tick()
            await self.tick()
            self.report({"downshift": 10})
            self.report({"power_switch": 1})
            await self.tick()
            self.assertTrue(task.done())
            task.result()
            worker = self.coordinator._speed_task
            self.report({"mode": 0})
            await worker

    async def test_disconnect_during_speed_preparation_stops_final_publish(self):
        self.report({"downshift": 11})
        with patch(
            "custom_components.airmate_cn.coordinator.SPEED_PREPARE_DELAY", 0.01
        ):
            task = asyncio.create_task(self.coordinator.async_set_speed(10))
            await self.tick()
            self.coordinator._connection_changed(False)
            self.coordinator._connection_changed(True)
            self.report({"downshift": 11})
            with self.assertRaises(HomeAssistantError):
                await task
        self.assertEqual(self.publish.await_count, 1)

    async def test_speed_timeout_does_not_repeat_either_stage(self):
        self.report({"downshift": 11})
        with (
            patch("custom_components.airmate_cn.coordinator.SPEED_PREPARE_DELAY", 0),
            patch("custom_components.airmate_cn.coordinator.COMMAND_TIMEOUT", 0.02),
        ):
            task = asyncio.create_task(self.coordinator.async_set_speed(10))
            await asyncio.sleep(0.005)
            worker = self.coordinator._speed_task
            await task
            await worker
        self.assertEqual(self.publish.await_count, 2)
        self.assertEqual(self.coordinator.data["downshift"], 11)

    async def test_swing_commands_and_select_options(self):
        from custom_components.airmate_cn.select import AirMateHorizontalSwing
        from custom_components.airmate_cn.switch import AirMateVerticalSwing

        horizontal = AirMateHorizontalSwing(self.coordinator)
        vertical = AirMateVerticalSwing(self.coordinator)
        self.assertIsNone(horizontal.current_option)
        self.assertIsNone(vertical.is_on)
        self.report({"horizontal_swing": 1, "vertical_swing": 0})
        self.assertIsNone(horizontal.current_option)  # No unsupported option leaked.
        self.assertNotIn("on", horizontal.options)
        task = asyncio.create_task(horizontal.async_select_option("60°"))
        await self.tick()
        self.assertEqual(
            json.loads(self.publish.call_args.args[2])["data"], {"horizontal_swing": 3}
        )
        self.report({"horizontal_swing": 3})
        await task
        self.assertEqual(horizontal.current_option, "60°")
        task = asyncio.create_task(vertical.async_turn_on())
        await self.tick()
        self.report({"vertical_swing": 1})
        await task
        self.assertTrue(vertical.is_on)
        self.assertEqual(
            horizontal.unique_id, "airmate_cn_fan_horizontal_swing_testdevice"
        )
        self.assertEqual(vertical.unique_id, "airmate_cn_fan_vertical_swing_testdevice")

    async def test_fan_speed_mapping_and_zero(self):
        from custom_components.airmate_cn.fan import percentage_to_speed

        fan = AirMateFan(self.coordinator)
        self.assertIsNone(fan.percentage)
        self.assertIsNone(fan.oscillating)
        for speed in range(1, 33):
            self.report({"power_switch": 1, "downshift": speed})
            self.assertEqual(percentage_to_speed(fan.percentage), speed)
        with (
            patch.object(self.coordinator, "async_set_power", AsyncMock()) as power,
            patch.object(self.coordinator, "async_set_speed", AsyncMock()) as speed,
        ):
            await fan.async_set_percentage(0)
            power.assert_awaited_once_with(0)
            speed.assert_not_called()
            await fan.async_set_percentage(100)
            speed.assert_awaited_once_with(32)
        for invalid in [-1, 101, True, "10"]:
            with self.assertRaises(ValueError):
                await fan.async_set_percentage(invalid)
        self.report({"power_switch": 0})
        self.assertEqual(fan.percentage, 0)
