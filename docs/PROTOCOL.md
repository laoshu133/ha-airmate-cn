# 本地 MQTT 协议

## 主题与消息

设备上行：`<product_id>/<device_id>/data`；设备订阅下行：`<product_id>/<device_id>/rrpc`。消息使用 MQTT QoS 0、非 retained JSON。状态消息的 `data` 可以只包含变化字段，集成必须增量合并，并在 HA 存储中保存最近一次已知值。恢复值只用于显示，不会被当作实时在线状态或命令确认。

## 字段映射

| 字段 | 值 |
| --- | --- |
| `power_switch` | 0 关闭，1 开启 |
| `downshift` | 1–32 档 |
| `mode` | 0 标准风，1 婴儿风，2 暴风（只读） |
| `horizontal_swing` | 0 关闭，2/3/4 为 30°/60°/90° |
| `vertical_swing` | 0/1 关闭/开启 |
| `mute`、`light`、`wind_mode`、`failure`、`filter_life` | 设备状态（只读） |

控制消息使用 `command=300013`、`method=thing.property.update`、设备 ID、毫秒时间戳和唯一 `msg_id`。开关直接写 `power_switch`。调速先写目标 `downshift`，等待约 1 秒，再写 `power_switch=1, mode=0, downshift=目标`；仅最终步骤后的新上报用于确认。水平摇头写 0/2/3/4，垂直摇头写 0/1。

主动 `thing.property.get`、模式/灯光/静音写入以及两步调速的固件内部原因尚未确认。
