# 本地 MQTT 协议

## 主题与消息

设备上行：`<product_id>/<device_id>/data`；设备订阅下行：`<product_id>/<device_id>/rrpc`。消息使用 MQTT QoS 0、非 retained JSON。状态消息的 `data` 可以只包含变化字段，集成必须增量合并，并在 HA 存储中保存最近一次已知值。恢复值只用于显示，不会被当作实时在线状态或命令确认。

## 字段映射

| 字段 | 值 |
| --- | --- |
| `power_switch` | 0 关闭，1 开启 |
| `downshift` | 1–32 档 |
| `mode` | 0 标准风，1 婴儿风，2 暴风；使用完整 `power_switch=1,mode,downshift` 报文可写并会回报 |
| `horizontal_swing` | 0 关闭，2/3/4 为 30°/60°/90° |
| `vertical_swing` | 0/1 关闭/开启 |
| `mute`、`light`、`wind_mode`、`failure`、`filter_life` | 设备状态（只读） |

控制消息使用 `command=300013`、`method=thing.property.update`、设备 ID、毫秒时间戳和唯一 `msg_id`。开关直接写 `power_switch`。调速先写目标 `downshift`，等待约 10 ms，再写 `power_switch=1, mode=0, downshift=目标`；实测 0 ms 会失败，10 ms 可稳定工作。连续请求会在短暂窗口内合并，只执行最后目标；最终命令发出后先乐观显示目标，后台等待新上报并在失败时恢复旧值。水平摇头写 0/2/3/4，垂直摇头写 0/1。

原厂 App 的 APK 表明刷新状态使用 `command=300009`，形状为
`data: [{device_id, status: "online_status", dp_status: [...]}]`；按此格式对本地
broker 做只读验证没有得到设备回复。因此本地固件当前不会主动提供完整状态，灯光和静音在没有对应上报时必须保持 unknown，不能用默认值冒充实时状态。模式已通过 0/1/2 三个值的完整更新报文验证，集成支持风扇预设模式；调速正式报文明确选择标准风，集成会把这一已确认值写入最近状态缓存。
