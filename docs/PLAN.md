# AirMate CN 实现方案

## 目标

原厂云服务不可用时，保留风扇固件内置域名，通过 DNS 将其连接导向局域网 Mosquitto，再由 Home Assistant MQTT 集成控制设备。集成不包含 broker，也不调用原厂 HTTP API。

## 已验证协议

- 设备使用明文 MQTT 3.1.1，固定 TCP 3866，状态主题为 `<product_id>/<device_id>/data`，命令主题为 `.../rrpc`。
- 状态消息为 JSON，可为完整或增量属性；缺失字段必须保留已有值或 unknown。
- 已确认字段：`power_switch`、`downshift`（1–32）、`mode`、`horizontal_swing`（0/2/3/4）、`vertical_swing`（0/1）、`mute`、`light`、`wind_mode`、`failure`、`filter_life`。
- 开关、调速、水平摇头和垂直摇头已在真实设备与 HA 2026.10.2 中验证。调速使用先发 `downshift`、间隔约 10 ms 再发 `power_switch=1,mode=0,downshift` 的两步流程；实测 0 ms 会失败，10 ms 可稳定工作。

## 集成结构

协议解析、增量状态合并和命令编码位于独立模块；实体层复用原有风扇功能映射。每个配置条目对应一台设备，通过 Home Assistant 官方 MQTT API 订阅和发布。命令不 retain、不以发布成功冒充设备成功，并等待新的匹配上报确认。MQTT 断开或约 180 秒没有有效上报时标记不可用。

集成创建风扇、水平角度选择器、垂直摇头开关和六个状态传感器。模式、灯光和静音目前只读；水平摇头写入只开放关闭、30°、60°、90°。

## 兼容性边界

本实现针对已验证的 HF-LPT270 / BL602 固件。主动全量查询、未开放属性写入和其他型号/固件尚未确认。用户应按 [部署指南](DEPLOYMENT.md) 配置 broker 和 DNS，并按 [验收清单](ACCEPTANCE.md) 检查真实设备动作。
