# AirMate CN

Home Assistant 自定义集成，通过本地 MQTT 继续使用原厂云服务不可用的 AirMate 风扇。本项目在 HF-LPT270 / BL602 设备上验证，支持开关、1–32 档调速、水平摇头角度和垂直摇头；模式、灯光、静音提供只读状态。其他型号和固件需要单独验证。

项目不调用原厂云 API，也不内置 MQTT broker。请先准备 Mosquitto 等独立 broker，再配置 Home Assistant 的 MQTT 集成。部署步骤见 [部署指南](docs/DEPLOYMENT.md)，最终边界见 [方案](docs/PLAN.md)。

## 安装

通过 HACS 添加本仓库并安装 **AirMate CN**，或将 `custom_components/airmate_cn` 复制到 Home Assistant 配置目录，然后重启 Home Assistant。

配置顺序：

1. 部署 broker，并将设备固件内置域名解析到 broker 主机；设备使用 TCP 3866。
2. 在 Home Assistant 中配置 MQTT 集成。集成 manifest 声明了内置 `mqtt` 依赖，不会安装 broker 或自动创建 MQTT 连接。
3. 添加 AirMate CN，填写名称、`product_id` 和 `device_id`。两者来自设备主题 `<product_id>/<device_id>/data`，不是 MQTT client ID 或密码。

首次不知道主题时，可用临时只读观察账号订阅 `#`，确认身份后立即收紧 ACL。仓库提供不输出完整报文的发现脚本：

```bash
python3 tools/discover_device.py --host <broker-host> --port 3866 --username <observer>
```

## 实体与边界

集成创建一个风扇、一个水平角度选择器、一个垂直摇头开关和六个状态传感器。命令等待新的设备上报确认；未知字段保持 unknown，设备超过约 180 秒没有有效上报时标记不可用。调速使用设备已验证的两步流程，0% 单独表示关机。

已验证环境为 Home Assistant 2026.10.2、MQTT 3.1.1 设备连接和 Mosquitto 2.x。主动全量查询、模式/灯光/静音写入及其他型号兼容性尚未确认。

## 测试

```bash
./tools/test.sh
```

测试使用隔离的合成 MQTT 消息，不连接真实设备。

## License

MIT
