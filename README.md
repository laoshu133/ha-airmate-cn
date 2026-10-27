# AirMate CN

Home Assistant 自定义集成，通过本地 MQTT 控制原厂云服务不可用的 AirMate 风扇。
当前实现基于一台 HF-LPT270 / BL602 设备验证，支持开关、32 档调速、水平摇头和垂直摇头。
其他型号和固件需要单独验证。

本项目不调用艾智家云端 API，也不包含 MQTT broker。Home Assistant 的 MQTT 集成是客户端，
broker 需要作为独立服务运行，例如 Mosquitto。broker 可以运行在 HA 主机、NAS、树莓派或其他局域网主机。

本项目文档：

- [部署与迁移指南](docs/DEPLOYMENT.md)
- [实现方案](docs/PLAN.md)
- [协议实验记录](docs/PROTOCOL.md)
- [验收清单](docs/ACCEPTANCE.md)

## 功能范围

- 风扇开关，等待新的设备状态回报后确认。
- 1–32 档调速。调速使用设备所需的两步 MQTT 流程，并等待最终档位回报。
- 水平摇头：关闭、30°、60°、90°；`horizontal_swing=1` 目前只识别上报，不作为写入选项。
- 垂直摇头：独立开关。
- 模式、灯光、静音：当前只展示设备上报，不提供写入控件。
- 增量状态合并；没有收到的字段保持 unknown，不使用默认值伪造状态。
- MQTT 断开或设备超过 180 秒没有有效上报后标记不可用。

调速、摇头和开关均在真实设备及 HA 2026.10.2 容器中验证过，但不同型号可能使用不同协议。
两步调速的内部固件原因尚未确定，不能据此推断其他设备也需要同样流程。

## 安装

### HACS

1. 在 HACS 中添加本仓库作为自定义集成仓库。
2. 安装 **AirMate CN**。
3. 重启 Home Assistant。

### 手动安装

将 `custom_components/airmate_cn` 复制到 Home Assistant 配置目录：

```text
/config/custom_components/airmate_cn/manifest.json
```

然后重启 Home Assistant。

## 配置

1. 先在 Home Assistant 中配置 MQTT 集成。
2. 准备一个 MQTT broker，并让风扇能够将固件内的服务器域名解析到该 broker。
   设备使用 TCP 3866；broker 也可以在其他端口监听后通过端口映射提供 3866。
3. 设备账号必须使用设备原有 MQTT 凭据；HA 使用单独的 MQTT 账号。
   不要把设备密码、抓包或生产 ACL 提交到仓库。
4. 添加 **AirMate CN** 集成，输入设备上报主题中的 `product_id` 和 `device_id`：

```text
<product_id>/<device_id>/data
```

不要把 MQTT client ID、username 或 password 当作 `device_id`。

集成会创建一个风扇、一个水平摇头角度选择器、一个垂直摇头开关和六个状态传感器。
如果设备刚连接时只上报档位，电源和其他字段会保持 unknown，等待后续上报即可。

## MQTT broker 部署建议

推荐使用 Mosquitto 或发行版提供的 MQTT broker，单独维护其数据目录、密码文件和 ACL：

```yaml
services:
  mosquitto:
    image: eclipse-mosquitto:2
    ports:
      - "3866:1883"
    volumes:
      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - ./broker-data:/mosquitto/data
      - ./broker-private:/mosquitto/private:ro
```

ACL 应至少满足以下方向：

```text
user <device-username>
topic write <product_id>/<device_id>/data
topic read <product_id>/<device_id>/rrpc

user <ha-username>
topic read <product_id>/<device_id>/data
topic write <product_id>/<device_id>/rrpc
```

设备域名的 DNS 接管方式取决于你的网络设备。解析到 broker 主机的局域网地址，
不要解析到 `127.0.0.1`：对风扇来说那是风扇自身，而不是 broker。
不要把 3866 暴露到公网，也不要为了部署本项目修改不相关的路由、防火墙或代理配置。

## 从旧版本迁移

旧版本使用原厂账号和云端设备列表；本版本每台设备单独配置 MQTT 身份，无法从旧账号自动迁移。
升级前备份 Home Assistant 配置，记录旧实体及自动化引用，然后删除旧 AirMate 配置条目并重新添加本地条目。
旧版本的调速和摆头自动化需要检查实体 ID 与选项名称。

## 开发与测试

项目测试使用 Docker 中的 Home Assistant 运行时，不要求在开发机安装 Home Assistant：

```bash
./tools/test.sh
```

测试容器禁用网络，使用合成 MQTT 消息和身份，不会连接真实设备。测试覆盖协议解析、增量状态、
开关、两步调速、摇头、超时、断连、并发、卸载和实体映射。

真实设备验证需要你自行准备 broker、MQTT 凭据和设备基线；仓库不提供也不保存这些私有数据。

## 兼容性边界

- 已验证环境：Home Assistant 2026.10.2、MQTT 3.1.1 设备连接、Mosquitto 2.x。
- 未验证：婴儿风/暴风模式写入、灯光写入、静音写入、主动全量状态查询、其他型号。
- 设备重连不保证重新发送完整属性；集成不会用磁盘缓存冒充当前状态。

## License

MIT
