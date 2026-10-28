# 部署指南

本项目只提供 Home Assistant 集成；MQTT broker 需要单独运行。Home Assistant Container 没有 Mosquitto add-on，HA 的 MQTT 集成只是客户端。HA OS 用户可以使用 Mosquitto add-on，其他部署可使用 Docker Compose 或系统服务。

## 1. Broker

在与风扇同一局域网的主机运行 Mosquitto 2.x。将宿主机 TCP 3866 映射到 broker 的 MQTT 1883：

```yaml
services:
  mosquitto:
    image: eclipse-mosquitto:2
    restart: unless-stopped
    ports:
      - "3866:1883"
    volumes:
      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - ./broker-data:/mosquitto/data
      - ./broker-private:/mosquitto/private:ro
```

配置至少包含：

```conf
listener 1883
allow_anonymous false
password_file /mosquitto/private/passwords
acl_file /mosquitto/private/acl
persistence true
persistence_location /mosquitto/data/
```

设备账号只能写 `<product_id>/<device_id>/data`、读 `.../rrpc`；HA 账号只能读 `.../data`、写 `.../rrpc`。使用 `mosquitto_passwd` 创建密码文件，密码和 ACL 不要提交仓库。

## 2. DNS 与端口

将风扇固件内置的服务器域名精确解析到 broker 主机的局域网地址，不要解析到 `127.0.0.1`。风扇的已验证业务连接是 TCP 3866；旧集成访问原厂 HTTPS API 属于 HA 到云端的流量，不能据此推断风扇访问 80/443。不要把 3866 暴露到公网，并确保没有其他代理或 fake-IP 规则抢先接管连接。

## 3. 设备身份

状态主题为 `<product_id>/<device_id>/data`，命令主题为 `<product_id>/<device_id>/rrpc`。首次接入可临时给观察账号 `#` 的读取权限，使用发现脚本读取第一条有效状态后立即删除通配符权限：

```bash
python3 tools/discover_device.py --host <broker-host> --port 3866 --username <observer>
```

脚本只输出主题、产品 ID 和设备 ID，不输出完整 payload。

## 4. Home Assistant

1. 在设置中添加 MQTT 集成，填写 broker 主机、3866 端口和 HA 账号。
2. 安装并添加 AirMate CN，填写名称、产品 ID 和设备 ID。
3. 等待设备上报。

manifest 的 `mqtt` 依赖只控制内置集成的加载顺序，不会安装 Mosquitto，也不会自动创建 MQTT 配置。

## 5. 故障排查

- 没有实体：确认 MQTT 已配置，且 ID 来自目标设备主题。
- 实体不可用：检查 DNS、TCP 3866、broker ACL 和设备上报。
- 命令超时：确认设备在线、命令主题正确且没有 retained 旧命令。
- 状态 unknown：设备可能只上报部分字段，等待后续增量消息。

不要公开设备密码、CONNECT 报文、真实主题、IP、MAC、抓包或生产 ACL。
