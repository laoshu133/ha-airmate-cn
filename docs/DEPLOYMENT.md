# 部署与迁移指南

本文面向公开仓库使用者，所有地址、账号、产品 ID 和设备 ID 都是占位符。
项目本身只提供 Home Assistant 集成；MQTT broker 必须单独部署。

## 架构

```text
风扇 -- TCP 3866 / MQTT --> Mosquitto broker <-- MQTT 集成 -- Home Assistant
          原固件域名解析到 broker 主机
```

Home Assistant Container 没有 Mosquitto add-on。HA 的 MQTT 集成只负责连接 broker、订阅状态和发布命令。
如果使用 HA OS，可以使用 Mosquitto add-on；如果使用 HA Container，应通过 Docker Compose、系统服务或独立主机运行 Mosquitto。

## 1. 部署 broker

选择一台与风扇在同一局域网的主机，安装 Mosquitto 2.x。让主机的 TCP 3866 映射到 Mosquitto 的 1883：

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

示例 `mosquitto.conf`：

```conf
listener 1883
allow_anonymous false
password_file /mosquitto/private/passwords
acl_file /mosquitto/private/acl
persistence true
persistence_location /mosquitto/data/
```

设备账号和 HA 账号应分开。设备账号只能发布状态主题、订阅命令主题；HA 账号只能订阅状态主题、发布命令主题：

```text
user <device-username>
topic write <product_id>/<device_id>/data
topic read <product_id>/<device_id>/rrpc

user <ha-username>
topic read <product_id>/<device_id>/data
topic write <product_id>/<device_id>/rrpc
```

使用 `mosquitto_passwd` 创建密码文件，并将密码文件和 ACL 限制为 broker 进程可读。不要提交这两个文件。

## 2. 接管设备解析

设备固件仍会访问其内置服务器域名。需要在你自己的 DNS 设备上，将该域名精确解析到 broker 主机的局域网 IP。
本项目不要求修改固件，也不要求把域名改成新域名。

确认以下条件：

- 风扇能解析到 broker 主机，而不是 `127.0.0.1`。
- broker 主机允许局域网风扇访问 TCP 3866。
- 没有其他透明代理、fake-IP 规则或端口转发抢先接管该连接。
- 3866 不暴露到公网。

## 3. 获取设备身份

设备状态主题格式为：

```text
<product_id>/<device_id>/data
```

下行命令主题格式为：

```text
<product_id>/<device_id>/rrpc
```

`product_id` 和 `device_id` 来自状态消息及主题。它们与 MQTT client ID、username、password 不同。
首次接入时使用只读 MQTT 客户端订阅目标设备主题，保存一条脱敏的主题和状态记录即可。
原始 CONNECT、密码和真实 payload 只能保存在本地私有目录。

## 4. 配置 Home Assistant

1. 在设置中添加 MQTT 集成，填写 broker 主机、端口 3866、HA 账号和密码。
2. 添加 AirMate CN 集成。
3. 输入名称、product ID 和 device ID。
4. 等待设备上报。

成功后会创建：

- 风扇实体：开关、32 档调速、水平摇头。
- 水平摇头角度选择器：关闭、30°、60°、90°。
- 垂直摇头开关。
- 六个状态传感器，包括档位、模式、水平/垂直摇头、灯光和静音。

命令使用 QoS 0、retain=false。集成不会把发送成功当作设备成功，而是等待新的匹配属性上报。
调速先发送目标档位，再等待约 1 秒发送完整的开机/标准风/档位组合；中间断连会终止本次操作。

## 5. 迁移旧云版本

旧版本需要原厂账号；本版本一个配置条目对应一台设备。升级时：

1. 备份 Home Assistant 配置和自动化。
2. 记录旧实体 ID。
3. 删除旧 AirMate 云条目。
4. 按本指南配置 MQTT 和本地 AirMate 条目。
5. 检查自动化中的实体 ID、调速百分比和水平角度选项。

集成不会把缺少 MQTT 身份的旧云条目静默转换成本地条目。

## 6. 故障排查

- 没有实体：检查 MQTT 集成是否已加载、product/device ID 是否来自目标主题。
- 实体 unavailable：检查 broker 连接、DNS、TCP 3866 和设备是否在上报。
- 调速超时：检查设备是否在线；确认 broker 没有保留旧命令；等待设备新上报后重试。
- 状态 unknown：设备重连后可能只发送部分字段，等待后续完整或增量状态。
- 设备连接不上：检查 DNS 是否解析到 broker 主机，检查是否存在其他 fake-IP/代理规则。

## 7. 安全与隐私

不要公开设备 MQTT 密码、CONNECT 报文、client ID、真实主题、IP、MAC、抓包或生产 ACL。
不要把 broker 端口暴露到公网。调试完成后删除宽泛 ACL，只保留该设备的精确主题权限。
