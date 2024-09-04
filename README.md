# AirMate(艾美特) Custom Component For Home Assistant

此项目是 Home Assistant 平台 AirMate(艾美特) 的自定义组件的集成实现。

组件基于 艾智家APP 相关接口实现，需要提供相关帐号密码。

## 支持设备

- 当前仅支持直流风扇

## 接入方法

1. 将项目 ha-airmate-cn 目录部署到自定义组件目录，一般路径为 `~/.homeassistant/custom_components/`
2. 通过 [HACS](https://hacs.xyz/) 载入自定义存储库(Custom repositories)，添加后搜索 `AirMate(艾美特)` 进行安装
    - 设置URL: https://github.com/laoshu133/ha-airmate-cn
    - 类别: 集成(Integration)

## 配置方法

本集成已支持 HA 可视化配置，在 `配置-集成-添加集成` 中选择 AirMate(艾美特)，依次填入用户信息即可。

## License

MIT
