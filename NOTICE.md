# 来源与许可

脚本、模板、测试和组合配置使用 GPL-3.0-only，完整许可见 LICENSE。这是个人维护的配置，不是 Shadowrocket 官方项目。

当前发布数据来自 [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)，使用 MIT 许可，Copyright (c) 2017 Yifan Gao。原文保留在 licenses/gaoyifan-MIT.txt；发布对应原始数据保存在 dist/inputs/china4.txt 和 china6.txt，提交与文件哈希记录在 dist/manifest.json。

转换只包含 CIDR 校验、重复删除、地址集合等价合并及 Shadowrocket 规则格式生成。公网流量按目标 IP 分流，不再使用域名分类、品牌白名单或域名强制代理保护层。

Git 历史及历史报告中曾使用 v2fly/domain-list-community（MIT）、Loyalsoldier/clash-rules 与 v2ray-rules-dat（GPL-3.0）、publicsuffix/list（MPL-2.0）及其数据链中的 dnsmasq-china-list（WTFPL v2）。相关许可证文件继续保留；当前产物不再包含这些域名数据。历史发布的具体来源和处理方式以对应提交的 NOTICE 和 manifest 为准。

Shadowrocket、GitHub 及各服务商商标归各自所有者。
