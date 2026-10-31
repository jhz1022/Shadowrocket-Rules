# 来源与许可

本工程脚本、模板、测试和组合配置使用 GPL-3.0-only；完整许可见 `LICENSE`。
这是自建的数据转换与发布工程，不是 Shadowrocket 官方项目。

发布的原始数据及对应转换：

- `v2fly/domain-list-community`：MIT，Copyright (c) 2018-2019 V2Ray。原文见 `licenses/v2fly-MIT.txt`，原始归档见 `dist/inputs/direct.tar.gz`。
  来源：https://github.com/v2fly/domain-list-community
- `Loyalsoldier/clash-rules`：GPL-3.0，完整原文见 `LICENSE`。发布源 `proxy.txt` 保留在 `dist/inputs/proxy.txt`。
  来源：https://github.com/Loyalsoldier/clash-rules
  上游生成代码：https://github.com/Loyalsoldier/clash-rules/blob/master/.github/workflows/run.yml
  其数据来自 Loyalsoldier/v2ray-rules-dat 及其列明的社区数据链。
- `gaoyifan/china-operator-ip`：MIT，Copyright (c) 2017 Yifan Gao。原文见 `licenses/gaoyifan-MIT.txt`，原始 CIDR 见 `dist/inputs/china4.txt`、`dist/inputs/china6.txt`。
  来源：https://github.com/gaoyifan/china-operator-ip

固定来源 URL、提交和文件哈希记录在 `dist/manifest.json`。修改包括类型转换、相同策略压缩、普通源代理优先冲突处理、带依据的本地精确例外、国内地址合并、局域网及默认策略拼接；实现和完整原始输入随工程一起提供。

未使用 blackmatrix7 的规则、广告拦截列表、脚本或 MITM 数据。Shadowrocket、GitHub 及各服务商商标归各自所有者。

本地精确例外是从服务商/设备厂商公开文档中核实用途后独立整理的主机事实，不全量导入第三方配置或 DNS 服务器值。部分例外另以已有 v2fly 固定归档中的专用分类和 @cn 属性作构建核查；出处 URL 及说明保留在 config/overrides.json。felixonmars/dnsmasq-china-list 仅用于交叉参考 Apple 中国可达主机，没有新增其全量数据下载、转换或分发依赖。
