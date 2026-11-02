# 来源与许可

本工程脚本、模板、测试和组合配置使用 GPL-3.0-only；完整许可见 `LICENSE`。
本项目用于个人维护和发布分流配置，与 Shadowrocket 官方无关。

发布的原始数据及对应转换：

- `v2fly/domain-list-community`：MIT，Copyright (c) 2018-2019 V2Ray。原文见 `licenses/v2fly-MIT.txt`，原始归档见 `dist/inputs/direct.tar.gz`。
  来源：https://github.com/v2fly/domain-list-community
- `Loyalsoldier/clash-rules`：GPL-3.0，完整原文见 `LICENSE`。发布源 `proxy.txt` 保留在 `dist/inputs/proxy.txt`。
  来源：https://github.com/Loyalsoldier/clash-rules
  上游生成代码：https://github.com/Loyalsoldier/clash-rules/blob/master/.github/workflows/run.yml
  其数据来自 Loyalsoldier/v2ray-rules-dat 及其列明的社区数据链。
- `gaoyifan/china-operator-ip`：MIT，Copyright (c) 2017 Yifan Gao。原文见 `licenses/gaoyifan-MIT.txt`，原始 CIDR 见 `dist/inputs/china4.txt`、`dist/inputs/china6.txt`。
  来源：https://github.com/gaoyifan/china-operator-ip
- `publicsuffix/list`：MPL-2.0，完整许可原文见 `licenses/publicsuffix-MPL-2.0.txt`。未经修改的源文件及其声明保存在 `dist/inputs/registry.txt`，仍按 MPL-2.0 提供；构建只读取 ICANN 部分作为直连边界校验，不将 PSL 转换成客户端路由表。
  来源：https://github.com/publicsuffix/list

固定来源 URL、提交和文件哈希记录在 `dist/manifest.json`。上游数据的处理包括类型转换、相同策略压缩、受保护代理优先、增强白名单优先于普通国外分类的冲突处理、带依据的本地精确例外及中国政府/教育服务类别、国内地址合并、局域网及默认策略拼接；实现和完整原始输入随工程一起提供。

未使用 blackmatrix7 的规则、广告拦截列表、脚本或 MITM 数据。Shadowrocket、GitHub 及各服务商商标归各自所有者。

本地精确例外根据服务商和设备厂商的公开文档核实用途后整理；gov.cn、edu.cn 则根据 CNNIC/CERNET 的注册用途作为独立国内服务类别，不全量导入第三方配置或 DNS 服务器值。部分例外另以已有 v2fly 固定归档中的专用分类和 @cn 属性作构建核查；出处 URL 及说明保留在 config/overrides.json。现通过 Loyalsoldier/v2ray-rules-dat 的增强直连表及 apple-cn.txt 引入 felixonmars/dnsmasq-china-list 数据，其原始许可为 WTFPL v2，原文见 licenses/dnsmasq-china-WTFPL.txt。

新增发布源：Loyalsoldier/v2ray-rules-dat（GPL-3.0，见 LICENSE），原始发布文件见 dist/inputs/enhanced.txt 和 apple_cn.txt。来源 https://github.com/Loyalsoldier/v2ray-rules-dat 。国外服务的 @cn 分类从同一 v2fly 固定归档另存 dist/inputs/regional.tar.gz，保留 MIT 声明。所有下载文件保持原始内容；构建中的正则省略记录于 manifest。
