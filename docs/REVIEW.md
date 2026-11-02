# 技术审查与依据

> 历史记录：本文对应当时的配置。2026-10-31 后续已重构为增强白名单；当前数据源、分流优先级及覆盖结果以 [ENHANCED_WHITELIST.md](ENHANCED_WHITELIST.md) 和 README 为准。本文中的真机结果不代表新版已完成同样测试。

审查日期：2026-10-31（Asia/Shanghai）。我在这里分别记录查到的事实、设计推断和仍待实测的部分。

## 原故障不能据检测页定性

`42.81.*.*` 是检测站观察到的递归解析出口，并不提供“哪个业务域名、哪次客户端查询、哪条物理链路”的完整证据。解析器还可能转发给别的递归服务，其 ASN/地域不一定等同第一跳 DNS。不能据此前观察直接认定 macOS DNS 泄漏根因。

国内直连域名使用国内解析器属于本项目的有意设计。真正要排查的是：**应走代理的境外域名是否被不期望的本地/国内解析器查询**。WebRTC 公网 IP 测试只覆盖另一条路径，既不证明也不反证 DNS 路径。

原配置的 `GEOIP,CN,DIRECT` 及无 `no-resolve` 的 IP 规则，是可能为域名匹配额外触发本地解析的线索，并不是已确认的故障原因。把 Google DoH URL 换进配置，也不自动决定 DoH 的传输策略；加密查询直连与通过代理是两个问题。

全局“代理”正常，而“配置”失败，只说明规则模式引入了差异。地区策略组空选项、不可用节点、节点引导循环、DNS 回退、应用缓存或 TUN 路径都需要日志证据。此前 LingJing 配置的故障原因仍未确认，不把它归因于某个参数。

## 参数依据与证据强度

我的 Mac 安装了 `/Applications/Shadowrocket.app`，我从 Info.plist 确认版本为 **2.2.93**。初期参数核查只读，没有涉及节点数据库、密码或订阅；随后我导入 DNS 修订候选并复测，见 `MAC_DNS_FIX.md`。

只读检查的一手材料：

- `Contents/Resources/default.conf`：明示 `dns-direct-system` 的用途、代理域名默认远端解析、UDP 不支持时的拒绝选项等。
- `Contents/Resources/zh-Hans.lproj/Localizable.strings`：DNS 回退说明、独立 Direct DNS、fake-IP 与硬编码 DNS、Include All Networks / Enforce Routes 及本地网络排除提示。
- 程序的参数字符串：存在 `dns-fallback`、`direct-dns-server`、`proxy-dns-server`、`always-ip-address`；未发现 `dns-fallback-system`。**字符串出现证明支持线索，不证明所有版本、模式及协议的行为。**

我从 [App Store 页面](https://apps.apple.com/us/app/shadowrocket/id932747118) 确认 Shadowrocket 开发者官网为 [shadowlaunch.com](https://shadowlaunch.com/)，没有把搜索结果中自称“官方手册”的其他域名当成官方来源。App Store 的更新记录也明确提到独立直连 DNS 及 DNS/TUN 修复，说明版本差异有实际影响。

[LOWERTOP 社区手册](https://github.com/LOWERTOP/Shadowrocket) 仅作为查找语法和待验行为的辅助资料，**不是官方协议规范**。其中 `#proxy`、节点 DNS 与 `no-resolve` 的解释须以本机导出配置、DNS 日志与实际链路交叉确认。本次没有把社区描述当成客户端联网验收。

## DNS 取舍

当前代理 DNS 将 Cloudflare 和 Google 两家都列为显式主 DoH，经当前节点转发。不再依赖备用字段实现切换；单主故障的真实 TXT 对照及否定应答延迟边界见 [PRECISION_FIX.md](PRECISION_FIX.md)。IP 字面量避免解析器域名的 bootstrap。节点 DNS 独立使用直连阿里 DoH，不把“先解析节点”建立在节点已可用的前提上。阿里仍知道节点域名；这项暴露被明确限定，不是把所有业务域名交给国内 DNS。

国内/LAN 选当前网络系统 DNS，以便网络切换后采用新的局域网解析服务，保留企业内部域、路由器 DNS 和国内 CDN。这里没有承诺国内查询加密。比起引入缺少实测依据的 wildcard Host DNS 覆写，显式使用已有 `dns-direct-system` 语义更易维护。如果特定客户端忽略该设置或回退限制，应判客户端验收失败，而不是添加检测站例外。

`dns-direct-fallback-proxy = false` 要求直连 DNS 故障不把整个业务切换成代理。`dns-fallback = false` 要求非直连加密 DNS 故障不退回系统 DNS。这两项分别控制不同层次，实际先后与故障表现仍需目标版本验证。

2026-10-31 用 curl 保持证书校验，向 `223.5.5.5`、`1.1.1.1`、`8.8.8.8` 的 `/dns-query` 发送 RFC 8484 请求，均返回可解析 DNS 应答（RCODE 0，有 Answer）。这只验证本次执行环境的端点 TLS/协议可用性，**不是中国大陆可达性、经选中节点可达性或 Shadowrocket 使用了它们的证明**。第二个节点引导地址 `223.6.6.6` 也需要客户端实测。

参考解析服务的一手协议文档：[Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/)、[Google Public DNS DoH](https://developers.google.com/speed/public-dns/docs/doh)。

## TUN、IPv6 与旁路

系统 HTTP 代理的 bypass 与 Packet Tunnel 的路由接管不是同一个层次。选择 None（TUN）也不等于捕获所有 DNS。macOS 的 Network Extension、作用域 DNS、已有 VPN/路由、浏览器安全 DNS 和缓存都可能影响结果。

本项目关闭宽泛的 `bypass-system`，只保留明确局域网代理跳过项及本地路由排除。没有旁路 Apple 全球地址块、测试网段或整个 fake-IP 网段。CGNAT `100.64/10` 作为本地地址规则直连，以兼容常见本地/覆盖网络；该范围不承诺是可信设备。

保留本地 IPv6 规则和动态国内前缀；当前经微信故障对照后采用 `ipv6=false` 的 IPv4 兼容基线，这不是 IPv6 防火墙。首轮保留 IPv6 启用的判断遗漏了本地直连 IPv6 出口检查，已在 `WECHAT_IPV4_FIX.md` 纠正。即使关闭客户端 IPv6，节点本身仍可能经 IPv6 连接。是否存在 IPv6 外发/端口 53 旁路只能通过实际路由和日志确认。IPv6-only/NAT64 网络、企业自定义内网域、其他 VPN 共存均待实测。

初版裸 IP 的 `hijack-dns` 名单未在本机接管硬编码 DNS，此处纠正。实测选择 `*:53`，对 IPv4 UDP 返回 Fake-IP；对未捕获的外部端口 53 增加 REJECT 兜底，局域网保留在前。TCP 无答案不等于透明解析，IPv6 超时也不等于接管成功。未知 DoH、应用自己的解析栈、不经过 Shadowrocket 的 DNS 不受该列表全面控制。没有宣称配置文件能阻止一切绕过，也不通过屏蔽检测站获得好看的结果。

## 数据源审查

候选 [v2ray-rules-dat 构建脚本](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/master/.github/workflows/run.yml) 的计划为 UTC 22:00。它合并多种来源，并保留 `full`、`regexp`、`keyword`。实际样本约 110,194 条直连、27,475 条代理，不能全部视为后缀，也不能视为严格境内/境外地理界限。

我首轮用同源的 Clash 全量直连/代理数据构建到约 145,745 条、4.8 MiB，没有将其作为最终发布版本。随后约 5,700 条的中间 `cn.txt` 未通过淘宝直连哨兵，也未发布。最终直接使用 [v2fly 原始数据语法](https://github.com/v2fly/domain-list-community#structure-of-data)，展开 `include` 属性过滤和 `&affiliation`，避免依赖中间生成器是否跟上数据格式变化。归档只在内存读取，不解压到磁盘，并限制下载及解压大小、循环 include 和格式类型。

[Loyalsoldier/clash-rules 构建脚本](https://github.com/Loyalsoldier/clash-rules/blob/master/.github/workflows/run.yml) 在 UTC 22:30 计划生成代理域名集，明确剔除正则与关键词。本工程严格解析其实际输出格式。完整匹配和后缀的区分不丢失；缺失正则带来的代理例外覆盖不足仍是已知限制，而非假装完整兼容原 V2Ray 列表。

[gaoyifan 更新工作流](https://github.com/gaoyifan/china-operator-ip/blob/master/.github/workflows/build.yml) 在 UTC 02:45 计划生成数据。其 `china` 集合使用可信国内 BGP 分类和未宣告 RIR-CN 登记补充，**不应简化成“所有中国公网 IP 的绝对真值”**。IPv4/IPv6 都只生成带 `no-resolve` 的地址规则。原始前缀可能重叠，转换后用标准库进行同策略精确合并，比较合并后的覆盖量防止意外超大前缀。

blackmatrix7 可作格式参考，但本工程不再叠加另一套分类、广告脚本或许可证依赖。所有选用源的来源、修改方式和许可随工程提供；不把数据仓库的“可下载”当成“无许可限制”。

## 自动化实际边界

本地已真实下载、转换并运行静态测试；工作流 YAML 经静态检查。GitHub 手动触发、bot 推送及托管环境执行须另行验证，进展及实际运行链接记录在 `VALIDATION.md`；schedule 的首次定时触发和客户端实测分别验收，不据手动运行声称都已完成。

任何 URL 下载、输入或质量门禁失败，都不会以空列表或陈旧缓存伪装当天成功更新。没有数据变化时保留最后发布版本的可复现源快照。GitHub 的 commit/push 是发布边界；失败任务的工作区变化不会成为远端正式配置。
