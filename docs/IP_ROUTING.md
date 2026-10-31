# 按服务器目标 IP 分流

2026-10-31 起采用用户明确要求的目的地址策略，替代此前的增强域名白名单。公网域名本身不决定 DIRECT/PROXY；同一域名解析到不同目的地址，可以使用不同出口。

## 配置

1. 局域网、本地保留名称及相关地址直连。
2. 未被 DNS 接管机制处理的公网端口 53 请求拒绝。
3. 命中完整大陆 IPv4 / IPv6 地址表的目的地址直连。
4. 其余目的地址使用当前节点代理。

移除 `.cn` 整段放行、业务/品牌直连、强制代理域名层和所有域名数据源。没有单独给 us.ip111.cn 等检测站加代理规则。保留全部大陆 IP 数据、每日更新、源哈希、数量/覆盖变化门槛、独立审计和失败保留旧版机制。

`always-ip-address = true` 要求 TUN DNS 返回真实 IP；公网 IP-CIDR 规则去掉 no-resolve，允许按需解析。`use-local-host-item-for-proxy = true` 尽量使用本地已映射地址建立代理连接，避免分流后又在节点重新解析成另一地址。`dns-direct-system = false` 避免直连策略再改用系统 DNS 得到另一答案。

公网域名使用经代理访问的 Cloudflare/Google DoH。节点域名单独用直连阿里 DoH 引导；保留 dns-fallback=false 及不支持 UDP 时 REJECT。局域网旁路仍存在，不能宣称覆盖所有系统流量。

这意味着代理节点不可用时，新的公网 DNS 解析也可能失败；境外解析器可能返回境外 CDN 节点，随后该节点就会走代理。没有为了让某个国内品牌必定直连而恢复域名例外。DNS 污染、应用自带解析器、节点自身实现和多地址选择仍须结合实际客户端连接核对。

IPv4 兼容设置继续保留（ipv6=false、prefer-ipv6=false），完整 IPv6 地址库仍生成和审计。它不等于禁用系统 IPv6，也不是本次已经验证了原生 IPv6 上网。应另行验证手机蜂窝、网络切换及 IPv6-only/NAT64 场景。

## 数据边界

地址表来自 gaoyifan/china-operator-ip。上游采用国内 BGP 分类和未宣告 RIR-CN 登记兜底，并非服务器机房的实时物理定位数据库；误分类和遗漏可能发生。CDN / Anycast 使用的是实际连接目的地址及其分类，不追踪 CDN 后的源站。

依据：

- [上游数据语义](https://github.com/gaoyifan/china-operator-ip#readme)
- 本机 Shadowrocket 2.2.93 内置 default.conf 对 use-local-host-item-for-proxy、dns-direct-system 的说明。
- 本机应用「总是真实 IP」提示说明 TUN DNS 返回真实地址。

## 检查

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py --offline --check
python3 scripts/audit.py --output .build/policy-audit.json
```

审计独立读取原始 CIDR，以整数区间合并校验所有地址集合完全一致；禁止业务域名插入和公网 no-resolve 回归。使用同一国内/境外目的地址搭配不同域名验证决策独立于域名。静态审计不模拟客户端 DNS/TUN，也不证明 IP 地理库绝对准确。

本机候选实测：ip111.cn（122.114.192.226）使用国内出口；us.ip111.cn（162.222.90.70）使用 VPS 出口。Google generate_204 返回 204，Bing 中国和百度收到 HTTP 响应；Claude 根路径返回 403，说明收到服务器响应，不能据此声称 Claude 登录或会话功能通过。测试中 curl 已报告真实目标地址，而非 198.18.0.0/15 Fake IP。个人出口 IP 和原始记录仅保留在本地 .build/ip-routing。

本机原生连接记录进一步确认：ip111.cn 命中大陆 IP-CIDR DIRECT；us.ip111.cn 命中 FINAL PROXY。测试时临时开启的代理日志已关闭，恢复原设置。五个 IPv4 UDP DNS 目标返回真实 A 记录，三个 TCP DNS 和两个 IPv6 DNS 探测没有收到答案；TXT 正向解析成功。后两类无答案仅证明本次请求未获应答，不单独作为规则拒绝或无泄漏的证明。
