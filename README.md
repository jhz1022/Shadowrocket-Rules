# Shadowrocket 分流规则

> 墙外有更广阔的信息，也有偏见、误解和未经证实的说法。多看一种声音，是为了多一份判断的依据。愿你始终保有独立思考的心：不因观点顺耳就全盘接受，也不因立场不同就急着否定。多查证、多思考，把判断留给自己。

个人自用的 Shadowrocket 配置，公开分享。以「绕过大陆」为基础，让国内及适合直连的服务尽量直连，海外服务按规则走代理，未命中的流量默认代理。

## 使用

在 Shadowrocket 的「配置」页从 URL 添加：

```text
https://raw.githubusercontent.com/jhz1022/Shadowrocket-Rules/main/dist/Shadowrocket.conf
```

也可以在 Shadowrocket 的「配置」页扫码添加：

<img src="docs/assets/config-qr.png" alt="Shadowrocket 配置订阅二维码" width="280" height="280">

选择「使用配置」，首页的「全局路由」设为「配置」，再选择自己的节点并连接。

**这里只提供分流配置，不提供节点。** 配置计划每天北京时间 12:23 自动检查上游并更新；客户端需要刷新配置才能获取新版。更新情况可在 [Actions](https://github.com/jhz1022/Shadowrocket-Rules/actions) 查看。

## 分流方式

- 局域网、国内网站及上游收录的可直连服务优先直连。
- 国外服务的中国站点和国内下载节点单独判断，例如 Bing 中国、iCloud 中国、Steam 国内下载，不按品牌一概代理。
- Claude、OpenAI、Copilot 等受保护服务优先走代理；Google 按具体服务分类，中国下载和字体资源可直连。
- 未分类域名解析后按中国 IP 规则判断，最后由代理兜底；不因 `.cn` 后缀直接放行。中国政府、教育域按服务类别直连。

使用首页当前选择的代理节点，没有复杂的地区分组，也不包含广告拦截、MITM、脚本或重写。

## 几点说明

- **DNS**：直连服务使用当前网络的系统 DNS，保留国内 CDN 和局域网解析；代理侧及未分类域名使用代理解析或经代理访问的加密 DNS。未分类服务仍可能受海外 DNS 的 CDN 调度影响。
- **IPv6**：默认采用 IPv4 兼容设置。这不等于关闭手机或电脑的系统 IPv6；iPhone 建议开启小火箭「隧道 → 包括所有网络」，重连后检查实际出口。
- **UDP**：节点不支持转发时拒绝请求，不回退到直连；部分游戏、语音等功能需要支持 UDP 的节点。
- **体积**：完整规则内置在一份配置中。小火箭导入后显示的大小还包含数据库和索引，不等于 VPN 运行内存。保留覆盖范围，只做不改变分流结果的去重与合并。

规则会随上游更新，但无法保证所有地区、运营商和服务都始终适用。遇到异常，可先在小火箭的连接记录中查看命中的规则和出口；检查方法见 [客户端检查说明](docs/CLIENT_TEST.md)。

## 来源

感谢这些持续维护的数据来源：

- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)：增强直连列表、Apple 中国服务。
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)：国内域名及国外服务的中国节点分类。
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)：代理域名列表。
- [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)：中国 IPv4 / IPv6 地址段。
- [Public Suffix List](https://github.com/publicsuffix/list)：域名边界校验。

构建、排查与测试记录见 [docs](docs/)。代码及组合配置按 [GPL-3.0](LICENSE) 分发，上游数据的许可与署名见 [NOTICE](NOTICE.md)。
