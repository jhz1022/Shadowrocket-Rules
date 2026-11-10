# 大陆网站入口与海外业务直连复核

2026-11-10，以正式提交 `4e76a8a` 为基线。比较对象为 v2rayN 7.25.6 的 Xray 绕过大陆模板及 Loyalsoldier 202611092204 数据库。范围取自上轮全表差异，按原始名称去重。

| 复核组 | 总数 | 调整 | 已测入口维持原策略 | 待核 |
|---|---:|---:|---:|---:|
| v2rayN 的 cn 组直连，项目明确代理 | 74 | 8 | 24 | 42 |
| v2rayN 无域名命中，项目普通直连后缀命中 | 253 | 20 | 60 | 173 |

[逐项清单](review.tsv) 包含原规则、上游归集文件、变更范围、依据、两处 DNS 回答及 HTTPS 结果。[待核清单](pending.tsv) 含 215 个暂缓的原始名称，以及 5 个同域部分修订后仍需验证的入口。维持原策略的结论只覆盖本次证据。

## 大陆入口

| 允许精确直连的主机 | en0 接口 HTTPS 结果 |
|---|---|
| www.airbnb.cn、www.dynacw.com.cn、www.futu.cn、longbridge.cn、www.msi.cn | 有效证书，首页 HTTP 200。华康另有[官网产品页](https://www.dynacw.com.cn/index.aspx)，微星另有[大陆销售点](https://www.msi.cn/wheretobuy)。 |
| longportapp.cn、www.longportapp.cn | www 跳至裸域，裸域跳至 /en/ 并返回 200。另见[长桥产品团队发布页](https://longportapp.cn/zh-CN/topics/21451002?app_id=longbridge)。 |
| logitech.com.cn、logitechg.com.cn、www.logitechg.com.cn | 跳至对应罗技官网，前两个目的路径为 /zh-cn。例外只覆盖左列的跳转入口，最终目的主机继续独立分流。 |

两处大陆解析均将这些主机指向候选中国 IP 表内的地址。www.logitech.com.cn 从所测节点连续跳回同一 URL，单次 301 容易误判为可用；msi.cn 裸域和 www.longbridge.cn 也未取得成功响应。这几项继续使用旧策略。

## 撤回普通直连后缀

以下 20 个后缀进入项目已有的 `omit_ordinary_direct_suffixes`。对未命中更具体业务规则的连接，当前候选按目标地址分流。后续上游收录的具体主机仍可独立匹配。

| 原因 | 域名 |
|---|---|
| 海外或跨境业务的企业站、投资者门户或零售站。逐域官网证据及地址记录见清单 | bocaviation.com、bocgi.com、bocigroup.com、chinamobileltd.com、chinatelecom-h.com、citiccapital.com、clsa.com、joybuy.com、joybuy.es、oppodigital.com、sealsuite.com |
| 同一个后缀下有大陆和表外接入点 | larksuitecdn.com、taptap.com |
| 当前入口为出售、停放或转往与旧归集依据不符的站点 | sinajs.com、yowhale.com、myelasticsearch.com、ics.design、ivweb.io、tcdlive.com、isd.com |

中银航空自述总部在新加坡、经营全球飞机租赁业务。中行公开名录列有香港中银投资及其网站；bocgi.com 本次只有表外 A 证据，根域未完成 HTTPS，www 返回 NXDOMAIN。收回整域直连的依据是现有境外业务资料及地址，网站能否正常使用仍需另测。[中银航空](https://www.bocaviation.com/en/Careers/Graduate-Management-Associate-GMA-Program) · [中国银行子公司名录](https://www.boc.cn/en/investor/ir2/202503/P020250326622277080882.pdf)

火山引擎在海外地区以 SealSuite 名称分发飞连，www.sealsuite.com 的两处解析也都返回表外地址。sealsuite.net 缺少相应主机证据，已单列待核。[飞连官方分区说明](https://docs.volcengine.com/docs/feilian/download-client?lang=zh)

Lark 官网实际引用了下列资源主机，官方文档也列出了该 CDN。lf-static-sg 在阿里与腾讯分别返回 23.59.252.184 等、23.218.94.57 等表外地址，根路径返回 200；p16-hera-sg 在两处均为表外地址，返回 400；sf16-sg 在两处均有中国表内的 42.202.219.207。TapTap 的根域在两处均返回表外地址，www 在两处均为 39.107.195.45；HTTPS 分别以 302、301 跳往 www.taptap.cn。运行时 DNS 和 CDN 调度可改变实际选择。[Lark 官方文档](https://www.larksuite.com/hc/en-US/articles/235185325198-use-the-link-preview-extension-in-base) · [TapTap 中国官网](https://www.taptap.cn/download)

sinajs.com 的根域和 www 都跳往 Atom，且能核对到[对应的出售页面](https://domains.atom.com/lpd/name/sinajs.com)。这些观察只用于撤回旧的整域直连依据。hr-welink.com、mzyygk.com 等出现与上游归集不符的页面标题，已列入待核，待查所有者或实际业务请求。

## 取证及验证边界

逐项检查根域与 www，共 654 个名称。阿里公共 DNS 使用同日样本并补齐缺项，腾讯公共 DNS 另查同名 A 记录。以基线中国 IPv4 前缀并集划分表内、表外，私网单列。IP 表只给出本项目的路由分类。NODATA 指返回成功但无 A 记录；SERVFAIL、NXDOMAIN、网络请求失败单独标记。CDN 和私有 API 经常只在特定业务主机返回有效应答。

HTTPS 使用 Mac 的 en0 接口、公开 A 地址、原域名和系统证书校验，记录根路径响应或重定向。failed 表示未获得通过证书校验的 HTTP 响应。未测表示该主机没有合适的公开地址或不在该轮 HTTPS 验证范围。公开端点验证到首页或资源响应为止；账户登录、交易、支付、游戏和会议未测试。Mac 客户端对照见下文。公开下载、域名解析、TLS/HTTP、业务账户和原生 VPN 路由分别有自己的验证范围。

审核针对上游泛 .cn 直连与普通代理规则重叠的 4 个精确名称，审批指纹绑定本次基线及候选。原始来源快照与 IP 表保持基线版本，便于逐行复核配置差异。

## Mac 实机复测

测试前保存了 6 份配置数据库的一致性备份，逐份通过 SQLite 完整性检查。活动配置及其备份的有序规则和 General 设置与正式版 `4e76a8a` 一致。候选以独立文件导入，使用原 Wi-Fi、原节点和「配置」路由模式。

首轮的 10 个大陆入口均命中精确直连。Lark 的 `sf16-sg.larksuitecdn.com` 从旧后缀直连变为 `FINAL,PROXY`，根路径耗时由约 0.2 秒升至 1.8 秒。立即切回原配置，复核该主机恢复后缀直连并在约 0.37 秒返回 200。回退对照期间微星首页有一次 12 秒超时，命中旧代理规则；两轮候选直连该首页均返回 200。耗时是当次观察。

修订版保留一个 Lark 精确例外，仍省略整个 CDN 的普通直连后缀。两处大陆 DNS 对该主机均给出中国 IP；从 Lark 官网取得实际样式表，旧配置、指定大陆节点及修订候选三次下载均为 7,734,648 字节，SHA-256 相同。修订版正常请求约 0.39 秒完成下载。另一主机 `lf-static-sg.larksuitecdn.com` 实测命中 `FINAL,PROXY`。

修订版 22 个 HTTPS 请求均完成证书验证并返回预期状态，且逐项对上本轮原生日志。10 个大陆入口均为 `DOMAIN,…,DIRECT`；Joybuy、中银航空、中信里昂、OPPO Digital 走代理；TapTap 根域走代理，www 命中中国 IP 直连。百度直连，Google、GitHub、OpenAI API 走代理，API 未带凭据时返回 401。测试后代理日志恢复关闭。

最终配置 SHA-256 为 `4ca07752a7ad75e29d2106d57cb497649dc85bbdb192a1ec591f917877292c13`，原生客户端的 148,929 条有序规则及 General 设置均与它一致。相对正式基线，生成配置新增 11 条精确直连，删除 20 条整域直连。91 项单元及故障测试全部通过。静态验证覆盖 185 个路由用例、559,691 个域名边界、IPv4/IPv6 集合及离线逐字节复现。
