# 精确分流与更新可靠性修订

> 历史记录（2026-10-31）：以下配置和测试结果仅对应当时版本。后续调整见 [ENHANCED_WHITELIST.md](ENHANCED_WHITELIST.md)，当前使用说明见 README。

注册后缀收紧、双主 DNS 和后续 Apple 下载测试见 [PRECISION_FIX.md](PRECISION_FIX.md)。

日期：2026-10-31，Asia/Shanghai。修订范围包括精确直连例外、规则校验和更新健康检查；未测试节点解锁能力。

## 已实现

| 原缺口 | 修订后的行为 | 检查方式 |
| --- | --- | --- |
| 品牌管理域名可能走代理 | 18 个精确管理主机 DIRECT，本地/私网路径保留 | 来源记录、相似域名边界测试；具体硬件需在对应网络验证 |
| 公共 Wi-Fi 检测依赖代理 | captive.apple.com 精确 DIRECT | 公开检测页及原生策略日志；没有模拟真实酒店认证流程 |
| 中国 NTP 被全球代理后缀覆盖 | cn.pool.ntp.org 与 0～3.cn.pool.ntp.org 精确 DIRECT | UDP/123 请求/应答校验，全球与日本池负向样本仍 PROXY |
| 国内业务例外被压缩/覆盖 | 三个汇丰中国业务域族、指定 Qoder CN 账户主机前置 DIRECT | 官方业务依据、上游专用分类核查、公开页面与边界回归 |
| 系统校时依赖节点 UDP | 三个 Apple 校时主机精确 DIRECT | Apple 文档、time.apple.com UDP 应答；不修改系统时间 |
| 下载通道未区分 | 17 个 Apple、4 个 Microsoft 指定下载/更新主机 DIRECT | 官方用途、现有数据链交叉核查、公开根路径协议响应 |
| 普通代理优先规则覆盖一切 | 独立维护经过审查的例外层，普通上游表之间仍代理优先 | 52 条例外逐条路由检查、52 条 DNS 端口保护检查 |
| 少量哨兵无法覆盖转换边界 | 每次构建独立检查 141,228 个域名边界样本和 IP 精确集合 | CI 中执行 scripts/audit.py；不是逐域名联网 |
| 无变化不提交时难以判断停更 | 独立只读 health 工作流检查更新运行、失败与 36 小时陈旧状态 | 单元故障样本、真实 GitHub API、Actions 执行 |

新的完整配置仍由同一订阅地址发布。规则从 42,450 条增至 42,502 条；IPv4 兼容基线、no-resolve、统一 PROXY、无广告过滤/解密/脚本/远程规则集均保留。

## 优先级与 DNS

实际顺序：私网 IP 和本地保留命名空间 → 外部端口 53 拒绝兜底 → 精确管理主机 → 经审查直连例外 → 普通代理 → 普通国内直连 → 国内 IP → FINAL,PROXY。

公共品牌管理域名位于端口兜底之后，避免仅因域名就放开对公共地址的 DNS 连接；目的地址已知为私网时，仍由前面的私网规则允许。品牌域名正确解析到路由器，仍依赖该网络的本地 DNS/DHCP，不固定写死家庭网关地址。

DIRECT 域名使用当前网络的系统 DNS，查询不一定加密。应用自带 DoH/DoT、私网旁路和 Tunnel 外流量需单独检查。

## 例外规则的校验

- config/overrides.json 每组都记录类型、范围、用途和 HTTPS 来源。
- 管理域名仅允许 DOMAIN。专门的业务域族才使用 DOMAIN-SUFFIX；中国 NTP 和账户服务使用 DOMAIN，不把 cn、整个品牌或共享 CDN 直接放行。
- 代理保护与直连例外发生域名范围相交时停止构建。Google、ChatGPT、Claude、GitHub、Netflix、Copilot、Apple TV/News/Intelligence 等继续代理。
- 带 community_check 的例外，以本次固定的同一个 v2fly 归档核验专用分类或 @cn 属性。证据被移除或字段格式改变时停止发布，不静默改成更宽的白名单。
- 局域网与经审查例外独立生成，不参与普通直连表的后缀压缩，防止 .cn 把精确证据吞掉。
- dist/conflicts.json 中 ordinary-sources 是普通源处理阶段，reviewed-policy 是最终审查例外覆盖阶段；前者的 drop-direct 不代表最终必然代理。

## 审查后维持代理的条目

此前发现的 12 项交叉记录中，并非 12 项都是误分类。下列七项依据不足或无需调整，维持原策略：

- api.alibabacloud.com、cn.alibabacloud.com、status.alibabacloud.com：@cn 是可直连分类线索，不证明整个国际站服务属于国内业务；只纳入官方明确列出的 account-cn 主机。
- 三个 Qualcomm 时间地址：已有社区标记，但本轮没有独立确认其当前国内接入用途，也没有 Mac/iPhone 场景的实际命中需求。
- lenovo.com.cdn.cloudflare.net：这是特定 CDN 别名，正常 lenovo.com 本来已直连；没有因为 CNAME 就放开整个 cloudflare.net。

## 实测结果与未测项目

Mac 候选下，中国 NTP 的五个指定主机和 time.apple.com 均收到有效 UDP/123 应答（检查 NTP 模式、同步状态、stratum、请求时间戳及响应长度），脚本没有设置系统时间。第二轮 time.apple.com 曾出现一次超时，单独复查收到有效 stratum 1 应答；两次结果分别保留，单次复查成功不代表长期稳定。中国池五个指定主机两轮均收到有效应答。联网检测返回 200；App Store、三个国内业务公开主页、指定账户入口均收到 HTTP 响应；Google 和 GitHub 继续可用。

下载 CDN 根路径返回的 400/404 仅说明收到了协议响应；完整安装包下载、账户登录、商城地区和流媒体播放资格需另行验证。测速受当时网络和 CDN 调度影响，直连不保证处处更快。原生客户端日志已核对 NTP、联网检测、国内业务和下载主机均命中前置 DIRECT；Google/GitHub 保持代理。原始客户端日志留在本机，不发布个人出口、节点信息或账号数据。

更新健康检查每天北京时间次日 00:23 运行，最近完成的更新失败、36 小时没有成功、运行超过 1 小时或长时间排队时显示失败；成功 NO_CHANGE 算作新鲜。邮件由 GitHub 账户通知设置决定。整个仓库 Actions 停用、GitHub 调度/平台故障无法靠仓库内部任务自行恢复，需要独立的外部监控。

尚未在 iPhone 上逐项核查原生日志，也未完成新增例外、IPv6-only/NAT64、长期内存、真实公共 Wi-Fi 认证、特定路由器/NAS 或节点/DNS 全失败的故障注入验收。微信 IPv6 故障仍采用 IPv4 兼容设置，VPS 未改动。

## 正式发布验收

- 修订提交：`21eef67bc4982fb8caf7af5452c1fadca79e84f4`。GitHub [完整更新工作流](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41167255928) 已成功运行：40 项测试、在线下载、离线复现、全源审计和无变化跳过提交均通过。
- 独立健康检查的 [push 运行](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41167255925) 和 [手动运行](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41167503549) 均成功。定时表达式已检查，未来每日运行仍取决于 GitHub 调度。
- 匿名下载的正式配置与本机产物 SHA-256 相同：`e9fb1cdf880672f8a54e1c046708ea03497fb7646d04c787234978bfcbf6bc32`。
- Mac 在 12:08:29 从正式 GitHub 订阅更新，原生编辑器解析出 42,502 条规则，已选中正式配置并保持全局“配置”模式连接。
- 正式配置下 13 项公开 HTTP 探测均完成协议交换。NTP 首轮 5/6 应答有效，`cn.pool.ntp.org` 一次超时，单独复查有效（约 108 ms）；其余四个中国池主机和 Apple 校时成功。五个中国池主机的原生日志均为精确 DOMAIN / DIRECT，首次超时与复查成功分别记录。
- 正式配置的 10 项实时 DNS 检查符合预期，三项公共 TCP/53 的原生日志明确命中 `DST-PORT,53,REJECT`。局域网网关 3/3 ping 应答。临时代理日志恢复关闭，本地候选下载服务器已停止。
