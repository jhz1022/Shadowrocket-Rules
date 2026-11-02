# 构建与验证记录

> 历史记录（2026-10-31）：以下配置和测试结果仅对应当时版本。后续调整见 [ENHANCED_WHITELIST.md](ENHANCED_WHITELIST.md)，当前使用说明见 README。

日期：2026-10-31，Asia/Shanghai。

## 本地构建与检查

- 解析三个上游仓库的固定提交，下载四份输入并构建规则。
- 生成 44,189 条规则，配置大小 1,595,883 字节（约 1.52 MiB），UTF-8 / LF。
- `DOMAIN` 176 条、`DOMAIN-SUFFIX` 34,350 条、IPv4 地址规则 6,182 条、IPv6 地址规则 3,479 条、DST-PORT 1 条、FINAL 1 条。IP 数量包括局域网规则；前缀经过精确合并，可能与原始行数不同。
- 国内源可表达的唯一条目 7,934；代理源 27,324；IPv4 输入 6,174；IPv6 输入 3,475。国内源有 3 条正则明确省略并记录。注册/TLD 直连排除 52 项；跨策略记录的普通源与审查例外分阶段统计见当前 conflicts.json。
- 23 个静态路由哨兵、74 个审查例外路由检查及 6 个基础 DNS 端口哨兵通过：包括百度、淘宝、腾讯直连；Google、GitHub、ChatGPT 代理；未收录域名默认代理；局域网、国内/境外 IPv4/IPv6 分类。
- 全部 IP 规则带 `no-resolve`；无广告拦截规则、远程规则集、MITM、脚本、重写或地区节点策略组。
- `python3 -m unittest discover -s tests -v`：**50 项测试通过**，本机 Python 3.9。覆盖精确/后缀边界、IDNA、include/affiliation/属性过滤、循环 include、未知格式、CIDR 家族/公有性/规范化、冲突优先级、404/超时重试、空/超大/损坏输入、计数和覆盖量门禁、原始快照哈希、重复构建，以及失败时旧版所有文件不变。
- 上游提交号或注释变化、实际规则无变化时，测试确认所有已发布文件字节和 mtime 不变。
- 完成第二次真实在线构建，返回 `NO_CHANGE`，保留既有发布配置、报告和源快照。
- `python3 scripts/build.py --offline --check`：完整配置、源快照及报告逐字节复现通过。
- 官方 `actionlint v1.7.12`（下载文件核对官方发布 SHA-256 后运行）：工作流语法、表达式和 cron 静态检查通过。命令：`actionlint -shellcheck= -pyflakes= .github/workflows/update.yml`；未执行 shellcheck/pyflakes。
- 主 DNS、备用 DNS、节点引导主地址的 IP 地址 DoH TLS/应答探测通过，范围仅限本次执行环境，详见 `REVIEW.md`。
- 初期只读核查本机 Shadowrocket 2.2.93；随后导入候选并完成 macOS 分流、DNS 接管对照测试，见 `MAC_DNS_FIX.md`。没有更改节点凭据或 VPS。

配置 SHA-256：

```text
c3461bc8c0526d46b1a0cad28d839c5c80ce86961628929e3b0bf13758337aae
```

以上数量及哈希是本次发布快照，不是以后每日输出的固定值；当前数据以 `dist/manifest.json` 为准。

## GitHub 发布验收

- 已发布公开仓库：[jhz1022/Shadowrocket-Rules](https://github.com/jhz1022/Shadowrocket-Rules)，默认分支 `main`。
- 已匿名下载 [唯一订阅地址](https://raw.githubusercontent.com/jhz1022/Shadowrocket-Rules/main/dist/Shadowrocket.conf)，初版与当时本地配置逐字节一致；DNS 修订版发布记录见下。
- [首次 push 运行](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41160093172) 已成功完成 `verify` 和 `update`：托管 Ubuntu / Python 3.12 上 24 项测试、真实下载、构建门禁和离线复现均通过。
- 首次在线构建返回 `NO_CHANGE`，发布步骤正常跳过提交；没有为了测试制造规则变更或空提交。bot 提交、推送及冲突处理尚未实测。
- Actions 已启用。仓库默认令牌权限保持只读，`update` 任务日志确认获得 `Contents: write`；没有放宽整个仓库的默认权限。
- [workflow_dispatch 手动验收](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41160097988) 已成功完成 `verify` 和 `update`，确认可以手动运行完整流水线。
- 默认分支当前未启用分支保护；未来如果启用，需重新评估 bot 的提交/推送策略。
- 工作流配置了每日 UTC 04:23 / 北京时间 12:23 的 schedule，状态 active；首次真实定时触发尚待计划时间到达，不以手动运行替代定时运行证据。

联网复核确认 `jhz1022` GitHub CLI 授权有效，具有 `repo` 和 `workflow` 权限。首次检查误将运行环境的网络限制判断为凭据失效；复核后沿用原有登录，密钥未写入脚本或记录。

## macOS 测试与 DNS 修订

- Shadowrocket 2.2.93 / macOS 26.7.1，“配置”模式，本机 TUN；未传入 curl 显式代理或账号凭据。
- 25 个站点的 TCP/TLS/HTTP 交换完成；403、401、501 等 HTTP 状态不等于业务完整可用。原生日志核对百度、淘宝 DIRECT，Google、YouTube、GitHub、Netflix、ChatGPT、Claude 等 PROXY。
- 首轮 BrowserLeaks DNS：70 个 Google/Cloudflare 解析出口，本轮均为美国；WebRTC 显示 No Leak。该结果只代表该浏览器该轮请求。
- 首轮 YouTube 实际观察到 720p 视频播放、readyState 4、时间推进、无媒体错误；Netflix 仅首页 200，未验证登录、片库及播放授权。
- 全量域名边界模型 105,766 个样本无策略差异，IPv4/IPv6 合并前后覆盖集合完全相同；未在原生客户端逐条联网测试。
- 硬编码 DNS 初轮失败；实测改为 `hijack-dns = *:53`，并在 LAN 之后、业务规则之前设置 `DST-PORT,53,REJECT`。五个公共 IPv4 DNS 的 UDP 查询均得到 Fake-IP；三项 TCP 查询关闭且无 DNS 答案；两项 IPv6 UDP 无答案。进一步查看本轮原生拒绝日志，五项 TCP/IPv6 UDP 均命中 `DST-PORT,53,REJECT`；物理网卡抓包未执行。
- IPv6 字面量和纯 IPv6 域名均失败，IPv4 对照正常。VPS 当时未启用 IPv6；首轮保留客户端 IPv6 处理及 IPv4 优先。后续微信故障表明该判断遗漏本地直连出口，当前已改为 IPv4 兼容基线，见下。

- 修订候选下重跑 BrowserLeaks DNS：67 个 Google/Cloudflare 出口，均为美国，无中国解析出口；这是该轮浏览器结果，不代表所有应用。

- DNS 修订 [bd11bc0](https://github.com/jhz1022/Shadowrocket-Rules/commit/bd11bc012e6e825e9faca7864800252341eecf28) 已发布；[该版 Actions](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41163723164) 的 verify / update 均成功，26 项测试、在线下载、离线复现通过，无规则变化跳过提交。
- 匿名下载修订版与本机发布文件 SHA-256 一致；Mac 正式 GitHub 订阅已更新并选用，原生解析 42,450 条规则。正式订阅下再次运行 10 项 DNS 探测全部符合预期，11:18:33 的原生拒绝日志再次核对 TCP / IPv6 UDP 命中端口兜底。25 个站点请求重新完成，HTTP 状态与候选一致。
- 正式订阅下最后一轮 BrowserLeaks 为 70 个 Google/Cloudflare 美国出口。临时代理日志已恢复关闭；VPN 仍连接、全局路由仍为“配置”，没有更改首页节点。

详细对照、取舍及实时复测命令见 [MAC_DNS_FIX.md](MAC_DNS_FIX.md)。原始诊断日志仅在本机忽略目录，不发布个人出口 IP、节点名称或凭据。

## 微信头像/图片故障修订

- 微信加载缓慢；文件传输助手测试显示文字消息正常，头像和图片加载很慢，且问题早于聊天记录导入。
- 对应消息长连接实际经 en0 直连，RTT 约 54–60 ms，本轮该连接未观察到重传；这不等于所有图片链路正常。
- 图片请求大量尝试国内公网 IPv6，但物理网卡只有链路本地 IPv6 地址；隧道进程的对应出口持续 SYN_SENT、零接收数据。IPv4 图片连接可建立并接收数据。
- 仅关闭现用配置 IPv6 支持，保留分流、DNS 接管和拒绝兜底；头像域名 AAAA 在本机返回映射到 IPv4 的地址，微信新连接转为 IPv4。重新打开头像和图片后，加载速度明显恢复。
- 模板和构建器改为 `ipv6=false` / `prefer-ipv6=false`，新增 4 个微信路由哨兵，27 项自动测试通过。没有采用仍在研究的国内例外草案。
- 公开 CDN 根路径探测：wx.qlogo.cn TLS 成功、HTTP 400，约 0.12 秒；mmbiz.qpic.cn TLS 成功、HTTP 400，约 0.20 秒。缺少对象路径时 400 不能算图片下载验证；wx.qpic.cn 的根路径 TLS 探测失败。头像和图片的改善依据是实际打开前后的对照及微信连接变化。
- 详细证据与兼容边界见 [WECHAT_IPV4_FIX.md](WECHAT_IPV4_FIX.md)。原始聊天截图、节点标识及个人接口地址未发布。

## 精确例外与自动更新审计修订

- 上线 18 个精确管理主机、34 条经审查直连规则，明确来源与用途；中国 NTP 规则随此次修订上线。
- 中国 NTP 五个主机、三个汇丰中国业务域族、指定 Qoder CN 账户、联网检测、系统校时和指定下载通道进入独立前置例外层，保留普通表代理优先和海外服务保护。
- 40 项自动测试通过；每次构建/发布新增独立全源审计：当前 141,228 个域名边界样本无策略差异，IPv4/IPv6 精确集合相同。source @cn 证据失效、例外越界、DNS 兜底被绕过或受保护海外服务被直连均会拒绝构建。
- 真实在线构建返回 NO_CHANGE，离线逐字节复现及 actionlint v1.7.12 检查两个工作流通过；未运行 shellcheck/pyflakes。
- 本机候选首轮 6 个 NTP 主机收到有效 UDP/123 应答；第二轮中国池五项均成功，Apple 校时有一次超时后单独复查成功。13 项公开 HTTP 探测均完成协议交换；下载根路径的 400/404 不等同完整下载通过。10 项实时 DNS 结果符合预期。
- GitHub [完整更新运行](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41167255928) 已成功：40 项测试、在线下载、离线复现和全源审计均通过，NO_CHANGE 未创建提交。独立只读健康检查的 [手动运行](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41167503549) 也已成功。
- Mac 已从正式 GitHub 订阅更新并启用 42,502 条规则；正式配置下 13 项 HTTP 协议交换、10 项 DNS 预期结果及局域网 3/3 ping 应答通过。NTP 首轮 5/6 成功，cn.pool.ntp.org 一次超时后复查成功，原生日志确认五个中国池主机精确 DIRECT。详情见 HARDENING 的正式验收记录，保留候选及正式轮次原始超时。
- 详情及未实测边界见 [HARDENING.md](HARDENING.md)。原始请求和日志只保存在本机忽略目录。

## 待测项目

- iPhone 真机及长期性能；Mac 短时采样不能代替 iPhone 内存验收。
- 主备 DNS / 节点故障注入、Wi-Fi/热点切换、其他 VPN 共存。
- VPS 启用 IPv6 后的纯 IPv6 目标、IPv6-only/NAT64 网络。
- 管理员物理网卡抓包（本次无管理员权限）、应用自带 DoH/DoT、私网旁路。
- Netflix 登录播放、区域片库和“原生 IP”资格；规则不能承诺节点的出口信誉或服务商授权。

验收清单见 `CLIENT_TEST.md`。上述检查不足以保证所有网络下“100% 零泄漏”，服务可用性也受节点和账户条件影响。

## 注册后缀收紧与故障实测

规则行为、独立解码审计、DNS 故障注入和下载测试结果见 [PRECISION_FIX.md](PRECISION_FIX.md)。此前章节中的旧数量、单主/备用设计和历史运行均按对应轮次理解，当前产物以本页顶部及 manifest 为准。
