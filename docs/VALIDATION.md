# 交付验证记录

日期：2026-10-31，Asia/Shanghai。

## 已实现且在本地验证

- 在线解析三个上游仓库的固定提交并实际下载四份输入。没有使用空占位表或编造的示例规则交付。
- 生成 42,450 条规则，配置大小 1,537,288 字节（约 1.47 MiB），UTF-8 / LF。
- `DOMAIN` 100 条、`DOMAIN-SUFFIX` 32,687 条、IPv4 地址规则 6,182 条、IPv6 地址规则 3,479 条、DST-PORT 1 条、FINAL 1 条。IP 数量包括局域网规则；前缀经过精确合并，可能与原始行数不同。
- 国内源可表达的唯一条目 7,934；代理源 27,324；IPv4 输入 6,174；IPv6 输入 3,475。国内源有 3 条正则明确省略并记录。70 项跨策略交叉记录按代理优先处理。
- 16 个静态路由哨兵及 6 个 DNS 端口哨兵通过：包括百度、淘宝、腾讯直连；Google、GitHub、ChatGPT 代理；未收录域名默认代理；局域网、国内/境外 IPv4/IPv6 分类。
- 全部 IP 规则带 `no-resolve`；无广告拦截规则、远程规则集、MITM、脚本、重写或地区节点策略组。
- `python3 -m unittest discover -s tests -v`：**26 项测试通过**，本机 Python 3.9。覆盖精确/后缀边界、IDNA、include/affiliation/属性过滤、循环 include、未知格式、CIDR 家族/公有性/规范化、冲突优先级、404/超时重试、空/超大/损坏输入、计数和覆盖量门禁、原始快照哈希、重复构建，以及失败时旧版所有文件不变。
- 上游提交号或注释变化、实际规则无变化时，测试确认所有已发布文件字节和 mtime 不变。
- 完成第二次真实在线构建，返回 `NO_CHANGE`，保留既有发布配置、报告和源快照。
- `python3 scripts/build.py --offline --check`：完整配置、源快照及报告逐字节复现通过。
- 官方 `actionlint v1.7.12`（下载文件核对官方发布 SHA-256 后运行）：工作流语法、表达式和 cron 静态检查通过。命令：`actionlint -shellcheck= -pyflakes= .github/workflows/update.yml`；没有声称执行了 shellcheck/pyflakes。
- 主 DNS、备用 DNS、节点引导主地址的 IP 地址 DoH TLS/应答探测通过，范围仅限本次执行环境，详见 `REVIEW.md`。
- 初期只读核查本机 Shadowrocket 2.2.93；随后经用户授权导入候选并完成 macOS 分流、DNS 接管对照测试，见 `MAC_DNS_FIX.md`。没有更改节点凭据或 VPS。

配置 SHA-256：

```text
2a583093fb0c506b7e71678409ad8c1fdc35bc425e9d7d00ae67efefd8735abb
```

以上数量及哈希是本次交付快照，不是以后每日输出的固定值；当前数据以 `dist/manifest.json` 为准。

## GitHub 发布验收

- 已发布公开仓库：[jhz1022/Shadowrocket-Rules](https://github.com/jhz1022/Shadowrocket-Rules)，默认分支 `main`。
- 已匿名下载 [唯一订阅地址](https://raw.githubusercontent.com/jhz1022/Shadowrocket-Rules/main/dist/Shadowrocket.conf)，初版与当时本地配置逐字节一致；DNS 修订版发布记录见下。
- [首次 push 运行](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41160093172) 已成功完成 `verify` 和 `update`：托管 Ubuntu / Python 3.12 上 24 项测试、真实下载、构建门禁和离线复现均通过。
- 首次在线构建返回 `NO_CHANGE`，发布步骤正常跳过提交；没有为了测试制造规则变更或空提交。真实 bot 提交/推送及推送冲突尚未遇到，不能写成已经实测。
- Actions 已启用。仓库默认令牌权限保持只读，`update` 任务日志确认获得 `Contents: write`；没有放宽整个仓库的默认权限。
- [workflow_dispatch 手动验收](https://github.com/jhz1022/Shadowrocket-Rules/actions/runs/41160097988) 已成功完成 `verify` 和 `update`，确认可以手动运行完整流水线。
- 默认分支当前未启用分支保护；未来如果启用，需重新评估 bot 的提交/推送策略。
- 工作流配置了每日 UTC 04:23 / 北京时间 12:23 的 schedule，状态 active；首次真实定时触发尚待计划时间到达，不以手动运行替代定时运行证据。

联网复核确认现有 `jhz1022` GitHub CLI 授权有效，具有 `repo` 和 `workflow` 权限。首次检查把沙箱网络限制误判为凭据失效，此处纠正。本次无需重新登录或向脚本、聊天提供密钥。

## macOS 真实客户端验收及 DNS 修订

- Shadowrocket 2.2.93 / macOS 26.7.1，“配置”模式，本机 TUN；未传入 curl 显式代理或账号凭据。
- 25 个站点的 TCP/TLS/HTTP 交换完成；403、401、501 等 HTTP 状态不等于业务完整可用。原生日志核对百度、淘宝 DIRECT，Google、YouTube、GitHub、Netflix、ChatGPT、Claude 等 PROXY。
- 首轮 BrowserLeaks DNS：70 个 Google/Cloudflare 解析出口，本轮均为美国；WebRTC 显示 No Leak。该结果只代表该浏览器该轮请求。
- 首轮 YouTube 实际观察到 720p 视频播放、readyState 4、时间推进、无媒体错误；Netflix 仅首页 200，未验证登录、片库及播放授权。
- 全量域名边界模型 105,766 个样本无策略差异，IPv4/IPv6 合并前后覆盖集合完全相同；不声称原生客户端逐条联网。
- 硬编码 DNS 初轮失败；实测改为 `hijack-dns = *:53`，并在 LAN 之后、业务规则之前设置 `DST-PORT,53,REJECT`。五个公共 IPv4 DNS 的 UDP 查询均得到 Fake-IP；三项 TCP 查询关闭且无 DNS 答案；两项 IPv6 UDP 无答案，但不能单凭超时证明规则命中或物理链路未外发。
- IPv6 字面量和纯 IPv6 域名均失败，IPv4 对照正常。用户确认 VPS 未启用 IPv6；保留客户端 IPv6 处理及 IPv4 优先，没有宣称规则修复了节点的 IPv6 出口。

详细对照、取舍及实时复测命令见 [MAC_DNS_FIX.md](MAC_DNS_FIX.md)。原始诊断日志仅在本机忽略目录，不发布个人出口 IP、节点名称或凭据。

## 待补充验收

- iPhone 真机及长期性能；Mac 短时采样不能代替 iPhone 内存验收。
- 主备 DNS / 节点故障注入、Wi-Fi/热点切换、其他 VPN 共存。
- VPS 启用 IPv6 后的纯 IPv6 目标、IPv6-only/NAT64 网络。
- 管理员物理网卡抓包（本次无管理员权限）、应用自带 DoH/DoT、私网旁路。
- Netflix 登录播放、区域片库和“原生 IP”资格；规则不能承诺节点的出口信誉或服务商授权。

验收清单见 `CLIENT_TEST.md`。不宣称“100% 零泄漏”或“任意节点所有服务可用”。
