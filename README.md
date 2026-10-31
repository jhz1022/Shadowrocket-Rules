# Shadowrocket 自建分流规则

每日由 GitHub Actions 下载数据、清洗、检查并更新一份完整的 [`dist/Shadowrocket.conf`](dist/Shadowrocket.conf)。客户端只订阅这一份配置。国内分类直连，境外及未命中流量默认 `PROXY`，使用首页当前选择的节点。

没有节点、订阅密码、地区策略组、广告拦截、MITM、脚本、重写或远程 RULE-SET。DNS 检测站没有人工添加的特殊规则。

当前仓库：[jhz1022/Shadowrocket-Rules](https://github.com/jhz1022/Shadowrocket-Rules)。可直接订阅：

```text
https://raw.githubusercontent.com/jhz1022/Shadowrocket-Rules/main/dist/Shadowrocket.conf
```

GitHub 发布及 Mac 客户端验证状态见 [验证记录](docs/VALIDATION.md)和[本机修复验收](docs/MAC_DNS_FIX.md)。已在 macOS 26.7.1 / Shadowrocket 2.2.93 实测基础分流与 DNS 修复；iPhone、故障注入和物理网卡抓包仍未验收，不承诺“零 DNS 泄漏”。

本仓库已完成发布。直接使用上面的订阅地址即可；以下步骤用于自行 Fork 或部署另一份仓库。

## 一次性部署

1. 在自己的 GitHub 账户创建公开仓库，建议命名 `Shadowrocket-Rules`，默认分支 `main`。上传本工程所有文件，包含 `.github/`、`dist/inputs/` 和许可证。ZIP 本身不用上传；本地 `.git`、`.build` 不上传。
2. Settings → Actions → General：允许 Actions。默认 Workflow permissions 可保持只读；本工程只为 `update` 任务显式申请 `contents: write`。工作流仅使用 GitHub 自动提供的 `GITHUB_TOKEN`，不用填写个人 PAT。
3. Actions → **Update Shadowrocket rules** → **Run workflow**，在默认分支运行一次；确认 `verify`、`update` 都成功。
4. 在 Shadowrocket 的配置页面从 URL 添加以下地址，把占位内容替换成自己的仓库；启用该配置，全局路由选“配置”，首页选择任意可用节点。节点或机场订阅仍单独保留在首页，禁止提交到本仓库。

   ```text
   https://raw.githubusercontent.com/<用户名>/<仓库名>/main/dist/Shadowrocket.conf
   ```

需要公开原始文件地址才能方便客户端匿名下载。私有仓库不要把含 PAT 的地址填进配置。若 GitHub Raw 在当前网络不可达，可先在已有可用代理下导入或导入本地 `.conf`，随后保留上述订阅地址。

每天北京时间 **12:23（UTC 04:23）**计划运行。上游没变化就不提交；客户端自行决定何时刷新，没有客户端定时更新脚本。这里只把默认分支里的配置作为发布入口，不要求 GitHub Pages 或 GitHub Releases。

## DNS 设计

| 查询用途 | 配置及预期路径 | 边界 |
| --- | --- | --- |
| 国内/LAN 直连域名 | `dns-direct-system = true`，使用当前网络的系统 DNS | 有意保留国内 CDN、企业 split DNS、路由器内网名称；可能是明文 DNS，可见国内解析器是正常现象 |
| 代理/未命中域名 | 代理协议支持时交给节点解析；需要本地答案时使用 `https://1.1.1.1/dns-query#proxy` | 通过首页当前节点；不同节点协议的远端解析能力不同，必须实测 |
| 加密 DNS 的备用路径 | `https://8.8.8.8/dns-query#proxy` | 备用也经代理；`dns-fallback = false` 要求禁用隐式系统 DNS 回退 |
| 节点自身域名 | `proxy-dns-server`，直连阿里 IP 地址 DoH | 仅节点引导，阿里会知道节点域名和本地出口；不依赖代理先启动 |

`proxy-dns-server` **不是代理网站使用的 DNS**。解析器使用 IP 地址 DoH URL，TLS 校验保持开启，不需要先查询解析器域名。国内直连使用系统 DNS 是本项目为局域网及 CDN 作出的明确选择，不是误配或检测规避。

所有地址规则都带 `no-resolve`。未命中域名不会仅为匹配中国 IP 表而额外请求本地 DNS；已知国内 IP 直接连接可以命中 IP 表。代价是**未收录的国内域名也可能走默认代理**，这是隐私优先的边界，不为“猜国内 IP”主动解析。已明确匹配代理的域名不会因为最终落在中国 IP 上而改成直连。

`always-ip-address = false` 避免强迫所有域名本地解析。代理不能转发 UDP 时拒绝而不改走直连；这不是广告过滤，但不支持 UDP 的节点可能无法使用部分 QUIC/游戏/语音流量。选择可用节点并不意味着任意节点都能访问所有有地区限制的服务。

本机 Shadowrocket **2.2.93** 的内置默认配置、提示文本和程序参数字符串已经只读核对。建议 Mac/iPhone 使用同版或更新版。`dns-fallback` 是本机可识别的回退键；不采用未经本机依据确认的 `dns-fallback-system`。参数识别与真实执行效果是两回事，导入后仍需按 [客户端验收](docs/CLIENT_TEST.md) 核对。

IPv6 **启用**，同时内嵌国内 IPv6 前缀。客户端支持 IPv6 不代表所选节点拥有 IPv6 出口：IPv4-only VPS 可以正常处理有 IPv4 地址的常见服务，但 IPv6-only 目标仍需节点服务器实际启用 IPv6。本次所选 VPS 未启用 IPv6，纯 IPv6 连接失败与该限制吻合，未通过关闭客户端 IPv6 掩盖，也未擅自更改服务器。

`hijack-dns = *:53` 已在上述 Mac 版本实测能接管 IPv4 UDP DNS。原来的裸 IP 名单、空地址 `:53` 写法没有达到预期，已移除。客户端未接管的外部端口 53 流量，由局域网规则之后、业务规则之前的 `DST-PORT,53,REJECT` 拒绝；本次 TCP 和 IPv6 DNS 探测没有获得上游答案。**这部分是拒绝兜底，不是把 TCP/IPv6 DNS 自动转换成 DoH**；应用自带的 TCP DNS 可能因此失败，应使用系统解析。

局域网、链路本地及组播旁路得到保留，私网 DNS 仍可使用；因此不能把此规则称为系统级 DNS 防火墙。应用自带 DoH/DoT、私网旁路及未进入 Tunnel 的流量仍有独立边界。客户端内部的直连系统 DNS、代理 DoH 和节点 DoH 引导不由这条端口兜底代替。TUN、其他 VPN、系统路由、浏览器 DoH/Private Relay 也可能改变实际路径。

## 上游与取舍

地址、格式、阈值和许可证集中在 [`sources/sources.json`](sources/sources.json)。下载时先解析仓库分支的提交 SHA，再按固定 SHA 下载；同一仓库的多个文件使用同一 SHA，避免读取到两次发布之间的混合数据。

| 用途 | 实际上游 | 格式及许可 |
| --- | --- | --- |
| 国内域名 | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)，固定提交的完整归档，入口 `data/cn` | 原生 `domain`/`full`/属性/`include`/`&affiliation`；MIT |
| 明确代理域名 | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)，`release/proxy.txt` | `payload` 域名集；普通值是完整域名，`+.` 才是后缀；GPL-3.0 |
| 国内 IPv4 / IPv6 | [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)，`ip-lists/china.txt`、`china6.txt` | 标准 CIDR；MIT |

没有全量采用候选 `v2ray-rules-dat/direct-list.txt`：实取样构建产生约 14.6 万条、4.8 MiB 的配置，且它是可直连白名单，不是严格地理分类。精简中间产物也未通过淘宝哨兵，所以国内域名最终直接读取官方分类源，正确处理新的 affiliation 语法。当前输出控制在 **7 万条、3 MiB**以内，超过预算即停止发布。

Loyalsoldier 的代理域名集由候选 V2Ray 数据生成，其上游工作流明确排除 `regexp`/`keyword`，所以它**不等价于完整原始列表**。本项目不伪造正则转换；代理集未覆盖的流量仍由默认代理处理，但与直连分类交叉时可能缺少部分代理例外，这是上游分类的已知限制。少量关键服务保护后缀保存在 [`config/overrides.json`](config/overrides.json)，不涉及 DNS 检测站。

国内源的 `domain:` → `DOMAIN-SUFFIX`，`full:` → `DOMAIN`。`@ads`、`@!cn` 条目不进入直连白名单，**不会生成拦截策略**，仍继续匹配其他规则或 FINAL。直连正则没有可靠等价形式，明确省略并把原文记录进 manifest，优先让漏收请求走默认代理。直连 `keyword`、未知记录、异常 include 等直接报错；不静默降级。暂不引入 blackmatrix7，避免叠加另一套分类及许可范围。

IP 表是 BGP/登记分类数据，不代表每个地址的实时物理位置，也不是全网准确性保证。细节和证据见 [技术审查](docs/REVIEW.md)。

## 规则顺序与冲突

局域网保护 → 未接管 DNS 的端口 53 拒绝兜底 → 明确代理 → 国内域名直连 → 国内 IPv4/IPv6 直连 → `FINAL,PROXY`。端口 53 的 REJECT 仅用于 DNS 安全，不生成广告拦截策略。

相同策略的子后缀、被后缀涵盖的完整域名会被压缩。跨策略统一代理优先：代理后缀完整覆盖的直连条目删除；直连父后缀内的代理子域名保留并排在前面。全部交叉项及处理结果见 [`dist/conflicts.json`](dist/conflicts.json)。局域网保留命名空间被上游侵入时停止构建。

不使用内置 `GEOIP`：已经内嵌国内地址表，可避免另一份隐式 IP 数据库成为依赖。若以后使用 GEOIP，同样需要 `no-resolve`，并重新评估数据来源与规则优先级。

## 本地构建与检查

Python **3.9+**，仅标准库，不用安装 pip 依赖。

```bash
python3 scripts/build.py                      # 实际下载并构建
python3 scripts/build.py --offline             # 从已提交源快照重建
python3 scripts/build.py --offline --check     # 只读检查完整可复现性
python3 -m unittest discover -s tests -v        # 转换、路由、异常输入与保留旧版测试
python3 scripts/probe_client_dns.py            # 仅在实际客户端 Mac 上运行；需要已启用配置
```

修改模板、构建器或 sources 后，先离线重建、运行测试，再提交源码和 `dist/`。`--check` 会比较生成器、模板、源配置和产物哈希，因此故意修改源码却不重建会失败。`--check` 不模拟 Shadowrocket 原生解析器。

`dist/manifest.json` 包含每份数据的来源提交、URL、SHA-256、输入数量、被省略正则、地址覆盖量和生成文件哈希；`dist/inputs/` 保留发布时的原始数据，是审计及离线重建材料，**客户端不需要下载它们**。报告没有每日时间戳；只有上游提交号变化、实际规则不变时，保留上一份已发布报告和快照，避免无意义提交。

## 失败保护、权限与回滚

- 下载 HTTPS、30 秒单次超时、最多 3 次重试；空文件、超限文件、错误页面、非 UTF-8、非法域名/CIDR/归档全部失败。
- 每个源有绝对上下限；相比上一发布版本，唯一条目数以及 IP 地址覆盖量不得下降超过 20% 或增长超过 50%。重复输入超过 5%、正则省略比例异常也失败。阈值不是准确性的证明；异常时先审查上游，不自动放宽门槛。
- 全部下载、转换、冲突处理、DNS 基线和路由哨兵通过后才写产物。配置文件通过临时文件原子替换。普通下载/解析/检查失败不会触碰旧版文件；突然断电或磁盘写错不构成整个目录的事务保证，但配置替换始终是原子的。
- CI 先做离线测试，再在独立的有写权限任务中在线构建及复现候选；仅在成功后提交整个 `dist/`。不强推、不自动 rebase。并发人工提交导致推送拒绝时，下次重新构建，远端旧版保持不变。
- 默认分支若要求 PR 或禁止 bot 推送，更新任务会明确失败。请为个人规则仓库允许 Actions 更新默认分支，或自行采用受保护分支的 PR 审核流程；本工程不会绕过分支保护。无需配置私人令牌。
- 回滚使用 GitHub 历史中最后正常提交的整个 `dist/`，或 revert 对应更新提交；临时回滚模板/脚本时保持两者配套。也可暂停 Actions 防止下次正常更新覆盖回滚。在 Shadowrocket 手动刷新一次即可。
- GitHub 定时任务只在默认分支运行，可能排队、延迟或被丢弃，不是严格的每日 SLA。公开仓库长期（通常 60 天）无活动可能自动停用 schedule；Fork 后也需确认 Actions 已启用。通过 Actions 页面检查运行状态，必要时手动 Run workflow。[GitHub 官方说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

## 项目结构

```text
.github/workflows/update.yml   每日、手动、PR 检查及成功后提交
config/template.conf          固定 DNS / 局域网 / 模板
config/overrides.json         少量关键服务代理保护
sources/sources.json          上游、类型、许可、质量阈值
scripts/build.py              标准库构建器
scripts/probe_client_dns.py   可选的本机实时 DNS 验收，不在 Actions 中冒充真机测试
tests/test_build.py           解析、冲突、失败保护、可复现性测试
dist/Shadowrocket.conf        唯一客户端订阅入口
dist/manifest.json            来源与质量报告
dist/conflicts.json           交叉规则及处理结果
dist/inputs/                  发布对应原始快照
docs/                         技术审查、客户端验收、交付验证记录
licenses/                     MIT 上游许可原文
LICENSE                       GPL-3.0 原文
NOTICE.md                     数据来源及分发许可说明
```

工程及组合配置按 GPL-3.0 分发，MIT 数据保留原声明；详情见 [NOTICE](NOTICE.md)。不要将私人节点、密码、机场订阅、DNS 日志或个人抓包提交到公开仓库。
