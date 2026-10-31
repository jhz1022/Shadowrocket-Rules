# 项目修复与同类方案评估（2026-10-31）

> 后续用户反馈揭示了本报告未充分验证的业务覆盖问题。直连来源与优先级已按 [增强白名单重构](ENHANCED_WHITELIST.md) 修订；本文是之前版本的历史验收，不代表当前分流策略。

## 结论与范围

本轮已修复三个能复现的缺陷，并生成通过本地检查的候选产物。对本项目既定目标——一份 Shadowrocket 配置、国内分类直连、境外及未知默认代理、保留局域网、不引入广告拦截和 MITM——目前没有在已执行检查中发现新的阻断问题。**这足以支持继续使用和受控发布，不能证明“完美”、全网分类准确或所有手机网络下零泄漏。**

本报告中的验证数据记录于提交前的本地验收阶段。对应提交的远端检查结果以 [GitHub Actions](https://github.com/jhz1022/Shadowrocket-Rules/actions) 为准；发布后，手机仍需刷新订阅并重新连接。先前手机测试不能视为更新后配置已经在手机生效的证明。

调研核对了 36 个仓库或来源候选：29 个规则、数据或相关工具资源仓库有近期提交，1 个维护中的 PSL 安全数据源，另外包含历史仓库、归档镜像及无法读取的候选。没有宣称穷尽互联网所有维护项目，也没有对每个上游进行完整代码审计。

## 已修复缺陷

| 缺陷 | 之前的后果 | 修复与验证 |
| --- | --- | --- |
| P1：注册后缀过滤不完整 | 上游腾讯游戏分类含 `in.th`，生成整段 DIRECT；陌生注册者的域名也会直连。原校验器与独立审计均漏报 | 引入固定提交的 PSL，解析 ICANN 部分；排除精确注册边界、通配边界及其父域，尊重例外。构建与独立审计分别解析和判断；加入输出注入回归 |
| P2：更新健康检查按首次创建时间排序，且只看最新未完成任务 | 旧任务近期重跑失败可被新建成功任务掩盖；新排队任务可盖住旧运行超时；旧任务重跑成功也可能被误报陈旧 | 按当前记录更新时间选最近完成结果；逐一检查所有未完成任务；分页读取 31 天历史并单独查询任意年龄的未完成任务，超过 API 查询上限明确失败 |
| P2：属性大小写与上游语义不一致 | `@ADS`、`@!CN` 可错误进入直连；`@CN` 选择器漏收。独立解码器也有同样问题 | 两个解码器分别规范化属性、include 引用、affiliation、类型和属性选择器，保留正则内容；新增混合大小写回归 |

PSL 快照包含 6,949 条 ICANN 记录；原始文件、固定提交、SHA-256 和 MPL-2.0 声明随项目保存。PRIVATE 部分保留在原始文件中，但不自动删除国内共享托管平台的路由；它是独立的业务分类问题。通配语法、例外和国际化域名的规则依据来自 [PSL 格式规范](https://github.com/publicsuffix/list/wiki/format)。

更新查询的分页、状态和 1,000 条搜索限制按 [GitHub Workflow Runs API](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow)处理；31 天窗口覆盖 GitHub 允许的 [30 天重跑期限](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)。

真实配置差异只有删除 `DOMAIN-SUFFIX,in.th,DIRECT` 一行；相关冲突报告和 provenance 同步变化。规则由 44,189 减至 **44,188**，文件为 **1,595,856 字节**，仍在 7 万条 / 3 MiB 预算内。DNS、UDP 不支持时拒绝、IPv4 兼容基线及其他业务策略保持一致。

## 本轮实际检查

| 检查 | 结果及边界 |
| --- | --- |
| 单元与故障保护测试 | 59 项通过；包括本轮新增的 9 项回归。最后一次本机执行约 44.6 秒，Python 3.9.6 |
| 完整离线重建 | `python3 scripts/build.py --offline --check` 通过，产物与来源记录一致 |
| 独立全源审计 | 141,316 个域名边界样本零差异；中国 IPv4、IPv6 压缩前后地址集合完全一致 |
| 配置基线 | 24 个路由哨兵、6 个 DNS 端口哨兵、74 个经审查例外检查通过 |
| 工作流语法 | actionlint 通过 |
| 修复版健康脚本联网运行 | GitHub 现有更新记录及五份上游数据源均通过；检查的是现有线上运行记录，不表示新脚本已在 Actions 上运行 |
| 手机已提供证据 | 一次 5G / Claude 连接列表选择 PROXY、IPv4 出口符合预期、IPv6-only 测试不可达；详见 [客户端记录](CLIENT_TEST.md) |

候选配置 SHA-256：`c7275e5ed3af28e7027b78587ed3189c82aac827f819240e60731b41e8674bc4`。

静态规则模型验证的是转换、匹配边界与约定策略，不是 Shadowrocket 原生 DNS/TUN 实现，也不是上游分类真实性。上表为本机执行结果，不能代替对应提交的远端 CI。

## 调研方法与维护状态

核对时间为 2026-10-31 05:10 UTC 左右，以下时间均为 UTC。来源为仓库 API、目标分支提交、官方 README、部分工作流和实际规则文件；完整提交 SHA、仓库状态及链接保存在 [元数据快照](UPSTREAM_SNAPSHOT_2026-10-31.json)。

初始名单覆盖 Shadowrocket、Surge、Clash/Mihomo、sing-box、国内 DNS/IP 基础数据；再用 GitHub 搜索补充：
- `shadowrocket rules archived:false pushed:>2026-05-01 stars:>500`
- `surge rules archived:false pushed:>2026-05-01 stars:>500`
- `clash rules archived:false pushed:>2026-05-01 stars:>1000`

这些筛选只用于发现候选，不是质量排名或穷尽证明。客户端本身和通用订阅生成框架没有当成分流数据库比较。低星、私有、其他托管平台的项目可能遗漏。

**近期提交不等于每个分类近期维护，也不等于持续人工审查。** 数据自动发布分支与代码分支分别核对；例如 SagerNet 的主分支代码较旧，但 release 在当天发布；ConnersHua 默认分支名含形似字符，实际 ASCII `master` 才有近期更新，不能仅看默认分支就判定停更。

| 仓库 | 核对分支 | 最新目标分支提交（UTC，链接到证据） |
| --- | --- | --- |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | `master` | [2026-10-27 21:45:18](https://github.com/blackmatrix7/ios_rule_script/commit/0b6897dc17e0c513d25449c935a9694818e32f0c) |
| [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | `master` | [2026-10-31 03:39:07](https://github.com/ACL4SSR/ACL4SSR/commit/2d5d027c2c527d20ab7f942c9d3741e45d53bf6b) |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | `release` | [2026-10-30 22:34:48](https://github.com/Loyalsoldier/clash-rules/commit/611f7e9db13b5c824233ed7451abdf867fc08a41) |
| [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) | `release` | [2026-10-30 22:32:27](https://github.com/Loyalsoldier/surge-rules/commit/b814e41f244f734a0cd6b6888b7a7507c8c9596d) |
| [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | `release` | [2026-10-30 22:04:26](https://github.com/Loyalsoldier/v2ray-rules-dat/commit/e8c869ef82e03f8cfb02f820f99e9f10e5b15e8a) |
| [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) | `release` | [2026-10-29 00:23:08](https://github.com/Loyalsoldier/geoip/commit/33824131927ddbc19c540f2a301cc4ef4e123478) |
| [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | `release` | [2026-10-31 01:45:20](https://github.com/MetaCubeX/meta-rules-dat/commit/3a48ad7d923246038c9d8a86b17a3c839876e4b7) |
| [SukkaW/Surge](https://github.com/SukkaW/Surge) | `master` | [2026-10-30 12:53:28](https://github.com/SukkaW/Surge/commit/2ee066d7255db0ada982e37673ff4ad1e261634f) |
| [johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) | `release` | [2026-10-30 23:03:02](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/commit/e16c78f76f7d30f1d5e0f17880dfa97ef1eabb10) |
| [ConnersHua/RuleGo](https://github.com/ConnersHua/RuleGo) | `master` | [2026-08-01 06:56:08](https://github.com/ConnersHua/RuleGo/commit/3a0b88db0104d48a7aa9bd45f303821d9e3e9009) |
| [lm-Firefly/Rules](https://github.com/LM-Firefly/Rules) | `master` | [2026-10-27 14:37:44](https://github.com/LM-Firefly/Rules/commit/cf4a1aeba35867401ee92bf44fb3a246aed2f497) |
| [dler-io/Rules](https://github.com/dler-io/Rules) | `main` | [2026-10-28 05:07:27](https://github.com/dler-io/Rules/commit/03429f8e546041a7918642d554b973ea55d9b26f) |
| [DustinWin/ruleset_geodata](https://github.com/DustinWin/ruleset_geodata) | `mihomo-ruleset` | [2026-10-30 22:48:19](https://github.com/DustinWin/ruleset_geodata/commit/4a061f841846c6bc02faa24e981c9c37fd358fe6) |
| [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite) | `release` | [2026-10-31 04:49:22](https://github.com/SagerNet/sing-geosite/commit/0ddee2d89337534c866dc9a78d4aaf7b82f03b5f) |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | `master` | [2026-10-30 13:25:16](https://github.com/v2fly/domain-list-community/commit/1daade8c4bb957d21d1f5c09c2b050d699e8e96c) |
| [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) | `ip-lists` | [2026-10-30 09:07:05](https://github.com/gaoyifan/china-operator-ip/commit/f7533065e164cbe0cf24b488a77ca75b8e897923) |
| [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) | `master` | [2026-10-30 00:08:26](https://github.com/felixonmars/dnsmasq-china-list/commit/a8942d3ac6ebd8dcfc582d4e97fbb443a2176cb2) |
| [gfwlist/gfwlist](https://github.com/gfwlist/gfwlist) | `master` | [2026-10-30 05:24:33](https://github.com/gfwlist/gfwlist/commit/a1932f2aec3597e257ef974854f2b19f023e2cd0) |
| [NobyDa/Script](https://github.com/NobyDa/Script) | `master` | [2026-08-12 17:55:26](https://github.com/NobyDa/Script/commit/0b8d083d444f4476700cb9d5d059c07b42da85eb) |
| [deezertidal/shadowrocket-rules](https://github.com/deezertidal/shadowrocket-rules) | `main` | [2026-10-31 04:25:29](https://github.com/deezertidal/shadowrocket-rules/commit/123c0509048d68c523c666c194b59d5b87f0a865) |
| [GMOogway/shadowrocket-rules](https://github.com/GMOogway/shadowrocket-rules) | `master` | [2026-10-31 01:47:19](https://github.com/GMOogway/shadowrocket-rules/commit/f3d27fd05ccd1c2b77847d4bdacab1ef6ebecc36) |
| [LingJingMaster/Shadowrocket-Rules](https://github.com/LingJingMaster/Shadowrocket-Rules) | `main` | [2026-10-21 10:05:18](https://github.com/LingJingMaster/Shadowrocket-Rules/commit/0c233b06d9c26c5036c8d3ce61415eab6396fe0c) |
| [zhouzhouprogram/Shadowrocket-ADBlock-Rules](https://github.com/zhouzhouprogram/Shadowrocket-ADBlock-Rules) | `master` | [2026-10-30 19:00:18](https://github.com/zhouzhouprogram/Shadowrocket-ADBlock-Rules/commit/34d91b760b7c0de05533c62ccd34b321ebd623ef) |
| [PaPerseller/chn-iplist](https://github.com/PaPerseller/chn-iplist) | `master` | [2026-10-18 14:32:25](https://github.com/PaPerseller/chn-iplist/commit/a8d0002936a3287f90185113583293660633a45d) |
| [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) | `main` | [2026-10-31 01:55:50](https://github.com/VPSDance/ai-proxy-rules/commit/182cdb26260b9ff4963d5a92da24e76093b2d8da) |
| [Semporia/Clash](https://github.com/Semporia/Clash) | `master` | [2026-10-26 12:32:01](https://github.com/Semporia/Clash/commit/a1fdbb9625268171e4c00b36327d12e471d9f9c2) |
| [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) | `main` | [2026-10-31 02:53:02](https://github.com/Aethersailor/Custom_OpenClash_Rules/commit/ec652058f2e2535d062705824ae7100fcf560e7b) |
| [luestr/ShuntRules](https://github.com/luestr/ShuntRules) | `main` | [2026-10-26 19:22:10](https://github.com/luestr/ShuntRules/commit/e6320fd3e2b1742b6e037a8f0862a18655fac9a9) |
| [n0de-sudo/Perfect-Rules](https://github.com/n0de-sudo/Perfect-Rules) | `main` | [2026-10-07 16:37:38](https://github.com/n0de-sudo/Perfect-Rules/commit/04a2304f5581684f3362083803193b2e4a38f3d5) |

其中 NobyDa、deezertidal 的范围包含脚本和模块，不能把整仓近期提交当成每份分流规则都在维护；本项目只参考结构和边界，不引入这些脚本或模块。

另行处理的候选：

| 候选 | 观察与处理 |
| --- | --- |
| [publicsuffix/list](https://github.com/publicsuffix/list) | 安全数据来源而非分流项目；main 提交 2026-10-28，本轮实际引入 |
| [h2y/Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) | 已归档，目标分支最后提交 2021-04-12；只作历史参考，活跃派生项目单独列出 |
| [Hackl0us/SS-Rule-Snippet](https://github.com/Hackl0us/SS-Rule-Snippet) | main 最后提交 2023-01-19，不作为近期维护样本 |
| [GeQ1an/Rules](https://github.com/GeQ1an/Rules) | 默认 rm 分支最后提交 2019-06-24，仓库最后 push 为 2024-12-21；未确认近期维护 |
| [SukkaLab/ruleset.skk.moe](https://github.com/SukkaLab/ruleset.skk.moe) | API 显示归档；README 指向 SukkaW/Surge 源码仓库。镜像状态与源码项目状态分别记录 |
| [DivineEngine/Profiles](https://github.com/DivineEngine/Profiles)、[QiuSimons/Rules](https://github.com/QiuSimons/Rules) | 本轮公开 API 返回 404；不能据此区分删除、私有或迁移，未列为已验证维护项目 |

## 与同类方案的实质比较

| 方案与原始依据 | 值得参考的特点 | 对本项目的决定 |
| --- | --- | --- |
| [blackmatrix7 分类目录](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/README.md) | 细分服务与多客户端格式，Apple/媒体/AI 等分类丰富 | 作服务域名交叉参考；不能直接合并全部 DIRECT、广告或共享平台类别 |
| [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/blob/master/README.md) | 提供黑白名单、多种分片及订阅转换配置，部分直连列表按国内公司而非物理位置划分 | 使用其 AI 清单作比对；不把国内公司海外资源自动认定为国内出口 |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules/blob/master/README.md) 与 [MetaCubeX](https://github.com/MetaCubeX/meta-rules-dat/blob/master/README.md) | 前者提供自动生成的域名集；后者提供多种 geodata/MRS 并调整分类来源 | 当前代理源继续保留；MRS 等跨内核能力不是此单一 Shadowrocket 项目的缺陷 |
| [SukkaW/Surge](https://github.com/SukkaW/Surge/blob/master/README.md)、[构建与测试入口](https://github.com/SukkaW/Surge/blob/master/package.json) | 区分域名/non-IP/IP 规则，强调 DNS 触发顺序，具备构建、测试和性能工具 | 本项目已有业务域名先于公网 IP、所有 IP 规则 no-resolve；原生客户端性能测量仍弱于专门性能研究，不能凭条数声称更快 |
| [DustinWin](https://github.com/DustinWin/ruleset_geodata/blob/main/README.md)、[SagerNet 发布工作流](https://github.com/SagerNet/sing-geosite/blob/main/.github/workflows/release.yaml) | 前者组合国内标签、游戏平台、AI 等分类；后者定时生成 geosite 与 rule-set | 参考来源链和发布方式；不因支持更多格式就增加客户端依赖 |
| [Johnshall](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/blob/release/readme.md)、[zhouzhouprogram](https://github.com/zhouzhouprogram/Shadowrocket-ADBlock-Rules/blob/master/readme.md) | 延续 h2y 的多配置方案和每日生成，黑名单与白名单默认行为不同 | 保留本项目明确的 FINAL,PROXY；不用可直连的海外 top500 数据替换严格的业务白名单 |
| [GMOogway](https://github.com/GMOogway/shadowrocket-rules/blob/master/README.md) | 模块化直连/代理/拦截表；当前 README 列出约 11 万直连规则 | 本项目约 4.4 万总规则及单文件交付更贴合既定范围；数量不能作为覆盖准确性或速度的直接评分 |
| [LingJingMaster](https://github.com/LingJingMaster/Shadowrocket-Rules/blob/main/README.md) | 地区策略组、香港银行/券商、Apple 等细分策略 | 用户只使用当前节点，不需要照搬地区策略组；香港银行直连也不同于本项目汇丰中国例外 |
| [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules/blob/main/README.md) | 聚合多个来源，按 AI 服务和地区分类 | 用其 Anthropic 列表做静态交叉检查，未全量导入关键词、进程、ASN 规则 |
| [PaPerseller/chn-iplist](https://github.com/PaPerseller/chn-iplist/blob/master/README.md) | IPv4 多源、IPv6 APNIC，并主动筛除部分 ASN | 说明“国内 IP”存在不同政策口径；本项目继续固定 gaoyifan，不能把两表取并集当更准确 |
| [Aethersailor](https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/main/README.md) | 将 DNS 防护与 Fake-IP、流量接管、终端设置及实际测试条件关联 | 采用这种条件化验收思想；OpenClash 的路由器设置不能直接用于 iOS 隧道 |
| [luestr/ShuntRules](https://github.com/luestr/ShuntRules/blob/main/README.md) | 合并 blackmatrix7 分类供 Loon/Clash 使用 | 属于同源转换，不算独立第二份分类证据 |
| [Perfect-Rules 的实际配置](https://github.com/n0de-sudo/Perfect-Rules/blob/main/Shadowrocket/perfect_rules.conf) | 使用远程规则集、地区/服务策略；其 DNS 和 IPv6 设置与本项目不同 | 没有照搬其 IPv6 开启、系统备用 DNS、未带 no-resolve 的 GEOIP 方案；项目名称或宣传中的“完美”不能代替本机验证 |

LM-Firefly、dler-io、Semporia 的维护状态和配置资源结构也纳入候选筛查；没有完整重演这些项目的构建或对其所有规则作优劣排名。

多个项目共享 v2fly、Loyalsoldier、blackmatrix7 或 dnsmasq-china-list。MetaCubeX、DustinWin、luestr 的 README 均能看到相应来源链；不能将三个同源派生表的一致意见当成三次独立事实验证。本轮没有添加这些路由表为新的运行时上游，新增的只有注册边界校验数据。

## Claude / AI 的交叉检查

读取三份公开参考表，对其中明确域名检查自身；后缀规则另检查一个子域名；VPSDance 的两条 IP 网段检查首尾地址。以当前完整配置的顺序匹配模型判断是否 PROXY：

| 参考文件 | 样本数 | 非 PROXY |
| --- | ---: | ---: |
| [blackmatrix7 Claude](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/Claude/Claude.list) | 5 | 0 |
| [ACL4SSR AI](https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/Ruleset/AI.list) | 80 | 0 |
| [VPSDance Anthropic](https://github.com/VPSDance/ai-proxy-rules/blob/main/rules/shadowrocket/anthropic.list) | 78 | 0 |

共 163 次检查，存在跨表重复，不能称为 163 个独立服务。VPSDance 的 PROCESS-NAME、IP-ASN、DOMAIN-KEYWORD，以及 ACL4SSR 的关键词未作等价验证。名单归属没有逐一向服务商核实，抽查通过也不证明完整包含 Claude App 所有第三方连接。

`claude.ai`、`api.claude.ai`、`claude.com`、`anthropic.com`、`claudeusercontent.com` 及所检查的 Sift/Datadog/Google 端点均为 PROXY。其余未知域名原本就默认代理，通常无需为新海外域名追加重复规则；真正需要防范的是错误 DIRECT 分类和实际隧道未接管。

手机已有中国运营商 IPv6 地址本身不是泄漏证据；目标是否看到该地址取决于实际出口。当前 VPS 不启用 IPv6 也可提供 IPv4 代理出口。现有一次 5G 测试未发现绕过，不构成账户审查结果保证，也不能代替 Wi-Fi 切换或断线阶段测试。

## 尚未被证明的部分

| 状态 | 边界 | 下一步需要什么 |
| --- | --- | --- |
| 已修复并通过静态回归 | 上述三项可复现缺陷 | 发布本次候选并观察远端 CI；客户端刷新后核对版本 |
| 待手机现场验证 | Wi-Fi/5G 切换、锁屏唤醒、节点故障和重连期间的路由 | 在实际手机上按 CLIENT_TEST 操作，并关联目的端或接口证据；本机代码测试不能代替 |
| 待特定网络验证 | IPv6-only/NAT64、完整原生 IPv6 代理 | 需要对应网络与 VPS 出口；当前不为追求功能数量启用 IPv6 |
| 持续数据风险 | 上游误分类、共享 CDN/托管平台、域名转手 | 结合具体业务日志修订并加回归；PSL 不是地理或信誉数据库 |
| 明确转换边界 | 国内源 3 条正则省略；代理中间源不含所有 keyword/regexp | 默认 PROXY 减少漏收影响，但不能证明所有跨表冲突正确；如出现误直连，核实后加精确保护，不伪造等价转换 |
| 监控边界 | 健康检查与更新同依赖 GitHub Actions | 整个平台/仓库调度停用时需独立外部监控；本轮没有擅自连接通知服务或创建定时任务 |
| 性能与原生实现边界 | 模型与实际客户端有差异，未量化所有设备耗电/内存/导入耗时 | 使用具体设备记录冷启动、内存、功耗与吞吐，无法由规则数量推断 |

因此，本项目当前可以描述为：**针对现有使用目标，已修复已知缺陷、可复现、有来源记录和回归保障的候选配置。** 不能描述为“市面最完美”“所有网站永不误分流”或“手机绝对不会泄漏”。剩余工作主要是实际网络条件下的验收和持续维护，不是继续堆叠整套规则库。
