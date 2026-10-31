> 历史记录：本文描述此前已发布的增强白名单及当时测试，不代表当前工作区候选。新的混合分流设计与验收状态见 [MIXED_ROUTING.md](MIXED_ROUTING.md)。

# 增强白名单重构与验收（2026-10-31）

用户反馈 Bing 中国、iCloud 中国和 Steam 国内下载走了代理。全表检查进一步证明：旧项目只读取 v2fly 原版 cn，加上普通国外分类优先以及删除中国注册后缀，不能满足“大陆可用服务尽量直连”的目标。旧版本的转换测试通过，不代表该策略满足用户需求。本轮修复来源与优先级，不以手工增加品牌名单作为覆盖方案。

## 最终策略

局域网 → DNS 端口保护 → 管理主机 → 受保护代理 → 本地例外 → 自动中国服务类别 → 增强直连表 → 普通代理分类 → 中国 IP → 默认代理。

增强白名单优先于普通国外规则是本轮全表检查后的明确调整：若照搬此前提出的“普通国外规则在增强直连之前”，仍有 134 条上游直连记录被遮盖，其中包括中国服务、软件和游戏下载主机。最终采用更接近用户 v2rayN 绕过大陆的白名单优先策略；不把这 134 条逐个手工修补。

自动同步的覆盖层：

- Loyalsoldier/v2ray-rules-dat 的完整 direct-list.txt，包含中国域名及可在大陆使用的境外服务，作为可达性白名单。
- v2fly 原生 cn 分类作补充；同一提交的全部 geolocation-!cn 分类按 @cn 属性递归选择，服务类别可随上游增加。
- Loyalsoldier 的 apple-cn.txt，保留 full 精确语义；不把共享 CDN 整个后缀放行。
- 中国 IPv4/IPv6 继续使用 gaoyifan 数据；IP 仍为 no-resolve。DNS、UDP 拒绝回落直连及 IPv4 兼容基线不变。

明确允许 cn、xn--fiqs8s、xn--fiqz9s 三个中国域名后缀；其他注册后缀继续用 PSL 过滤。未知 .cn 直连是白名单政策，不是“中国后缀保证境内服务器”的判断。Google、Claude、OpenAI、Copilot 等受保护服务优先于白名单。Bing 不再整族强制代理，Sydney/Copilot 仍受保护。

普通代理分类现在主要记录其余国外服务；同名冲突由增强白名单胜出。上游直连收录不等于每个地区、运营商、账号和时间点都能直连。源的误分类、未识别的境外服务及新接入点仍可能需要上游修正。

## 全表验证与持续维护

独立审计器不调用构建器的源解码函数，检查全部来源和产物边界；精确主机、子域、相似字符串、外部后缀都有样本。产物额外注入的未知域名也纳入检查。中国 IP 压缩前后做集合等价检查。

本次候选静态结果：

| 项目 | 结果 |
| --- | --- |
| 总规则 | 147,154 |
| 配置大小 | 5,060,028 字节（约 4.83 MiB） |
| 域名边界样本 | 559,287，零差异 |
| 增强直连来源 | 110,097 条主机名匹配 DIRECT；41 条受保护服务匹配 PROXY；48 条未批准注册后缀不放行 |
| 国外服务 @cn 来源 | 1,073 条 DIRECT，42 条被保护层保留 PROXY |
| Apple 中国精确主机 | 165 条 DIRECT |
| 普通国外分类遮盖增强直连 | 0 |
| 中国 IPv4 / IPv6 地址集合 | 均完全等价 |
| 对旧版的边界策略变化 | 211,309 个样本 PROXY → DIRECT；不是独立网站数、真实请求量或实测可用率 |

来源中的不支持直连正则不做扩大转换；原文及数量保留在 manifest，仍由其余规则和默认代理判定。区域类别不选择 @ads/@!cn，但增强发布表已扁平化，因此不承诺全局排除这些域名；没有增加广告 REJECT。

每天更新会重新运行全部构建门槛、独立审计和离线复现；来源错误、数量异常、地址覆盖异常、规则越界或审计不一致均阻止推送。新旧配置的全量边界变化统计写入 Actions 摘要。审计 artifact 保存每份来源覆盖统计、全部直连来源的代理例外及原因、前 100 条变化样例；样例有明确截断，统计不截断。上游每日产物与分类维护活动继续由独立健康任务检查。

构建上限调整为 20 万条 / 8 MiB。这是发布保护预算，不是 Shadowrocket 的已验证性能上限。没有测得新版 iPhone 内存/加载耗时，也没有把旧手机 IPv6 测试冒充新版网络切换验收。

本轮增加新厂商 @cn 自动覆盖、裸域名与 full 类型、注册后缀允许范围、保护层优先、输出未知域名注入、整源覆盖与版本变化回归测试。旧的 NTP/阿里云/Apple 范围断言根据全量来源的新策略调整；保留精确主机扩大为后缀、错误 IP 集合、解析失败及保留旧发布等故障检测。

本地交付检查：66 项测试全部通过（约 258 秒）；完整离线复现通过；actionlint 与 git diff --check 通过；八份来源的联网健康检查通过。远端执行状态以对应提交的 GitHub Actions 结果为准。

## 依据与复现

- [增强数据生成工作流](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/master/.github/workflows/run.yml)
- [国外服务 @cn 并入直连的工作流](https://github.com/Loyalsoldier/domain-list-custom/blob/master/.github/workflows/build.yml)
- [Loyalsoldier 分类与推荐顺序](https://github.com/Loyalsoldier/v2ray-rules-dat#geositedat-1)
- [MetaCubeX 的区域服务分类参考](https://github.com/MetaCubeX/meta-rules-dat/blob/meta/README.md)：交叉研究，未盲目合并另一套全量数据。

发布对应的每份实际 SHA、原始 URL 和内容摘要见 dist/manifest.json；源快照见 dist/inputs。未上传用户 Windows 包、数据库、节点凭据或手机私人日志。

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py --offline --check
python3 scripts/audit.py --output .build/policy-audit.json
# 如保存了旧配置，可额外传入 --compare previous.conf
```

客户端刷新配置、重连后，需要核对中国服务直连、海外 AI 代理、手机切网及断线恢复。静态匹配不能证明真实线路质量或零泄漏。
