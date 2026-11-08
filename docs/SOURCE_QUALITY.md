# 规则收集的持续复核

2026-11-02。新增上游变更复核、转换缺口检查和问题回归，用于控制自动发布。规则调整仍需审查，客户端配置不会自动修改。

## 从来源到候选

每次更新在下载前保存上一版的来源定义、全部输入、manifest 和配置。候选完成离线复现后，`check_source_quality.py` 对比这两组快照。旧输入缺失、摘要不符或来源定义发生变更时停止自动发布，需要单独审查迁移。

报告包含：

- 每个域名来源完整的新增和删除记录，不只保留少量例子。
- 所有直连/代理来源在具体域名边界上的重叠、命中证据及最终规则。来源名称、提交、URL 和摘要可追溯；v2fly 和继承它的 Loyalsoldier 不被当成多份独立投票。
- 新出现或证据改变、最终仍为 DIRECT 的冲突进入待复核队列。受保护层最终为 PROXY 的重叠仍展示，但不会被当成放宽直连。
- 某直连来源删除记录、候选却仍直连时，记录剩余来源和最终命中。既检查根域名、代表性子域，也检查当前已知的子域规则边界，避免遗漏“删除大范围规则但另一来源保留具体子域”的情况。
- 同一来源把具体记录合并到覆盖它的父后缀，视为表示方式调整，不当成撤回直连。删除动机无法从集合差异推断，报告明确要求核对上游重分类、整理和同步时间差。

现存重叠完整列出，尚未全部逐项复核。初始快照有 764 个重叠域名边界，它们不是 764 个已确认错误。11 月 1 日至 2 日的历史对照有 3 条 enhanced 新增、9 条 proxy 新增，没有触发待复核项。

## 发布前复核

任意未复核的上述变更都会令检查失败；报告在失败退出前保存，Actions 继续上传报告，后面的发布步骤跳过，订阅保留旧版。上一轮的数量/比例预算继续生效，本机制补充其检测不到的小规模语义冲突。

复核先查看报告中的原始新增/删除、源提交和匹配范围，再查上游修改理由，必要时做对应业务测试。可以修复来源处理或本地策略；确认为合理变化时，才在 `config/source-reviews.json` 增加审批记录：

```json
{
  "id": "从待复核报告原样复制的指纹",
  "reason": "说明删除或冲突的原因，以及为什么维持该策略",
  "evidence": ["上游修改链接或本地实测记录"],
  "expires": "YYYY-MM-DD"
}
```

指纹绑定具体发现和新旧两份 manifest；输入或候选变化后不能重复沿用，过期也不能放行。审批只允许这一轮候选继续接受其余检查，不直接把域名添加到 DIRECT。没有全局忽略冲突的开关。

上游同步时间差也可能触发复核，导致更新暂缓。

### 2026-11-07 的九项待审规则

腾讯游戏的变动发生在分类引用上。v2fly 把 `category-games-cn` 中的引用改为 `include:tencent-games @-!cn`，即排除带 `!cn` 的条目。这次新增并标记海外业务的是 `tencentgames.com`、`levelinfinite.com` 和 `nikke-en.com`。待审的八个域名仍在原文件里，均无标签。[上游补丁](https://github.com/v2fly/domain-list-community/pull/4261/files)

Loyalsoldier 的生成器把带筛选条件的引用作为正向属性查找，`@-!cn` 不会命中无标签记录。核对其相邻两次发布的 `cn.txt`，旧版含这八条，新版全部消失。本项目按 v2fly 的排除语义读取原始文件，仍会得到这八条。这个差异解释了撤表原因，域名该走哪条线路还要看业务和接入地址。[生成器实现](https://github.com/Loyalsoldier/domain-list-custom/blob/0b3b2122b819ff0b8a747663890e6b3ef4ace4a0/listinfo.go#L197-L231) · [旧表](https://github.com/Loyalsoldier/domain-list-custom/blob/27d7b38a569e730d6251967afd7f989e8eaced22/cn.txt) · [新表](https://github.com/Loyalsoldier/domain-list-custom/blob/e036fcca2cfe1e8d89e5a41f8e0849f6bfae10d6/cn.txt)

11 月 8 日用阿里公共 DNS 查了根域 A、AAAA 和 www 的 A 记录。

| 域名 | 查询结果 | 当前策略 |
|---|---|---|
| `gameitop.com` | 根域返回 193.112.125.33，在中国地址表内 | 按该应答直连 |
| `gameloop.com` | 根域和 www 均返回 104.20.43.73、172.66.174.89，均在中国地址表外 | 按该应答走代理 |
| `mahjongai.net`、`mahjongcup.com`、`mahjongcup.net`、`proximabeta.com`、`texasholdemcup.com`、`texasholdemcup.net` | 根域无 A/AAAA，www 返回 NXDOMAIN。其他业务主机未实测 | 有地址时按中国 IP 表分流，未解析时按默认代理策略处理 |

这八项仅移除普通直连表中覆盖整棵域名树的后缀条目。后续收录的具体业务主机及区域规则仍可优先命中。此次验证范围为 DNS、地址表和配置路由，未测试游戏登录或对局。

Apple Radio 保留上游的精确直连。v2fly 给 `full:radio.itunes.apple.com` 标了 `@cn`，并附有四个大陆网段的 DNS 结果。本次复查得到金山云 CDN 的 CNAME 链，返回地址在中国 IP 表内。保留主机名向 120.220.213.129 发起 HTTPS 请求，证书校验通过，根路径返回 403。已验证大陆接入点，未验证账号、节目授权或实际播放。审批只绑定本次新旧快照和这个精确主机，子域仍走原规则。[上游实测与补丁](https://github.com/v2fly/domain-list-community/pull/4266)

## 正则转换缺口

`config/coverage-review.json` 逐条记录暂未找到已验证等价转换的正则、处理理由和代表性回归样本。检查从已校验输入重新读取省略项，并核对 manifest，不只相信一份手写清单。

新出现的未登记正则、记录与源不一致、已登记样本的策略变化都会阻止发布。上游删除正则后，对应记录列为 inactive，供后续清理。不会执行上游正则，也不会把正则随意扩大成共享 CDN 后缀。

当前 8 种缺口的代表性结果（不提供 DNS 答案）：

| 类型 | 样本当前如何处理 |
| --- | --- |
| 两类 awsdns-cn 主机 | 无域名直连命中，进入 IP 兜底/默认代理；有真实 DNS 答案时可能不同 |
| mihayo 的 akamaized 主机 | 命中普通代理后缀 |
| zh.okaapps 主机 | 已由 okaapps.com 后缀直连 |
| 两类 Epic myqcloud 下载主机 | 已由 myqcloud.com 后缀直连 |
| 指定 googlevideo 主机 | 受保护代理优先，维持 PROXY |
| 指定 xn--ngstr-lra8j 主机 | 命中普通代理后缀 |

每条同时检查外部后缀反例。这些合成样本用于检查规则边界，不对应实际服务器，也不覆盖正则的全部可能匹配。报告的整体覆盖结论始终是 UNKNOWN；“登记并接受暂时省略”不等于“缺口已经修好”。

## 问题记录与回归测试

`tests/incidents.json` 把问题背景、公开的本地验证文档、测试编号和实测范围关联起来，复用 `tests/routing_cases.json` 的测试，避免重复维护断言。缺少证据文件、引用不存在的用例或用例失败都会阻止检查通过。

初始记录包括国际品牌中国服务误走代理、国内业务受海外 CDN 解析影响，以及 iPhone ChatGPT 代理路径。加入了手机实际观察到的 OpenAI、ChatGPT 长连接和静态资源主机。Claude 仅保留静态保护回归，不调用其服务。Steam 下载、完整 iCloud 同步仍未完成验证。

问题记录应包含脱敏后的必要证据、复现条件、期望策略和边界反例。修复后运行完整检查。这套机制不会自动收集或上传浏览记录，也不会自动给上游发送 issue。

## 使用和限制

```sh
# 当前清单、转换缺口和事件回归；不代表已完成版本间比较。
python scripts/check_source_quality.py --output .build/source-quality.json
# 自动发布必须提供包含 dist/ 和 sources/sources.json 的旧快照目录。
python scripts/check_source_quality.py --previous-root .build/previous-root --require-baseline --output .build/source-quality.json
```

JSON 保存完整证据，同名 Markdown 和 Actions 摘要提供简要结果。该机制仍无法自动认定上游分类的真伪、重建上游所有删除动机或发现尚未收录的新业务。语义检查是静态的，不代替运营商网络下的原生客户端测试。

本轮本地验证：90 项单元/故障测试、118 项路由/DNS 契约、559,387 个域名边界及 IPv4/IPv6 精确集合审计、离线复现、actionlint 均通过。专项故障覆盖删除父后缀后仍保留子域、新增父子冲突、等价合并、未知正则、样本回归、缺失旧快照及复核指纹过期/跨版本失效。命令行失败测试确认报告保存且配置文件不变。未修改订阅配置、Mac 或 iPhone 设置。
