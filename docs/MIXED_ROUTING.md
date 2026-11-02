# 混合分流与 Mac 验证记录（2026-10-31）

**Mac 实机验证已完成，测试前已备份并准备恢复措施。结果仅适用于下列网络、节点和请求；手机及其他业务需单独验证。**

候选配置 SHA-256：`61848c3c66a466dfdf72cf679f013d6757e119d345e4ffa7fd233897fdc8dedc`。
148,877 条规则，5,011,887 字节。规则数量增加来自恢复被 `.cn` 总规则压缩掉的具体国内服务；中国地址覆盖范围没有删减。

## 分流设计

局域网 → DNS 端口保护 → 本地管理名称 → 受保护代理服务 → 有依据的国内服务类别/例外 → 完整中国区域服务分类 → 完整国内及可直连服务分类 → 普通海外服务分类 → 中国 IP 兜底 → 默认代理。

- 保留八份固定来源的完整数据、递归 include/属性/affiliation 处理和独立源解码审计，按上游分类统一生成规则。
- 中国区域分类仍从全部 `geolocation-!cn @cn` 自动生成，另使用完整 Apple 中国服务列表；新厂商符合上游属性即可进入分类，不需要逐厂商加代码。
- 从上游直连列表中过滤整个 `.cn`、`.中国`、`.中國` 及其他公共注册后缀，防止不明服务因后缀直接放行。不能把注册地区当服务器所在地。
- 保留国内普通业务的域名优先策略：其海外 CDN 结果不会自动把整个国内业务转成代理。
- Google 不再把 `google.com`、`googleapis.com`、`gstatic.com`、`google.cn` 整族列入本地强制代理层。完整上游分类仍代理搜索、Gemini 等业务；中国下载、字体等明确区域分类先匹配。Claude、OpenAI、Copilot 等原有受保护规则保留。
- 中国 IP 兜底层去掉 `no-resolve`，允许未被域名规则识别的连接触发解析；前置 LAN IP 规则继续保留 `no-resolve`，防止在服务分类之前提前解析所有域名。
- 国内服务使用系统 DNS；代理业务及未分类业务使用经代理的 Cloudflare/Google DoH 或协议端远程解析。海外 DNS 可能返回海外 CDN 地址，导致未分类的国内服务仍走代理。
- IPv4 兼容设置、端口 53 保护和不支持 UDP 时拒绝的策略保持不变；这不构成 iPhone IPv6 旁路验证。

## 国内公共服务的分类例外

移除 `.cn` 总规则后，部分国内公共服务不在上游具体域名名单中。实际查询 Cloudflare 得到 `www.gov.cn` 的地址 `156.225.111.236/237/238`，均不属于当前中国地址集合：如果只交给 IP 兜底，它会被代理。

根据注册用途，将 `gov.cn`、`edu.cn` 整类归入中国政府、教育服务并直连；这些域名的服务器也可能位于境外。商业注册空间如 `.cn`、`.com.cn` 不享受这一例外；`gov.cn.example.net`、`fakeedu.cn` 也不会命中。

依据：[CNNIC GOV.CN 使用规范](https://cnnic.cn/n4/2022/0830/c57-10123.html)、[CERNET EDU.CN 说明](https://www.cernet.edu.cn/xxh/yc/202508/t20250804_2684370.shtml)。理由和来源同时记录在 `config/overrides.json`。

Loyalsoldier、v2fly 与 blackmatrix7 ChinaMax 的交叉检查表明，成熟列表也可能依赖中国总后缀；盲目堆叠更多列表不能解决 DNS 与分类的顺序问题。blackmatrix7 仅供交叉研究，没有合并其数据。

## 自动检查结果

| 检查 | 结果与范围 |
| --- | --- |
| 自动化测试 | 完整套件 75 项通过（312.688 秒） |
| 全来源独立审计 | 559,287 个域名边界样本，零转换差异；不表示上游分类绝对正确 |
| 中国 IP 集合 | IPv4、IPv6 压缩前后集合完全一致 |
| 跨服务与 DNS 触发契约 | 115 个场景全部通过；独立文本解释器与注入 DNS，非 Shadowrocket 模拟器 |
| 故障回归 | 重新加入中国 IP 的 no-resolve、提前触发 LAN 解析、增加注册后缀直连均能被拦截 |
| 离线复现 | 配置、manifest、冲突记录、原始输入精确复现 |
| 工作流 | actionlint 通过；新增契约检查接入 verify 和 update 两个阶段 |
| 上游维护状态 | 八份来源及远端既有更新任务检查通过；不代表候选已在 GitHub 验证 |
| 真实 DNS 观察 | 18 个公开域名查询成功，覆盖电商、社交、公共服务、区域 CDN、海外 AI 与 us.ip111.cn；将查询答案交给候选文本模型，未测量候选配置的实际出口 |
| Mac 配置身份 | 按客户端实际选中的配置读取数据库；148,877 条有序规则及 General 设置与候选一致 |

测试矩阵保存在 `tests/routing_cases.json`。其中为未知域名注入的国内/国外 IPv4、IPv6、空答案、超时及私网答案是受控测试数据，不是对这些域名真实托管地点的声明。IPv6 规则测试只检查数据/决策，当前默认仍不启用 IPv6。

域名边界模型相对回滚版本：2,291 个样本从 DIRECT 变为 PROXY，46 个从 PROXY 变为 DIRECT。无地址模型用 PROXY 表示域名层没有直连命中；新版本在实际解析到国内地址后仍可由 IP 层转为 DIRECT。样本包含合成子域，不是受影响网站数量或流量占比。

详细本地证据位于 `.build/mixed-policy/`：`audit.json`、`routing-contract.json`、`live-dns.json`、`domestic-regression.json`、`upstream-health.log`、`mac-unchanged.json`。这些是本地诊断产物，不上传私人客户端日志。

## Mac 实测

测试环境：macOS 上的 Shadowrocket 2.2.93、配置模式、原有 VLESS 节点。测试前以 SQLite 一致性备份保存全部现有配置数据库、原配置文本和偏好设置；节点故障测试前另外备份节点存档。私密备份和日志只保存在本地 `.build/mixed-live/`，不提交仓库。

| 实机检查 | 观察结果 |
| --- | --- |
| 国内业务 | 百度、淘宝、Bing 中国返回 200；网易、抖音、高通中国、政府/教育站点、iCloud 中国及 Google 字体请求命中 DIRECT。403/400 只算协议响应，不算登录或完整业务通过 |
| 海外业务 | Google 返回 204、GitHub 返回 200；Claude、Anthropic、OpenAI、Gemini 命中 PROXY。Claude 403、API 根路径 404/421 不算 AI 账户/聊天功能通过 |
| 国内服务的 DNS | 日志显示国内服务采用系统/国内解析；没有因海外解析结果把已分类国内业务一律代理 |
| 未收录域名与 Fake-IP | `122.114.192.226.sslip.io` 经路由 DNS 解析后命中中国 IP DIRECT；`1.1.1.1.sslip.io` 命中 FINAL,PROXY；已在原生客户端核对 |
| 检测站分流 | `ip111.cn` 命中中国 IP DIRECT，`us.ip111.cn` 命中 FINAL,PROXY；两者均得到真实 HTTP 响应 |
| Apple 实际内容 | 通过官方查询取得并下载图片；下载真实 Rosetta 安装包，校验目录摘要/大小、归档条目及 Apple 签名；未安装或执行 |
| Steam | 商店和社区返回 200 且命中 PROXY；`dl.steam.clngaa.com` 命中 DIRECT；安装包路径重定向后返回 403，恢复旧配置后同样返回 403。下载测试未通过，暂未定位原因 |
| 硬编码 DNS | 5 个 IPv4 UDP/53 目标返回 Fake-IP；3 个 TCP/53 目标无答案且原生日志为 DST-PORT,53,REJECT；IPv6 DNS 无答案，当前 Mac 无可用公网 IPv6，不能外推为手机防泄漏证明 |
| 主 DoH 故障 | 临时将主 DoH 改为不可用路径，TXT 查询由备用 Google DoH 经代理成功回答，原生 DNS 日志确认 |
| 两个 DoH 均故障 | 临时将两者及 fallback 路径设为不可用；新 TXT 查询在 8 秒内无答案，百度仍返回 200。恢复后同一查询由 Cloudflare DoH 经代理成功回答 |
| 节点故障与恢复 | 预先启动本地测试进程，再临时改变节点端口；代理请求失败、百度仍 200，测试请求的原生日志仍为 PROXY。立即恢复原端口后返回 200，出口与测试前一致；未观察到直连回退 |

NTP 首轮有两个池域名超时，已立即切回原配置做对照：原配置也出现另一 NTP 服务超时，且部分池域名解析地址变化。恢复候选复测后，6 项 NTP 全部收到有效协议应答、13 项 HTTP 探测完成。首轮失败、回滚对照和复测结果分别记录；单次超时不足以定位为分流错误。

节点故障测试最初因测试工具联网受影响而延迟执行，这两轮结果已排除；上表仅使用预启动进程在故障窗口内记录的 `node-failed-valid.json`，并与同一时刻原生日志关联。

`verify_client_config.py` 读取客户端实际选中的配置名，以只读模式比较完整规则顺序及 General 设置。身份不符时，DNS/HTTP/NTP 验收入口会在联网前停止。数据库相符只是前置条件，仍需确认 VPN 状态、日志和真实流量。

原始实机证据包括 `services.json`、`ntp-rollback-control.json`、`services-retest.json`、`cross-services.json`、`dns-guard.json`、`dns-*-failed.json`、`dns-restored.json`、`node-failed-valid.json`、`ip-fallback-and-port53-native.json` 及 `apple-content/result.json`，均保留在本地 `.build/mixed-live/`。公开文档不包含节点凭据、私人请求日志或住宅出口地址。

## 未测项目与已知限制

- 本次 Mac 验证不覆盖 iPhone 蜂窝/Wi-Fi 切换、锁屏唤醒、IPv6-only/NAT64，也不替代 Claude App 登录后的完整对话测试。
- 网页/API 根路径可达、策略命中及小文件/部分内容下载，不等于支付、登录、游戏全量下载或所有子资源均通过。
- 未收录域名的多 A/AAAA、缓存变化及海外 DNS 的 CDN 调度仍可能改变 IP 兜底选择。新增域名仍需持续跟踪。
- 未做物理接口全流量抓包或可控目的端审计。所测请求与原生日志未发现直连回退，其他协议和隧道外流量仍待验证。

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py --offline --check
python3 scripts/audit.py --output .build/policy-audit.json
python3 scripts/check_routing_contract.py --output .build/routing-contract.json
# 只读；未选中与待测版本一致的配置时会拒绝：
python3 scripts/verify_client_config.py
```
