# 交付验证记录

日期：2026-10-31，Asia/Shanghai。

## 已实现且在本地验证

- 在线解析三个上游仓库的固定提交并实际下载四份输入。没有使用空占位表或编造的示例规则交付。
- 生成 42,449 条规则，配置大小 1,537,087 字节（约 1.47 MiB），UTF-8 / LF。
- `DOMAIN` 100 条、`DOMAIN-SUFFIX` 32,687 条、IPv4 地址规则 6,182 条、IPv6 地址规则 3,479 条、FINAL 1 条。IP 数量包括局域网规则；前缀经过精确合并，可能与原始行数不同。
- 国内源可表达的唯一条目 7,934；代理源 27,324；IPv4 输入 6,174；IPv6 输入 3,475。国内源有 3 条正则明确省略并记录。70 项跨策略交叉记录按代理优先处理。
- 16 个静态路由哨兵通过：包括百度、淘宝、腾讯直连；Google、GitHub、ChatGPT 代理；未收录域名默认代理；局域网、国内/境外 IPv4/IPv6 分类。
- 全部 IP 规则带 `no-resolve`；无广告拦截规则、远程规则集、MITM、脚本、重写或地区节点策略组。
- `python3 -m unittest discover -s tests -v`：**24 项测试通过**，本机 Python 3.9。覆盖精确/后缀边界、IDNA、include/affiliation/属性过滤、循环 include、未知格式、CIDR 家族/公有性/规范化、冲突优先级、404/超时重试、空/超大/损坏输入、计数和覆盖量门禁、原始快照哈希、重复构建，以及失败时旧版所有文件不变。
- 上游提交号或注释变化、实际规则无变化时，测试确认所有已发布文件字节和 mtime 不变。
- 完成第二次真实在线构建，返回 `NO_CHANGE`，保留既有发布配置、报告和源快照。
- `python3 scripts/build.py --offline --check`：完整配置、源快照及报告逐字节复现通过。
- 官方 `actionlint v1.7.12`（下载文件核对官方发布 SHA-256 后运行）：工作流语法、表达式和 cron 静态检查通过。命令：`actionlint -shellcheck= -pyflakes= .github/workflows/update.yml`；没有声称执行了 shellcheck/pyflakes。
- 主 DNS、备用 DNS、节点引导主地址的 IP 地址 DoH TLS/应答探测通过，范围仅限本次执行环境，详见 `REVIEW.md`。
- 只读核查本机 Shadowrocket 2.2.93 的内置配置、提示和参数字符串；未更改现用配置、节点或网络连接。

配置 SHA-256：

```text
e0ac8b4a35dd395346d678cddd59d7138ff7ec88eeec3702fb02aa8ec2ff6bfa
```

以上数量及哈希是本次交付快照，不是以后每日输出的固定值；当前数据以 `dist/manifest.json` 为准。

## GitHub 发布验收

- 每日 UTC 04:23 / 北京时间 12:23 的 schedule。
- `workflow_dispatch` 手动运行、默认分支写权限、成功后提交、无差异时跳过提交。
- 托管 Ubuntu / Python 3.12 上的实际 CI 执行。
- GitHub 权限、分支保护和推送冲突的真实表现。

联网复核确认现有 `jhz1022` GitHub CLI 授权有效，具有 `repo` 和 `workflow` 权限。首次检查把沙箱网络限制误判为凭据失效，此处纠正。正在发布到 `jhz1022/Shadowrocket-Rules`；上述远端项目须以实际 Actions 结果补充，不据本地检查认定通过。无需向脚本或聊天提供密钥。

## 待客户端实测

尚未把本配置导入 Mac 或 iPhone 并实际接管流量。下列项目不能据静态测试判通过：

- “配置”模式下实际网站、子资源和局域网服务可用性。
- `dns-fallback`、直连系统 DNS、代理端解析与节点引导的真实执行路径。
- BrowserLeaks 生成查询与实际 DNS/代理日志的对应关系。
- 主备 DNS 和节点失效时是否存在非预期回退。
- 网络切换、IPv6/IPv6-only/NAT64、硬编码 DNS、浏览器自带 DNS、其他 VPN 共存。
- iPhone 导入及 Network Extension 内存/性能。

验收清单在 `CLIENT_TEST.md`。未经这些验证，不宣称“已解决原 DNS 故障”“实测零泄漏”或“任意节点所有服务可用”。
