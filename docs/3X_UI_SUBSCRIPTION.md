# 3x-ui 订阅源码审查与接入选择

审查来源：官方 `MHSanaei/3x-ui`，提交
`5297fd3c8495d80fab97ae511553fa545c69e913`（2026-11-15 本地读取）。
未修改上游仓库、面板设置或订阅。用户截图证明面板有相应入口，但不能据此确定实际安装版本；
下述实现事实对应已审查源码，实际面板仍需部署验收。

## 节点与格式

- 订阅服务器独立于管理面板运行；同一 Sub ID 可产生 URI/Base64、Xray JSON、Mihomo YAML。
- 使用 `/mihomo/<sub-id>` 或配置的 Clash/Mihomo 路径。`/clash-legacy/` 排除 VLESS，
  并忽略自定义 Clash 路由；不适用于当前 VLESS TCP TLS 节点。
- Mihomo 节点导出处理 UUID、传输、TLS/SNI、指纹、ALPN；Vision `flow` 按客户端、入站与传输条件输出。
  输出 `udp: true` 只是客户端声明，不证明服务端 UDP、节点证书或具体业务已经验证。
- 默认 `PROXY` 组包含节点及 `DIRECT`，可能还有流量/到期信息用的假节点。
  本项目不导入该组，只把订阅当作原生 `proxy-providers` 的节点数据。

## 面板远程规则功能

`subClashEnableRouting`、`subClashRules` 与 `subClashRemoteDNS` 分别控制路由开关、
远程 HTTPS URL/内联规则以及是否接收远程 `dns`、`sniffer`。

- URL 模式默认只接收 `proxy-groups`、`rule-providers`、`rules`；不会接收远程节点。
- 开启 Remote DNS 才接收 `dns` 和 `sniffer`；不接受完整配置的任意顶层字段。
- 同名远程组替换面板同名组，不自动注入节点；`use` 指向 `proxy-providers` 的组被拒绝。
- 远程规则有 MATCH 时，替换默认规则；否则添加到默认 MATCH 前。
- 远程正文上限 2MiB，展开写出预算 4MiB，嵌套深度 16；本仓库完整规则不能直接塞入该入口。
- YAML 以通用 map 解码并重新序列化，不把原始 DNS 映射顺序当作接口承诺。
  本项目的有序 DNS 策略不依赖这一次二次合并。

## 刷新与故障

- 进程启动预热，每 5 分钟运行后台刷新任务；有效缓存 TTL 10 分钟，失败重试退避 30 秒。
- 请求超时 6 秒，使用 ETag/Last-Modified；保持 HTTPS 并检查重定向/地址。
- 有旧有效规则时，远端失败保留旧值，并持久化到数据库。
- **没有有效缓存时**，订阅请求不会等待远端；生成器可能跳过远程规则，继续输出默认节点组
  和 `MATCH,PROXY`。不能把这一路径理解为本项目的严格失败关闭。
- `Profile-Update-Interval` 默认 12 小时，是给客户端的建议，不等于客户端立刻刷新；
  “面板更新了规则”和“OpenClash 已下载并使用新版”是两件事。

## 已采用的方案

3x-ui 只生成节点订阅；公共规则、DNS 和拒绝保护在 OpenClash/Mihomo 主配置内。
节点订阅通过原生 `proxy-providers` 提取 `proxies`，即使响应包含其他规则或 DNS 也不接收。
节点地址、UUID 和订阅 token 均不进入本仓库；公共配置与私有节点提供者独立更新。
详见 [部署与验证](MIHOMO.md)。

## 对照的官方源码

- [格式、组、VLESS 与远程规则合并](https://github.com/MHSanaei/3x-ui/blob/5297fd3c8495d80fab97ae511553fa545c69e913/internal/sub/clash_service.go)
- [远程规则缓存、限制与持久化](https://github.com/MHSanaei/3x-ui/blob/5297fd3c8495d80fab97ae511553fa545c69e913/internal/sub/remote_routing.go)
- [订阅路径与响应头](https://github.com/MHSanaei/3x-ui/blob/5297fd3c8495d80fab97ae511553fa545c69e913/internal/sub/controller.go)
- [后台任务](https://github.com/MHSanaei/3x-ui/blob/5297fd3c8495d80fab97ae511553fa545c69e913/internal/web/job/remote_routing_job.go)
- [远程 DNS 测试](https://github.com/MHSanaei/3x-ui/blob/5297fd3c8495d80fab97ae511553fa545c69e913/internal/sub/clash_remote_dns_test.go)
- [订阅格式文档](https://github.com/MHSanaei/3x-ui/blob/5297fd3c8495d80fab97ae511553fa545c69e913/docs/content/docs/zh/config/subscription.mdx)
