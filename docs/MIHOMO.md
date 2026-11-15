# Mihomo / OpenClash 输出与本地验证

本目标复用现有审核过的源数据和 Shadowrocket 构建结果，不引入新的分流名单。
节点由 3x-ui 的 Mihomo 订阅独立提供；规则和 DNS 由本仓库维护。
不让 3x-ui 再合并公共规则，原因和源码审查见 [3x-ui 订阅说明](3X_UI_SUBSCRIPTION.md)。

## 文件与更新边界

- `dist/Shadowrocket.conf`：原有输出，分流规则及 General 设置不变。
- `dist/mihomo/Mihomo.yaml`：完整、无节点的 YAML；八个规则集内嵌在同一个文件。
- `dist/mihomo/manifest.json`：源配置身份、生成器身份、完整规则数与产物摘要。
- `config/mihomo.json`：部署网络的明确本地 DNS。当前为主路由 `192.168.1.1`，
  适配旁路由 `192.168.1.99/24`；换网络前必须核对，不能将它改成 OpenClash 自身
  或 `system` 而制造 dnsmasq → Mihomo → dnsmasq 自环。
- `config/openclash-local-nodes.ini`：本地覆写模块模板，不注册、不启用、不包含订阅地址。
- `scripts/prepare_mihomo_nodes.py`：读取本地私有订阅 URL 文件，生成 mode 0600 的
  节点提供者 YAML 和本地模块；不会下载订阅、操作路由器或启动代理。

规则采用一份完整的更新快照，避免八个独立 HTTP 规则集刷新时混用不同日期的数据。
构建仍由 Python 标准库完成；PyYAML 6.0.3 是独立产物验证的开发依赖，使用安全加载器，
拒绝重复键，不参与上游业务分类。通过 `requirements-test.txt` 固定版本。

## 保留的分流契约

展开 `RULE-SET` 后，全部原规则、顺序、DIRECT/PROXY/REJECT 与解析标志逐条一致：

局域网 → DNS 端口保护 → 本地管理名称 → 受保护服务 → 已审查直连例外 →
区域服务 → 普通直连 → 普通代理 → 中国 IP → 默认代理。

- 不新增 `.cn` 总直连、GEOIP 数据库替代或广告拦截。
- 中国 IP 使用原 IPv4/IPv6 地址集合，不改变覆盖范围。
- LAN IP 规则保留 `no-resolve`；中国 IP 层允许未知域名触发解析。
- `FINAL,PROXY` 转成 `MATCH,PROXY`。
- Mihomo 会跳过不支持 UDP 的出站，因此两个代理层后紧接相同集合的 UDP REJECT。
  最终代理后另有 REJECT，避免内核的隐式直连默认值。
- 无节点时 `PROXY` 只有明确的 `REJECT`。这不是可用节点，不允许无人确认就启用。

## DNS 契约

`nameserver-policy`、Fake-IP 过滤都沿用相同的域名层顺序。
Mihomo 对 classical 集合提示“DNS 仅使用域名规则”是预期行为：IP 判断仍在路由阶段，
DNS 选择不依赖其 IP 条目。不要排序或合并这些有序域名层。

| 查询用途 | 路径 |
| --- | --- |
| 已分类 DIRECT 与局域网名称 | 明确的本地网络 DNS，当前 `192.168.1.1:53#DIRECT` |
| PROXY、未分类域名 | `1.1.1.1` 与 `8.8.8.8` DoH，均指定 `#PROXY` |
| 节点域名 | 独立阿里 DoH，指定 `#DIRECT` |
| 私有节点订阅的域名 | 本地模块增加该**精确主机名**的独立引导解析，指定 `#DIRECT` |

最后一项只服务于节点订阅冷启动，是明确的控制面主机名例外，不是未知域名的系统 DNS 回退。
模块以前置合并保持其优先级；其他域名继续遵循公开规则。URL 是 IP 字面量时不添加例外。

`direct-nameserver-follow-policy: true`，而 DIRECT 默认解析器仍为经代理 DoH，
确保未分类域名在中国 IP 层决定 DIRECT 后，不被再次交给本地 DNS。
不使用 Mihomo 的国内/国外 `fallback-filter` 重写此决策，也不使用系统 hosts 改写代理域名。
两台代理 DNS 均故障时，不退回本地 DNS；节点失败时，应代理请求失败，直连业务仍可用。

IPv4 兼容设置不等于在客户端禁用了系统 IPv6。选定终端的原生 IPv6 路径仍需部署时单独验收。

## 私有节点文件与 OpenClash 接入

接入前先准备本地私有文件；此命令本身不启用代理：

```sh
python3 scripts/prepare_mihomo_nodes.py \
  --subscription-file /path/to/subscription.private.txt
```

该文件应含一条自己的 HTTPS Mihomo 订阅地址。3x-ui 可使用 `/mihomo/<sub-id>`，
也可使用面板配置的 Clash/Mihomo 路径；VLESS 不应使用 `/clash-legacy/`。
不要将 URL 放在命令行、公开配置或提交记录中。

对于用户已明确指定的现有 HTTP 订阅，准备与检查命令可加 `--allow-http`；
默认仍拒绝 HTTP。HTTP 地址和响应内的节点凭据是明文传输，后续应在订阅服务配置 TLS；
这些工具不修改面板证书或自动改写订阅地址。User-Agent 固定为 `mihomo`，使 3x-ui 的
格式自动识别入口返回 Mihomo YAML；不会自行猜测另一条订阅路径。

生成 `.build/nodes.private.yaml` 与 `.build/nodes.private.ini`：

1. 后续部署时，私有 YAML 对应 `/etc/openclash/custom/nodes.private.yaml`。
2. 私有 INI 是本地覆写模块，匹配完整路径 `/etc/openclash/config/Mihomo.yaml`，注册时保持关闭。
3. 原始公共配置更新后，本地模块仍在：它只注入 `proxy-providers.nodes` 和一个 `PROXY`
   选择组，不接收节点订阅中的规则、DNS 或 DIRECT 选项。
4. 公开主配置默认拒绝。填入有效订阅、验证并显式选中真实节点后才准备启用。
5. 节点提供者每 3600 秒更新；规则由 OpenClash 的公共配置订阅更新。
   准备脚本不创建定时任务、不注册模块，也不将地址写到路由器；实际部署须另行备份、验证。

公共配置订阅地址是：

```text
https://raw.githubusercontent.com/jhz1022/Shadowrocket-Rules/main/dist/mihomo/Mihomo.yaml
```

首次使用前应确认对应提交已推送、工作流验证通过，且该地址能返回完整配置。
本地尚未推送的修改不会出现在订阅中；不能只填写 URL 就认定更新已经生效。
要保留“单一规则快照”，不要再把规则集拆成若干独立更新 URL。

### OpenClash 覆写约束

已按 v0.48.002 的 `yml_change.sh`、`yml_rules_change.sh`、`YAML.rb` 核对模块格式：

- `enable_custom_dns=0`，禁用额外 Fake-IP、DNS 策略、hosts、规则和 BT/PT 直连覆写；
  `china_ip_route=0` / `china_ip6_route=0`，不让另一份区域数据提前放行。
- `disable_udp_quic=0`：不新增原规则没有的 UDP/443 拒绝。
- `enable_redirect_dns=2`、`router_self_proxy=0`：DNS 由插件防火墙接管，避免默认的
  Fake-IP + dnsmasq 转发 + 本机代理关闭组合插入额外的源地址 DIRECT 规则。
- `ipv6_enable=0` / `ipv6_dns=0`，UDP 透明代理保持开启，限定内网访问。
- 私有订阅 URL 用 `ruby_cover` 从数据文件载入，不作为模块环境变量展开；保留 URL 中的字面 `$`。

模块只准备本地文件，不是此刻已生效的路由器配置。真实 OpenClash 启动后的运行 YAML、
DNS 抢答、浏览器 DoH、终端 IPv6、直接出口和节点出口都必须再次检查。

## 本地验证

```sh
python3 -m pip install -r requirements-test.txt
python3 scripts/build.py --offline
python3 scripts/build.py --offline --check
python3 -m unittest discover -s tests -v
python3 scripts/check_mihomo.py --output .build/mihomo-contract.json
mihomo -t -d dist/mihomo -f dist/mihomo/Mihomo.yaml
python3 scripts/verify_mihomo_native.py --binary /path/to/mihomo
```

`check_mihomo.py` 独立解析序列化 YAML、验证摘要、展开全部规则，并运行已有路由场景。
同时测试规则换序、删除 UDP 拒绝、将空节点设成 DIRECT、增加系统 DNS 等故障是否被拦截。

原生测试在 127.0.0.1 建立临时 DNS、节点订阅、SOCKS 节点与目的端；不改系统代理、DNS、
路由或路由器。为可控地观察中国 IP 判断，测试副本增加 `127.0.0.1/32` 作为合成 CN 地址；
把加密 DNS 上游换成通过同样 DIRECT/PROXY 路径的本地 TCP DNS。它验证引擎选择与故障行为，
**不证明公网 DoH 的 TLS、真实 VLESS 认证、UDP 服务端能力或客户端透明转发已经可用**。

测试读取完整的模拟 3x-ui YAML，并放入与公共配置相冲突的规则/DNS，检查只提取节点；
覆盖有效节点更新、空/坏订阅保留最后有效节点、两台 DNS 都失败、节点失败及直连仍可用。
UDP 测试有负向对照：删除拒绝保护后，相同请求确实会落入后面的合成中国 IP DIRECT；
有保护时必须为 REJECT，且目的端不得收到数据。

原始日志保存在 `.build/mihomo-native/`。提供真实节点后，下一轮还需验证证书/SNI/flow、
节点与 DoH 冷启动、选中/未选中设备、IPv6，以及节点失效时的真实出口。

私有订阅只读检查（仅 `-t` 解析真实节点，不启动其代理进程）：

```sh
python3 scripts/check_mihomo_subscription.py \
  --subscription-file /path/to/subscription.private.txt \
  --binary /path/to/mihomo
```

原始响应、私有候选及原生诊断只存 `.build/subscription-check/`，文件权限 0600。
公开报告仅含节点数量、协议与语法结果，不含 URL、名称、地址、UUID。
