# iPhone 实机验证记录

2026-11-02，Asia/Shanghai，通过 Mac 的 iPhone 镜像测试 ChatGPT 的 Wi-Fi 和蜂窝连接。Claude、节点故障和 VPN 断开不在此次测试范围内。

## 测试范围与现场状态

手机沿用原来的 `Shadowrocket.conf`，配置页显示更新时间 2026-11-01 22:37:24、148,891 条规则、20.6M。全局路由为“配置”，原节点保持连接，“包括所有网络”已开启。本轮未安装新配置，也未改动节点、路由、DNS 或隧道设置。未提取手机文件摘要，尚不能确认与仓库 `6aafdee` 完全一致。

测试时临时开启代理日志，测试后恢复原来的关闭状态；没有导出节点或公开原始个人日志。在手机上切换到蜂窝网络后，镜像状态栏显示 5G。

## 观察结果

| 场景 | 实际结果 | 证据范围 |
| --- | --- | --- |
| 原生规则测试 | `chatgpt.com` 命中 DOMAIN-SUFFIX / PROXY | 客户端规则匹配，不是联网结果 |
| Wi-Fi，约 21:10 | ChatGPT 临时聊天收到 `OK` 回复 | 同时段 `ios.chat.openai.com`、`ws.chatgpt.com`、`persistent.oaistatic.com` 日志为 PROXY |
| 5G，约 21:15 | 同一临时聊天完整收到 1～20 的回复 | 21:14～21:15 的 OpenAI HTTPS/UDP 记录和 ChatGPT 长连接均为 PROXY |
| 5G，约 21:16 | Safari 的 test-ipv6.com 检测 IPv4 与 VPS 出口相符，未检测到 IPv6 | IPv4 和双栈检测成功；IPv6 记录、大包、IPv6 ISP 检测超时；相关可见测试连接为 FINAL / PROXY |
| 同期后台连接 | `gateway.icloud.com.cn` 为 DOMAIN-SUFFIX / DIRECT | 仅证明这个网关的路由，不代表完整 iCloud 同步验收 |
| 收尾，约 21:18 | 小火箭仍连接、全局路由仍为“配置”、日志关闭 | 没有执行断开或回退直连操作 |

此次未观察到测试流量通过国内蜂窝 IPv6 绕过代理。检测网站的 0/10 是 IPv6 可用性评分，不是代理隐私评分；DNS 服务器能访问 IPv6 也不等于手机泄漏 IPv6。

## 仍未覆盖

- 代理日志只能看到进入小火箭的连接，单靠它不能排除所有隧道外流量；浏览器检测也不能证明所有 App、所有时间均无泄漏。
- 未进行代理节点/DNS 全失败、VPN 主动断开、长期锁屏或多轮网络切换故障注入。为保持 Claude 的代理连接，未做上述故障注入。
- 未完成 IPv6-only/NAT64 网络、长期耗电/内存、ChatGPT 语音和文件上传、Steam 实际下载及完整 iCloud 同步验收。
- 手机已安装配置的实测与仓库自动检查分别记录，尚未核对两者的文件摘要。

镜像要求 Wi-Fi 和蓝牙开启，蜂窝测试保留无线开关，只断开当前 Wi-Fi 网络。参考 [Apple 的 iPhone 镜像说明](https://support.apple.com/en-us/120421)。
