# iPhone 上的 iCloud+ 储存空间套餐打不开

2026-11-05，云上贵州账户能显示已用容量，但点「获取更多储存空间」提示「无法连接」。小火箭日志里，容量接口 `p220-quota.icloud.com.cn` 已经直连，打开套餐页时出现的 `amp-api-edge.media.apple.com` 则命中了 `apple.com` 的代理规则。

同一部 iPhone、同一 Wi-Fi 和节点，只切换后一个主机的规则：

| 时间 | 小火箭日志（HTTPS 和 UDP） | 套餐页 |
|---|---|---|
| 19:00:39 | PROXY | 无法连接，重试仍失败 |
| 19:04:49–50 | DIRECT | 显示 50 GB、3 个月的优惠 |
| 19:05:47 | 恢复 PROXY | 再次提示无法连接 |

因此只把 `amp-api-edge.media.apple.com` 加入精确直连例外。测试到优惠页为止，未开通试用或付款。
