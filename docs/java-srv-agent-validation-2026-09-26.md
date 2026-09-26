# Java Link SRV / Agent 独立环境联测（2026-09-26）

## 环境边界

- B：`/root/jlshell-link-validation`，独立 Compose 项目、PostgreSQL、Redis、临时 TLS 证书及 Website 后端；未复用生产数据库或容器。监听 `13575/TCP`（WSS）、`13576/UDP`（STUN）、`13577/TCP`（临时 HTTPS API）。
- C：`/home/voghost/jlshell-link-validation`，独立 Agent 身份、凭据、白名单和 JVM truststore；以前台 `run` 命令的后台进程承载。未安装系统服务。
- A：本机 `/private/tmp/jlshell-link-validation-a`，独立测试身份和 truststore。测试凭据均未放入仓库。
- B 上三个容器运行正常，后端约 415 MiB、PostgreSQL 83 MiB、Redis 3 MiB；隔离栈使用独立内存上限。

## 网络和业务结果

经 B 的 Binding STUN 观察，A 出口映射为 `117.143.39.250:2055`（41.5 ms），C 出口映射为 `61.140.95.147:16008`（8.3 ms）。两端是不同公网出口，本次测试使用 **relay-only**，不将该结果计作直连 ICE 验收。

A/C 均先建立持钥证明的 WSS 控制连接。A 从临时 Website 获得真实短票据和当前访问会话；C 从 Website 读取在线租约与已激活的目标，再出站连接 B。每个会话 A 均收到 `SESSION_INVITE`。随后 A 经 B 的密文 WSS 中继、内层 TLS 1.3 mTLS 与 HTTP/2 CONNECT 访问 C 本地网络：

| C 侧目标 | 观察到的响应 | 建连耗时 | A 侧操作 |
| --- | --- | ---: | --- |
| `192.168.31.1:80` | HTTP 响应首段 36 字节 | 4927 ms | 发送半关闭 |
| `192.168.31.151:22` | SSH banner 40 字节 | 9870 ms | 发送半关闭 |
| `192.168.31.202:22` | SSH banner 22 字节 | 9801 ms | 发送半关闭 |

这是三个不同的数值 IP 目标，Website 策略和 C 本地白名单均只允许对应端口。测试证明 A 发出半关闭；远端 EOF 与双向半关闭的完整行为仍需单独验收。B 重启后 C 日志出现短暂 `control-wss-disconnected` / `website-unavailable`，随后重新进入 `online` 和 `control-wss-online`，证明控制连接自动恢复。尚未演练真实账号/节点吊销及租约到期的跨主机关闭时延。

首次短会话联测发现用量快照可能在事务关闭后才异步冲刷，导致落账为 0。修正为关闭预留前纳入内存累计后重测，隔离数据库的关闭预留汇总为 11 个会话、A→C 13391 字节、C→A 11534 字节；另有 1 个过期且未传输的预留。数值包含握手后的加密帧，不代表业务明文字节。

## 结论和剩余工作

单次独立 Website 部署已提供 Java WSS 控制信令、中继与 STUN，真实票据、在线节点和三个目标的 A—B—C 业务闭环已跑通。该部署使用七天有效的自签证书，仅供验证。正式发布还需版本化 Maven 包、生产 TLS/公网端口配置、平台服务托管和安装包生命周期；Agent 的 ICE/direct KCP 产品组装属于后续 NET/AGENT 工作。
