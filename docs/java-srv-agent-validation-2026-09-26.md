# Java Link SRV / Agent 独立环境联测（2026-09-26）

## 环境边界

- B：`/root/jlshell-link-validation`，独立 Compose 项目、PostgreSQL、Redis、临时 TLS 证书及 Website 后端；未复用生产数据库或容器。监听 `13575/TCP`（WSS）、`13576/UDP`（STUN）、`13577/TCP`（临时 HTTPS API）。
- C：`/home/voghost/jlshell-link-validation`，独立 Agent 身份、凭据、白名单和 JVM truststore；通过通用 Linux `systemd-user` 安装脚本运行 `jlshell-link-agent.service`。Agent 状态与验证目录分离；未替换既有生产服务。
- A：本机 `/private/tmp/jlshell-link-validation-a`，独立测试身份和 truststore。测试凭据均未放入仓库。
- B 上三个容器运行正常，后端约 415 MiB、PostgreSQL 83 MiB、Redis 3 MiB；隔离栈使用独立内存上限。

## 网络和业务结果

经 B 的 Binding STUN 观察，A 出口映射为 `117.143.39.250:2055`（41.5 ms），C 出口映射为 `61.140.95.147:16008`（8.3 ms）。两端是不同公网出口，本次测试使用 **relay-only**，不将该结果计作直连 ICE 验收。

A/C 均先建立持钥证明的 WSS 控制连接。A 从临时 Website 获得真实短票据和当前访问会话；C 从 Website 读取在线租约与已激活的目标，再出站连接 B。每个会话 A 均收到 `SESSION_INVITE`。随后 A 经 B 的密文 WSS 中继、内层 TLS 1.3 mTLS 与 HTTP/2 CONNECT 访问 C 本地网络：

| C 侧目标 | 观察到的响应 | 建连耗时 | A 侧操作 |
| --- | --- | ---: | --- |
| `192.168.31.1:80` | HTTP 响应 859 字节，直到 EOF | 1121 ms | 双向半关闭 |
| `192.168.31.151:22` | SSH 响应 1176 字节，直到 EOF | 10019 ms | 双向半关闭 |
| `192.168.31.202:22` | SSH 响应 1062 字节，直到 EOF | 9806 ms | 双向半关闭 |

这是三个不同的数值 IP 目标，Website 策略和 C 本地白名单均只允许对应端口。重连同一 HTTP 目标时，Website 返回了新的 session、tunnel 与 access ticket，并再次送达 `SESSION_INVITE`。B 重启后 C 日志出现短暂 `control-wss-disconnected` / `website-unavailable`，随后重新进入 `online` 和 `control-wss-online`，证明控制连接自动恢复。

随后通过 Website 真实 `/sessions/{id}/close` 撤销活动 SSH session。A 收到 `SESSION_REVOKED`，该 session 的 relay stream 在 **47 ms** 内关闭。再次创建两个同时活动的跨主机 Website session，分别连接 `192.168.31.202:22` 与 `192.168.31.151:22`；关闭第一条 session 后，其 relay stream 在 **412 ms** 内关闭，第二条未收到撤销且仍可用，继续完成 SSH 双向半关闭并收到 **1136 字节**响应。由此覆盖“仅撤销指定 session”的真实 A—B—C 路径。

C 的通用 `install-user-service.sh` 使用独立状态目录和临时 truststore 成功部署为 `jlshell-link-agent.service` 用户级 unit，Agent 回到 `online/control-wss-online`；联测时 Java 进程约 108 MiB。该 unit 不替换现有服务。macOS 15 LaunchAgent 与 Windows 2025 WinSW 的隔离 runner 生命周期检查均已通过 [GitHub Actions run 36222765696](https://github.com/Voghost/JLShellLink/actions/runs/36222765696)：覆盖安装、运行状态、优雅停止、卸载和状态保留。两平台测试使用受控假 Java Agent 进程验证服务管理集成，不携带生产凭据或连接生产控制面。

首次短会话联测发现用量快照可能在事务关闭后才异步冲刷，导致落账为 0。修正为关闭预留前纳入内存累计后重测。完成双 session 撤销联测后，隔离数据库汇总为 **23 个已关闭 Relay 预留、A→C 39641 字节、C→A 40401 字节**；另有 1 个过期且未传输的预留。数字累计本日多轮验收并包含加密传输帧，不代表业务明文字节，也不包含用户凭据。

## 结论和剩余工作

单次独立 Website 部署已提供 Java WSS 控制信令、中继与 STUN，真实票据、在线节点、重连重新授权、实时撤销和三个目标的 A—B—C 业务闭环已跑通。该部署使用七天有效的自签证书，仅供验证。Linux systemd 已在 C 实际安装；macOS LaunchAgent 与 Windows Service 生命周期已由各自 GitHub hosted runner 验收。生产 TLS/公网端口启用须另排维护窗口。Agent 的 ICE/direct KCP 产品组装属于后续 NET/AGENT 工作。
