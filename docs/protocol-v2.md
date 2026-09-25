# JLShell Link v2 协议契约

状态：CORE-01 基线；协议标识 `link-v2`。Maven、Website、插件版本与协议版本独立。

## 角色与标识

- A（CLIENT）是桌面端进程内引擎；B（SERVER）是 Website 内嵌协调/中继；C（AGENT）是远端网络网关。
- `sessionId` 是一条 A—C 底层承载的 UUID；`tunnelId` 是该承载上的一次 TCP CONNECT UUID。已有 session 可复用，每个 tunnel 必须重新授权。
- 每次网络重启递增 `generation`。候选、选路确认和迟到结果只对同一 `sessionId + generation` 有效。
- 业务 `deviceId`/`agentId` 与 `nodeKeyFingerprint` 分开；指纹是标准 X.509 SPKI 公钥编码的 SHA-256 小写十六进制。

## 版本协商

控制连接首帧声明 `minProtocol`、`maxProtocol` 和能力集合。v2 当前只接受二者都覆盖 `link-v2`；无交集返回 `PROTOCOL_UNSUPPORTED` 并关闭。未知可选字段可忽略，未知消息类型、必需字段或安全关键枚举必须拒绝。

## WSS 控制消息

每条消息都有 `type`、`messageId`、`sessionId`（会话消息）、`generation`（网络消息）和 `sentAt`。一条 WSS 连接完成短期凭据及持钥挑战后才接受下列消息：

| 消息 | 方向 | 必需内容 |
|---|---|---|
| `HELLO` | A/C→B | 节点 ID、角色、协议范围、能力、凭据 ID |
| `CHALLENGE` / `PROOF` | B↔A/C | 32 字节以上随机数、用途、节点 ID、可选 sessionId、Ed25519 签名 |
| `SESSION_INVITE` | B→C | sessionId、generation、A/C 指纹、策略版本、过期时间 |
| `ICE_CANDIDATE` | A/C↔B | generation、candidateId、类型、transport、IP、端口、priority、foundation |
| `ICE_END` | A/C↔B | generation |
| `PATH_READY` | A/C→B | `DIRECT`/`RELAY`、generation、选中候选 ID；不发送 ICE 密码到日志 |
| `RELAY_PREPARE` | B→A/C | 分角色中继凭据、B 实例和到期时间 |
| `REVOKE` | B→A/C | session/tunnel、策略版本、稳定原因码 |
| `PING` / `PONG` | 双向 | messageId 与单调时间戳 |

B 只能在同账号且已授权的 A/C 间路由候选。旧 generation、跨 session 或身份不匹配的候选返回错误且不进入 ICE Agent。

## 选路与重试

- `AUTO`：先尝试直接路径；预算结束且错误属于 `DIRECT_TIMEOUT` 或临时网络错误时，最多启用一次已授权中继。
- `DIRECT_ONLY`：不准备中继；直接失败即返回。
- `RELAY_ONLY`：跳过 ICE 数据路径，但仍执行相同的端到端 TLS 和 CONNECT 授权。
- 授权、身份、票据、协议、配额和用户取消错误不得通过换路径重试。
- 首版不做活跃 tunnel 的无损换路。路径失败后关闭旧 session，重新取票并建立新 session/tunnel。

### 掉线后的重新授权

每次建立目标 TCP 流或在断线后重建该流，A 都调用 `POST /api/v2/link/access-requests`。
仍有效的 A—C 承载可以沿用 `sessionId`，但 Website 每次必须生成新的 `tunnelId`、JTI
和签名访问票据；客户端不得缓存并重放旧票据。`POST /sessions/{sessionId}/renew` 只续订
已建立 tunnel 的运行期授权租约，不签发新的目标访问票据，也不能代替掉线后的授权请求。
授权成功后，direct 与 relay 竞争同一份新 grant；如果 direct carrier 在目标 CONNECT 之前
遇到可重试的网络失败，relay 使用同一份 grant 建立 carrier。授权、身份、ACL、配额或协议
失败不进入另一条路径；CONNECT 已尝试后也不重放一次性票据。已建立的 tunnel 掉线后，
无论沿用还是新建 session，都重新向 Website 授权并使用新的 tunnel/JTI。

## WSS Relay 身份证明与配对

本实现的 Relay listener 提供 `POST /link/v2/relay-challenges` 和
`GET /link/v2/relay` WebSocket Upgrade。两次请求都带 `Authorization: Bearer ...`，以及
`X-Link-Role`、`X-Link-Node-Id`、`X-Link-Agent-Id`、`X-Link-Session-Id`、
`X-Link-Tunnel-Id` 和 `X-Link-Key-Fingerprint`。挑战响应返回一次性 32 字节 nonce；节点
对绑定角色、双方业务 ID、session、tunnel、指纹和 nonce 的规范签名输入作 Ed25519 签名，
Upgrade 请求再提交 `X-Link-Challenge-Id` 与 `X-Link-Proof`。B 每次都重新委托控制面验证
凭据、在线 C、当前会话/tunnel/账号/身份，再原子消费 proof challenge。Bearer、proof 和
票据不得写入访问日志。

Upgrade 后，B 只允许同账号、同 agent/session/tunnel、同票据过期时间和预期 A/C 指纹的
两个不同角色配对；C 必须仍在在线节点租约内。一个 tunnel 只能配对一次。B 将 WSS 二进制
帧按有界队列双向原样转发，不解密内层 A—C TLS，也不转发文本帧。SRV-01 的在线信令和
候选路由不是这个 Relay listener 的一部分，必须与实际实现区分。

## STUN

Link Server 的 UDP listener 只提供 RFC 5389 Binding request/response 和
XOR-MAPPED-ADDRESS（IPv4/IPv6），响应有大小上限并按源 IP 限速；它不分配中继地址，不是
TURN 服务。公网 UDP bind、NAT 映射及候选信令的生产配置由 Website/SRV 部署集成负责。

## 数据面与 CONNECT

直连承载为 ICE 选定 UDP socket 上的可靠有序字节流；中继承载为 A/C 主动出站的 WSS 密文字节流。两者之上使用相同的 A—C TLS 1.3 双向认证和 `h2` ALPN。

CONNECT 请求使用 HTTP/2 扩展头传递业务授权元数据：

| Header | 含义 |
| --- | --- |
| `:authority` | 规范化的数值 `targetIp:targetPort`；IPv6 使用 `[address]:port`。不允许主机名。 |
| `x-jlshell-target-ip` | 票据授权的数值 IP，必须与 `:authority` 一致。 |
| `x-jlshell-target-port` | 票据授权的 TCP 端口，必须与 `:authority` 一致。 |
| `x-jlshell-tunnel-id` | 本次 TCP 隧道的 UUID。 |
| `x-jlshell-access-ticket` | 一次性访问票据；不得写入日志或错误响应。 |

C 依次验证 TLS 对端指纹、票据、目标、当前 ACL、jti 单次消费，再连接目标 TCP。成功返回 `:status 200`；字段缺失或错误返回 `400`，缺票据返回 `401`，授权拒绝返回 `403`，非 CONNECT 请求返回 `405`，目标连接失败返回 `502`，授权服务不可用或建连超时返回 `503`；拒绝不打开目标 socket。`401`、`403` 是本实现的 HTTP/2 CONNECT 映射约定，外层 TLS 必须已完成身份认证。

- HTTP/2 DATA 对应 TCP 字节；流控必须向底层读取传播背压。
- 请求 END_STREAM 映射为目标 TCP `shutdownOutput`；目标 EOF 映射为响应 END_STREAM。
- RST_STREAM、授权租约终止或承载关闭取消两个方向的等待并释放目标 socket。
- 单个 tunnel 的失败不关闭可复用 session，除非错误表明承载或 TLS 已失效。

## 关闭与幂等

`close(sessionId|tunnelId, reason)` 可重复处理。收到重复 messageId 返回原结果，不重复消费票据或记账。关闭顺序为停止新流、取消等待、发送半关闭/重置、释放队列和定时器、最后关闭承载。进程退出后不得保留监听、网络线程或续租任务。

## 稳定错误码

| 错误码 | 类别 | 可换路径重试 |
|---|---|---|
| `DIRECT_TIMEOUT`、`NETWORK_TRANSIENT` | 网络 | 仅 AUTO，一次 |
| `AUTH_DENIED`、`TICKET_INVALID`、`TICKET_REPLAY` | 授权 | 否 |
| `IDENTITY_MISMATCH`、`PROOF_INVALID` | 身份 | 否 |
| `TARGET_DENIED` | ACL | 否 |
| `PROTOCOL_UNSUPPORTED`、`PROTOCOL_ERROR` | 协议 | 否 |
| `RELAY_QUOTA_EXCEEDED` | 配额 | 否 |
| `CANCELLED` | 用户/生命周期 | 否 |

错误响应不回显票据、ICE 密码、签名内容或内部异常栈。
