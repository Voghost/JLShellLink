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

## 数据面与 CONNECT

直连承载为 ICE 选定 UDP socket 上的可靠有序字节流；中继承载为 A/C 主动出站的 WSS 密文字节流。两者之上使用相同的 A—C TLS 1.3 双向认证和 `h2` ALPN。

CONNECT 请求至少携带 `tunnelId`、数值 `targetIp`、`targetPort`、`accessTicket`。C 依次验证 TLS 对端指纹、票据、目标、当前 ACL、jti 单次消费，再连接目标 TCP。成功返回 2xx；拒绝不打开目标 socket。

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
