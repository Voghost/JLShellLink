# Java A 客户端引擎接入边界

`link-client` 的 `LinkClientEngine` 按 Website、账号、A 节点和协议版本固定作用域。每个 Agent 单独维护重授权会话；每次 `openTunnel` 都由 `ReauthorizingConnectionFlow` 申请新目标票据，再由 `ConnectionCoordinator` 完成安全承载和目标 CONNECT。目标建流成功后才绑定 `127.0.0.1` 随机端口，租约只接受一次本地 TCP 连接，双向传递字节与半关闭。取消待完成请求、作用域变化、SSH 关闭和引擎关闭都会回收资源；活跃与等待隧道数量受许可数限制。

构造引擎时必须提供：

- 通过宿主账号网关获取的当前账号/设备作用域；切换账号或 A 身份后创建新引擎。
- 设备 Ed25519 私钥的宿主安全存储适配、短期控制凭据提供者，以及 `WebsiteAccessRequestProvider`。
- 可验证 B 公签 TLS 与 C 内层 mTLS 身份的 `CarrierPlanFactory`。正式 relay-only 路径应使用一次性持钥挑战、`WssSecureConnector` 和 `ConnectClientMultiplexer`；不得把原型测试凭据或信任管理器用于产品。
- 明确的并发上限、握手预算与路径诊断观察者。事件不得包含票据、控制凭据或目标地址。

当前分支只提供引擎生命周期和 loopback 数据桥，**尚未提供产品级 A 控制连接、C 身份发现、真实 relay carrier 的应用组装，也未完成客户端生产 SSH/SFTP 验收**。这些仍是 CLIENT-01/PLUGIN-01 的未完成项。集成前不得用此类宣称产品直连或中继已经可用。
