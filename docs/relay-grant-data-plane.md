# Relay Grant 数据面接入约束

当前 Website 已提供 Relay Grant 签发、Relay 凭据验证、幂等累计用量上报和配额预留，
但标准 Circuit Relay v2 握手没有携带 JLShell Grant 的扩展字段。rust-libp2p 0.56
公开的 Relay server API 还存在两个关键限制：

- `RateLimiter` 只能按源 PeerId/IP 决定是否放行，无法同时核对目标 Agent PeerId。
- `CircuitClosed` 只暴露双方 PeerId 和错误，不暴露真实双向字节数。

因此不能仅在事件回调中调用 Website 后宣称已经完成安全闭环：请求在事件产生前已经
被接受，而且无法准确报告流量。本阶段保持 Relay 原型非生产状态。

正式实现采用版本化的 `/jlshell/link/relay-auth/1.0.0` 预授权协议，并对
`libp2p-relay` server behaviour 做最小、锁版本的内部封装：

1. Agent 用节点凭据为 reservation 建立短期授权缓存。
2. Connector 在发起 Circuit 前提交 Relay Grant，Relay 在线验证并绑定
   `connectorPeerId + agentPeerId + grantId + expiresAt + byteLimit`。
3. Relay behaviour 在接受 reservation/Circuit 之前查询缓存，默认拒绝未授权请求。
4. 转发循环记录真实双向字节数，按单调 sequence 定期和关闭时调用 Website。
5. 超额、到期、吊销或控制平面长期不可达时停止新 Circuit；已有 Circuit 按明确的
   fail-closed 宽限策略关闭。

该扩展必须包含绕过测试、错误目标测试、并发 Grant 测试、断网恢复和字节数一致性测试，
不能只依赖 UI 或 Agent 最终票据校验。
