# Relay Grant 数据面接入约束

Website 已提供 Relay Grant 签发、Relay 凭据验证、幂等累计用量上报和配额预留。
标准 Circuit Relay v2 握手没有携带 JLShell Grant 的扩展字段，而 rust-libp2p 0.56
公开的 Relay server API 存在两个关键限制：

- `RateLimiter` 只能按源 PeerId/IP 决定是否放行，无法同时核对目标 Agent PeerId。
- `CircuitClosed` 只暴露双方 PeerId 和错误，不暴露真实双向字节数。

因此本仓库固定并内置 `libp2p-relay 0.21.1` 的最小安全补丁，保留上游 MIT
许可证；补丁只增加 Circuit 接受前授权、动态额度/有效期和双向字节计数，不改变
Circuit Relay v2 的线上协议。

当前实现采用版本化的 `/jlshell/link/relay-auth/1.0.0` 加密预授权协议：

1. Agent 先通过 `/jlshell/link/relay-reservation-auth/1.0.0` 加密流提交节点凭据；Relay
   在线验证后将真实源 PeerId 加入五分钟 reservation 授权租约，Agent 每两分钟刷新。
2. Connector 只从文件读取短期 Relay Grant，先与 Relay 建立 Noise 加密流并提交。
3. Relay 在线验证 Grant，并绑定
   `connectorPeerId + agentPeerId + grantId + expiresAt + byteLimit`。
4. Relay behaviour 在接受 reservation/Circuit 之前查询对应缓存；错误目标、缺少授权、
   重放、过期或额度耗尽全部在接受前拒绝。
5. 转发循环在两个方向精确计数，额度或有效期到达时关闭 Circuit；每 10 秒及关闭时
   使用单调 sequence 向 Website 上报累计值。
6. 公网监听强制要求控制平面和 Relay 凭据；无控制平面的未鉴权模式仅允许显式的
   回环原型监听。

自动测试覆盖绕过拒绝、错误目标、单次消费、重放/过期/耗尽和双向字节一致性。

仍待安全发布阶段完成：生产环境代码签名和更细粒度的吊销推送。控制平面持续不可用时，
新 Circuit 立即拒绝，reservation 最多保留一个五分钟租约，已有 Circuit 则在 Grant
到期或额度耗尽时关闭。当前 Relay 仍标记为非生产原型。
