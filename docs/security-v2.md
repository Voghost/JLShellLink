# JLShell Link v2 安全契约

## 身份和密钥

- A/C 各自在本地生成 Ed25519 节点密钥。A 通过宿主安全存储适配器保存，C 使用受限文件或系统密钥库；核心 DTO 永不序列化私钥。
- `nodeKeyFingerprint = hex(SHA-256(X.509 SubjectPublicKeyInfo))`。业务 ID 与指纹分别校验，重装或同名节点不能自动替换旧密钥。
- 绑定、换钥、WSS 控制和中继连接都使用随机挑战的持钥证明。签名输入包含固定域、`link-v2`、用途、nodeId、可选 sessionId 和原始挑战；挑战至少 256 位且只能使用一次。
- TLS 1.3 证书公钥必须匹配控制平面已绑定指纹，同时检查有效期、用途和算法；禁止 trust-all。票据签名钥与节点 TLS 私钥分开。

## 访问票据

访问票据是 compact JWS，固定 `alg=Ed25519`，必须携带 `kid`。使用 Nimbus JOSE+JWT 解析 JWS，签名在原始 compact signing input 上验证，不把解析后的 JSON 重新序列化再验签。

标准字段：`iss`、单值 `aud`、`iat`、`nbf`、`exp`、`jti`。私有字段：`protocolVersion`、`accountId`、`clientKeyFingerprint`、`agentId`、`agentKeyFingerprint`、`targetIp`、`targetPort`、`capabilities`、`policyVersion`。

C 在打开目标 socket 前固定顺序验证：允许的算法 → `kid` 信任来源 → 签名 → issuer/audience → 时间和可注入时钟偏差 → `link-v2` → A/C 身份 → 精确目标 → 当前策略 → 原子消费 jti。任何失败都不能通过直连/中继切换绕过。建议建连票据有效期 60 秒，允许的时钟偏差上限 2 分钟；运行期使用独立授权租约。

`ReplayStore.consume(jti, exp, now)` 必须原子化。单 JVM 可使用内存实现；多实例 Website/Agent 使用共享或持久化实现。过期条目可删除，未过期的重复 jti 必须拒绝。

## 目标 ACL

- 目标只能是规范化的数值 IPv4/IPv6 和 1..65535 端口，不在授权判断时解析 DNS；拒绝 IPv6 scope 和含前导零的模糊 IPv4。
- 精确地址转换为 `/32` 或 `/128`，CIDR 先清除 host bits。旧目标逐条迁移为精确规则，不能扩大网段。
- DENY 规则优先于 ALLOW。回环地址即使命中 ALLOW，也需要策略级 `allowLoopback=true`；默认关闭。
- C 以 Website 策略和本地限制的交集做最终判定。候选公网地址不是目标 ACL。

## 存储和日志

`ClientSecureNodeKeyStore` 只委托宿主的 OS 安全存储；`RestrictedFileNodeKeyStore` 原子替换文件，并在 POSIX 系统设置 0600。生产实现应按平台补充 Windows ACL。任何私钥、账号令牌、访问票据、ICE 密码、挑战/签名原文和目标业务内容都不写普通日志。

依赖：`com.nimbusds:nimbus-jose-jwt:10.9`，Apache-2.0，固定版本。该库负责 JOSE/JWT 格式和原始 JWS 输入；Ed25519 运算使用 Java 21 JCA，避免引入可选 Tink。参考 [Nimbus 官方说明](https://connect2id.com/products/nimbus-jose-jwt) 与 [Ed25519 JWS 示例](https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-eddsa)。
