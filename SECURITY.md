# Security Policy

JLShell Link 当前是 unsigned Stage 0 prototype，不接受生产环境部署建议。

请通过 GitHub 私有安全报告渠道提交漏洞，不要创建公开 Issue，也不要附带真实
SSH 凭据、节点私钥、Authority 私钥或尚未过期的票据。报告应包含受影响版本、
最小复现步骤和潜在影响。

当前安全不变量：Connector 仅回环监听；Agent 仅连接显式精确 IP:端口；票据
Ed25519 签名、短时有效、绑定双方 PeerId、单流且 nonce 防重放；节点传输使用
QUIC TLS 或 TCP + Noise，并由 Yamux 复用。

生产化前仍需完成威胁建模、第三方审计、密钥轮换与吊销、限流/配额、正式控制
平面、审计日志、供应链签名和各平台代码签名。

