# Security Policy

JLShell Link 当前是 unsigned Stage 0 prototype，不接受生产环境部署建议。

请通过 GitHub 私有安全报告渠道提交漏洞，不要创建公开 Issue，也不要附带真实
SSH 凭据、节点私钥、Authority 私钥或尚未过期的票据。报告应包含受影响版本、
最小复现步骤和潜在影响。

当前安全不变量：Connector 仅回环监听；Agent 仅连接显式精确 IP:端口；票据
Ed25519 签名、短时有效、绑定双方 PeerId、单流且 nonce 防重放；节点传输使用
QUIC TLS 或 TCP + Noise，并由 Yamux 复用。

网站控制平面已经提供一次性节点持钥 challenge、Agent/Relay 限时凭据轮换、
Authority 新旧公钥过渡以及 Relay Grant 并发/月流量配额。Rust Agent 已支持轮换
keyring；Rust Agent/Relay 主动调用控制平面 HTTP 接口仍属于下一阶段，未完成前不得
把开发票据或本地 Relay 当成生产授权链路。

生产化前仍需完成完整威胁建模、第三方审计、凭据吊销运维、数据平面限速与强制
配额联调、供应链签名和各平台代码签名。
