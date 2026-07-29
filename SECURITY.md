# Security Policy

JLShell Link 当前仍是 unsigned prototype，不接受生产环境部署建议。

请通过 GitHub 私有安全报告渠道提交漏洞，不要创建公开 Issue，也不要附带真实
SSH 凭据、节点私钥、Authority 私钥或尚未过期的票据。报告应包含受影响版本、
最小复现步骤和潜在影响。

当前安全不变量：Connector 仅回环监听；Agent 仅连接显式精确 IP:端口；票据
Ed25519 签名、短时有效、绑定双方 PeerId、单流且 nonce 防重放；节点传输使用
QUIC TLS 或 TCP + Noise，并由 Yamux 复用。

供插件调用的 Connector/Agent/Relay 身份探测和 challenge 签名模式只读写 0600
身份文件并立即退出；隧道模式的
机器可读生命周期输出不得包含票据、私钥或凭据。Program 插件负责子进程退出和临时
票据清理，但正式签名发布物启用前仍只能执行用户明确配置的可信二进制。

网站控制平面已经提供一次性节点持钥 challenge、Agent/Relay 限时凭据轮换、
Authority 新旧公钥过渡以及 Relay Grant 并发/月流量配额。Rust Agent/Relay 使用
Rustls HTTPS 和 0600 节点凭据心跳，Agent 刷新失败时保留最后一个已验证 keyring。
Circuit Relay 尚未把 Grant 验证绑定到每次 reservation/流量统计，因此当前 Relay
仍不得作为生产授权链路。

Agent 只上报精确 IP TCP/QUIC multiaddr，Connector 连接时仍强制匹配 Agent PeerId。
Windows SCM 模式由最小包装进程托管数据平面子进程，节点凭据仍只以文件路径传递；
Linux/macOS 的服务沙箱和远端文件权限由插件生成的原生服务定义负责。

生产化前仍需完成完整威胁建模、第三方审计、凭据吊销运维、数据平面限速与强制
配额联调、供应链签名和各平台代码签名。
