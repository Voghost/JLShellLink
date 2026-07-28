# JLShell Link

JLShell Link 是 JLShell 的私有商业网络组件原型，预定仓库为
`Voghost/JLShellLink`。它通过 rust-libp2p 在本机 Connector 与远端 Agent
之间建立加密 TCP 隧道，优先直连，并可通过 Circuit Relay v2 回退。

> 当前仍是 unsigned prototype，不可直接用于生产环境。网站控制平面已经定义账号
> 权限、节点持钥注册、短期凭据、Authority 轮换和 Relay Grant 配额接口；Rust
> 进程主动调用这些 HTTP 接口、自动部署、二进制签名和生产 Relay 运维属于下一阶段。

## 组件

- `jlshell-agent`：运行在远端服务器，只访问显式授权的精确 IP:端口。
- `jlshell-connector`：运行在 JLShell 所在机器，只监听回环地址。
- `jlshell-relay`：Circuit Relay v2 中继，默认只允许回环监听。
- `jlshell-linkctl`：生成开发 Authority、节点身份和五分钟单流票据。
- `link-protocol`：版本化 Protobuf 控制帧和 `/jlshell/link/tcp/1.0.0`。
- `link-crypto`：Ed25519 票据签发、验证与 nonce 防重放。
- `link-transport`：封装 QUIC、TCP/Noise/Yamux、AutoNAT、DCUtR 和 alpha
  `libp2p-stream`，不向业务接口泄漏其类型。

传输链路中的 QUIC 或 Noise 提供节点间加密与身份认证；授权票据的签名对象是
原始 `claimsBytes`。Relay 只能看到加密后的 libp2p 流量。网站控制平面使用同一
version 1 Protobuf wire format 和 Ed25519 key-id 算法；`link-protocol` 中的固定
兼容性夹具用于防止 Java/Rust 编码产生漂移。

Agent 的 `--authority-public` 既接受 `authority-init` 生成的旧版单公钥 JSON，也接受
网站 `GET /api/v1/link/ticket-authority` 返回的轮换 keyring JSON。过渡期新旧公钥
可同时验证票据，但签发端只使用当前 active key。

当前安全基线只接受 `/ip4` 或 `/ip6` multiaddr。DNS multiaddr 暂时禁用，以避免
libp2p 0.56 DNS 依赖中的已知 RustSec DoS 公告；CI 会验证 Hickory 不在实际构建
依赖图中。由于 libp2p 元包仍会把未启用的可选依赖记录到 `Cargo.lock`，安全审计仅
临时豁免 `RUSTSEC-2026-0118` 和 `RUSTSEC-2026-0119`；升级到修复版依赖后必须移除
豁免，再评估是否恢复 DNS multiaddr。

## 构建与验证

需要 Rust/Cargo 1.97.1：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

常用 CLI：

```text
jlshell-linkctl authority-init
jlshell-linkctl identity-init
jlshell-linkctl identity-proof --identity <node.key> --payload <base64url-payload>
jlshell-linkctl ticket-issue
jlshell-relay
jlshell-agent --connect-policy auto|direct-only|relay-only
jlshell-connector --print-identity --identity <connector-identity.key>
jlshell-connector --connect-policy auto|direct-only|relay-only
```

`--print-identity` 只创建或读取 0600 Connector 身份文件，输出稳定的
`CONNECTOR_PEER_ID` 后退出，供 Program 插件在取票前完成设备身份绑定。正常隧道模式
额外输出 `CONNECTOR_EVENT` 生命周期行，已有参数和人类可读日志保持兼容。

标签发布包保留标准的 `jlshell-agent` 可执行文件，同时额外包含供 Program 插件部署使用的
平台文件名：`jlshell-agent-linux-x64`、`jlshell-agent-macos-arm64` 和
`jlshell-agent-windows-x64.exe`。

完整的回环直连和 Relay 演示步骤见 [docs/local-smoke-test.md](docs/local-smoke-test.md)。
Linux 双网络场景可直接以 root 运行
[scripts/linux-netns-smoke.sh](scripts/linux-netns-smoke.sh)。脚本创建隔离的 Agent 和
Connector network namespace，并强制经 Relay 完成二进制 Echo；GitHub-hosted runner
会尝试运行，但不保证具有创建 namespace 所需的能力。

## 发布边界

Cargo workspace 全部设置 `publish = false`，不会发布到 crates.io。GitHub Actions
只向私有仓库的 GitHub Release 上传 unsigned prototype 压缩包和 SHA-256。
