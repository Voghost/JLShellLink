# JLShell Link

JLShell Link 是 JLShell 的私有商业网络组件原型，预定仓库为
`Voghost/JLShellLink`。它通过 rust-libp2p 在本机 Connector 与远端 Agent
之间建立加密 TCP 隧道，优先直连，并可通过 Circuit Relay v2 回退。

> 当前仍是 unsigned prototype，不可直接用于生产环境。网站控制平面已经定义账号
> 权限、节点持钥注册、短期凭据、Authority 轮换和 Relay Grant 配额接口。Rust
> Agent/Relay 已能通过 HTTPS 主动心跳，Agent 会在线刷新 Authority；Relay Grant
> 对 Circuit Relay 数据面的强制执行、二进制签名和生产 Relay 运维仍未完成。

## 一键安装 Agent

Website 与 OSS 发布链路配置完成后，Linux x64 和 macOS ARM64 服务器可执行：

```bash
curl -fsSL https://jlshell.oomn.net/api/v1/link/agent/install.sh | sh
```

脚本会交互式隐藏读取 Website 生成的一次性注册密钥，校验 OSS Runtime 的 SHA-256，
并把程序、身份和节点凭据安装到 `~/.jlshell-link`。Linux 使用 systemd 用户服务，
macOS 使用 LaunchAgent；注册密钥被 Agent 消费后会立即删除。生产控制平面签发的票据
已经绑定精确目标 IP 和端口，因此控制平面模式可以不传 `--allow-target`；需要额外收紧
单台服务器权限时仍可显式传入一个或多个本地白名单。

## 组件

- `jlshell-agent`：运行在远端服务器，只访问显式授权的精确 IP:端口。
- `jlshell-connector`：运行在 JLShell 所在机器，只监听回环地址。
- `jlshell-relay`：Circuit Relay v2 中继，默认只允许回环监听。
- `jlshell-linkctl`：生成开发 Authority、节点身份和五分钟单流票据。
- `link-protocol`：版本化 Protobuf 控制帧和 `/jlshell/link/tcp/1.0.0`。
- `link-crypto`：Ed25519 票据签发、验证与 nonce 防重放。
- `link-transport`：封装 QUIC、TCP/Noise/Yamux、AutoNAT、DCUtR 和 alpha
  `libp2p-stream`，不向业务接口泄漏其类型。
- `link-control-plane`：关闭重定向的 Rustls HTTPS 客户端，负责节点心跳和 Authority
  刷新；明文 HTTP 只允许显式回环开发地址。

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
jlshell-agent --print-identity --identity <agent-identity.key>
jlshell-agent --connect-policy auto|direct-only|relay-only \
  --control-plane-url <https-url> --credential-file <0600-token-file> \
  --advertise /ip4/203.0.113.10/tcp/7001
jlshell-connector --print-identity --identity <connector-identity.key>
jlshell-connector --identity-proof <base64url-payload> --identity <connector-identity.key>
jlshell-connector --connect-policy auto|direct-only|relay-only
```

使用受控 Relay 时，Connector 额外传入 `--relay-grant <credential-file>`。Connector
会先通过 `/jlshell/link/relay-auth/1.0.0` 加密流完成一次性预授权，再发起 Circuit；
Grant 不应直接出现在命令行或日志中。公网 Relay 必须同时配置控制平面 URL 和 Relay
节点凭据，未配置控制平面的模式只用于回环开发测试。

配置控制平面的 Agent 会在申请 Relay reservation 前自动使用节点凭据完成加密
预授权，并每两分钟刷新五分钟租约。Relay 会将 Website 返回的注册 PeerId 与 Noise
连接的真实源 PeerId 精确匹配；凭据撤销、冒用或控制平面持续不可用时拒绝续约。

Relay server 使用仓库内固定的 `vendor/libp2p-relay` 安全补丁，在接受 Circuit 前核对
Connector/Agent 绑定并记录精确双向字节数。该目录保留上游 MIT 许可证，CI 会独立运行
其测试。

`--print-identity` 只创建或读取 0600 Connector 身份文件，输出稳定的
`CONNECTOR_PEER_ID` 和 `CONNECTOR_PUBLIC_KEY` 后退出，供 Program 插件在取票前完成
设备身份绑定；`--identity-proof` 使用同一私钥签名网站 challenge。Agent 和 Relay
提供等价的持钥输出。正常隧道模式
额外输出 `CONNECTOR_EVENT` 生命周期行，已有参数和人类可读日志保持兼容。

Agent 心跳会把经过严格校验的 `--advertise` 和实际监听 IP multiaddr 上报给网站，
供插件自动填充直连地址；未指定地址、组播、DNS 和 Circuit 地址不会上报。Windows
构建包含供 SCM 调用的内部 service-host 模式，普通用户不应手工使用该参数。

标签发布包保留标准的 `jlshell-agent` 可执行文件，同时额外包含供 Program 插件部署使用的
平台文件名：`jlshell-agent-linux-x64`、`jlshell-agent-macos-arm64` 和
`jlshell-agent-windows-x64.exe`。

Release 还会生成 `jlshell-link-plugin-runtime-<version>.tar.gz`。它同时包含三平台
Connector 和 Agent，以及逐文件 `size + SHA-256` 的 `manifest.json`。Program 插件构建
只消费这个整体运行时包，并在解包到用户目录前后再次验证清单；普通用户无需配置本地
可执行文件或 Agent 发布目录。该原型发布物目前仍未进行平台代码签名。

完整的回环直连和 Relay 演示步骤见 [docs/local-smoke-test.md](docs/local-smoke-test.md)。
Linux 双网络场景可直接以 root 运行
[scripts/linux-netns-smoke.sh](scripts/linux-netns-smoke.sh)。脚本创建隔离的 Agent 和
Connector network namespace，并强制经 Relay 完成二进制 Echo；GitHub-hosted runner
会尝试运行，但不保证具有创建 namespace 所需的能力。

## 发布边界

Cargo workspace 全部设置 `publish = false`，不会发布到 crates.io。GitHub Actions
只向私有仓库的 GitHub Release 上传 unsigned prototype 压缩包和 SHA-256。
