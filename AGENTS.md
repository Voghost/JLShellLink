# JLShellLink 协作说明

始终使用简体中文沟通。

本目录是独立 Git 仓库，预定远程为私有 `Voghost/JLShellLink`。不要把本仓库的
提交与父级聚合目录、`JLShell`、`JLShellWebsite` 或 `JLShellLinkPlugin` 混合。

## 分支流程

- 日常开发和功能分支以 `develop` 为基线，提交先进入 `develop`。
- `main` 只接收 GitHub 上的 `develop -> main` Pull Request，不得直接推送开发提交。
- 发布标签只从 `main` 创建。

## 当前状态与后续方向

- 当前 `develop` 上仍是 Rust 2024 实现；它是待迁移的历史运行时代码，不代表新的开发目标。
- 后续产品运行时按 `../docs/jlshell-link-java-architecture.md` 全部改为 Java 21；实施顺序按 `../docs/jlshell-link-java-implementation-plan.md`。
- Java POC 阶段不删除 Rust 代码或现有制品；只有迁移和恢复演练完成后，才按计划退役活跃 Rust 实现。
- 以下 Rust 专项限制只约束现存 Rust 代码，除非同一安全边界也适用于 Java 实现。

## 现存 Rust 代码约束

- Rust 1.97.1、2024 edition，workspace 内所有 crate 禁止发布到 crates.io。
- 网络协议 ID 为 `/jlshell/link/tcp/1.0.0`；破坏性协议变更必须使用新版本 ID。
- `link-protocol` 的票据声明禁止 map 字段；Ed25519 只签名原始 `claimsBytes`。
- `libp2p-stream` 只能出现在 `link-transport` 和二进制内部，不成为公共业务 API。
- Connector 只能监听回环地址；Agent 目标必须是显式精确 IP:端口。
- Agent 只可向控制平面上报精确 IP TCP/QUIC multiaddr；Windows SCM 隐藏模式仅供
  插件生成的服务配置调用，不能暴露节点凭据。
- Relay 默认只能监听回环地址，公网监听必须显式确认且不得宣称生产可用。
- 当前只使用 IP multiaddr；在依赖安全公告修复前不得重新启用 libp2p `dns` feature。
- RustSec 对 `RUSTSEC-2026-0118`、`RUSTSEC-2026-0119` 的临时豁免必须与 CI 的实际
  构建图检查同时存在；若 Hickory 进入构建图，CI 必须立即失败。
- 不提交身份私钥、Authority 私钥、票据或运行日志中的敏感数据。
- Release 必须同时生成 `jlshell-link-plugin-runtime-<version>.tar.gz`，内含三平台
  Connector/Agent 和逐文件 SHA-256 清单；更改文件名或清单 schema 时必须同步修改
  JLShellLinkPlugin 的内置运行时加载器。

## 现存 Rust 验证

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

网络行为变更还应分别验证 `direct-only`、`relay-only` 和 `auto` 回退，并确认
二进制数据双向完整、半关闭正常、进程退出后监听端口释放。

## Java 实施约束

- Java 工程使用 Java 21 和 Maven；Link 模块按已批准的 Java 架构与实施计划建立。
- P0 网络验证通过前，不把 ICE、可靠 UDP、TLS 和 HTTP/2 组合标记为生产可用。
- 新增 Java 依赖需固定版本并记录许可证、来源、传递依赖与平台支持；不引入 JNI 或 Rust sidecar。
- 安全默认拒绝；认证或授权失败不能通过直连/中继回退绕过。
- 不提交私钥、票据、账号令牌、目标设备数据或未脱敏网络日志。
- Java 改动使用 `mvn verify`；若环境没有 JDK 21，需在报告中记录实际运行时并安排 JDK 21 CI 验证。
