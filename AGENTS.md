# JLShellLink 协作说明

始终使用简体中文沟通。

本目录是独立 Git 仓库，预定远程为私有 `Voghost/JLShellLink`。不要把本仓库的
提交与父级聚合目录、`JLShell`、`JLShellWebsite` 或 `JLShellLinkPlugin` 混合。

## 分支流程

- 日常开发和功能分支以 `develop` 为基线，提交先进入 `develop`。
- `main` 只接收 GitHub 上的 `develop -> main` Pull Request，不得直接推送开发提交。
- 发布标签只从 `main` 创建。

## 技术与边界

- Rust 1.97.1、2024 edition，workspace 内所有 crate 禁止发布到 crates.io。
- 网络协议 ID 为 `/jlshell/link/tcp/1.0.0`；破坏性协议变更必须使用新版本 ID。
- `link-protocol` 的票据声明禁止 map 字段；Ed25519 只签名原始 `claimsBytes`。
- `libp2p-stream` 只能出现在 `link-transport` 和二进制内部，不成为公共业务 API。
- Connector 只能监听回环地址；Agent 目标必须是显式精确 IP:端口。
- Relay 默认只能监听回环地址，公网监听必须显式确认且不得宣称生产可用。
- 不提交身份私钥、Authority 私钥、票据或运行日志中的敏感数据。

## 验证

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

网络行为变更还应分别验证 `direct-only`、`relay-only` 和 `auto` 回退，并确认
二进制数据双向完整、半关闭正常、进程退出后监听端口释放。
