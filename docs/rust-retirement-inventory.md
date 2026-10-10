# Rust 退役代码盘点

日期：2026-10-10。此文只盘点代码与构建引用，未删除源码、执行数据库清理或停用服务。RETIRE-01 仍依赖真实 QA、正式 Java 发布、恢复窗口结束及旧对象处理完成；不能以迁移不适用或本轮诊断收包代替这些条件。

## Link

| 范围 | 放行后的操作 | 必须保留 |
| --- | --- | --- |
| `Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml`、`apps/`、`crates/`、`vendor/libp2p-relay/` | 删除活跃 Rust workspace 与 vendored Relay | Git 历史、必要历史说明和审计；Java `pom.xml`、`link-*/` |
| `scripts/install-agent.sh`、`scripts/install-agent.ps1`、`scripts/create-plugin-runtime-bundle.py`、`scripts/linux-netns-smoke.sh` | 确認无 Java 引用后删除旧安装、bundle 和 Rust 网络 smoke 工具 | `scripts/java-agent/`、`scripts/package-java-agent.*`、签名工具、QA/安全扫描工具 |
| `.github/workflows/release.yml`、`docker-relay.yml` | 删除旧 Rust release/container 发布入口 | `publish-java.yml`、`package-java-agent.yml`、`release-java-agent.yml` |
| `.github/workflows/ci.yml` | 按 job 编辑，移除 Rust `quality`、`native-build`、`linux-musl`、`relay-image` | 保留 `java-poc` 与依赖它的 `platform-delivery`，以及 Java 平台包与安全门禁；不能删除整个 CI 文件 |
| `docker/Dockerfile.relay`、同名 dockerignore、`docker/relay-entrypoint.sh` | 旧运行态退役后清理 | 独立 Java 公网 STUN 和 Website 嵌入式 Java B 的部署资源 |

每个删除 PR 先从最新 develop 重新核对引用和准确路径；不能按目录名包含 `link` 或文件内容含 `Rust` 批量删除。旧 Relay 运行态停用和源码清理是两个检查点，先保存受限恢复快照，运行态核对通过后再移除部署入口。

## 插件

在 `link-program-plugin/src/main/java/com/jlshell/link/plugin/program/` 盘点到旧类：`ConnectorProcessManager`、`ConnectorConfiguration`、`BundledRuntimeManager`、`LinkAccountClient`、`PeerIdCodec`、`TunnelOpenRequest`，以及 `session/LinkSessionContribution`、`LinkSessionController`、`AgentDeploymentService`、`AgentServiceInstaller`。

这些旧类目前已从正式 fat JAR 排除，源码和部分历史测试仍保留。放行后逐类检查引用并删除对应旧测试与排除配置；不能通过扩大排除规则掩盖残留依赖。`JavaAgentDeploymentService`、Java 签名/安装资源和 `LinkSessionStatusContribution` 仍有当前产品职责，必须保留。宿主 SDK 的会话、账号受限请求和真实目标验钥契约继续回归。

## Website

旧入口包括 `LinkTicketController`、`LinkNodeController` 与 `docker-compose.prod.relay.yml`；应先停用 v1 新连接和旧 Relay bootstrap，再逐方法收缩旧协议逻辑。`PublicLinkRuntimeController`/`ActionLinkRuntimeController` 中同时存在 Java 安装包职责，按端点清理，不能整类删除。

以下服务已经由 v2 直接引用，**不能当作旧类删除**：

- `LinkAuthorizationService`：v2 节点、控制凭据、访问与 Relay 鉴权。
- `LinkCredentialService`：v2 节点凭据及持钥证明。
- `LinkPlanLimitService`：v2 Agent 和 Relay 配额。
- `LinkAuditService`：v2 访问、节点、设备与用量审计。

旧 `RelayGrant`/`RelayUsagePeriod` 等历史对象、审计和用量保持可查询。既有 Flyway migration 不删除、不改写；字段清理必须另加 migration，先证明已无引用且没有需保留的数据。不导出账号、节点或票据行级数据到 PR。

## 完成判据

1. `check-release-readiness.py --phase retire` 使用人工核对过的真实脱敏报告放行。
2. 四仓库功能 PR 各自合回 develop；main 合并由用户确认，正式制品从 main 产生。
3. 重新独立构建：Java Agent 三平台、插件固定依赖、Website 实际 Jenkins 镜像和兼容宿主。
4. 当前构建不调用 Cargo，正式 A/B/C 不启动 Rust，v1 不接收新连接；历史记录和用量保持可查。
5. 更新四仓库 README、AGENTS 与运维文档的实际实现/版本说明，并核查默认部署入口。
