# 第 10 章剩余验收与操作顺序

本文件是可执行检查入口和操作边界，不是通过证据。

## 已完成的交付准备

- 提交绑定的内部 Maven 发布已实际运行成功；稳定制品仍要求 main。
- Java 依赖/源码秘密/许可门禁和三平台包完整性/运行时 CPE 检查已接入 CI。
- 独立 Ed25519 发行私钥由 GitHub Secret 管理；受限备份在独立验收环境，绝不进源码或普通日志。
- 公钥随插件资源独立交付，Website 从 `JLSHELL_AGENT_PUBLISHER_PUBLIC_KEYS` 配置加载。公钥指纹为 `b09fdad09dd00e19e31080d7c21e8599218596d5234ad0f471399cdad44b2176`。
- 私钥不会被公钥验证器、TLS 回源证书或下载清单替代。轮换须独立更新两端信任锚，不从清单自动添加信任。

## 本轮候选的实际核对（2026-10-07）

- [CI run 37563185707](https://github.com/Voghost/JLShellLink/actions/runs/37563185707) 十项检查全部通过；三平台归档来自 PR 合并提交 `b32bc62f7b6130de97cb5dbfb0850f2a81d53b0e`，不是正式 main 发行。
- 下载后的三个 ZIP 已逐文件复核，并核对包内 Agent JAR 来源和外部 manifest 的共同元数据；外部清单中的 ZIP/TAR 大小及 SHA-256 均已复核。
- 三个外部 manifest 均已使用专用 Ed25519 发布密钥签名，并通过插件随包公钥的独立 OpenSSL 验签。签名后删除本机临时私钥，保留 GitHub Secret 和隔离环境受限备份。
- macOS 实机已使用候选内置 Java 21.0.12.1 启动运行时及 Agent `help`。这只验证可启动，不代表服务注册、登录边界、升级恢复或业务验收通过；未安装服务或改动生产。
- 三平台真实生命周期和产品业务验收尚未完成；Windows 连接信息与 Website Jenkins 验证仍待提供。

## DIST-01 / QA-01

1. 从同一个通过 CI 的提交取 Linux/macOS/Windows 包，检查包内 JAR 来源 SHA 与外部 manifest 一致。
2. 以独立信任锚验签后在专用工作目录安装；每个平台记录注册、权限、启停、登录条件、升级恢复与卸载的实际结果。
3. 不覆盖已有服务或用户配置；若安装脚本固定服务名会与已有 Agent 冲突，先在独立测试账号/设备执行，不把 HOME 指向临时目录来混用系统服务。
4. Windows 必须有实际连接入口；无用户登录启动和重启不能用 PowerShell 语法检查代替。macOS 的 LaunchAgent 与 Linux systemd-user 的登录/linger 条件分别记录，不承诺统一无人值守开机。
5. A/C 使用不同公网出口。STUN 映射、最终候选对和业务路径的原始证据只保留在受限验收目录；公开记录仅保留来源 SHA、结果、耗时和证据摘要，不包含账号、目标 IP、设备 ID、票据或密钥。
6. 实际桌面宿主须包含 SDK 1.5.0 的路由能力；已发布 0.1.66 缺少该提交，0.1.67 是准备中的兼容版本，尚未把未发行安装包当作可用稳定制品。

`verify-business-tunnels.py` 使用实际产品生成的 `LocalForward` 租约证据，核对 DIRECT/RELAY 后执行真实 SSH 认证、SFTP 写读摘要、HTTP 请求及 PostgreSQL `SELECT 1`。它拒绝相同公网出口、回环 STUN 映射、缺少业务场景和路径不匹配。该脚本不创建隧道，不把配置中的路径字符串当作网络探测结果：输入须取自实际插件租约及 STUN 探测，不得手工伪造。

私有配置中提供 `linkSourceRevision`、`networkEvidenceFile` 和八个 `cases`（DIRECT/RELAY × ssh/sftp/http/postgres）；每个 case 提供 `path`、`protocol`、`leaseEvidenceFile`，协议参数如下：

| 协议 | 私有配置参数 |
|---|---|
| SSH | username、knownHostsFile、hostKeyAlias |
| SFTP | 同 SSH，另 remoteTestDirectory；目录预先限定在隔离工作目录 |
| HTTP | hostHeader，可选 requestPath；禁止重定向绕过隧道 |
| PostgreSQL | username、database、passwordFile，可选 sslMode |

`networkEvidenceFile` 含实际 `aStunMappingIp`/`cStunMappingIp`，租约证据含产品返回的 `localHost`/`localPort`/`path`。配置和证据为 0600 普通文件；只使用当前仍有效且各自独立的单次租约，不重用已关闭的回环端口。失败仍记录失败，不用直接 SSH 或 Echo 替代业务结果。

```sh
python3 scripts/qa/verify-business-tunnels.py --config /private/acceptance.json --output business-summary.json
```

慢消费者、丢包、100 并发尝试、长连接和反复启停必须另外实测。客户端默认最多 16 个打开隧道、上限 64；100 是试验点，不是承诺一个实例可以接受 100 条。统计成功、受限拒绝、其他失败与资源占用，不能提升限额或关闭授权来获得漂亮结果。

## REL-01

- 汇总三平台、业务、压力、签名及无 sidecar 证据，使用 `check-release-readiness.py --phase qa` 检查字段是否齐全。
- 四仓库候选使用已发行依赖；代码 PR/MR → develop 及 develop → main 都由用户通过链接手动合并。
- 宿主发布说明已准备为 0.1.67；Link 库/Agent 和插件下一版按正式已存在 tag 核对，不提前写入不可解析的新依赖版本。
- 先保存当前稳定 Website 镜像/配置、已安装 Java Agent 与宿主包的受限恢复快照。首发没有上一稳定 Java 平台包时明确记录，不虚构历史版本；实测 Website 镜像恢复与候选 Java 服务升级恢复，确认其适用范围。
- 合并并部署 Website v2/验签 → 兼容宿主 → main 来源签名 Agent → 插件 → 选定节点验收 → 开放正式入口。
- 正式发布前执行 `check-release-readiness.py --phase release`；维护时间和恢复窗口由用户安排，不因 PR 合入自动切换生产。

## RETIRE-01

正式验收与恢复窗口结束后执行 `check-release-readiness.py --phase retire`。它要求真实验收、来源已进 main、恢复演练，以及没有仍待处理的旧 Agent/活动 Relay/Grant/未过期票据。

通过后分独立 PR 清理：

- Link 的 Cargo、Rust apps/crates/vendor、旧打包安装脚本、Rust quality/native/musl/Relay 镜像 jobs 与旧部署入口；保留 Java jobs/平台包审计。
- 插件仅用于旧 Connector 的进程、解包、PeerId、临时票据协议类及对应测试；保留具有 Java 职责的会话安装与贡献类。
- Website v1 新连接、旧 libp2p/Relay 部署与 bootstrap 入口；保留历史审计和用量，未确认引用移除前不删历史字段。
- 更新四仓库 README/AGENTS 与架构链接到实际 Java 版本。

源码清理 PR 不等于旧服务已停用；运行态停用必须在同一验收窗口核对。当前这些条件未全部满足，不执行生产停服或删除恢复所需源码。
