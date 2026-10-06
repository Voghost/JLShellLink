# Java Link 发布就绪状态

更新日期：2026-10-06。本文记录平台交付、迁移、综合验收、发布切换和 Rust 退役的
放行状态。只记录版本、提交、汇总结果和公开工作流链接；不记录账号、节点标识、IP、
SSH 信息、凭据、票据或原始生产日志。

## 已有结果

- Java Agent 使用 Java 21 `jlink` runtime，可生成 Linux x64、macOS arm64、Windows x64
  的 `.tar.gz` 与 `.zip`；包内含 CLI、服务脚本和逐文件 SHA-256 manifest。
- [JLShellLink PR #52](https://github.com/Voghost/JLShellLink/pull/52) 按用户确认已合并到
  develop。对应多平台 CI 曾全部通过，包括打包 smoke check、macOS LaunchAgent 与
  Windows Service 生命周期任务。
- [JLShellWebsite MR !53](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/53)
  按用户确认已合并；Website 后端 Link Server 依赖固定到 0.1.3，Jenkins 改为执行
  `mvn verify`。本机用 Link workspace 安装的 `0.1.0-SNAPSHOT` 完成过后端 89 项测试；
  这不替代 Jenkins 对 0.1.3 已发布制品的验证。
- [JLShellLinkPlugin PR #37](https://github.com/Voghost/JLShellLinkPlugin/pull/37)
  已合并，Linux、macOS、Windows CI 均通过。
- MIG-01 于 2026-09-27 完成 Website 数据库只读汇总盘点：旧版 Agent、启用目标、活动
  Relay Grant、Grant 用量记录、未过期票据和待处理挑战均为 0；旧版 Relay 中有 1 个官方
  注册仍启用且最近在线，未发现自定义 Relay 注册。只保留这些汇总数，不保存任何节点、
  网络或账号明细。根据用户确认旧桌面插件未实际使用，Agent/项目迁移工具与切换演练不适用；
  仍在线的旧 Relay 归 RETIRE-01，必须在新版本发布及明确维护安排后处理，当前未停用。
- Java 专用 Website 上传/manifest 校验和 Java 21 Agent 发布 workflow 已通过
  [Link PR #53](https://github.com/Voghost/JLShellLink/pull/53) 与
  [Website MR !54](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/54)
  合入 develop。Link PR #53 的九项 GitHub CI 检查通过；Agent 注册与在线心跳现使用发行
  JAR 版本。Website 的三平台 manifest、共同源码 revision、sidecar 与归档摘要校验已接入，
  中文/英文安装说明已更新；前端生产构建曾通过。固定发布依赖仍需 Jenkins 验证。
- 随机 release ID 暂存的 Link 发布 workflow 已由
  [Link PR #54](https://github.com/Voghost/JLShellLink/pull/54) 合入 develop。对应 Website
  [MR !55](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/55) 提供暂存对象复核、
  不可变版本目录和单次 latest 指针替换；正式运行发布前须确认该服务端能力已部署并验收。
- 插件 [PR #38](https://github.com/Voghost/JLShellLinkPlugin/pull/38) 已合并，显示完整 Agent ID
  和一次性令牌；Linux、macOS、Windows CI 全部通过。本机插件编译使用 Link 0.1.0-SNAPSHOT
  覆盖本地解析，因为当前环境不能读取 GitHub Packages 的 0.1.3 制品。
- 2026-09-30 Website 后端 `mvn -Djlshell-link.version=0.1.0-SNAPSHOT verify` 完成，93 项
  测试通过；2026-10-02 最终缓存头变更后的定向测试 6 项通过。完整验证使用本地 Link SNAPSHOT，
  不替代 CI 对固定发布依赖的检查。

## 仍未放行

- Java Agent 稳定发布工作流尚未在 `main` 上运行；Website 公开 Java 包入口尚未经该工作流
  完成端到端上传和下载验收。
- 外部 manifest 与 SHA-256 用于比对构建输出和发现传输损坏，尚未实现客户端可验证的
  数字签名。Agent/插件安装不得把 SHA-256 单独描述为可信发布者签名。
- 插件尚未完成使用 Java Agent 压缩包的真实 SFTP 安装、远端校验、服务升级及失败回滚。
- 受签名清单约束的离线安装、提交唯一版本的内部制品流程、Java 依赖漏洞与许可门禁、
  发布秘密扫描和四仓库全新 CI 交付证据仍需补齐。
- Linux systemd、macOS LaunchAgent、Windows Service 的真实目标机生命周期、登录状态和
  权限边界需要在目标平台验收；不以 CI 代替生产设备验收。
- 公网双出口 A—C 直连、真实 SSH/SFTP、Web TCP 与数据库转发的候选版本验收仍待执行。
- 旧 Rust 桌面插件据用户确认未实际使用，且 Website 只读盘点没有旧 Agent、目标、授权
  或票据，因此不开发用户迁移工具，也不执行没有对象可切换的 Agent 演练。旧 Relay 仍有
  1 个官方注册启用且最近在线；在退役门槛满足前必须保留运行。文档只保留脱敏汇总计数，
  不导出行级数据；本地项目文件未扫描。
- 四仓库兼容候选、发布说明、维护窗口与恢复步骤仍需在以上验收通过后确定。Rust 删除、
  libp2p v1 关闭和旧部署入口清理依赖正式 Java 版本成功发布及迁移恢复窗口结束。

## 交付追溯更新（2026-10-06）

- Link [PR #54](https://github.com/Voghost/JLShellLink/pull/54) 将 Java Agent 发布改为随机暂存、
  版本目录校验和原子更新 latest；[PR #55](https://github.com/Voghost/JLShellLink/pull/55)
  为 Agent 归档记录固定运行时依赖；[PR #56](https://github.com/Voghost/JLShellLink/pull/56)
  为每个 Maven JAR 写入构建源码 SHA、部署 CycloneDX SBOM，并在发布前逐个核对；Agent 平台包
  也携带依赖 SBOM。最新 develop `3c1f0ae` 已包含 #54 与 #55；本次 #56 整合保留随机
  暂存发布、固定运行库版本和完整 SBOM。整合前 #56 的 `44b7f61` 九项 CI 检查全部通过；
  整合后的检查待 GitHub CI 完成。此前本机全模块 `mvn -B -ntp clean verify` 已通过，
  CycloneDX 为 9 个模块生成 JSON/XML 清单，Agent BOM 中有组件缺少许可声明，需要后续核实。
- 插件 [PR #39](https://github.com/Voghost/JLShellLinkPlugin/pull/39) 为发行 JAR 记录源码 revision、
  固定依赖版本、CycloneDX SBOM 与 checksum。显式设置 `skipNotDeployed=false` 修复未生成
  SBOM 的 CI 失败，并将 SBOM 纳入 Release 校验及 SHA256SUMS。提交 `39f13fa` 的三平台 CI
  全部通过；合并状态以该 PR 为准。
- Website [MR !55](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/55) 实现 Java Agent
  发布随机暂存和原子 latest 更新；[MR !56](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/56)
  归档 Jenkins 构建来源清单、前后端 SBOM 及其摘要并增加 OCI 来源标签；提交 `c678df4`
  已推送到 !56。前端构建、真实 npm SBOM 生成、清单脚本检查及 Groovy/shell 语法检查通过；
  高风险 npm 公告已在现有版本约束内修复，仍有 KaTeX/Mermaid 两项 low 公告。后端默认
  0.1.3 依赖解析返回 401，待 Jenkins 用既有只读凭据验证。此前跨仓库核对时 !55/!56 的
  分支提交尚未进入 develop；本次解决 Link 冲突不重新验收 Website 部署或 Jenkins 结果。
- 合入后仍需实际交付验收，当前未完成稳定发布验收。来源追溯不提供数字签名，也不替代客户端
  签名验证、漏洞/许可审查与秘密扫描、真实平台生命周期及公网产品验收。CycloneDX SBOM
  提供直接和传递依赖清单，但不等同于漏洞扫描或许可审批。

## 当前发布入口

Link PR #53 与 Website MR !54 已合入 develop，分别实现 Link 仓库
`.github/workflows/release-java-agent.yml` 和 Website Java Runtime 上传接口。稳定发布
工作流只允许从 `main` 手动运行，要求仓库配置
`JLSHELL_SITE_URL` 与已有的 `JLSHELL_ACTION_WEBHOOK_SECRET`；签名值本身不应写入此文档。
发布前应确认 Website 对应变更已部署，并检查公开
`/api/v1/link/java-agent/latest` 清单中的版本、源码 revision、平台资产名和摘要。

## MIG-01 判定规则

若盘点显示没有旧 Agent、目标、活动授权和有效票据，且用户确认旧桌面插件未实际使用，
则将 Agent/项目迁移工具与切换演练标为“不适用”，以脱敏汇总结果关闭 MIG-01。旧 Relay
即使仍启用，也单独按 RETIRE-01 的维护与退役门槛处理，不能为关闭 MIG-01 而提前停服。
若存在仍需保留的旧节点或授权，只为这些对象制定最小迁移与恢复流程。任何行级快照只能
作为单独的加密、受访问控制备份保存在仓库之外。


## 2026-10-06：签名发行与 Java SSH 安装候选

此前 Link #54/#55/#56、插件 #39、Website !55/!56 均已合入 develop。
本轮补独立 Ed25519 发布清单签名、Website 发布前验签、插件安装前验签及远端摘要复核；
新增 Java 专用 SSH/SFTP 安装、可选文件注册、语义版本防降级和服务失败恢复脚本。
Windows 包包含固定摘要的 WinSW，离线安装无需再次下载包装器。

本机 JDK 27 使用 `--release 21` 定向编译：Website 发布校验 7 项、插件包/部署边界 4 项通过；
签名脚本 2 项、隔离目录和模拟服务管理器下的升级恢复 2 项通过。
完整 Website/插件 Maven 仍无法读取本机私有 0.1.3 制品（401），不能用定向编译代替独立 CI。
GitHub Actions 的 Java 21 全量结果和 Website Jenkins 的结果另行记录。

本轮不执行正式 main 发布、生产升级或 Rust 退役。真实平台的权限/开机/升级恢复、
双出口业务访问和综合压力验收尚未完成；恢复脚本模拟不计入真实平台完成项。
配置格式和合入依赖见 `docs/agent-service.md` 的发布签名章节。
