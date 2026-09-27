# Java Link 发布就绪状态

更新日期：2026-09-27。本文记录平台交付、迁移、综合验收、发布切换和 Rust 退役的
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
- 本轮增加的 Java 专用 Website 上传与 manifest 校验代码，在本机使用 SNAPSHOT 依赖完成
  `mvn -DskipTests compile`；Link `Release Java Agent` workflow 的 YAML 语法检查通过。
  这两项变更仍需各自仓库的 PR/MR 评审与 CI。

## 仍未放行

- Java Agent 稳定发布工作流尚未在已合并的 `main` 上运行；Website 公开 Java 包入口尚未
  经该工作流完成端到端上传和下载验收。
- 外部 manifest 与 SHA-256 用于比对构建输出和发现传输损坏，尚未实现客户端可验证的
  数字签名。Agent/插件安装不得把 SHA-256 单独描述为可信发布者签名。
- 插件尚未完成使用 Java Agent 压缩包的真实 SFTP 安装、远端校验、服务升级及失败回滚。
- Linux systemd、macOS LaunchAgent、Windows Service 的真实目标机生命周期、登录状态和
  权限边界需要在目标平台验收；不以 CI 代替生产设备验收。
- 公网双出口 A—C 直连、真实 SSH/SFTP、Web TCP 与数据库转发的候选版本验收仍待执行。
- 旧 Rust 桌面插件据用户确认未实际使用，因此不预设开发完整迁移工具或执行全量切换
  演练。仍需完成 Website 旧节点/凭据/Relay 汇总盘点，以及必要时的桌面本地项目配置
  只读盘点。可使用 Website 仓库的 `ops/link-validation/mig-01-read-only-inventory.sql`；
  文档只保留汇总计数，不导出行级数据。
- 四仓库兼容候选、发布说明、维护窗口与恢复步骤仍需在以上验收通过后确定。Rust 删除、
  libp2p v1 关闭和旧部署入口清理依赖正式 Java 版本成功发布及迁移恢复窗口结束。

## 当前发布入口

待合并的实现为 Link 仓库 `.github/workflows/release-java-agent.yml` 与 Website 仓库的
Java Runtime 上传接口。稳定发布工作流只允许从 `main` 手动运行，要求仓库配置
`JLSHELL_SITE_URL` 与已有的 `JLSHELL_ACTION_WEBHOOK_SECRET`；签名值本身不应写入此文档。
发布前应确认 Website 对应变更已部署，并检查公开
`/api/v1/link/java-agent/latest` 清单中的版本、源码 revision、平台资产名和摘要。

## MIG-01 判定规则

若汇总盘点显示没有未撤销的旧 Agent、启用目标、有效 Relay、未过期票据/授权，且本地
桌面项目未配置待保留的旧 Link 绑定，则将用户级迁移工具和切换演练标为“不适用”，以
脱敏汇总结果关闭 MIG-01。若存在仍需保留的旧节点或授权，只为这些对象制定最小迁移与
恢复流程。任何行级快照只能作为单独的加密、受访问控制备份保存在仓库之外。
