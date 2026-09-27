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
- [JLShellLinkPlugin PR #37](https://github.com/Voghost/JLShellLinkPlugin/pull/37)
  已合并，Linux、macOS、Windows CI 均通过。
- MIG-01 于 2026-09-27 完成 Website 数据库只读汇总盘点：旧版 Agent、启用目标、活动
  Relay Grant、Grant 用量记录、未过期票据和待处理挑战均为 0；旧版 Relay 中有 1 个官方
  注册仍启用且最近在线，未发现自定义 Relay 注册。只保留这些汇总数，不保存任何节点、
  网络或账号明细。根据用户确认旧桌面插件未实际使用，Agent/项目迁移工具与切换演练不适用；
  仍在线的旧 Relay 归 RETIRE-01，必须在新版本发布及明确维护安排后处理，当前未停用。
- 本轮增加的 Java 专用 Website 上传与 manifest 校验代码，在本机使用 SNAPSHOT 依赖完成
  `mvn -DskipTests compile`；Link `Release Java Agent` workflow 的 YAML 语法检查通过。
  对应 [Link PR #53](https://github.com/Voghost/JLShellLink/pull/53) 与
  [Website MR !54](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/54)
  已创建，等待各自 CI 与手动合并。

## 仍未放行

- Java Agent 稳定发布工作流尚未在已合并的 `main` 上运行；Website 公开 Java 包入口尚未
  经该工作流完成端到端上传和下载验收。
- 外部 manifest 与 SHA-256 用于比对构建输出和发现传输损坏，尚未实现客户端可验证的
  数字签名。Agent/插件安装不得把 SHA-256 单独描述为可信发布者签名。
- 插件尚未完成使用 Java Agent 压缩包的真实 SFTP 安装、远端校验、服务升级及失败回滚。
- Linux systemd、macOS LaunchAgent、Windows Service 的真实目标机生命周期、登录状态和
  权限边界需要在目标平台验收；不以 CI 代替生产设备验收。
- 公网双出口 A—C 直连、真实 SSH/SFTP、Web TCP 与数据库转发的候选版本验收仍待执行。
- 旧 Rust 桌面插件据用户确认未实际使用，且 Website 只读盘点没有旧 Agent、目标、授权
  或票据，因此不开发用户迁移工具，也不执行没有对象可切换的 Agent 演练。旧 Relay 仍有
  1 个官方注册启用且最近在线；在退役门槛满足前必须保留运行。文档只保留脱敏汇总计数，
  不导出行级数据；本地项目文件未扫描。
- 四仓库兼容候选、发布说明、维护窗口与恢复步骤仍需在以上验收通过后确定。Rust 删除、
  libp2p v1 关闭和旧部署入口清理依赖正式 Java 版本成功发布及迁移恢复窗口结束。

## 当前发布入口

Link PR #53 与 Website MR !54 分别实现 Link 仓库
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
