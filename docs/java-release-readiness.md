# Java Link 发布就绪状态

更新日期：2026-10-10。本文记录平台交付、迁移、综合验收、发布切换和 Rust 退役的
放行状态。只记录版本、提交、汇总结果和公开工作流链接；不记录账号、节点标识、IP、
SSH 信息、凭据、票据或原始生产日志。

## 最新核对（2026-10-10）

Link #62、插件 #43 和 Website !62 均已确认合入 develop。本轮用户明确授权隔离短期测试 JWT 经本地中转到验收 A；A/B测试JWT及中转文件均已删除；测试数据库已停止并撤销本轮新增规则。最新真实验收如下，历史结果不替代本轮结果。

- 构建检出源码 `fed45800d61b78b6ae1fdc41dd04e0f95a290e27`：真实双出口 HTTP RELAY_ONLY/AUTO 均完成 262144 字节摘要校验；DIRECT_ONLY 在约 1134 ms 后返回 `direct.ice_selected_unknown`，已定位到 ICE 选中动态候选后无法绑定初始候选 ID。
- 同一 A/C Java 候选完成真正 PostgreSQL 启动协议及 `SELECT 1`（隔离空库只信任C精确地址，未覆盖密码认证），RELAY_ONLY 建连 7435 ms。持续连接再测：13 次查询、间隔 15 秒，总耗时 189307 ms，数据正确，关闭后打开/等待隧道均为 0。这是 180 秒持续业务组件验收，不代表长期稳定性或桌面宿主完整验收。
- A/C 在持续业务运行时各采集到一个 Java 进程，指定组件子树中的已知 Rust Link 进程计数均为 0；此证据不包含桌面宿主及正式三平台启动流程。
- PostgreSQL 单次与持续连接脱敏证据 SHA-256 分别为 `964fdddac57607f1a7c9309e3c0f0a975dc9a33c7e5ffb6d84b0c7ac28609702`、`7f513f9f8a2c61afb1044f89f4502f587f7c73a9e88bd884bd2118a96a0a95f9`。地址和身份只保留在私有验收目录。
- 旧版本握手预算耗尽时关闭事件先于限额错误返回，真实100次尝试出现8个通用关闭错误。修复 `d531f177a6b186ecaba2eca1ff585d04ae33afe4` 延迟关闭至限额错误已可被外层观察；Java21全模块102项测试通过。真实复验100次同时发起：8条连接及262144字节摘要全部通过，92条明确限额拒绝，其他错误0，最大实测打开8条，结束打开/等待均0（19023 ms）。这不是100条成功并发流。
- 动态 peer-reflexive 协商修复涉及 ICE_END 后候选策略，自动审批拒绝该变更；草稿已移出工作树，等待具体边界授权，不计作已实施。
- NAS 只读核对：运行的网站后端 JAR 仍为 2026-09-26 的旧部署，两镜像缺少源码 revision 标签，旧 Relay 容器仍在运行。该结果不能证明本次 Jenkins 后端/实际镜像门禁通过；未修改或停止生产服务。

- 新修复候选 SSH/SFTP 三轮均通过（6个真实业务用例），专用 SSH 身份和严格主机指纹校验，SFTP 每次262144字节上传/下载/摘要/删除，结束打开/等待隧道0。新候选三轮慢消费者（每1024字节暂停25 ms）HTTP均完成262144字节摘要校验，结束隧道0。压力及三轮业务证据摘要见 [脱敏记录](chapter10-real-acceptance-2026-10-10.json)。

- 本轮本地候选JAR清单仍标记 `development`；报告源码SHA记录实际构建检出，但报告配置中的SHA不构成签名制品来源证明。A薄客户端及B仍混用前序组件修订。这些结果不能满足同一Git tree正式制品放行门槛，正式CI/发布须填写 `jlshell.build.revision` 并核验清单。

- Link #59/#60、插件 #42、Website !59/!60、宿主 #87 已合入 develop；尚未完成 main 来源正式发行。
- Linux 和 macOS 真实机器的候选 Java 21 启动、身份初始化、状态查询及文件/目录私有权限检查通过；未注册节点或安装服务，不表示服务生命周期完成。
- 隔离 B 已在保留原身份和受限备份的前提下续期过期证书，只重建隔离后端，严格 HTTPS 检查返回 200。
- 本机 A 与 C 出口相同；备用真实公网 A 与 C 的不同公网出口已实测确认。真实 HTTP 的 RELAY_ONLY/AUTO（实际 RELAY）已传输 262144 字节且 SHA-256 一致，打开/等待隧道均回收为 0；DIRECT_ONLY 仍未通过，八类业务矩阵未完成。原始映射、候选与身份仅保留在私有验收目录。
- 新增正式 Agent 发布前的强制验收记录及相同 Git tree 检查；门禁脚本的六项模拟边界测试通过。这些模拟数据不作为真实验收证据。当前未配置正式放行记录。
- Windows 连接信息、Website Jenkins 结果仍待提供；QA-01、REL-01 和 RETIRE-01 未完成。详细操作见 [执行顺序](chapter10-execution.md)。

## 历史核对（2026-10-07）

本节和“仍未放行”为当前状态，下方带日期的段落保留为历史快照。

- Link #57/#58、插件 #41、Website !58 已合入。内部 Maven 提交版本实际发布成功，见 [run 37560051557](https://github.com/Voghost/JLShellLink/actions/runs/37560051557)。
- 本轮 [Link #59](https://github.com/Voghost/JLShellLink/pull/59) 的 [CI run 37563185707](https://github.com/Voghost/JLShellLink/actions/runs/37563185707) 十项检查全部通过；[插件 #42](https://github.com/Voghost/JLShellLinkPlugin/pull/42) 的 [CI run 37562472239](https://github.com/Voghost/JLShellLinkPlugin/actions/runs/37562472239) 三平台通过。许可、漏洞、秘密和实际平台包来源/摘要/运行时门禁已执行。Website !59 的实际后端和镜像仍待 Jenkins。
- 同一 PR 合并提交 `b32bc62f7b6130de97cb5dbfb0850f2a81d53b0e` 的三平台包均为 Java 21.0.12.1，包内 JAR 来源与清单一致。外部归档摘要已复核，三个发布清单已签名，使用插件内置独立公钥全部验签通过。仅作隔离候选，尚未正式发布或切换生产。
- 公钥已加入 Website 环境配置，插件默认内置官方公钥并允许显式私有部署配置；指纹见 [执行顺序](chapter10-execution.md)。已删除本机临时私钥副本，保留 GitHub Secret 和隔离环境的受限备份。
- 兼容宿主 0.1.67 的说明在 [宿主 #87](https://github.com/Voghost/JLShell/pull/87)；插件最低宿主已修正。已发布 0.1.66 不具备本次必需的 v2 路由能力。
- 三平台真实生命周期、双出口业务、压力与恢复验收均未放行。Windows 机器已由用户确认存在，具体连接入口尚待提供。验收工具只负责执行/核对真实证据，不构成通过结论。

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
- 客户端可验证的 Ed25519 签名已实现，三个 CI 候选已独立验签；仍需 main 来源的正式签名发行及真实下载/安装验收。SHA-256 本身不等于发布者签名。
- 插件尚未完成使用 Java Agent 压缩包的真实 SFTP 安装、远端校验、服务升级及失败回滚。
- 离线安装和门禁代码、内部实际发布已完成；真实离线目标机验收及 Website Jenkins 的后端/实际镜像结果仍需补齐。四仓库交付证据尚未全部收齐。
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


DIST-02 另补内部 Maven 发布模式：`Publish Java libraries` 的 `internal` 只接受 develop，
版本自动为 `0.0.0-internal.g<完整源码 SHA>`，不得手填稳定版本；`stable` 仍仅接受 main。
内部产物仍执行完整 verify、JAR 来源/SBOM 校验再 deploy，避免复用浮动 SNAPSHOT。
工作流代码已实现，实际内部发布尚未执行；不能记作已存在的下游依赖。

## 真实组件联测修复（2026-10-09）

[Link #61](https://github.com/Voghost/JLShellLink/pull/61) 和
[Website !61](https://gitlab.ooml.net/root/jlshellwebsite/-/merge_requests/61) 已合入 develop；Link #61 的最终
[CI run 38011417571](https://github.com/Voghost/JLShellLink/actions/runs/38011417571) 十项检查全部通过。
真实鉴权发现可选诊断接口的旧版本兼容问题，随后发现 A/C 异步 ICE 采集时早到信令丢失、
Relay 激活响应 UUID 对象与 JSON 字符串误比较。修复保持核心鉴权失败关闭，缓存只接受已授权
会话/代次并限制容量、失效和回收；错误汇总只输出固定码。

Java 21 全模块 100 项测试通过；Website Java 21 全部
96 项测试通过，配套 Link 使用本地 SNAPSHOT。本轮 B/C/A 使用明确记录的不同候选提交，
仅作组件联测，不能配置正式发布放行记录。原生产未切换，隔离 B 更新前保存了数据库及 JAR 备份。

已实测 HTTP 中继及 AUTO 中继传输完整性。直连、SSH/SFTP/PostgreSQL、真实桌面宿主、
Windows 生命周期、慢消费者/丢包/长连接和正式升级恢复仍须完成，不能把本轮结果提升为 QA-01 完成。

### 已完成的隔离业务及负载测量

- 客户端 `13786f318d378209f2be6a1e46625e5f19a521a0`，Agent 网络修复候选
  `730cd363bdebb090b1ffa3f88238e4a13c25c1a6`；隔离 Website 为配套能力声明候选。
  这些不同提交仅作组件联测，不构成正式发行清单。
- HTTP RELAY_ONLY 与 AUTO 实际均走 RELAY，各传输 262144 字节且摘要一致。
- SSH RELAY_ONLY 完成专用测试密钥认证和实际命令；SFTP RELAY_ONLY 完成 262144 字节上传、
  下载、SHA-256 核对和删除测试文件。系统 SSH 服务、用户原密钥及生产节点未修改。
- 慢消费者每读取 1024 字节暂停 25 ms，HTTP 262144 字节摘要一致；本轮约 14.7 秒完成。
- 同时发起 100 次 RELAY_ONLY 打开尝试，保持产品 16 隧道及 8 握手上限：连接 8、
  数据校验通过 8、隧道限额拒绝 84、其他建连失败 8；观测打开峰值 8，约 26.6 秒。
  这不是 100 条成功并发流，也不是全部无错误通过；另外 8 条失败仍需分类复验。
- 以上各轮结束后打开及等待隧道均为 0。真实 DIRECT_ONLY 仍超时/未选出可达候选对，
  没有最终候选对通过证据；原始候选与映射只保存于受限目录。
- 最终 Java 21 `mvn verify` 全部 100 项测试通过，
  [最新三平台 CI](https://github.com/Voghost/JLShellLink/actions/runs/37936567671) 全部通过。

数据库、直连业务矩阵、真实桌面宿主、丢包/长连接、三平台登录/重启/升级恢复与正式发布仍未通过。
C 的数据库环境在下方 2026-10-10 补充记录中更新；业务路径验收仍未完成。

## 后续核对（2026-10-10）

- 可选控制能力、早到信令和 Relay 激活校验修复的三平台 CI 已通过；新增 TLS 容量专用异常及
  客户端 `transport.handshake_limit` / QUOTA 分类，保持不可跨路径重试，Java 21 完整 101 项测试通过。
- 双向 UDP 独立诊断只发送固定小包：A/C 各发送 200，均接收 0，未发现来源端点变化。
  A STUN 首次单包曾超时，有限重试后取得映射；不是缺少 STUN 映射，也尚不能归因到具体某条防火墙规则。
  端点证据 SHA-256 分别为 `7f2d15d1926fecc96566922bea267b725c389f98cd4b72f47ed22cb1581c1c3f`
  和 `1395e272261ee5c281adcb6a421eab0c57d7727068d5b50eb002a5ca1b5fdf9b`。
- 当前不同出口的直连网络条件仍未放行；已请求确认 UDP 出站/回包策略或替换验收出口。
  未改生产防火墙，未把中继或同出口测试写作直连通过。
- Windows 目标机连接方式、Website Jenkins 后端/实际镜像结果、同一正式候选的桌面/生命周期、
  数据库、直连业务、丢包/长连接及恢复演练仍未完成；发布和 Rust 退役继续受门禁约束。

- 容量分类修复后的最终压力复验尚未执行完成：旧隔离登录票据返回 401；重新登录成功后，
  自动审批拒绝将隔离 JWT 经本地中转到验收 A，具体凭据传递授权待确认。此前的压力记录保持原值，
  不把新分类代码的测试通过写成真实负载复验通过。

## 独立服务与数据库准备补充（2026-10-10）

- C 的工作目录内下载并解包官方 Arch PostgreSQL 18.6 和配套依赖，逐包核对本机官方包数据库的 SHA-256；没有安装系统包或修改系统服务。独立数据库已启动，本地 `SELECT 1` 通过，目录和密码文件为 0700/0600。当前仅本地监听；尚未开放为 Link 业务目标，不能计入 A—B—C 数据库访问通过。
- 用户服务脚本新增显式私有安装根目录和独立实例名，默认目录/名称保持兼容；升级及卸载使用相同布局，Linux 显式指定配置文件。安装根目录、名称、符号链接等 10 项离线边界测试和默认/独立布局的 4 项升级恢复测试通过。
- 真实 C 使用专用 systemd-user 实例完成安装启动（约 4318 ms）、3 次停止/启动、缺失签名元数据导致升级失败后的程序及服务恢复、卸载保留状态。结束后已恢复原隔离 Agent，未覆盖已有默认服务；新实例注册链接已移除。
- 最终脚本另使用两个摘要不同的实际候选 JAR 复验：失败后旧 JAR 恢复、服务仍可启动；实例绑定有效，节点身份逐字节摘要保持一致，原隔离 Agent 恢复，独立服务注册清除。macOS 本地 Java 21 包已构建并通过包内检查，但不是正式签名发行或真实 LaunchAgent 验收。
- 该演练使用已有候选 JAR/runtime 和本轮服务脚本，升级失败为隔离故障注入；它证明组件恢复流程，不是同一个 main 来源签名正式包的 DIST-01 全验收。用户登录边界、整机重启、Windows 实机及真实 macOS 生命周期仍待实测。
- Java 21 完整 `mvn verify` 101 项测试通过。Website 的客户端准备脚本改为读取权限受限的精确目标输入，移除实际内网地址，不跟随认证重定向；10 项离线测试通过。
- 正式直连缺陷、Windows 连接及 Jenkins 结果仍是后续验收前置条件；本轮 JWT 传递已明确授权并执行。QA-01、REL-01、RETIRE-01 保持未完成。

## 双出口复测与独立制品（2026-10-10）

- UDP 第一轮使用新运行标识和新 STUN 映射，保持同一 socket，拒绝读取旧轮端点文件。A 发送 246、应用收到 0；网卡记录本轮发出 245、收到 0。C 发送 244、收到 238，238 个来源端点均不同于 A 的 STUN 端点。两端分别收到 13/14 次 STUN 响应，同一目标上的 STUN 映射各稳定为一个。
- 第二轮允许诊断程序按本轮固定测试包的实际来源端点回发：A/C 各发送 231，分别收到 199/210；A 网卡收到同轮测试包 199。C 观测到 A 的 IP 与 STUN 一致，端口不同，更新回程端点一次。该结果证明此轮网络存在可双向交换诊断包的路径；不能把旧“双方均 0 包”的诊断作为当前网络结论。
- 诊断没有 Website 授权、ICE 校验、KCP、mTLS 或真实业务，**不能算作产品 DIRECT_ONLY 通过**。不同结束/开始时刻的计数也不作为稳定丢包率。原始端点仅存 0600 私有文件；C 两轮脱敏汇总摘要分别为 `75206af4eb2c8f842896d840a3a8bcc3ba21ba4ae7226ca65b9971d29be36310`、`049b34f9ed1f3c239f30a462ea75bad6eaf6b5fb615ffdda454fad4cfbdba694`。
- 源码复核发现 `Ice4jDirectSession.pollSelection()` 只按已交换候选的精确地址/类型查找 ID；动态 peer-reflexive 候选不在该索引中会被拒绝。该限制需要在真实授权直连联测中定位和修复；尚未证明它是此前实际超时的唯一原因。不通过跳过候选绑定或内层鉴权来“修复”直连。
- C 的用户 linger 配置只读结果为已启用；没有修改启动策略。当前隔离 Agent 进程树为一个 Java 进程、已知旧 Link 进程为 0；状态目录 0700，检查到的不安全状态文件为 0。RSS 141280 KiB、峰值 142688 KiB，宿主逻辑 CPU 数 20；这是当前空闲组件测量，不是最低硬件要求或负载保证。隔离 B 后端进程树同样为一个 Java、已知旧 Link 进程为 0。A 尚未完成本轮业务启动，因此不放行完整 A/B/C 无 sidecar 项。
- 最新 Link develop 的固定内部版本 `0.0.0-internal.ga1dc176438770398856f634885ef2b5fb071c5eb` 已由 [run 38049443725](https://github.com/Voghost/JLShellLink/actions/runs/38049443725) 实际发布成功，包含 #61 的网络/授权修复。插件 [PR #43](https://github.com/Voghost/JLShellLinkPlugin/pull/43) 新增全新 Maven 仓库的固定内部版本构建及所下载库的来源复核，常规 POM 仍固定 0.1.3。[CI run 38049951510](https://github.com/Voghost/JLShellLinkPlugin/actions/runs/38049951510) 的独立集成和三平台共四项全部通过；下载并复核了三个库的来源汇总及安全报告，来源报告摘要为 `487d69f3913645dea4bf9c00a96a71b2ebddf8ea3507aa11db15a866f77c6c70`，安全汇总 `passed=true`。这不替代 Jenkins 或真实业务验收。
- Rust 清理范围及仍由 v2 使用的共享授权/凭据/审计服务已只读盘点，见 [退役代码盘点](rust-retirement-inventory.md)。没有删除源码或停用服务，退役门禁继续生效。
- Windows 连接、Jenkins 后端及镜像证据和具体票据传递授权仍未收到；真实 direct/relay 全业务矩阵、压力/长连接、三平台正式包、正式切换及 Rust 退役继续保持未完成。
