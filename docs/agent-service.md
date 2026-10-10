# Java Agent 服务托管与安装包

Java Agent 发布包自带由 Java 21 `jlink` 生成的精简 runtime，使用者无需预装 JDK。
`scripts/package-java-agent.sh` 接收版本号和 shade 后的 Agent JAR，为当前平台生成
`.tar.gz` 与 `.zip`。包内包含 runtime、CLI 文档、Linux/macOS 服务管理脚本、Windows
Service 安装脚本、CycloneDX 格式的传递依赖清单 `dependencies.cyclonedx.json`、带源码
SHA、平台/架构/协议版本、核心运行库固定版本和逐文件 SHA-256 的 `manifest.json`，以及
`SHA256SUMS`。核心运行库版本列出 Netty、ice4j、KCP、Nimbus JOSE JWT 和 Bouncy Castle
的工程固定版本；完整传递依赖及可用许可信息由 SBOM 记录，有组件缺少许可声明时必须单独
核实。每个平台另输出包含归档大小与摘要的外部 `.manifest.json` 和 `.sha256` 文件。
SBOM 是依赖清单，不代表漏洞扫描、许可审批或数字签名。
生成时会运行包内 Java 检查版本、运行 Agent CLI help，并校验两种归档。
GitHub Actions 的 `Package Java Agent` 手动工作流在 Linux x64、macOS arm64、Windows x64
分别运行 Link 全量 `mvn verify` 并生成独立构建产物，供 develop 候选验收使用。稳定包由
`Release Java Agent` 工作流从 `main` 手动构建，上传到 Website 的 Java 专用 Runtime 入口；
需要配置仓库变量 `JLSHELL_SITE_URL` 和已有的 `JLSHELL_ACTION_WEBHOOK_SECRET` Secret。
Website 会核对三平台 manifest、源码 revision、checksum sidecar 和归档摘要后切换 latest。
SHA-256 只能发现文件损坏，尚未替代客户端可验证的数字签名；正式启用前仍须完成签名
和客户端验签。

## Linux 与 macOS

解压后用登录用户执行：

```sh
scripts/java-agent/install-user-service.sh install \
  ./link-agent.jar \
  wss://link.example:13575/link/v2/control \
  /secure/agent.p12 /secure/tls.password /secure/allowed-targets \
  https://website.example
```

脚本优先安装包自带的 Java 21 runtime，在 Linux 创建 systemd 用户服务，在 macOS 创建 LaunchAgent。旧的 JAR-only 包仍可用已安装的 Java 21。`uninstall` 只停止并
移除服务定义和配置，不会删除 Agent 注册身份、凭据、JAR 或日志。Java Agent 的 `stop`
命令负责写入专属停止标记并优雅退出。身份 PKCS12、密码文件和目标白名单需归运行用户
所有，POSIX 系统权限设为 `600`。可通过安装进程的 `JLSHELL_LINK_JAVA_TOOL_OPTIONS` 注入
非敏感 JVM 参数（例如私有 CA truststore 路径）；该值以用户独占权限保存在本机配置文件，
不要在其中放入凭据。也可设置 `JLSHELL_LINK_JAVA` 指定 Java 可执行文件路径；通常让脚本
使用当前用户 PATH 中的 Java 21 即可。

### 独立工作目录与服务实例

需要与已有默认 Agent 并存时，可显式指定安装根目录和实例名；未设置时保持原有目录与服务名。

```sh
mkdir -m 700 /private/validation/agent-instance
export JLSHELL_LINK_INSTALL_ROOT=/private/validation/agent-instance
export JLSHELL_LINK_SERVICE_INSTANCE=acceptance
scripts/java-agent/install-user-service.sh install ./link-agent.jar \
  wss://link.example/link/v2/control /secure/agent.p12 \
  /secure/tls.password /secure/allowed-targets https://website.example
```

根目录必须预先存在、归当前用户所有、权限为 `700`，使用可打印 ASCII 绝对路径，不含百分号、反斜杠或控制字符；空格允许。实例名为最多 32 位小写字母、数字和连字符，不能以连字符开头。同一根目录只允许一个实例名，卸载后仍保留实例标记和状态。程序、配置、状态、日志、升级锁和恢复备份均位于根目录内，不覆盖默认 Agent。

Linux 注册名为 `jlshell-link-agent-acceptance.service`，只在用户 systemd 目录创建指向工作目录的服务链接；macOS 注册名为 `com.jlshell.link.agent.acceptance`，服务定义位于用户 LaunchAgents 目录。系统服务管理器的注册文件是工作目录之外必要的例外，卸载时移除。Linux 服务显式传入所选配置文件，避免启动时误读默认 Agent 配置。

执行 `status`、`uninstall` 或 `upgrade-user-service.sh` 时须提供相同的两个环境变量；升级前仍必须由调用方核对发布签名及归档摘要。用户服务的登录/linger 条件不改变，脚本不会启用 linger、修改系统启动策略或防火墙。升级失败恢复程序与服务配置，不恢复旧节点凭据，以免撤销或凭据轮换被倒退。

## Windows Service

先用服务运行身份准备并注册 Agent 状态目录（其中含 `agent.properties`、
`agent.credential`、`node-key.ed25519`），再从管理员 PowerShell 执行：

```powershell
./scripts/java-agent/install-windows-service.ps1 install `
  -StateDirectory C:\secure\jlshell-agent-state `
  -LinkWssUri wss://link.example:13575/link/v2/control `
  -TlsIdentityP12 C:\secure\agent.p12 `
  -TlsPasswordFile C:\secure\tls.password `
  -AllowedTargetsFile C:\secure\allowed-targets `
  -TicketIssuer https://website.example
```

安装器会把密钥材料复制到 `ProgramData` 下的专属状态目录，ACL 仅允许
`SYSTEM`、管理员、当前安装管理员和 `NT SERVICE\\JLShellLinkAgent` 访问；服务停止时调用 Agent CLI 的
优雅停止命令。`status` 查询服务，`uninstall` 停止并删除服务和程序文件，状态目录与
凭据保留。再次安装时会沿用 `ProgramData` 中已有的完整 Agent 身份、TLS 材料与白名单；
仅在首次安装时从 `-StateDirectory` 导入，避免重装时覆盖受保护的身份凭据。

Windows Service 由 WinSW v2.12.0 包装。安装器从 WinSW 上游 release 下载 x64 文件，并
固定校验 SHA-256 `05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da`；
升级包装器前需要更新固定版本、摘要和对应 MIT 许可记录。[WinSW 官方说明](https://github.com/winsw/winsw)

## 包含与不包含

包中包含 Java 21 runtime、shaded Agent 和服务控制脚本。注册令牌、节点私钥、Agent 凭据、TLS
私钥/密码、节点白名单均由部署者提供，禁止放入发布包。Linux/macOS 采用用户级服务；
Windows 使用专属虚拟服务账号。首版不自动添加防火墙规则，也不启动公网监听。


## 发布签名与 SSH 安装（DIST-01 候选）

发布清单旁新增 `<包名>.signature.json`，签署 UTF-8 清单的**原始字节**，不重新序列化 JSON。
协议：`schemaVersion=1`、`algorithm=Ed25519`、`keyId=SHA-256(SPKI DER)`、
`manifestSha256` 和 base64 编码的 64 字节 `signature`。签名清单内的归档大小和 SHA-256
将 JAR、Java runtime、服务脚本及 SBOM 绑定为一个发行包。原 `.sha256` 仍覆盖两种归档和清单；
签名 sidecar 本身由 Ed25519 校验，不作为自签名输入。三平台发布共 15 个资产。

### 一次性配置

发布者使用独立 Ed25519 密钥，不能复用节点、票据或 TLS 私钥。GitHub Repository Secret
`JLSHELL_AGENT_PUBLISHER_PRIVATE_KEY` 保存 **PKCS8 DER 的 base64**；不要提交到仓库。
使用受保护工作目录生成：

```sh
umask 077
openssl genpkey -algorithm Ed25519 -out publisher.pem
openssl pkcs8 -topk8 -nocrypt -in publisher.pem -outform DER -out publisher.pkcs8.der
openssl pkey -in publisher.pem -pubout -outform DER -out publisher.spki.der
```

以上需要 OpenSSL 3。将 `publisher.pkcs8.der` 的 base64 放入上述 Secret；将
`publisher.spki.der` 的 base64 公钥独立核对后配置到 Website `.env` 的
`JLSHELL_AGENT_PUBLISHER_PUBLIC_KEYS` 和插件高级设置中的 **Agent 发布公钥**。
支持逗号分隔的多个公钥以轮换；先下发新公钥，再用新私钥发布。旧公钥只在旧签名安装版本
不再需要恢复后撤除。公钥没有保密要求；私钥只留在受保护工作目录与 GitHub Secret。
Website 未配置公钥会拒绝发布，插件未配置公钥会拒绝安装，不提供跳过验签的开关。

部署顺序：Website 验签 MR → 插件安装 PR → Link 签名发布 PR → main 来源的候选发布。
此次代码不触发发布、不修改生产配置，也不将候选构建标记为正式签名发行。

### 插件与离线包

使用现有 SSH 会话里的可选安装面板，选择同一目录中的 ZIP、manifest.json 与 signature.json。
插件验签、检查归档大小/SHA-256及 ZIP 路径，然后通过 SFTP 上传到随机私有暂存目录，
远端再次核对 ZIP 摘要才解包。只支持 Linux x64、macOS arm64、Windows x64。
首次注册填 Agent ID 和一次性令牌；令牌仅经 SFTP 文件传递，目录为当前用户独占，Unix
令牌文件为 600，注册后清理。准备好远端 Ed25519 TLS identity、密码文件和目标白名单；
不覆盖已有节点身份。升级时不填令牌，必须能核验已安装的 release manifest/signature，
拒绝降级及同版本不同清单。旧未签名安装需要先按运维流程核对并处理，不能自动信任。
Windows 发行 ZIP 内置固定摘要的 WinSW v2.12.0，因此已取得签名包后不需要再联网下载服务包装器。

`upgrade-user-service.sh` / `upgrade-windows-service.ps1` 在诊断后保存程序与服务配置，
停止旧服务，安装新版本并检查进程保持运行；失败时恢复旧程序和服务配置。注册身份和业务凭据
不参与版本替换。首次注册失败后可能保留新节点身份；Website 令牌已消费时必须重新取票，
不能声称控制平面注册操作也被回滚。恢复失败会返回非零状态，必须核对服务。

当前只完成脚本恢复边界与插件部署模拟；**真实三平台升级/启动条件、节点在线与业务恢复仍待验收**。
Linux 用户服务无登录启动需运维确认 linger；macOS LaunchAgent 依赖登录会话，
Windows 需要管理员安装及专属虚拟服务账号。服务进程运行不等于 B 控制连接或业务已经恢复。
