# Java Agent 服务托管与安装包

Java Agent 需要 Java 21 或更新版本，不携带 JRE。`scripts/package-java-agent.sh`
接收版本号和 shade 后的 Agent JAR，生成同内容的 `.tar.gz` 与 `.zip`，包内包含
CLI 文档、Linux/macOS 服务管理脚本、Windows Service 安装脚本和逐文件 SHA-256 清单。
GitHub Actions 的 `Package Java Agent` 手动工作流会先运行 Link 全量 `mvn verify`，再
上传 90 天有效的打包产物；此流程不会创建 GitHub Release 或部署到生产。

## Linux 与 macOS

解压后用登录用户执行：

```sh
scripts/java-agent/install-user-service.sh install \
  ./link-agent.jar \
  wss://link.example:13575/link/v2/control \
  /secure/agent.p12 /secure/tls.password /secure/allowed-targets \
  https://website.example
```

脚本在 Linux 创建 systemd 用户服务，在 macOS 创建 LaunchAgent。`uninstall` 只停止并
移除服务定义和配置，不会删除 Agent 注册身份、凭据、JAR 或日志。Java Agent 的 `stop`
命令负责写入专属停止标记并优雅退出。身份 PKCS12、密码文件和目标白名单需归运行用户
所有，POSIX 系统权限设为 `600`。可通过安装进程的 `JLSHELL_LINK_JAVA_TOOL_OPTIONS` 注入
非敏感 JVM 参数（例如私有 CA truststore 路径）；该值以用户独占权限保存在本机配置文件，
不要在其中放入凭据。也可设置 `JLSHELL_LINK_JAVA` 指定 Java 可执行文件路径；通常让脚本
使用当前用户 PATH 中的 Java 21 即可。

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
`SYSTEM`、管理员和 `NT SERVICE\\JLShellLinkAgent` 访问；服务停止时调用 Agent CLI 的
优雅停止命令。`status` 查询服务，`uninstall` 停止并删除服务和程序文件，状态目录与
凭据保留。再次安装时会沿用 `ProgramData` 中已有的完整 Agent 身份、TLS 材料与白名单；
仅在首次安装时从 `-StateDirectory` 导入，避免重装时覆盖受保护的身份凭据。

Windows Service 由 WinSW v2.12.0 包装。安装器从 WinSW 上游 release 下载 x64 文件，并
固定校验 SHA-256 `05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da`；
升级包装器前需要更新固定版本、摘要和对应 MIT 许可记录。[WinSW 官方说明](https://github.com/winsw/winsw)

## 包含与不包含

包中包含 Java 21 shaded Agent 和服务控制脚本。注册令牌、节点私钥、Agent 凭据、TLS
私钥/密码、节点白名单均由部署者提供，禁止放入发布包。Linux/macOS 采用用户级服务；
Windows 使用专属虚拟服务账号。首版不自动添加防火墙规则，也不启动公网监听。
