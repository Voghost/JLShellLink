# JLShell Link Java Agent CLI

`link-agent` 打包时生成带依赖的可执行 JAR，入口类为
`com.jlshell.link.agent.AgentApplication`。Java 运行时要求 21 或更新版本。

```text
java -jar link-agent-0.1.0-SNAPSHOT.jar help
java -jar link-agent-0.1.0-SNAPSHOT.jar init
java -jar link-agent-0.1.0-SNAPSHOT.jar enroll \
  --website https://website.example \
  --agent-id 00000000-0000-0000-0000-000000000000
java -jar link-agent-0.1.0-SNAPSHOT.jar status
java -jar link-agent-0.1.0-SNAPSHOT.jar diagnose \
  --link-wss wss://link.example:13575/link/v2/control \
  --tls-identity-p12 /secure/agent.p12 --tls-password-file /secure/p12.password \
  --allowed-targets-file /secure/allowed-targets
java -jar link-agent-0.1.0-SNAPSHOT.jar run \
  --link-wss wss://link.example:13575/link/v2/control \
  --tls-identity-p12 /secure/agent.p12 --tls-password-file /secure/p12.password \
  --allowed-targets-file /secure/allowed-targets
java -jar link-agent-0.1.0-SNAPSHOT.jar stop
```

默认状态目录为当前用户主目录下的 `.jlshell-link-agent`，可用 `--state-dir <path>` 指定。目录中保存 Ed25519 节点私钥、注册元数据和单独的 Agent 凭据；POSIX 系统会设置仅当前用户可访问的权限。

注册时，CLI 优先读取 `--token-file`。该文件必须是当前用户拥有的普通文件，不能是符号链接，且 POSIX 权限不得向组或其他用户开放；建议使用 `chmod 600 <path>`。未提供 token 文件时，CLI 仅在交互式终端通过隐藏输入读取。token 不支持作为命令行参数，也不会写入状态目录。

```sh
chmod 600 /path/to/enrollment-token
java -jar link-agent-0.1.0-SNAPSHOT.jar enroll \
  --website https://website.example \
  --agent-id 00000000-0000-0000-0000-000000000000 \
  --token-file /path/to/enrollment-token
```

`run` 前台常驻，使用已注册的 Agent 身份对 Website 发心跳、轮询撤销及 Relay 请求，
并与 B 建立独立的持钥证明 WSS 控制连接。当前数据路径支持出站 `relay-only`；
WSS 信令已接入，但 Agent 尚未实现 ICE 候选收集和 direct KCP 承载。
`stop` 通过同一状态目录内的当前用户专属标记请求优雅退出；`status` 根据独占文件锁
报告运行状态。系统服务安装器和自动凭据轮换仍属于后续工作。

首次部署推荐先生成使用 **Ed25519** 的 TLS 身份 PKCS12，再导入为节点身份，以保证
WSS 持钥身份和内层 mTLS 证书使用同一把公钥。例如在具备 JDK 的机器上：

```sh
keytool -genkeypair -alias jlshell-agent -keyalg Ed25519 -sigalg Ed25519 \
  -dname 'CN=jlshell-link-agent' -validity 365 -storetype PKCS12 \
  -keystore /secure/agent.p12
chmod 600 /secure/agent.p12 /secure/p12.password
java -jar link-agent-0.1.0-SNAPSHOT.jar init \
  --tls-identity-p12 /secure/agent.p12 --tls-password-file /secure/p12.password
```

上面的 `keytool` 会交互输入 PKCS12 密码；将同一密码写入当前用户独占的
`/secure/p12.password`。已注册节点不能替换私钥，必须提供与已注册公钥一致的证书。
`run` 启动时会校验 PKCS12 只有一个密钥条目、证书未过期且公钥与本地注册身份一致。
内层 A—C mTLS 对端必须提供单张自签 Ed25519 证书，证书公钥指纹必须等于 Website
授权给本次请求的 A 节点指纹。外层 Website HTTPS 和 B WSS 使用 JVM 的正常 TLS
信任配置，不接受跳过证书校验的选项。

本地目标白名单文件一行一个精确数值 IP 与 TCP 端口，例如：

```text
192.0.2.10:22
192.0.2.11:5432
[2001:db8::10]:443
```

文件必须为当前用户独占的普通文件，不能是符号链接；空白名单会阻止 Agent 启动。
它只会收紧 Website 的策略，不会扩大访问范围。`--ticket-issuer` 默认取注册 Website
地址；若 Website 的 `JLSHELL_SITE_PUBLIC_BASE_URL` 不同，需传入该 HTTPS issuer。
`diagnose` 在本地验证身份、TLS、白名单，并通过 HTTPS 读取 Website 公布的票据公钥。
