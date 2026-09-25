# JLShell Link Agent CLI（当前阶段）

`link-agent` 打包时生成带依赖的可执行 JAR，入口类为
`com.jlshell.link.agent.AgentApplication`。Java 运行时要求 21 或更新版本。

```text
java -jar link-agent-0.1.0-SNAPSHOT.jar help
java -jar link-agent-0.1.0-SNAPSHOT.jar init
java -jar link-agent-0.1.0-SNAPSHOT.jar enroll \
  --website https://website.example \
  --agent-id 00000000-0000-0000-0000-000000000000
java -jar link-agent-0.1.0-SNAPSHOT.jar status
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

当前 CLI 完成节点身份初始化、一次性注册和本地状态展示。`status` 明确报告常驻进程未启动；后台运行、服务安装、诊断、停止和自动凭据轮换尚未接入，因此此 CLI 不能单独提供持续在线的 C 网关。
