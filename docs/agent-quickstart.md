# 开始使用 JLShell Link Agent

解压对应平台的包，运行：

| 平台 | 入口 |
| --- | --- |
| Windows | 双击 `agent.cmd`，或在终端执行 `agent.cmd` |
| macOS | 双击 `Agent.command`，或终端执行 `./agent.sh` |
| Linux | 终端执行 `./agent.sh` |

首次选择 **1. 首次配置 / 注册**：

1. 填写 Website 和 Link 服务地址（Link 可直接填 HTTPS 域名）。
2. STUN 支持主机名或数字地址；不使用 STUN 时填 `-`，仅中继策略在桌面插件中选择 `RELAY_ONLY`。每次启动自动解析 STUN，不要求用户自己查询公网 IP。
3. 添加此网关能访问的设备 `IP:端口`。
4. 在 Website 创建 Agent，填写 Agent ID 和一次性令牌；令牌隐藏输入且不保存。
5. 选择启动网关。保持窗口打开，Ctrl+C 停止。

节点私钥、TLS 自签证书和随机密码由向导自动创建；接近到期自动续签，保留原节点公钥与注册身份。
不需要手工运行 keytool、设置密码文件或拼接启动参数。已有注册无需再次输入令牌。

以后选择菜单 **2. 启动网关**，或直接：

```sh
# Linux/macOS
./agent.sh start
./agent.sh configure
./agent.sh diagnose
./agent.sh status
./agent.sh stop
```

Windows 使用相同命令：`agent.cmd start`、`agent.cmd configure` 等。

配置默认保存到当前用户的 `.jlshell-link-agent/agent-config.properties`，只有服务地址、STUN 与精确目标。
私有身份和节点凭据分别保存；配置文件不包含注册令牌或密码。POSIX 目录/文件分别使用 700/600，Windows 使用当前用户私有 ACL。

## 修改与迁移

- 菜单 **5. 修改连接和目标** 保存后，下次启动生效。运行中请先停止。
- 已注册身份不能在向导内改绑另一个 Website；另一个账号/部署使用独立 `--state-dir`。
- 升级解压包不会覆盖用户目录的身份，不要删除私有目录或重复生成节点私钥。
- 身份文件损坏时明确报错，不会静默用新身份替换已注册节点。
- 本地目标仍须由 Website 策略允许；本地配置不能扩大远程授权。注册后可在 Website 核对同一目标。

## 高级操作

非交互式服务器直接使用 `agent.sh start --state-dir /private/profile`。首次配置需在交互式终端完成；不回显读取令牌。
高级 `init/enroll/run` 参数继续支持，见包内 `docs/agent-cli.md`。系统服务仍由独立安装脚本管理，需要明确安装；默认菜单不会修改系统服务、系统证书或全局执行策略。
Windows 双击无需安装 Java、PowerShell 模块或改执行策略；macOS 双击首次若被系统拦截，可用终端 `./agent.sh` 启动，不关闭系统安全机制。
