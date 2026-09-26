# 公网入口 STUN 部署

JLShell Link 的 STUN Binding 响应必须使用公网入口实际收到的客户端 UDP 地址。NAS 上的 Website 经普通 FRP UDP 代理接收请求时，看到的是 FRPC/容器网关地址，返回的 `XOR-MAPPED-ADDRESS` 可能是 `172.27.0.1` 一类私网地址。即使公网 `13576/UDP` 能收发，这种结果也不能用于 A—C 打洞。

`link-stun-server` 是独立的 Java 21 进程，复用 `link-server` 中受限、按来源地址限速的 Binding-only 实现。它不提供 TURN，不需要 Website 数据库或 TLS 私钥。生产入口应直接在公网 B 的 `13576/UDP` 运行它，并移除同端口的 FRP UDP 代理；Website WSS 的 FRP TCP `13575` 保持不变。

## 构建与隔离部署

在 JLShellLink 仓库执行：

```bash
mvn -B -ntp -pl link-stun-server -am verify
docker build -f link-stun-server/Dockerfile -t jlshell-link-stun:<版本> link-stun-server
```

公网 B 推荐使用 Docker host 网络运行，不经过 Docker bridge 的 UDP 端口映射：

```bash
docker run -d --name jlshell-link-stun --restart unless-stopped \
  --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e JLSHELL_LINK_STUN_BIND_ADDRESS=0.0.0.0 \
  -e JLSHELL_LINK_STUN_PORT=13576 \
  -e JLSHELL_LINK_STUN_MAX_REQUESTS_PER_SECOND=100 \
  jlshell-link-stun:<版本>
```

切换前先在其他仅回环监听的端口启动同一镜像，并从 B 本机验证 Binding。切换时从 FRPC 配置中**只移除** `jlshell-link-stun` UDP 代理并热重载 FRPC，确认 FRPS 释放 `13576/UDP` 后，再启动公网 STUN 容器。若失败，停止独立容器，恢复该 FRPC 代理并热重载。FRPC 的 Website、WSS 和官方 Relay 代理不能删除或重启。

## 验收

1. 公网 DNS/防火墙/云安全组允许客户端向 B 的 `13576/UDP` 发包，并能收到来自同一公网 IP、同一端口的 Binding 响应。
2. 从至少两个不同出口发送带随机事务 ID 的 Binding Request，逐个验证事务 ID、消息类型 `0x0101`、`XOR-MAPPED-ADDRESS` 为该出口的公网地址，而不是 FRPC、Docker 或 NAS 私网地址。
3. 重复验证 `wss://<Link 域名>/link/v2/control` 与 `/link/v2/relay` 的公网 TLS/代理路径；STUN 切换不应影响 WSS。
4. 生产客户端配置中的 STUN 目标使用公网 B 的地址和 `13576/UDP`。正式 A—C direct 产品选路仍由 NET-02 验收；Binding 成功本身不等于直连业务验收。

容器默认监听 `0.0.0.0:13576`，可用 `JLSHELL_LINK_STUN_BIND_ADDRESS`、`JLSHELL_LINK_STUN_PORT`、`JLSHELL_LINK_STUN_MAX_REQUESTS_PER_SECOND` 调整；端口必须为 1–65535，限速范围由 `StunBindingServer` 限制为每来源地址每秒 1–10000 次。
