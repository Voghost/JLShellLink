# 本地隧道验收

以下示例使用三个独立节点身份。先构建工作区，并在临时目录生成开发密钥：

```bash
cargo build --workspace
mkdir link-smoke
target/debug/jlshell-linkctl authority-init \
  --private-key link-smoke/authority-private.json \
  --public-key link-smoke/authority-public.json
target/debug/jlshell-linkctl identity-init --output link-smoke/relay.key
target/debug/jlshell-linkctl identity-init --output link-smoke/agent.key
target/debug/jlshell-linkctl identity-init --output link-smoke/connector.key
```

记录命令输出的三个 PeerId。启动一个仅监听回环的 Echo 或 SSH 服务，再分别启动
Relay 和 Agent：

```bash
target/debug/jlshell-relay --identity link-smoke/relay.key

target/debug/jlshell-agent \
  --identity link-smoke/agent.key \
  --authority-public link-smoke/authority-public.json \
  --allow-target 127.0.0.1:9000 \
  --connect-policy relay-only \
  --relay-address /ip4/127.0.0.1/tcp/4001 \
  --relay-peer RELAY_PEER_ID
```

签发票据并启动 Connector：

```bash
target/debug/jlshell-linkctl ticket-issue \
  --authority-private link-smoke/authority-private.json \
  --connector-peer CONNECTOR_PEER_ID \
  --agent-peer AGENT_PEER_ID \
  --target 127.0.0.1:9000 \
  --output link-smoke/ticket.pb

target/debug/jlshell-connector \
  --identity link-smoke/connector.key \
  --agent-peer AGENT_PEER_ID \
  --connect-policy relay-only \
  --relay-address /ip4/127.0.0.1/tcp/4001 \
  --relay-peer RELAY_PEER_ID \
  --ticket link-smoke/ticket.pb \
  --target 127.0.0.1:9000 \
  --local-bind 127.0.0.1:9022
```

`CONNECTION_PATH=Relay` 是 relay-only 的确定性验收信号。直连测试改为
`direct-only`，并向 Connector 传入 Agent 输出的 TCP 或 QUIC 地址。`auto` 会先
尝试直连三秒，失败后记录回退并建立 Relay；已建立流不会中途迁移。

票据只能使用一次。每次新测试都必须重新运行 `ticket-issue`。

