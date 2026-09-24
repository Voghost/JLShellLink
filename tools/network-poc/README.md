# 隔离网络探针（非产品实现）

`JavaTcpRelay` 是 B 上只运行一次的透明 TCP 字节转发器，`JavaTlsPeer` 是 A/C 的 Java TLS 1.3 双向证书与二进制回环探针。它们用于确认不同出口网络上 Java 运行时和端到端加密的基本可行性，**没有**实现 ICE、KCP、WSS、HTTP/2 CONNECT、控制平面授权或生产资源限制。不能用这些类替代 Link 服务。

`JavaStunProbe` 只查询 IPv4 STUN 映射；`JavaStunServer` 是 B 上短时运行的 IPv4 Binding 测试应答器。`JavaUdpPathProbe` 在同一个 UDP socket 上查询映射、经 B 的 `JavaTcpRelay` 交换候选，再发送短时 `PUNCH`/`ACK`。这也不是 ICE：没有候选优先级、connectivity checks、nomination 或可靠传输。

## 编译与隔离运行

三端各使用一个专用临时目录；B 和 C 只从该目录读取测试文件，不安装系统软件，也不修改现有服务。使用 JDK 21 或更新版本编译：

```bash
POC_DIR=/private/tmp/jlshell-link-p0-example
mkdir -m 700 "$POC_DIR"
javac --release 21 -d "$POC_DIR" JavaTcpRelay.java JavaTlsPeer.java
javac --release 21 -d "$POC_DIR" JavaStunServer.java JavaStunProbe.java JavaUdpPathProbe.java
```

使用 `keytool` 分别生成 A/C 的短期 PKCS12 身份库，交换**公有证书**并各自导入对端信任库。各端运行时目录分别需要 `<role>.p12` 和 `<role>-trust.p12`；私钥只给对应端。运行参数如下：

```text
JavaTcpRelay <port> <one-time-token> <max-seconds>
JavaTlsPeer <A|C> <B-host> <port> <work-directory> <one-time-token> <test-store-password>
```

B 若只有现成 Java 21 Docker 镜像，可在空闲且经确认允许的测试端口运行一次性只读容器：

```bash
docker run --rm --network host --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m \
  --mount type=bind,source=/var/tmp/jlshell-link-p0-example,target=/work,readonly \
  --entrypoint java bitnamilegacy/java:21 \
  -Xmx64m -cp /work JavaTcpRelay 13577 example-token 60
```

运行时先启动 B，随后启动 C，最后启动 A。预期 A/C 输出 `TLSv1.3` 和 `ECHO ... 4096`，B 输出两个角色的转发字节数与 `PLAINTEXT_SEEN false`。测试后核对监听和容器退出，清理三端临时目录及短期证书。令牌和证书密码仅用于一次性探针，不是产品授权方案。

## UDP 路径诊断

先在 A/C 的隔离目录编译并运行 `JavaStunProbe <B-host> <B-udp-port>`，确认自托管 B 的 UDP 入口可达。B 用同一现成 Java 21 容器模式运行 `JavaStunServer <B-udp-port> 60`；务必先确认该端口空闲并允许入站。若自托管入口不可达，也可使用 [公共 STUN 服务](https://developers.cloudflare.com/realtime/turn/)的 `stun.cloudflare.com 3478` 定位两端 UDP 出站问题。映射仅用于当次 socket；要实测直连，还应在 B 的一个空闲 TCP 测试端口启动 `JavaTcpRelay`，再让 A/C 几乎同时执行：

```text
JavaUdpPathProbe <A|C> <stun-host> <stun-port> <B-host> <B-tcp-port> <same-token> 12
```

两端输出 `DIRECT_BIDIRECTIONAL` 表示带本次令牌的 UDP 报文与确认都抵达对端。B 的 TCP 探针只转发各一行候选地址；其 UDP 探针只回答 Binding 请求。正式实现仍需自己的授权、候选信令与可靠的 UDP 协调服务。

## 真实网络 WSS 降级诊断

`JavaWssRelayProbe` 在 B 的独立目录中提供短时 TLS 1.3 WebSocket 配对；`JavaWssFallbackPeer` 在 C 上受控丢弃本次直连 UDP 探测包，让 A 的 2 秒直连预算真实超时后只连接一次 WSS。A/C 在 WSS 二进制帧之上再建立双向证书 TLS 1.3，并验证 4096 字节往返。选择 `http2` 模式时，内层 TLS 协商 `h2` ALPN，`JavaHttp2ConnectProbe` 使用一条 HTTP/2 CONNECT 流访问 C 的 `127.0.0.1:13779` 临时 TCP echo 目标，验证 4096 字节回显与半关闭。该探针只编码和解析此测试所需的少量 HTTP/2/HPACK 帧；生产实现应使用完整协议栈。

编译时额外包含 `JavaWssRelayProbe.java`、`JavaWssFallbackPeer.java`、`JavaHttp2ConnectProbe.java` 和 `JavaUdpPathProbe.java`。在同一个短期工作目录中生成三份测试身份：B 的外层证书需包含 `<B-host>` 的 DNS SAN，A/C 的内层证书分别只交给本端；A/C 都需要 `B-trust.p12`，A 需要 `A-trust.p12` 信任 C，C 需要 `C-trust.p12` 信任 A。测试身份与信任库只在该目录存在，结束后删除。

先在 B 的三个空闲测试端口分别运行 `JavaStunServer`、`JavaTcpRelay` 和 `JavaWssRelayProbe`；然后启动 C，最后启动 A：

```text
JavaWssRelayProbe <wss-port> <B.p12> <storepass> <same-token> <session> 180
JavaWssFallbackPeer <A|C> <B-host> <stun-port> <signal-port> <wss-port> <workdir> <same-token> <session> <storepass> [<echo|http2> <app-drop|os-block|os-baseline>]
```

默认模式成功时 A 输出 `DIRECT_TIMEOUT`、`RELAY_ATTEMPTS 1`、`WSS_CONNECTED A`、`INNER_TLS A TLSv1.3` 和 `WSS_ECHO_VERIFIED bytes=4096`；C 输出 `DIRECT_DROPPED` 且计数大于零；B 输出 `WSS_PAIR_READY`、双向转发字节和 `PLAINTEXT_SEEN false`。`http2` 模式另输出 `INNER_ALPN h2`、`HTTP2_CONNECT_ECHO_VERIFIED bytes=4096` 与 `HTTP2_CONNECT_TARGET_C`。此探针使用一次性测试令牌，未实现产品票据、配额或生产 Relay 的资源约束。

OS 级阻断诊断使用 B 上**独立 Docker bridge 网络命名空间**中的 A' 和远端 C。先以 `os-baseline` 模式确认直连成功，再仅在 A' 容器网络命名空间中用 `iptables OUTPUT` 丢弃对端 UDP，运行 `os-block` 模式。A' 需固定 UDP 本地端口并公布 Docker 映射端口：`-Djlshell.p0.udpPort=<port>`、`-Djlshell.p0.advertise=<B-public-ip>:<port>`；若 A' 的 STUN 服务器不同于 B 控制/中继入口，可用 `-Djlshell.p0.stunHost=<host>` 指定。`os-block` 下内核可能使 UDP `send` 返回 `Operation not permitted`，探针将其计入 `os_denied` 并在 2 秒预算后回退。只对一次性容器执行 `nsenter`，不要改宿主机规则；结束后删除容器及测试目录。2026-09-24 的远端对照与回退结果见 `docs/java-network-spike.md`。A' 与 B 同物理主机，不替代正式 ICE/KCP 或原 macOS A 的 OS 级测试。

## ICE/KCP/mTLS/HTTP2 跨 NAT 原型

`JavaIceKcpHttp2Peer` 是 P0 的单会话诊断程序。它使用 ice4j 从 B 的 IPv4 STUN 收集 `srflx`，经 B 的 TCP 探针交换 ICE 凭据和候选，执行 ICE checks/nomination，然后把同一 ICE socket 接到 KCP，承载双向 TLS 1.3、`h2` 与固定一条流的 HTTP/2 CONNECT。`auto` 给 ICE 2 秒预算；双方通过 B 协调路径后，若任一方不能直连，则释放 ICE 并经 WSS 只回退一次。使用自测生成的短期身份；**没有生产鉴权或多租户能力**。

在 Link 仓库运行下面脚本，把 Java 21 字节码和全部探针依赖编译到一个权限受限的专用目录；输出的 `classes/`、`lib/` 可复制到 A/C 各自临时目录。远端运行需 JDK 21 或更新版本；B 可继续用一次性 Java 21 容器。

```bash
umask 077
bash tools/network-poc/build-ice-poc.sh /private/tmp/jlshell-link-p0-example
```

使用上文生成的 A/C 身份与信任库。先在 B 的空闲端口运行 `JavaStunServer` 和 `JavaTcpRelay`，`auto` 还要运行 `JavaWssRelayProbe`；再启动 C，最后启动 A。三端均使用各自专用工作目录，`token` 和 `storepass` 仅用于本次短时探针，不要写入仓库或公开日志。

```text
JavaIceKcpHttp2Peer <A|C> <interface> <B-IPv4-or-name> <stun-port> <signal-port> <workdir> <token> <storepass> <ice|full|auto> [<wss-port> <session>]
```

`ice` 只验证候选选定；`full` 运行直连整链路；`auto` 执行直连优先及 WSS 降级。成功日志包括 `POC_CANDIDATE`（STUN 映射）、`POC_ICE_SELECTED`（最终候选对与耗时）、`POC_DIRECT_TLS` 或 `POC_ICE_FALLBACK`、`HTTP2_CONNECT_ECHO_VERIFIED bytes=4096` 和 `POC_RESOURCES_RELEASED agent_over=true`。A/C 进程退出码须为 0。提交证据时隐藏精确 IP:端口及凭据；工作区私有记录可保留精确候选值。原型中的 HTTP/2 编解码只覆盖这一条测试流，正式栈需独立实现授权、边界和容量控制。
