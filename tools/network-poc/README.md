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
