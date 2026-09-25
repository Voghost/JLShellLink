# Java 网络原型记录

- 日期：2026-09-24
- 分支：原始 POC 为 `feature/java-link-poc`，P0 收尾为 `feature/java-link-p0-completion`
- Java 基线：Java 21；本机当前默认运行时为 OpenJDK 26.0.1，Maven 3.9.16
- 状态：P0 **原型门槛通过**。真实不同出口 A/C 经公网 B 的 STUN 和信令完成 ICE 候选选定，在同一 UDP socket 上以 KCP、双向 TLS 1.3、`h2` 和 HTTP/2 CONNECT 访问 C 的 TCP echo 目标；4096 字节回显及半关闭通过。`auto` 模式真实跨 NAT 直连通过；B 上两个独立容器网络命名空间先直连，再在 A' 内核阻断业务 UDP，`auto` 于 2 秒后只回退一次 WSS，并完成内层 mTLS/CONNECT。精简 KCP 传递依赖后，真实跨 NAT 整链路复跑通过。本机 11 项 Java 测试通过；此前 Linux/macOS/Windows Java 21 CI 通过，本分支的 CI 待 PR 检查。Windows hosted runner 因缺少可用 ICE 候选跳过该项，不能宣称 Windows ICE 已验收。原型不能直接部署为生产 P2P/Relay，正式鉴权、限额和容量在后续阶段实现。

## NET-01 实施进度（2026-09-25）

- `ReliableDuplexChannel` 已补充异步读取、EOF、可写通知、完整写入完成、输出半关闭、异常终止和关闭结果的统一语义；目前仍没有正式直连与 WSS 通道实现。
- `TransportBudget` 已定义帧/头大小、并发流、写队列、单流和总缓冲、握手并发与超时的有限配置约束。
- `NettyReliableDuplexChannel` 已提供有界 `ByteBuf` 字节流适配，支持分块读取、主动读背压、共享总缓冲账本、写队列限制、读取消、承载定义的半关闭动作及失败传播。多流复用时必须让所有通道共享同一个 `TransportBufferBudget`。
- 新增 `TlsPeerContext` 与 `PinnedPeerTrustManager`：由显式信任库执行 PKIX 校验，并额外校验预期叶证书 SPKI SHA-256；TLS 仅启用 1.3，服务端要求客户端证书，ALPN 限定为 `h2`，每条隧道创建独立上下文。
- `TlsPeerHandler` 已将 TLS 1.3 peer context 接入 Netty `SslHandler`，并从共享传输预算应用握手超时。
- ICE/KCP/mTLS 集成测试现使用该 TLS 工厂，验证双向证书信任成功、未受信客户端被拒绝及公钥指纹错误被拒绝。Netty 字节流适配器契约测试验证了取消读取、切块、EOF、队列超限、跨通道总缓冲限制与半关闭委托；TLS handler 测试验证握手超时、TLS 版本和并发闸门。全工程 `mvn -B -ntp verify` 在本机 OpenJDK 26.0.1 上通过（37 项测试，Java 编译目标为 21）。
- 新增生产依赖 `netty-codec-http2` 和服务端 `ConnectStreamMultiplexer`：每条 HTTP/2 子流校验 CONNECT 与一次性票据字段，通过 fail-closed 授权回调后才连接规范化数值 IP；限制并发流、请求头/帧、建连队列与共享缓冲；DATA 写完后再归还入站流控信用，发送方向随写队列和 HTTP/2 可写状态暂停读取，较大的目标读取会切成协议允许大小的 DATA 帧。请求 END_STREAM 映射为目标 TCP 输出半关闭，目标 EOF 映射为响应 END_STREAM，RST 和通道关闭会回收目标与计时器。四条 EmbeddedChannel 测试覆盖双向二进制、大目标读取分帧、半关闭/EOF、拒绝、主机名目标、缺票据和授权超时。
- `TlsHandshakeGate` 已提供跨连接共享的 TLS 握手槽位：达到上限时在 TLS 握手前关闭新连接，握手结束或通道关闭时释放槽位。Netty 测试覆盖并发拒绝与关闭后重新接纳。连接入口必须共用一个 gate 实例；正式 direct/WSS 入口目前尚未接线，CONNECT setup 并发槽也仍沿用 `maxConcurrentHandshakes` 预算值。
- 此进度**不代表 NET-01 验收完成**：目前实现的是可复用的服务端 CONNECT 子流端点，授权器尚未接入真实票据/ACL 服务；客户端流复用器、direct/WSS 桥接、TLS 握手闸门与各入口接线、两种承载共用的契约测试及 Java 21 CI 仍待完成。

## 真实 A/B/C 主机联调（2026-09-24）

用户提供的拓扑：A 是开发机 macOS（`192.168.1.0/24` 网段），B 是云主机，C 是 Arch Linux 内网主机（`192.168.31.0/24` 网段）。B、C 以密钥 SSH 连通。所有探针只在三端同名的临时隔离目录 `jlshell-link-p0-20260924` 中运行；B、C 使用 `/var/tmp/`，A 使用 `/private/tmp/`。未修改现有进程、服务配置、防火墙或 Docker 容器。测试前核对端口空闲，结束后核对临时监听和 C 的探针进程已经退出。

| 检查 | 结果 | 证据边界 |
| --- | --- | --- |
| 运行时 | A 为 OpenJDK 26.0.1；C 为 OpenJDK 27；B 宿主机没有 `java` 命令，但已缓存 `bitnamilegacy/java:21` 镜像，其 Java 21.0.7 在只读、无网络的一次性容器中运行成功 | A/C 探针以 `javac --release 21` 编译；A/C 真实主机尚未以 JDK 21 执行，B 未安装系统 Java。 |
| B 的 UDP 协调（放通前） | 临时 Python 探针分别监听 UDP 34673 和 13575；A/C 均发出 `HELLO`，B 没收到。对 13575 的 B `eth0` 定向抓包为 0 包 | 这是用户调整云侧端口规则前的历史结果；不能据此判定当前入口状态。 |
| B 的 TCP 入口 | B 临时监听 TCP 13575；A、C 都收到固定探针应答 | 证明两端可主动出站到 B 的空闲 TCP 端口；不是 WSS/Website 服务验收。 |
| A—B—C 加密转发 | B 在空闲 TCP 13576 上运行一次性 Python 原始字节转发器，A/C 运行 Java 21 字节码探针，内层双向证书 TLS 1.3 握手成功，4096 字节二进制负载往返完全一致。B 记录 A→C 5178 字节、C→A 5751 字节，转发缓冲中未发现测试明文标记 | 证实真实不同出口网络上的透明 TCP 中继可承载 Java mTLS 数据。B 仍是 Python 测试夹具；本次未运行生产 Java Relay、WSS、HTTP/2 CONNECT、票据授权、ICE/KCP 或真实 UDP 失败后的自动回退，不能标记 P0 完成。 |
| 三端 Java 加密转发 | B 使用现有 Java 21 镜像中的一次性只读容器，在空闲 TCP 13577 上运行仓库 `tools/network-poc/JavaTcpRelay.java`；A/C 运行 `JavaTlsPeer.java`。双向证书 TLS 1.3 协商成功，4096 字节二进制往返一致；B 记录 A→C 5179 字节、C→A 5753 字节，所见缓冲中未检出测试明文标记。容器自动退出 | 证明三端 Java 基本部署和端到端加密在该真实 TCP 路径上可行。该探针是原始 TCP 转发，仍缺 WSS、HTTP/2 CONNECT、票据鉴权、生产流控、ICE/KCP 和真实自动回退；不能标记 P0 完成。 |
| 跨 NAT UDP 候选探测（放通前） | A/C 分别通过 [Cloudflare 公共 STUN](https://developers.cloudflare.com/realtime/turn/) 的 UDP 3478 获取各自映射地址，使用同一个本地 UDP socket 保持映射。B 在 TCP 13578 上运行一次性 Java 21 容器，只转发候选地址；随后 A/C 都收到对方的 `PUNCH`/`ACK` 并输出 `DIRECT_BIDIRECTIONAL`。B 只转发了 A→C 26 字节、C→A 27 字节的候选行 | 这是两端真实不同出口网络上的 UDP 打洞可行性证据，业务 UDP 没经过 B。诊断使用外部 STUN 和自定义探针，尚未用 ice4j 建立 ICE candidate pair，也没有 KCP、TLS、HTTP/2 CONNECT 或产品信令鉴权；**不等于 POC-02 整链路通过**。该轮测试时 B 自身的 UDP 入口尚不可达。 |
| B 自托管 UDP 复测（用户放通后） | B 使用已缓存的 Java 21 镜像在 UDP 13575 上运行一次性 `JavaStunServer`，对 A/C 共回答 4 次 Binding 请求；双方都拿到公网映射。B 的 `JavaTcpRelay` 在 TCP 13578 交换候选，各转发 27 字节。A/C 在原 UDP socket 上都输出 `DIRECT_BIDIRECTIONAL` | **B 的测试 UDP 入口已可达，A—C 经 B 辅助完成真实双向 UDP 打洞**。探针仅实现 Binding 与短报文；尚未跑跨 NAT 的 ice4j ICE checks、KCP、mTLS、HTTP/2 CONNECT。两个一次性容器退出后端口已释放。 |
| WSS 降级（真实 A/B/C） | B 在空闲 TCP 13579 上运行短时 Java TLS 1.3 WebSocket 配对探针，同时运行自托管 STUN 与 TCP 候选交换。C 保持同一 UDP socket，但主动丢弃收到的 20 个直连探测包；A 在 2 秒预算内发出 20 包且未收到 ACK，只发起一次 WSS 降级。A/C 均主动连到 B，建立内层双向证书 TLS 1.3，4096 字节二进制数据完整往返。B 转发 A→C 5170 字节（9 帧）、C→A 5677 字节（10 帧），其所见 WSS 帧未检出测试明文标记 | 证明真实不同出口网络上，**受控应用层丢包后的 WSS 传输与内层 mTLS 可用**。未修改系统防火墙；这不是 OS 防火墙级 UDP 阻断，也尚未在该远程探针上承载 HTTP/2 CONNECT、生产票据/配额或多连接背压。短时容器、证书和测试目录均已清理，不能标记 P0 完成。 |
| WSS 上的远程 HTTP/2 CONNECT（真实 A/B/C） | A 在 2 秒直连预算内发送 20 个 UDP 包，C 在应用层丢弃 20 包；A 只发起一次 WSS 回退。A/C 内层双向证书 TLS 1.3 协商 `h2` ALPN，HTTP/2 CONNECT `:authority=127.0.0.1:13779` 获得 `:status 200`，C 打开回环 TCP echo 目标；4096 字节 DATA 完整往返，END_STREAM 与目标 TCP 输出半关闭对应。 | 验证远程 WSS/内层 mTLS 可以承载实际 HTTP/2 帧及 CONNECT 到 C 的目标。此探针只实现固定的一条流和有限 HPACK 帧格式，**不是**通用 HTTP/2 栈或产品协议实现；该轮 UDP 失败仍是应用层丢弃。 |
| 容器网络命名空间的 OS 级 UDP 阻断（A'—B—C） | A' 是 B 上单独 Docker bridge 网络命名空间中的 Java 21 客户端，C 仍是远端主机。阻断前同一 A'—C 路径 `DIRECT_BASELINE_VERIFIED packets=2`，C 收到 2 个探测包。只在 A' 的网络命名空间加入 `iptables OUTPUT` UDP 丢弃规则后，规则计数 39 包 / 2067 字节；A' 记录 `DIRECT_TIMEOUT budget_ms=2000 packets=0 os_denied=39`、`RELAY_ATTEMPTS 1`，C 记录 `DIRECT_RECEIVED 0`。随后双方经 B 的 WSS/内层 mTLS `h2` CONNECT 完成 4096 字节回显与半关闭。B 转发 A'→C 7180 字节（44 帧）、C→A' 8126 字节（48 帧），`PLAINTEXT_SEEN false`。 | **内核防火墙阻断与直连对照、一次回退均成立**；规则仅存在于一次性容器网络命名空间，未更改 B/C 宿主机防火墙。A' 与 B 共用物理云主机但网络命名空间独立，故这不替代 macOS A 上的 OS 防火墙测试，也不证明正式 ICE/KCP 协议栈的回退。 |

### P0 收尾：同栈跨 NAT 与受限网络实验

下表为可提交到仓库的脱敏证据。完整 IP:端口记录只保存在聚合工作区根目录的私有 `docs/jlshell-link-p0-network-evidence-private.md`，不包含凭据。

| 实验 | STUN 映射与最终候选对 | 耗时、数据路径及结果 |
|---|---|---|
| 真实 A(macOS)↔C(Arch)，公网 B 辅助 | A/C 均收集到 `srflx` 公网映射；最终 A `prflx` ↔ C `srflx`，C 视角为 `host` ↔ A `prflx`。两端网段和出口不同。 | ICE A/C 为 197/165 ms；A—C 直接 UDP 上 KCP → mTLS 1.3 → `h2` → CONNECT；4096 字节回显和半关闭通过。B 仅转发候选信令 161/162 字节并回答两次 STUN Binding，无业务数据中继。 |
| 真实 A↔C 的 `auto` | 同类公网候选对 | 2 秒预算内选对 A/C 为 299/245 ms；直接路径的 mTLS、`h2`、CONNECT、4096 字节及半关闭通过。 |
| A'/C' 独立容器命名空间直连对照 | 两侧 `host` 候选对 | 选对 89/76 ms；同栈 KCP/mTLS/CONNECT 成功。 |
| 仅在 A' 容器内核阻断业务 UDP | A' 内核丢弃计数 7 包/1032 字节；无可用 ICE 对 | A'/C' 均在 2 秒后选择 `RELAY`；A' 发起一次 WSS。内层 mTLS、`h2`、CONNECT、4096 字节与半关闭通过；B 只见密文帧，未发现测试明文。规则仅存在于一次性容器命名空间。 |
| 排除 `netty-all` 后重跑真实 A↔C | A/C 仍收集 `srflx`；最终 A `prflx` ↔ C `srflx` | ICE A/C 为 122/124 ms；KCP/mTLS/`h2`/CONNECT、4096 字节和半关闭再次通过，两端进程退出码 0。 |

依赖集从 81 个 JAR / 29.7 MB 降至 41 个 JAR / 15.3 MB，压缩包约 13.9 MB。`kcp-fec` 虽名为 FEC，底层 `Kcp.encodeSeg` 实际依赖其 `Snmp` 类，不能移除；只排除 `netty-all`。P0 结论仅准许进入 CORE 协议和身份开发；正式 B 信令鉴权、会话授权、慢连接队列/配额、长时运行和 Windows ICE 仍未交付。旧 Rust 运行时保持原状，按迁移计划后续退役。

## 依赖候选

| 组件 | 固定候选 | 许可证 | 当前决策 |
|---|---|---|---|
| Netty | `4.2.18.Final` | Apache-2.0 | 原型 BOM 固定；正式使用前继续检查目标平台与许可证清单。KCP 间接引入的 `netty-all` 已排除并完成真实跨 NAT 复跑。 |
| ice4j | `org.jitsi:ice4j:3.2-17-geea6cd3` | Apache-2.0 | 固定在测试候选 profile；`Component.getSocket()` 的同 socket 数据面经跨 NAT ICE/KCP/CONNECT 验证。Windows 真网卡 ICE 与长期运行仍待验收。 |
| Java KCP | `com.github.l42111996:kcp-base:1.6` | Apache-2.0 | 仍是测试候选，不进入生产运行依赖；底层 `Kcp` 接入 ICE 已选 socket。`kcp-fec` 提供其必需 `Snmp` 类，不能排除；`netty-all` 已排除，依赖从 81 JAR 降至 41 JAR，跨 NAT 复跑通过。维护风险留到 NET 阶段审查。 |
| JDK API | Java 21 NIO DatagramChannel | 当前 POC 直接持有单个 UDP socket，并验证 STUN/Link 数据报分流与本地端口保持；未实现 STUN 完整解析或 KCP。 |

参考来源： [Netty 官方下载页](https://netty.io/downloads.html)、[Maven Central ice4j](https://central.sonatype.com/artifact/org.jitsi/ice4j)、[java-Kcp 上游 README](https://github.com/l42111996/java-Kcp/blob/master/README.en.md)、[Maven Central kcp-base](https://central.sonatype.com/artifact/com.github.l42111996/kcp-base)。版本与维护状况在进入正式依赖前重新核对。

## POC-01：socket 分流骨架

- 根 Maven 工程使用 Java 21 release，当前仅包含 `link-core`、`link-transport`。Netty 固定版本进入原型依赖；ice4j 和 KCP 候选只在 `network-poc-candidates` profile 的测试 classpath 中，避免把未验证库打入生产运行依赖。
- `ReliableDuplexChannel` 是传输候选 SPI，不含 TLS、HTTP/2 或生产生命周期实现。
- `IceDatagramDispatcher` 在一个 `DatagramChannel` 上识别 STUN magic cookie 并把其余数据报交给 Link 处理器。
- `KcpDatagramAdapter` 把指定 ICE 远端的输入送入 KCP 回调、输出写回同一 channel。POC 测试使用候选库的底层 `Kcp` 引擎与自定义 `KcpOutput`，并非其会自行开 socket 的高层 `KcpClient`。
- 本机 loopback 测试覆盖 STUN/Link 分流，以及两个 KCP 实例经各自分流器持有的 UDP socket 收发可靠数据；同一端口在收发前后保持不变。
- 结果仅证明本机 socket 接线可行。该测试不是 ICE connectivity check、NAT 打洞、丢包/乱序恢复、长时间资源稳定性或 TLS/HTTP2 证据。
- 用 `mvn -Pnetwork-poc-candidates -pl link-transport dependency:tree` 检查过候选库完整依赖和 Netty 版本仲裁；tree 结果已记录在下方。

### 本机验证记录

- 命令：`mvn -B -ntp verify`
- 结果：成功；当前 11 个 POC 测试通过，包含路径选择器单测和 ICE/KCP/TLS/HTTP2 完整集成测试。
- 实际 JVM：OpenJDK 26.0.1；该命令限制了 Java 21 API 编译级别，但并非在 JDK 21 运行。GitHub Actions 上 Linux/macOS/Windows Java 21 job 均通过。
- 机器：macOS ARM64；Linux x64 和 Windows x64 由 Java 21 CI 覆盖。Windows runner 没有 ice4j 所需的可用非回环 IPv4 地址，ICE 网络集成测试在该环境跳过，其他 Java POC 测试仍执行。
- 候选依赖树：ice4j 引入 JNA、Kotlin/Jitsi utilities 和 weupnp；KCP 1.6 的 kcp-fec POM 引入 `netty-all`，现已在 `link-transport/pom.xml` 排除该聚合包并复跑本机测试与真实跨 NAT 整链路。`kcp-fec` 本身不能排除。
- POC-01 的 socket 分流、同 socket KCP 接线和本机资源回收已完成。正式制品的最终许可与平台清单在 NET 阶段锁定。

## POC-02：ICE 与端到端直连进展

- 增加 `IceKcpTls13IntegrationTest`，调用固定候选版本的 Agent、Stream、Component API，在本机活动的非点对点 IPv4 网卡收集候选、交换 ICE 凭据并完成 nomination；再把底层 KCP 引擎连接到 ICE `Component.getSocket()`，通过选中的候选对往返二进制数据，并确认释放 KCP 与 ICE 后资源关闭。
- 源码检查确认应用数据面应从 `Component.getSocket()` 读写；ICE/STUN 由其内部多路复用。现有 NIO channel dispatcher 不能直接代替该接口，所以新增 `IceComponentDatagramAdapter` 原型，使用由 ICE 组件拥有的 `DatagramSocket` 收发 Link 数据，适配器不关闭 ICE socket。
- 本机同一局域网 ICE connectivity checks 已完成并选出 host candidate pair，随后 KCP 经 ICE 组件 socket 双向传输二进制流。测试确定性丢弃两个初始 KCP 数据报并重排后续一对数据报，仍重传恢复 4 KiB 数据；同时断言 ICE host candidate 与组件 application socket 的本地地址一致，并覆盖 Agent/KCP 资源回收。这证明候选 API、凭据交换、nomination、ICE socket 复用和 LAN KCP 接线可工作；因为两端在同一主机和同一局域网，不构成跨 NAT 或 P2P 可用性证据。低速接收者背压以四块上限队列消费 256 KiB 流并确认完整恢复；关闭测试确认传输关闭可取消阻塞读取，适配器不关闭 ICE 所有的 socket。
- 通过临时 JDK `keytool` 证书在 KCP 字节流上完成 JSSE TLS 1.3 双向身份校验及加密应用数据传输；使用未受信的客户端证书时，服务端拒绝握手。测试证书、私钥和信任库只存在系统临时目录，测试退出时删除。
- 完成同机整链路：ICE → KCP → TLS 1.3 mTLS → Netty HTTP/2 CONNECT → 本机 TCP echo 目标。HTTP/2 CONNECT 的 1 KiB 二进制 DATA 通过 TCP 目标完整往返；客户端 HTTP/2 END_STREAM 映射为目标 TCP 输出半关闭，回程 EOF 映射为响应 END_STREAM。HTTP/2 目前只在测试 profile 引入 `netty-codec-http2`；此集成证明本机编解码和接线，不是多网段性能或公网部署证据。
- ice4j 默认会探测 AWS 映射 harvester；该测试通过 `ice4j.harvest.mapping.aws.enabled=false` 关闭了无关探测，初始化从数秒降至亚秒。产品配置仍需明确决定是否启用云厂商专属 harvester。

Java 21 CI 发现 JSSE 应用缓冲区低于 `SSLSession.getApplicationBufferSize()` 时 `unwrap` 返回 `BUFFER_OVERFLOW`。现已让 TLS 握手和应用数据共用持久的 `TlsEndpoint`，并按 session 容量分配应用缓冲区；macOS ARM64 本机 `mvn verify` 与整链路测试通过，Linux/macOS/Windows Java 21 CI 均通过（Windows ICE 网络集成因 runner 网卡条件跳过）。新增路径选择器集成测试：模拟直连预算超时只触发一次回退，然后建立真实本机 WSS A/C 配对并传输完整二进制数据；权限拒绝和 TLS 身份错误不进入回退。该测试不代替网络级 UDP 阻断。WSS 客户端侧队列限制为 4 条消息，暂停消费时停止申请新消息，恢复读取后按序完整收齐 8 条 4 KiB 负载。最新版 PR 的所有检查均通过。

## P0 放行与后续边界

- POC-02：真实不同出口 A/C 的 ICE nomination、KCP、双向 TLS 1.3、HTTP/2 CONNECT、4096 字节回显和半关闭通过；B 只传递 STUN 与候选信令。STUN 映射、选定候选对与耗时见上方脱敏表，精确地址保存在工作区私有记录。
- POC-03：真实 A/C 的 `auto` 直连通过；独立命名空间内 OS 级 UDP 阻断后的同栈一次 WSS 回退通过；原型内层 mTLS 和 CONNECT 通过，资源释放及进程退出通过。
- 原型代码和短时测试凭据不具备生产授权、配额及多租户边界。它们只证明 Java 技术路线可行，正式产品实现从 CORE-01/02 的版本化契约与身份授权开始。
- Java 21 的新 CI 检查、Windows 真正可用网络下的 ICE、长时间网络与慢 Relay 容量仍需后续验证。Windows hosted runner 的 ICE 跳过不能当作通过。
- 依赖许可证按上游候选记录；`kcp-fec` 是运行时必需类来源，已排除其无用的 `netty-all` 传递包。正式引入运行时依赖前继续核对维护状态和最终制品许可清单。
- Rust 运行时在迁移及恢复演练完成前保留，不因 P0 原型放行而删除。
