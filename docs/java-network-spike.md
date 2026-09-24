# Java 网络原型记录

- 日期：2026-09-24
- 分支：`feature/java-link-poc`；B UDP 入口复测分支：`feature/java-link-b-stun-poc`
- Java 基线：Java 21；本机当前默认运行时为 OpenJDK 26.0.1，Maven 3.9.16
- 状态：POC-01 本机 socket 原型通过；POC-02 已验证同机 LAN ICE nomination、KCP 丢包/重排恢复、低速接收者背压与关闭取消、TLS/HTTP2 CONNECT 和半关闭；POC-03 已在本机 WSS 配对管道上验证内层 mTLS 1.3、HTTP/2 CONNECT 到本机 TCP echo 目标和半关闭，并覆盖有界慢消费者队列。当前 11 项 Java 测试及 Linux/macOS/Windows Java 21 CI 均通过，Windows hosted runner 因没有 ice4j 可用候选而通过 `JLSHELL_LINK_ICE_TEST_ENABLED=false` 跳过 ICE 集成测试；该测试在其他环境默认启用。真实 A/C 间已验证 B 自托管 STUN 辅助交换候选后的 UDP 双向打洞及 B 上 Java TCP 透明转发，但跨 NAT 的 ICE/KCP/TLS/HTTP2 整链路和真实 UDP 阻断后的 WSS 自动回退仍未验证；不得据此宣称已具备产品 P2P 或生产中继。

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

下一步要把已证明可行的 B 自托管 STUN 与跨 NAT UDP 候选路径接入 ice4j 的真实 ICE checks、KCP、mTLS、HTTP/2 CONNECT，并把 B 的候选交换替换为带鉴权的控制平面协议；随后受控阻断直连 UDP 并验证 WSS 自动降级。当前只保持现有 Rust 运行时代码，不据此开始退役。

## 依赖候选

| 组件 | 固定候选 | 许可证 | 当前决策 |
|---|---|---|---|
| Netty | `4.2.18.Final` | Apache-2.0 | 原型 BOM 固定。Netty 官方将此列为当前稳定推荐版；产品依赖目前只列出 transport/buffer，不直接配置 native transport。KCP 候选的传递依赖树会解析到更多 Netty/native 模块，进入生产依赖前必须缩减并复测。 |
| ice4j | `org.jitsi:ice4j:3.2-17-geea6cd3` | Apache-2.0 | 固定待评估版本，只在测试 profile。`Component.getSocket()` 提供应用数据 socket；`CandidatePair` 的 UDP socket API 已弃用，且返回 `DatagramSocket` 包装器。同机 LAN 候选检查和 nomination 已通过；跨 NAT 仍需实测。额外 Jitsi/Kotlin 依赖仍需评估。 |
| Java KCP | `com.github.l42111996:kcp-base:1.6`（Central 可见版本）；上游 README 另列 `1.6.2` | Apache-2.0 | 只放在默认启用的 Maven 测试候选 profile，不加入产品运行依赖。高层 `KcpClient` 会创建自己的 `NioDatagramChannel`；底层 `Kcp` 支持自定义输出，可由应用接到 ICE 已选 socket。候选 POM 引入 `netty-all`，当前 BOM 会解析到大量 Netty 模块及平台 native 包，依赖缩减、长时可靠性和维护风险仍未通过。 |
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
- 候选依赖树：ice4j 引入 JNA、Kotlin/Jitsi utilities 和 weupnp；KCP 1.6 的 kcp-fec POM 引入 `netty-all`。需要核对只使用 KCP core 所需的最小 Netty 模块并排除未用 native 包，再运行 KCP 回归。
- 当前可关闭范围：POC-01 的最小 socket 分流、同 socket KCP 接线和本机资源回收子项已完成。仍需审核候选依赖的完整许可证/平台兼容信息；POC-01 整体保持进行中。

## POC-02：ICE 与端到端直连进展

- 增加 `IceKcpTls13IntegrationTest`，调用固定候选版本的 Agent、Stream、Component API，在本机活动的非点对点 IPv4 网卡收集候选、交换 ICE 凭据并完成 nomination；再把底层 KCP 引擎连接到 ICE `Component.getSocket()`，通过选中的候选对往返二进制数据，并确认释放 KCP 与 ICE 后资源关闭。
- 源码检查确认应用数据面应从 `Component.getSocket()` 读写；ICE/STUN 由其内部多路复用。现有 NIO channel dispatcher 不能直接代替该接口，所以新增 `IceComponentDatagramAdapter` 原型，使用由 ICE 组件拥有的 `DatagramSocket` 收发 Link 数据，适配器不关闭 ICE socket。
- 本机同一局域网 ICE connectivity checks 已完成并选出 host candidate pair，随后 KCP 经 ICE 组件 socket 双向传输二进制流。测试确定性丢弃两个初始 KCP 数据报并重排后续一对数据报，仍重传恢复 4 KiB 数据；同时断言 ICE host candidate 与组件 application socket 的本地地址一致，并覆盖 Agent/KCP 资源回收。这证明候选 API、凭据交换、nomination、ICE socket 复用和 LAN KCP 接线可工作；因为两端在同一主机和同一局域网，不构成跨 NAT 或 P2P 可用性证据。低速接收者背压以四块上限队列消费 256 KiB 流并确认完整恢复；关闭测试确认传输关闭可取消阻塞读取，适配器不关闭 ICE 所有的 socket。
- 通过临时 JDK `keytool` 证书在 KCP 字节流上完成 JSSE TLS 1.3 双向身份校验及加密应用数据传输；使用未受信的客户端证书时，服务端拒绝握手。测试证书、私钥和信任库只存在系统临时目录，测试退出时删除。
- 完成同机整链路：ICE → KCP → TLS 1.3 mTLS → Netty HTTP/2 CONNECT → 本机 TCP echo 目标。HTTP/2 CONNECT 的 1 KiB 二进制 DATA 通过 TCP 目标完整往返；客户端 HTTP/2 END_STREAM 映射为目标 TCP 输出半关闭，回程 EOF 映射为响应 END_STREAM。HTTP/2 目前只在测试 profile 引入 `netty-codec-http2`；此集成证明本机编解码和接线，不是多网段性能或公网部署证据。
- ice4j 默认会探测 AWS 映射 harvester；该测试通过 `ice4j.harvest.mapping.aws.enabled=false` 关闭了无关探测，初始化从数秒降至亚秒。产品配置仍需明确决定是否启用云厂商专属 harvester。

Java 21 CI 发现 JSSE 应用缓冲区低于 `SSLSession.getApplicationBufferSize()` 时 `unwrap` 返回 `BUFFER_OVERFLOW`。现已让 TLS 握手和应用数据共用持久的 `TlsEndpoint`，并按 session 容量分配应用缓冲区；macOS ARM64 本机 `mvn verify` 与整链路测试通过，Linux/macOS/Windows Java 21 CI 均通过（Windows ICE 网络集成因 runner 网卡条件跳过）。新增路径选择器集成测试：模拟直连预算超时只触发一次回退，然后建立真实本机 WSS A/C 配对并传输完整二进制数据；权限拒绝和 TLS 身份错误不进入回退。该测试不代替网络级 UDP 阻断。WSS 客户端侧队列限制为 4 条消息，暂停消费时停止申请新消息，恢复读取后按序完整收齐 8 条 4 KiB 负载。最新版 PR 的所有检查均通过。

下一步仍需完成：

- 通过公网两端执行跨 NAT 实验，记录映射地址、候选对、建连耗时及实际路径。
- 等待 Java 21 Linux/macOS 完整 ICE 链路和 Windows 可运行测试的 CI 结果；Windows hosted runner 当前无法提供 ICE 所需网卡条件。
- 连接 TLS 1.3 双向校验、HTTP/2 CONNECT 和目标 TCP 服务，并记录 B 不可见业务明文的证据。

## 尚未完成的 POC-02/03 门槛

- 跨 NAT 候选协商；同机/同 LAN 测试和 UDP echo 不算跨 NAT 通过。
- 可靠有序双向通道已在同机 LAN 覆盖二进制往返、两个初始数据报丢弃、数据报重排、低速接收者下 4 块应用队列上限、取消、TCP/HTTP2 半关闭与资源回收；本机 WSS 客户端侧也覆盖 4 条消息上限、暂停取数与恢复后的有序完整传输。生产 Relay 慢连接下的排队和资源限额仍待验证。
- A—C TLS 1.3 + HTTP/2 CONNECT 到 TCP echo 目标已在同机 LAN 及本机 WSS 中继分别通过；跨 NAT 和真实部署网络尚未验证。WSS 测试还断言 relay 捕获帧中不包含 CONNECT 明文。
- 本机 WSS 测试已验证 A/C 主动出站、Bearer 凭据拒绝、二进制双向转发和孤立/断线配对清理。同一配对管道现承载 A—C 内层 TLS 1.3 双向证书认证与 HTTP/2 CONNECT 到本机 TCP echo 目标的 1 KiB DATA/END_STREAM；测试捕获的 relay 帧不含 CONNECT 明文负载。客户端慢消费者队列有界并可恢复；模拟直连超时后已在真实本机 WSS 配对上传输二进制数据，仍需用真实 UDP 阻断验证完整网络选路。生产 Relay 慢连接资源限额与跨网络验收未完成。认证或授权失败不能回退放行。
- Linux x64、macOS ARM64、Windows x64 的依赖和关闭行为。
- 每项记录库版本、许可证、传递依赖、抓取到的本地端口、实际路径、环境和脱敏证据。

POC-03 仍是测试范围的本机 WSS 配对原型；多平台基础行为和客户端慢消费者边界已覆盖。仍需验证生产 Relay 的有界排队、真实 UDP 阻断回退，以及不同出口网络的 NAT 穿透。

## POC 阶段选型结论

- Java 21 + Maven 的运行与编译链路可行；Linux x64、macOS ARM64、Windows x64 上的 Java/WSS/KCP 测试均通过。Windows hosted runner 没有可用 ICE host candidate，ICE 集成测试在 CI 明确跳过，不能据此宣称 Windows ICE 已验证。
- Netty `4.2.18.Final` 暂保留为 HTTP/2 编解码候选；目前只进入原型依赖，尚未用于正式产品传输模块。
- ice4j `3.2-17-geea6cd3` 暂保留为 ICE API 候选。同机 LAN host candidate nomination 及 socket 复用已验证；真实 NAT 映射、跨出口连通性、Windows ICE 和许可/传递依赖审查仍未完成。
- Java KCP `kcp-base:1.6` 仅用于原型测试，不加入产品运行依赖。自定义 `Kcp` 引擎可绑定 ICE 已选 socket并通过确定性丢包/重排及背压用例；`kcp-base` 的 `netty-all` 传递树、长时间可靠性和维护状态未达到生产准入条件。
- 本机 WSS 证明 A/C 主动出站、配对认证、转发内层加密字节以及 TLS/HTTP2/CONNECT 接线可行；Relay 服务实现、真实 UDP 阻断下的选路、跨 NAT 和慢网络容量限制尚未验证。
- 阶段决策：保留上述候选用于 POC 后续实验，不将它们视为已批准的生产技术栈。Java 数据面方向目前没有被本机验证否决，但 P0 仍未通过，不能开始切换产品运行时或退役 Rust。
