# Java 网络原型记录

- 日期：2026-09-24
- 分支：`feature/java-link-poc`
- Java 基线：Java 21；本机当前默认运行时为 OpenJDK 26.0.1，Maven 3.9.16
- 状态：POC-01 本机 socket 原型通过；POC-02 已验证同机 LAN ICE nomination、KCP 丢包/重排恢复、TLS/HTTP2 CONNECT 与半关闭；跨 NAT、背压和取消未验证；POC-03 未开始；不得据此宣称已具备 P2P 或生产中继

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
- 结果：成功；`link-core`、`link-transport` 按 `--release 21` 编译，3 个 POC 测试通过。
- 实际 JVM：OpenJDK 26.0.1；该命令限制了 Java 21 API 编译级别，但并非在 JDK 21 运行。后续 CI/复核需用 JDK 21 重跑。
- 机器：macOS ARM64；Linux x64 和 Windows x64 尚未运行。
- 候选依赖树：ice4j 引入 JNA、Kotlin/Jitsi utilities 和 weupnp；KCP 1.6 的 kcp-fec POM 引入 `netty-all`。需要核对只使用 KCP core 所需的最小 Netty 模块并排除未用 native 包，再运行 KCP 回归。
- 当前可关闭范围：POC-01 的最小 socket 分流、同 socket KCP 接线和本机资源回收子项已完成。仍需在 Java 21 运行时重跑，并审核候选依赖的完整许可证/平台兼容信息；POC-01 整体保持进行中。

## POC-02：ICE 与端到端直连进展

- 增加 `IceKcpTls13IntegrationTest`，调用固定候选版本的 Agent、Stream、Component API，在本机活动的非点对点 IPv4 网卡收集候选、交换 ICE 凭据并完成 nomination；再把底层 KCP 引擎连接到 ICE `Component.getSocket()`，通过选中的候选对往返二进制数据，并确认释放 KCP 与 ICE 后资源关闭。
- 源码检查确认应用数据面应从 `Component.getSocket()` 读写；ICE/STUN 由其内部多路复用。现有 NIO channel dispatcher 不能直接代替该接口，所以新增 `IceComponentDatagramAdapter` 原型，使用由 ICE 组件拥有的 `DatagramSocket` 收发 Link 数据，适配器不关闭 ICE socket。
- 本机同一局域网 ICE connectivity checks 已完成并选出 host candidate pair，随后 KCP 经 ICE 组件 socket 双向传输二进制流。测试确定性丢弃两个初始 KCP 数据报并重排后续一对数据报，仍重传恢复 4 KiB 数据；同时断言 ICE host candidate 与组件 application socket 的本地地址一致，并覆盖 Agent/KCP 资源回收。这证明候选 API、凭据交换、nomination、ICE socket 复用和 LAN KCP 接线可工作；因为两端在同一主机和同一局域网，不构成跨 NAT 或 P2P 可用性证据。低速接收者背压和取消仍待验证。
- 通过临时 JDK `keytool` 证书在 KCP 字节流上完成 JSSE TLS 1.3 双向身份校验及加密应用数据传输；使用未受信的客户端证书时，服务端拒绝握手。测试证书、私钥和信任库只存在系统临时目录，测试退出时删除。
- 完成同机整链路：ICE → KCP → TLS 1.3 mTLS → Netty HTTP/2 CONNECT → 本机 TCP echo 目标。HTTP/2 CONNECT 的 1 KiB 二进制 DATA 通过 TCP 目标完整往返；客户端 HTTP/2 END_STREAM 映射为目标 TCP 输出半关闭，回程 EOF 映射为响应 END_STREAM。HTTP/2 目前只在测试 profile 引入 `netty-codec-http2`；此集成证明本机编解码和接线，不是多网段性能或公网部署证据。
- ice4j 默认会探测 AWS 映射 harvester；该测试通过 `ice4j.harvest.mapping.aws.enabled=false` 关闭了无关探测，初始化从数秒降至亚秒。产品配置仍需明确决定是否启用云厂商专属 harvester。

下一步仍需完成：

- 通过公网两端执行跨 NAT 实验，记录映射地址、候选对、建连耗时及实际路径。
- 为 KCP over ICE 补低速接收者背压、取消测试，并将链路测试移至 Java 21 运行时重跑。
- 连接 TLS 1.3 双向校验、HTTP/2 CONNECT 和目标 TCP 服务，并记录 B 不可见业务明文的证据。

## 尚未完成的 POC-02/03 门槛

- 跨 NAT 候选协商；同机/同 LAN 测试和 UDP echo 不算跨 NAT 通过。
- 可靠有序双向通道已在同机 LAN 覆盖二进制往返、两个初始数据报丢弃、数据报重排、TCP/HTTP2 半关闭与资源回收；低速接收者背压和取消尚未验证。
- A—C TLS 1.3 + HTTP/2 CONNECT 端到端目标访问，B 不可见明文。
- 阻断 UDP 后经 WSS B 中继完成同一安全链路；认证或授权失败不能回退放行。
- Linux x64、macOS ARM64、Windows x64 的依赖和关闭行为。
- 每项记录库版本、许可证、传递依赖、抓取到的本地端口、实际路径、环境和脱敏证据。

POC-03 中继尚未开始：仍需实现 B 的测试 WSS 配对管道、UDP 阻断回退、认证失败拒绝、半开配对清理、慢消费者与断线回收。
