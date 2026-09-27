# NET-02 ICE 会话基础

## 本次实现

`link-transport` 新增 `Ice4jDirectSession`，为单个 Website 授权的 A—C session generation 创建有界 ICE Agent：

- 本地创建 ICE credentials，收集 UDP host/server-reflexive/peer-reflexive 候选，并生成本代次唯一的 candidate ID。
- 只接受当前 `sessionId` 和 `generation` 的远端 ICE 消息；远端凭据先于候选，`ICE_END` 后开始 connectivity checks。
- 候选数、STUN 服务器数、nominated path 检查时限、数据报上限和接收轮询时限均受配置约束。
- 不发布 loopback、link-local、any-local 或 multicast 地址；只允许引用本次授权交换中已登记的候选对。
- 选中候选对后返回 `IceSelectedDatagramPath` 和 `DIRECT` `PATH_READY` 消息；关闭会释放 ICE Agent、定时器和数据报接收适配器。
- Link 实现不主动记录 ICE credentials、候选地址或 STUN 地址；对应信号和配置的默认 `toString()` 也会脱敏。ice4j 的可选 AWS 地址映射器在初始化前关闭；Link 候选由显式配置的 STUN server 收集。发布前仍需检查 ice4j 自身日志及最终日志配置。

`link-transport/pom.xml` 将固定版本的 `org.jitsi:ice4j:3.2-17-geea6cd3` 从测试依赖提升为运行依赖。上游许可证为 Apache-2.0，来源为 [ice4j 上游仓库](https://github.com/jitsi/ice4j)；编译依赖树包括 `java-sdp-nist-bridge`、`weupnp`、`jitsi-utils` 和 `jicoco-config` 及其编译传递依赖。最终发行物仍需逐项核对所有传递依赖许可证。

## 完成边界

这是可复用的 ICE 会话层，不代表桌面客户端或 Java Agent 已完成产品接线。后续仍需实现 A/C 控制信令会话和邀请处理，把选中的 ICE 数据报路径接入 KCP、双向 TLS 1.3、HTTP/2 CONNECT 与目标 ACL，再交给 `ConnectionCoordinator` 执行 AUTO/RELAY_ONLY/DIRECT_ONLY。当前没有真实公网产品路径验收，也不能用此前的原型结果替代该验收。

此版本已通过 `link-transport` 离线编译；没有运行测试。Java 21 与 Linux/macOS/Windows 的运行时兼容性、Windows 可用网卡下的 ICE 行为、长时间运行及传递依赖许可检查仍待验证。
