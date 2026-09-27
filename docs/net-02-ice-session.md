# NET-02：ICE 直连、自动选路与生命周期

## 已实现

`JLShellLink` 和 `JLShellLinkPlugin` 当前工作分支已将 ICE 传输接入授权客户端与 Agent：

- A 与 C 使用 Website 控制 WSS 完成身份绑定后的 ICE 凭据、候选及路径选择交换。只接受当前授权 `sessionId + generation`，双方的 `PATH_READY` 必须引用同一对已交换候选。
- A/C 分别以 ice4j 收集受限 UDP 候选，并将选中路径接入 KCP、TLS 1.3、HTTP/2 CONNECT。TLS 对端公钥必须与 Website 授权返回的节点指纹一致。
- `ReliableCarrierBridge` 提供有界双向字节流桥接。业务票据与目标只交给最终选中的目标建流操作；ICE 信令组件不接触访问票据或目标。
- `AUTO` 同时准备直连和 WSS Relay。一个安全 carrier 获胜后取消另一条路径；迟到 carrier 关闭。只有目标 CONNECT 前的可重试网络错误可以回退，授权、身份、票据和协议错误失败关闭。
- Website Relay 在并行准备前按 session 激活额度，使 Agent 能领取对应 Relay 请求；若直连获胜，Website 结算已转发的 carrier 字节、释放未用额度并关闭未选中的 WSS Relay。Relay 配额不足不能覆盖成功的直连，也不会被伪装成网络成功。
- `DIRECT_ONLY` 不尝试 Relay；`RELAY_ONLY` 跳过 ICE。插件高级设置可选择策略及填写最多四个数值 STUN 地址。
- 每条目标 TCP 隧道使用独立 Website session/generation，避免同一 Agent 上后续授权覆盖并发隧道的 ICE 会话。建连失败、用户关闭或隧道结束后撤销 Website session；重连重新申请 session 和一次性票据。
- 插件每五秒在内存中比较网卡状态摘要。检测到网络变化时取消旧 generation 的候选建连；已建立流保持当前路径，重建流重新授权。
- Client WSS 信令具有指数退避重连。连接中断会使未完成 ICE generation 失败，后续隧道重新授权。插件显示控制信令状态、路径、耗时及固定失败类别。
- ice4j/Jitsi 的 INFO 日志会包含 ICE 候选地址和凭据，因此运行时将相关 JUL logger 降到 WARNING；Link 诊断只保留固定状态码，不输出候选、凭据或目标信息。

## 本地验证

当前实现已运行以下验证：

- `JLShellLink`：`mvn -o -pl link-client,link-agent,link-server,link-transport -am verify`。
- `JLShellLinkPlugin`：将 Link `0.1.0-SNAPSHOT` 安装到本机 Maven 仓库后，运行 `mvn -o -Djlshell.link.version=0.1.0-SNAPSHOT verify`。
- `JLShellWebsite/frontend`：`npm run build`，包括 Vue/TypeScript 类型检查和 Vite 生产构建。
- KCP 桥测试覆盖双向大载荷回显；协调器测试覆盖 AUTO 并行胜出及迟到路径清理；授权与信令测试覆盖邀请身份、generation 和网络失败边界。

## 尚待外部验收

本地测试未替代产品公网验收。仍需用不同公网出口的 A/C、正式 Website 票据及在线 Java Agent 验证：

1. 两侧 STUN 映射、最终候选对、建连耗时和数据路径；证明直连业务流量不经 B。
2. 禁止或阻断 UDP 后，`AUTO` 是否只因网络失败降级到 Relay；`DIRECT_ONLY` 是否明确失败且不经 B。
3. Website 授权拒绝、撤销和重连后重新授权；并发目标流彼此独立。
4. 长时间运行、账号/策略变化、网络切换、控制 WSS 重连和各平台运行时行为。

正式验证记录不得包含账号资料、主机名、私网地址、访问令牌或原始候选日志。当前分支尚未合并、发布或部署，故不能标记为已通过公网产品验收。
