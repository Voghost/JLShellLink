# SRV-01 生产入口验收记录（2026-09-26）

## 范围与部署

- Website 正式部署在 NAS，后端镜像为 `main-103-218cb8c7e2d8`，`USE_JAVA_LINK=true`，私有 TLS 证书 SAN 为 `jlink.oomn.net`，有效至 2027-09-26。
- 公网入口 B 为 `8.210.149.65`。`jlshell.oomn.net` 网站和 `jlink.oomn.net` Link 独立域名由 1Panel OpenResty 在 443/TCP 终止 Let's Encrypt 通配符证书；公网证书覆盖两个主机名，有效至 2026-11-28。
- `jlink.oomn.net` 经本机 `https://127.0.0.1:13575`、FRPS TCP 与 NAS 内置 Java Link WSS 相连。OpenResty 设置 `proxy_ssl_name jlink.oomn.net`、私有 CA 信任证书及 `proxy_ssl_verify on`；配置校验和热加载通过。
- 公网 B 的独立 Java `link-stun-server` 容器使用 host 网络直接监听 13576/UDP，镜像 `jlshell-link-stun:99ede29`，运行构建来自已合入 `develop` 的 PR #44。JAR SHA-256 为 `36f468b5e9911273fbe2a65244b6a38706a48b9979e42e752909d481def9395f`，与本地 `mvn -B -ntp -pl link-stun-server -am verify` 通过的产物一致。容器配置为非 root、只读文件系统、移除 Linux capabilities 与自动重启。
- NAS FRPC 只撤下 `jlshell-link-stun` UDP 代理并热重载；Website、WSS 和官方 Relay 的 FRPC 代理均保持 `running`。公网 B 的 FRPS 仍监听 WSS TCP 13575，Java 直接监听 STUN UDP 13576。

## 配置落点与复用清单

| 位置 | 本次设置 | 迁移到其他环境时 |
| --- | --- | --- |
| NAS Website Compose 工作目录 `/vol2/1000/Docker/compose/jlshell-site/.env` | `USE_JAVA_LINK=true`、`JLSHELL_LINK_SERVER_TLS_MODE=private`、`JLSHELL_LINK_SERVER_TLS_DOMAIN=jlink.oomn.net` | 换成新 Link 域名，继续由部署脚本生成私有 CA 与服务端证书；不要提交 `.env` |
| NAS 同目录 `secrets/` | `link-private-ca.crt` 为可分发的 CA 公证书；CA 私钥、`link-server.p12`、密码仅留在 NAS | 只向反代主机复制 CA 公证书；确认目录和证书权限 |
| 公网 B 的 `/opt/1panel/www/sites/jlink.oomn.net/proxy/root.conf` | 原有 `proxy_pass https://127.0.0.1:13575` 和 WebSocket 代理保留；设置 `proxy_ssl_server_name on`、`proxy_ssl_name jlink.oomn.net`、`proxy_ssl_trusted_certificate /www/sites/jlink.oomn.net/proxy/link-private-ca.crt`、`proxy_ssl_verify on`、`proxy_ssl_verify_depth 2` | 域名和 CA 路径随站点变化；该文件受 1Panel 管理，界面保存代理配置后复查，尽量迁入持久自定义配置 |
| 公网 B 的 1Panel/OpenResty 站点 | `jlink.oomn.net:443/TCP` 使用覆盖该域名的公签证书，回源经本机 FRPS TCP 13575 | 公签证书与私有 CA 各司其职；改动后检查 OpenResty 配置、热加载并公网复查 HTTPS/WSS 鉴权入口 |
| NAS FRPC 与公网 B | FRPC 仅移除 `jlshell-link-stun` UDP 代理；B 上的 `jlshell-link-stun` Docker 容器用 host 网络直接监听 `13576/UDP` | 不要删除其他 FRPC 代理；放行云安全组和 B 主机防火墙的 UDP 13576，从两个不同出口核对公网映射 |
| 公网 B 的 UFW | 在宽泛 TCP 允许规则之前拒绝外部直连 `13575/TCP`，保留本机回环访问 | 检查规则顺序及 IPv4/IPv6；公网客户端应只访问 443，STUN 使用 UDP 13576 |

这些是本次实例的**运行配置记录**，不是 Jenkins 自动管理项。不同项目复用时，应把域名、证书路径、FRP 入口、端口及防火墙规则按该项目网络拓扑调整；不要原样复制生产 `.env` 或任何私钥。部署步骤以 Website 的 `docs/docker-deployment.md` 和本仓库的 `docs/public-stun-deployment.md` 为准。

## 公网探测

| 项目 | 结果 |
| --- | --- |
| `https://jlshell.oomn.net/` | 200，公网 TLS 验证通过 |
| `https://jlink.oomn.net/link/v2/control-challenges`，伪造无效身份 | 401，公网 TLS 验证通过，命中 Java Link 鉴权边界 |
| `wss://jlink.oomn.net/link/v2/control`，带 WebSocket Upgrade 和伪造无效身份 | 401，公网 TLS 验证通过，命中 Java Link 鉴权边界 |
| 外网直接连接 `8.210.149.65:13575/TCP` | UFW 加入针对该端口的拒绝规则后超时；1Panel 本机 443 回源仍可用 |
| A 出口向 `8.210.149.65:13576/UDP` 发送 STUN Binding | 响应源 `8.210.149.65:13576`，映射 `117.143.39.250:2057`，约 209 ms |
| C 出口向同一 STUN 入口发送 Binding | 响应源 `8.210.149.65:13576`，映射 `61.140.95.147:15618`，约 49 ms |
| 防火墙收紧后再从 A 出口探测 STUN | 仍返回 `117.143.39.250:2058` 公网映射 |

探针逐项校验 Binding Success 类型 `0x0101`、STUN magic cookie、随机事务 ID、响应来源和 `XOR-MAPPED-ADDRESS`。两个出口真实不同；没有用 B 本机回环结果代替公网验收。公网 UDP 13576 已收到外部请求并返回有效映射，因此云安全组与主机防火墙的这条接入路径实际可用。

## 发现与修复

切换前，同一公网 UDP 端口经 FRPS→FRPC→NAS 转发，A/C 均能收到 Binding 响应，但映射地址均为 `172.27.0.1` 私网容器网关；端口可达不等于 STUN 可用。移除该 FRP UDP 代理并在 B 直接监听后，两端均得到各自公网映射。1Panel 原配置只启用了 `proxy_ssl_server_name`，没有启用回源证书校验；现已指定私有 CA、正确的 TLS 主机名和 `proxy_ssl_verify on`，热加载后外网鉴权入口仍正常。

## 验收边界

以上完成 SRV-01 的**生产基础设施启用**：正式公网 TLS、1Panel 反代、经私有 CA 验证的回源、针对 13575 的防火墙收紧、Link WSS 鉴权入口可达，以及双出口公网 STUN 映射。无效身份返回 401 不能代替生产 A/C 持真实票据建立 101 WebSocket、完成一次授权业务流。该生产业务会话仍需另行验收；正式 ICE/direct 产品选路继续由 NET-02 跟踪。本文不含令牌、私钥或客户端凭据。
