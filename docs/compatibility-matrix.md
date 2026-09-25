# JLShell Link v2 兼容矩阵

| 组件 | 当前开发版本 | 协议 | 兼容范围 |
|---|---|---|---|
| `link-core` / `link-transport` | `0.1.0-SNAPSHOT` | `link-v2` | Java 21+；公共 DTO 和安全规则的唯一权威实现 |
| `link-client` | `0.1.0-SNAPSHOT` 骨架 | `link-v2` | 后续供 JLShellLinkPlugin 进程内使用；不依赖 JavaFX/Spring |
| `link-agent` | `0.1.0-SNAPSHOT` 骨架 | `link-v2` | 后续 C 独立程序；不依赖 Spring Boot |
| `link-server` | `0.1.0-SNAPSHOT` 骨架 | `link-v2` | 后续 B 数据面；不依赖 Website JPA/领域类 |
| `link-server-spring` | `0.1.0-SNAPSHOT` 骨架 | `link-v2` | Website Spring 生命周期适配层 |
| JLShellWebsite | v1 仍在运行 | v1 | v2 API 尚未接入；接入后同时保留旧路由迁移窗口 |
| JLShellLinkPlugin | 当前 Rust Connector 外壳 | v1 | 后续依赖已发布的 `link-client`；不使用相邻源码路径 |
| Rust Agent/Connector/Relay | 历史运行时 | `/jlshell/link/tcp/1.0.0` | 与 `link-v2` 不做 wire 兼容；迁移/恢复演练前保留 |

兼容规则：协议主版本不自动降级；安全关键字段和算法不做宽松兼容。Maven 库、Website、Plugin SDK 和插件分别版本化，通过本表声明支持范围。公开制品前以固定版本替换 `SNAPSHOT`，并由各消费仓库的契约向量验证。
