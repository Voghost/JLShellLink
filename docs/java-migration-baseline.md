# JLShell Link Java 重构基线

- 日期：2026-09-24
- 本记录：SET-01 首批基线；只把 Link 最新 develop 用作本次 POC 分支基线
- 目标分支：`feature/java-link-poc`，起自 `origin/develop` 的 `05049b1427c7efb033dae4388eaa4c8b068e6390`
- 范围：记录本次工作开始时四个仓库的本地状态；没有清理其他仓库分支、工作区或文件

## 仓库状态

| 仓库 | 检查时分支与 HEAD | 跟踪状态 | 本次处理 |
|---|---|---|---|
| JLShellLink | `develop` / `a836db9a0c6a79c91c475c67bce95e7a7be30a31` | 检查时显示落后 `origin/develop` 44 个提交；随后只 fetch 此远端并确认最新为 `05049b1427c7efb033dae4388eaa4c8b068e6390` | 在最新 develop 上新建 `feature/java-link-poc`；保留 `scripts/__pycache__/create-plugin-runtime-bundle.cpython-314.pyc` |
| JLShellLinkPlugin | `fix/peer-id-encoding` / `45414a8ad0fbbb2ffed94e5e580319165233d3a1` | 刷新后 `origin/develop=4db4b8cd287c41dab542e456d851832f4f695a09`；当前修复分支原样保留 | 未切分支、未改文件 |
| JLShellWebsite | `feature/full-bleed-home-background` / `076e588fa3589d47ffd8736ab282e75c5f6071e8` | 远端 `develop` 不存在，`main=b0b0ab9abeb3f21a10a423aa84f1d2b9143b89d2`；`git fetch origin develop` 返回无此 ref。旧本地 `origin/develop=673e38d8e099ba326e85b22f15e14dd8f564ae99` 是过期跟踪引用 | 保留首页改动；未切分支、未改文件 |
| JLShell | `release/0.1.66` / `8b102af4254d0e7388bc5b1e28094abdd1c7284c` | 刷新后 `origin/develop=9ced731d2588dbb31100b99cf19c40ee46952d3d`；当前 release 分支原样保留 | 未切分支、未改文件 |

Link、插件、桌面已刷新远端 develop 跟踪引用；Website 远端没有 develop，仅有 main。Website 当前首页功能分支包含既有工作，Link 插件和桌面端也位于非 develop 分支；这些现有分支均未改动。后续 Website 编码需先恢复项目约定的 develop 流程，不能直接在 main 开发或覆盖首页改动。

## 数据和兼容边界

- 不在 POC 阶段迁移或改写 Website 数据库，不更换账号、设备、Agent 或项目绑定 ID。
- v2 身份、票据、精确目标 ACL、Relay 配额和租约迁移按获认可的 Java 架构/实施计划执行。
- SSH 主机密钥验证必须保留真实目标身份；隧道的 loopback 地址不能成为目标信任身份。
- 当前 Rust 工作树、插件 Connector 代码、Website 接口和历史数据均保持原状，直至明确的迁移阶段。
- 已发现的本地 `.pyc` 文件属于开始前未跟踪内容，已保留，不纳入本次改动。

## POC 分支和恢复点

- 当前 Java POC 基线：`05049b1427c7efb033dae4388eaa4c8b068e6390`
- 尚未建立 Java 对等生产服务；回滚 POC 只需停止合并 Java 原型分支，不需要数据库恢复。
- POC 完成前不得删除 Cargo workspace、现有 Rust releases、凭据或 Agent 数据。
- 正式迁移的恢复点、备份和回滚条件由 `MIG-01` 另行记录和演练。
