# Java Maven 制品发布记录

`Publish Java libraries` 只允许从 `main` 手动运行，并要求输入严格 SemVer 版本。发布使用
GitHub Actions checkout 得到的完整 commit SHA，通过 `jlshell.build.revision` 写入每个 JAR
的 `META-INF/MANIFEST.MF` 中 `JLShell-Build-Revision` 字段。工作流在调用 Maven deploy 前先
构建制品，逐个核对 JAR 内的 revision 和对应 CycloneDX JSON BOM，再发布制品。

每个 Java Maven 模块在发布时同时部署 CycloneDX XML/JSON 依赖清单，清单排除 test scope，
并包含 Maven 元数据中可用的许可声明。依赖坐标和固定版本也由随 Maven 制品部署的 POM 与
parent POM 给出；构建没有把相邻工作区源码作为隐式依赖。`JLShell-Build-Revision` 与 BOM
用于来源和依赖追溯，不是密码学签名、漏洞扫描或许可批准；无许可声明的组件仍需人工核实。
Java Agent 平台包另将 Agent 模块的 JSON
SBOM 与运行包、manifest 和逐文件 SHA-256 一起归档。
