# Java Maven 制品发布记录

`Publish Java libraries` 只允许从 `main` 手动运行，并要求输入严格 SemVer 版本。发布使用
GitHub Actions checkout 得到的完整 commit SHA，通过 `jlshell.build.revision` 写入每个 JAR
的 `META-INF/MANIFEST.MF` 中 `JLShell-Build-Revision` 字段。工作流在 Maven deploy 后逐个检查
生成的 JAR 都带有该字段和本次源码 SHA。

依赖坐标和固定版本由随 Maven 制品部署的 POM 与 parent POM 给出；构建没有把相邻工作区源码
作为隐式依赖。这个 manifest 字段与 POM 可用于来源追溯，不是密码学签名。Java Agent 平台包
另有独立 manifest、平台 runtime 及逐文件 SHA-256。
