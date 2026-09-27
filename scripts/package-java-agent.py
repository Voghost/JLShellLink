#!/usr/bin/env python3
"""Build a platform-specific Java 21 Agent package with a trimmed private runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PREFIX = "jlshell-link-agent-java"
REQUIRED_MODULES = ["java.se", "jdk.crypto.ec", "jdk.unsupported"]
OPTIONAL_MODULES = ["jdk.jfr", "jdk.sctp"]
PACKAGE_FILES = [
    (Path("docs/agent-cli.md"), Path("docs/agent-cli.md")),
    (Path("docs/agent-service.md"), Path("README.md")),
    (Path("scripts/java-agent/run-agent.sh"), Path("scripts/java-agent/run-agent.sh")),
    (Path("scripts/java-agent/stop-agent.sh"), Path("scripts/java-agent/stop-agent.sh")),
    (Path("scripts/java-agent/install-user-service.sh"), Path("scripts/java-agent/install-user-service.sh")),
    (Path("scripts/java-agent/install-windows-service.ps1"), Path("scripts/java-agent/install-windows-service.ps1")),
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def java_major(java: Path) -> int:
    result = subprocess.run([str(java), "-version"], check=True, capture_output=True, text=True)
    match = re.search(r'(?m)(?:openjdk|java) version "(\d+)', result.stderr + result.stdout)
    if not match:
        raise RuntimeError("无法读取打包 JDK 的主版本")
    return int(match.group(1))


def platform_id() -> tuple[str, str, str]:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Linux":
        os_id = "linux"
    elif system == "Darwin":
        os_id = "macos"
    elif system == "Windows":
        os_id = "windows"
    else:
        raise RuntimeError(f"不支持的打包操作系统：{system}")
    arch_map = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}
    try:
        arch = arch_map[machine]
    except KeyError as failure:
        raise RuntimeError(f"不支持的打包 CPU 架构：{machine}") from failure
    return os_id, arch, f"{os_id}-{arch}"


def find_java_home(value: str | None) -> Path:
    if value:
        java_home = Path(value)
    else:
        jlink_on_path = shutil.which("jlink") or shutil.which("jlink.exe")
        if not jlink_on_path:
            raise RuntimeError("找不到 jlink；请使用 JDK 21 并设置 JAVA_HOME")
        java_home = Path(jlink_on_path).resolve().parent.parent
    java_home = java_home.resolve()
    if not (java_home / "jmods").is_dir():
        raise RuntimeError("JAVA_HOME 缺少 jmods；打包必须使用完整 JDK 21")
    return java_home


def run_checked(command: list[str], description: str) -> None:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{description}失败：{detail[-3000:]}")


def copy_package_contents(root: Path, agent_jar: Path) -> None:
    shutil.copy2(agent_jar, root / "link-agent.jar")
    for source_rel, target_rel in PACKAGE_FILES:
        source = ROOT / source_rel
        target = root / target_rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if target.suffix == ".sh":
            target.chmod(0o755)


def file_manifest(root: Path) -> list[dict[str, object]]:
    files = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}):
        resolved = path.resolve()
        if root.resolve() not in resolved.parents:
            raise RuntimeError(f"包内链接指向目录以外：{path.relative_to(root)}")
        files.append({
            "path": path.relative_to(root).as_posix(),
            "sizeBytes": path.stat().st_size,
            "sha256": sha256(path),
        })
    return files


def write_manifests(root: Path, metadata: dict[str, object]) -> None:
    files = file_manifest(root)
    manifest = {**metadata, "files": files}
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in checksum_files]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")


def zip_directory(root: Path, destination: Path, arcname: str) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            info = zipfile.ZipInfo(f"{arcname}/{path.relative_to(root).as_posix()}")
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (path.stat().st_mode & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes())


def verify_archive(root: Path, tar_path: Path, zip_path: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = root / entry["path"]
        if not path.is_file() or path.stat().st_size != entry["sizeBytes"] or sha256(path) != entry["sha256"]:
            raise RuntimeError(f"包内文件与 manifest 不符：{entry['path']}")
    expected_checksums = {}
    for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        digest, relative = line.split("  ", 1)
        expected_checksums[relative] = digest
    actual_paths = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    if actual_paths != set(expected_checksums):
        raise RuntimeError("SHA256SUMS 未覆盖完整发行包")
    for relative, digest in expected_checksums.items():
        if sha256(root / relative) != digest:
            raise RuntimeError(f"SHA256SUMS 校验失败：{relative}")
    with tarfile.open(tar_path, "r:gz") as archive:
        archive.dereference = True
        archive.getmembers()
    with zipfile.ZipFile(zip_path) as archive:
        bad_file = archive.testzip()
        if bad_file:
            raise RuntimeError(f"ZIP 校验失败：{bad_file}")


def main() -> None:
    if os.name == "nt":
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--agent-jar", required=True, type=Path)
    parser.add_argument("--java-home", default=os.environ.get("JAVA_HOME"))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "link-agent/target/distribution")
    parser.add_argument("--source-revision", default=os.environ.get("GITHUB_SHA"))
    args = parser.parse_args()

    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?", args.version):
        raise SystemExit("version 必须为明确的 Maven 版本号")
    if not args.source_revision:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                capture_output=True, text=True)
        args.source_revision = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", args.source_revision):
        raise SystemExit("source revision 必须是完整 Git commit SHA")
    agent_jar = args.agent_jar.resolve()
    if not agent_jar.is_file():
        raise SystemExit(f"找不到 shaded Agent JAR：{agent_jar}")

    java_home = find_java_home(args.java_home)
    java_name = "java.exe" if os.name == "nt" else "java"
    jlink_name = "jlink.exe" if os.name == "nt" else "jlink"
    java = java_home / "bin" / java_name
    jlink = java_home / "bin" / jlink_name
    if java_major(java) != 21:
        raise SystemExit("Java Agent 包必须使用 Java 21 runtime")
    if not jlink.is_file():
        raise SystemExit("JAVA_HOME/bin 中找不到 jlink")

    os_id, arch, platform_label = platform_id()
    modules = [*REQUIRED_MODULES, *(name for name in OPTIONAL_MODULES if (java_home / "jmods" / f"{name}.jmod").is_file())]
    package = f"{PACKAGE_PREFIX}-{args.version}-{platform_label}"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tar_path = args.output_dir / f"{package}.tar.gz"
    zip_path = args.output_dir / f"{package}.zip"

    with tempfile.TemporaryDirectory(prefix="jlshell-java-agent-") as temporary:
        package_root = Path(temporary) / package
        package_root.mkdir()
        runtime_dir = package_root / "runtime"
        run_checked([
            str(jlink),
            "--module-path", str(java_home / "jmods"),
            "--add-modules", ",".join(modules),
            "--bind-services",
            "--strip-debug",
            "--no-header-files",
            "--no-man-pages",
            "--compress=2",
            "--output", str(runtime_dir),
        ], "jlink runtime 构建")

        copy_package_contents(package_root, agent_jar)
        runtime_java = runtime_dir / "bin" / java_name
        runtime_version = java_major(runtime_java)
        if runtime_version != 21:
            raise RuntimeError("打包 runtime 不是 Java 21")
        run_checked([str(runtime_java), "-jar", str(package_root / "link-agent.jar"), "help"], "Agent CLI smoke check")

        write_manifests(package_root, {
            "schemaVersion": 1,
            "product": "jlshell-link-agent-java",
            "version": args.version,
            "sourceRevision": args.source_revision.lower(),
            "protocolVersion": "jlshell-link-v2",
            "platform": os_id,
            "architecture": arch,
            "runtime": {"vendor": "Eclipse Temurin", "major": runtime_version, "modules": modules},
        })
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.dereference = True
            archive.add(package_root, arcname=package)
        zip_directory(package_root, zip_path, package)
        verify_archive(package_root, tar_path, zip_path)

    artifacts = [
        {"name": path.name, "sizeBytes": path.stat().st_size, "sha256": sha256(path)}
        for path in (tar_path, zip_path)
    ]
    external_manifest = args.output_dir / f"{package}.manifest.json"
    external_manifest.write_text(json.dumps({
        "schemaVersion": 1,
        "product": "jlshell-link-agent-java",
        "version": args.version,
        "sourceRevision": args.source_revision.lower(),
        "protocolVersion": "jlshell-link-v2",
        "platform": os_id,
        "architecture": arch,
        "runtime": {"vendor": "Eclipse Temurin", "major": 21, "modules": modules},
        "artifacts": artifacts,
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums = [(path.name, sha256(path)) for path in (tar_path, zip_path, external_manifest)]
    checksum_path = args.output_dir / f"{package}.sha256"
    checksum_path.write_text("".join(f"{digest}  {name}\n" for name, digest in checksums), encoding="ascii")
    print(f"Built Java 21 Agent packages: {tar_path}, {zip_path}, {external_manifest}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
        raise SystemExit(str(failure)) from failure
