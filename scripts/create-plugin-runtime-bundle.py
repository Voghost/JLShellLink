#!/usr/bin/env python3
"""Assemble the three native releases into one hash-pinned Program plugin runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
import tempfile
from pathlib import Path


PLATFORMS = (
    ("linux", "x64", "jlshell-link-linux-x64.tar.gz",
     "jlshell-connector-linux-x64", "jlshell-agent-linux-x64"),
    ("macos", "arm64", "jlshell-link-macos-arm64.tar.gz",
     "jlshell-connector-macos-arm64", "jlshell-agent-macos-arm64"),
    ("windows", "x64", "jlshell-link-windows-x64.tar.gz",
     "jlshell-connector-windows-x64.exe", "jlshell-agent-windows-x64.exe"),
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def copy_entry(source: Path, destination: Path, role: str,
               platform: str, architecture: str) -> dict[str, object]:
    if not source.is_file():
        raise FileNotFoundError(f"Release archive omitted {source.name}")
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    return {
        "role": role,
        "platform": platform,
        "architecture": architecture,
        "path": f"bin/{destination.name}",
        "size": destination.stat().st_size,
        "sha256": digest(destination),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="jlshell-link-runtime-") as temporary:
        temp = Path(temporary)
        root = temp / "runtime"
        binaries = root / "bin"
        binaries.mkdir(parents=True)
        entries: list[dict[str, object]] = []
        for platform, architecture, archive_name, connector_name, agent_name in PLATFORMS:
            extracted = temp / f"{platform}-{architecture}"
            extracted.mkdir()
            archive = args.archives / archive_name
            if not archive.is_file():
                raise FileNotFoundError(f"Missing release archive {archive}")
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(extracted, filter="data")
            entries.append(copy_entry(extracted / connector_name, binaries / connector_name,
                                      "connector", platform, architecture))
            entries.append(copy_entry(extracted / agent_name, binaries / agent_name,
                                      "agent", platform, architecture))

        manifest = {
            "schemaVersion": 1,
            "runtimeVersion": args.version,
            "files": entries,
        }
        (root / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        output = args.output / f"jlshell-link-plugin-runtime-{args.version}.tar.gz"
        with tarfile.open(output, "w:gz") as bundle:
            bundle.add(root / "manifest.json", arcname="manifest.json")
            bundle.add(binaries, arcname="bin")
        (args.output / f"{output.name}.sha256").write_text(
            f"{digest(output)}  {output.name}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
