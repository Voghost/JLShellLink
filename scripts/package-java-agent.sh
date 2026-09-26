#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
VERSION=${1:-}
AGENT_JAR=${2:-"$ROOT/link-agent/target/link-agent-$VERSION.jar"}
case "$VERSION" in
    ''|*[!0-9A-Za-z.+-]*) printf '%s\n' '用法: scripts/package-java-agent.sh <version> [shaded-agent.jar]' >&2; exit 2 ;;
esac
[ -f "$AGENT_JAR" ] || { printf '找不到 shaded Agent JAR: %s\n' "$AGENT_JAR" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' '打包需要 python3 标准库' >&2; exit 1; }

OUT_DIR="$ROOT/link-agent/target/distribution"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/jlshell-agent-package.XXXXXX")
PACKAGE="jlshell-link-agent-java-$VERSION"
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM

mkdir -p "$STAGE/$PACKAGE/scripts/java-agent" "$STAGE/$PACKAGE/docs" "$OUT_DIR"
install -m 600 "$AGENT_JAR" "$STAGE/$PACKAGE/link-agent.jar"
install -m 644 "$ROOT/docs/agent-cli.md" "$STAGE/$PACKAGE/docs/agent-cli.md"
install -m 644 "$ROOT/docs/agent-service.md" "$STAGE/$PACKAGE/README.md"
install -m 644 "$ROOT/scripts/java-agent/run-agent.sh" "$ROOT/scripts/java-agent/stop-agent.sh" \
    "$ROOT/scripts/java-agent/install-user-service.sh" \
    "$ROOT/scripts/java-agent/install-windows-service.ps1" \
    "$STAGE/$PACKAGE/scripts/java-agent/"
chmod 700 "$STAGE/$PACKAGE/scripts/java-agent/"*.sh
(cd "$STAGE/$PACKAGE" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 shasum -a 256 >SHA256SUMS)

python3 - "$STAGE" "$PACKAGE" "$OUT_DIR" <<'PY'
import pathlib
import sys
import tarfile
import zipfile

stage, package, output = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
root = stage / package
with tarfile.open(output / f"{package}.tar.gz", "w:gz") as archive:
    archive.add(root, arcname=package)
with zipfile.ZipFile(output / f"{package}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(stage))
PY

(cd "$OUT_DIR" && shasum -a 256 "$PACKAGE.tar.gz" "$PACKAGE.zip" >"$PACKAGE.sha256")
printf '已生成：%s/%s.tar.gz 与 .zip\n' "$OUT_DIR" "$PACKAGE"
