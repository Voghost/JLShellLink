#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
VERSION=${1:-}
AGENT_JAR=${2:-"$ROOT/link-agent/target/link-agent-$VERSION.jar"}

if [ -z "$VERSION" ]; then
    printf '%s\n' '用法: scripts/package-java-agent.sh <version> [shaded-agent.jar]' >&2
    exit 2
fi

exec python3 "$ROOT/scripts/package-java-agent.py" \
    --version "$VERSION" \
    --agent-jar "$AGENT_JAR" \
    --output-dir "$ROOT/link-agent/target/distribution"
