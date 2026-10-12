#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$ROOT/runtime/bin/java" -jar "$ROOT/link-agent.jar" "$@"
