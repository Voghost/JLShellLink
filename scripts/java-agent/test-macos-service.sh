#!/bin/sh
set -eu

[ "${GITHUB_ACTIONS:-}" = true ] || {
    printf '%s\n' 'This lifecycle test is restricted to a disposable GitHub Actions runner.' >&2
    exit 1
}

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
INSTALLER="$REPO_ROOT/scripts/java-agent/install-user-service.sh"
TEST_ROOT=$(mktemp -d "${RUNNER_TEMP:-/tmp}/jlshell-agent-macos.XXXXXX")
PLIST="$HOME/Library/LaunchAgents/com.jlshell.link.agent.plist"
LABEL="gui/$(id -u)/com.jlshell.link.agent"
CONFIG="$HOME/.config/jlshell-link-agent"
APP="$HOME/.local/lib/jlshell-link-agent"
STATE="$HOME/.local/state/jlshell-link-agent"
LOGS="$HOME/.local/share/jlshell-link-agent"
INSTALLED=0

cleanup() {
    if [ "$INSTALLED" -eq 1 ]; then
        HOME="$HOME" sh "$INSTALLER" uninstall >/dev/null 2>&1 || true
    fi
    rm -rf "$CONFIG" "$APP" "$STATE" "$LOGS" "$PLIST" "$TEST_ROOT"
}
trap cleanup EXIT HUP INT TERM

if [ -e "$PLIST" ] || launchctl print "$LABEL" >/dev/null 2>&1; then
    printf '%s\n' 'JLShell Agent LaunchAgent already exists on the CI runner.' >&2
    exit 1
fi
for path in "$CONFIG" "$APP" "$STATE" "$LOGS"; do
    if [ -e "$path" ]; then
        printf 'JLShell Agent test path already exists on the CI runner: %s\n' "$path" >&2
        exit 1
    fi
done

cat >"$TEST_ROOT/fake-java" <<'JAVA'
#!/bin/sh
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
case "${3:-}" in
  run)
    printf '%s\n' "$$" >"$script_dir/run.pid"
    trap 'printf terminated >"$script_dir/terminated"; exit 0' TERM INT
    while :; do sleep 1 & wait $!; done
    ;;
  stop)
    printf stop-requested >"$script_dir/stop-requested"
    exit 0
    ;;
  *) exit 2 ;;
esac
JAVA
chmod 700 "$TEST_ROOT/fake-java"
printf test >"$TEST_ROOT/identity.p12"
printf test >"$TEST_ROOT/password"
printf '192.0.2.1:22\n' >"$TEST_ROOT/allowed-targets"
JAR="$REPO_ROOT/link-agent/target/link-agent-0.1.0-SNAPSHOT.jar"
[ -f "$JAR" ] || { echo 'Built Agent JAR not found.' >&2; exit 1; }

INSTALLED=1
JLSHELL_LINK_JAVA="$TEST_ROOT/fake-java" sh "$INSTALLER" install \
    "$JAR" wss://127.0.0.1:1/link/v2/control \
    "$TEST_ROOT/identity.p12" "$TEST_ROOT/password" \
    "$TEST_ROOT/allowed-targets" https://127.0.0.1:1

attempt=0
while [ ! -f "$TEST_ROOT/run.pid" ] && [ "$attempt" -lt 40 ]; do
    sleep 0.25
    attempt=$((attempt + 1))
done
[ -f "$TEST_ROOT/run.pid" ] || { echo 'LaunchAgent failed to start.' >&2; exit 1; }
sh "$INSTALLER" status >/dev/null
launchctl print "$LABEL" >/dev/null
sh "$INSTALLER" uninstall
INSTALLED=0

attempt=0
while [ ! -f "$TEST_ROOT/terminated" ] && [ "$attempt" -lt 40 ]; do
    sleep 0.25
    attempt=$((attempt + 1))
done
[ -f "$TEST_ROOT/terminated" ] || { echo 'LaunchAgent process did not stop on uninstall.' >&2; exit 1; }
[ -f "$APP/link-agent.jar" ] || { echo 'Uninstall removed the Agent JAR.' >&2; exit 1; }
[ -d "$STATE" ] || { echo 'Uninstall removed the Agent state directory.' >&2; exit 1; }
[ ! -e "$CONFIG/agent.env" ] || { echo 'Uninstall retained the service configuration.' >&2; exit 1; }
if launchctl print "$LABEL" >/dev/null 2>&1; then
    echo 'LaunchAgent remained loaded after uninstall.' >&2
    exit 1
fi
printf '%s\n' 'macOS LaunchAgent install/status/uninstall lifecycle passed.'
