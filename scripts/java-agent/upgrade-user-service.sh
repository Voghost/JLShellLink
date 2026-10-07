#!/bin/sh
# Called only after publisher signature and archive digest verification by the installer.
set -eu
umask 077
[ "$#" -ge 5 ] && [ "$#" -le 6 ] || { printf '%s\n' '用法: upgrade-user-service.sh <wss> <identity.p12> <password-file> <targets-file> <manifest> [issuer]' >&2; exit 1; }
PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
APP_DIR="$HOME/.local/lib/jlshell-link-agent"
CONFIG_DIR="$HOME/.config/jlshell-link-agent"
STATE_DIR="$HOME/.local/state/jlshell-link-agent"
UNIT="$HOME/.config/systemd/user/jlshell-link-agent.service"
PLIST="$HOME/Library/LaunchAgents/com.jlshell.link.agent.plist"
LOCK="$HOME/.local/lib/.jlshell-link-upgrade-lock"
mkdir -p "$HOME/.local/lib"
mkdir "$LOCK" || { printf '%s\n' '另一个 Agent 安装正在进行；请确认后重试。' >&2; exit 1; }
BACKUP=$(mktemp -d "$HOME/.local/lib/.jlshell-link-backup.XXXXXXXX") || { rmdir "$LOCK"; exit 1; }
SUCCESS=false
MUTATED=false
WAS_RUNNING=false
OS=$(uname -s)

stop_service() {
    case "$OS" in
        Linux) systemctl --user stop jlshell-link-agent.service ;;
        Darwin) launchctl bootout "gui/$(id -u)/com.jlshell.link.agent" ;;
    esac
}
start_service() {
    case "$OS" in
        Linux) systemctl --user daemon-reload && systemctl --user start jlshell-link-agent.service ;;
        Darwin) launchctl bootstrap "gui/$(id -u)" "$PLIST" ;;
    esac
}
cleanup() {
    code=$?
    trap - EXIT HUP INT TERM
    if [ "$SUCCESS" != true ] && [ "$MUTATED" = true ]; then
        stop_service >/dev/null 2>&1 || true
        if [ "$OS" = Linux ] && [ ! -e "$BACKUP/unit" ]; then
            systemctl --user disable jlshell-link-agent.service >/dev/null 2>&1 || true
        fi
        rm -rf "$APP_DIR" "$CONFIG_DIR"
        rm -f "$UNIT" "$PLIST"
        [ ! -d "$BACKUP/app" ] || mv "$BACKUP/app" "$APP_DIR"
        [ ! -d "$BACKUP/config" ] || mv "$BACKUP/config" "$CONFIG_DIR"
        [ ! -f "$BACKUP/unit" ] || cp -P "$BACKUP/unit" "$UNIT"
        [ ! -f "$BACKUP/plist" ] || cp -P "$BACKUP/plist" "$PLIST"
        if [ "$WAS_RUNNING" = true ]; then
            if ! start_service >/dev/null 2>&1; then
                printf '%s\n' '升级失败：文件已恢复，但旧服务重启失败，请手动检查。' >&2
                code=2
            else
                printf '%s\n' '升级失败：已恢复上一版本及其服务配置。' >&2
            fi
        elif [ "$OS" = Linux ]; then
            systemctl --user daemon-reload >/dev/null 2>&1 || true
        fi
    fi
    rm -rf "$BACKUP"
    rmdir "$LOCK"
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
case "$OS" in
    Linux)
        command -v systemctl >/dev/null
        systemctl --user list-units --no-pager >/dev/null
        if systemctl --user is-active --quiet jlshell-link-agent.service; then WAS_RUNNING=true; fi
        ;;
    Darwin)
        command -v launchctl >/dev/null
        if launchctl print "gui/$(id -u)/com.jlshell.link.agent" >/dev/null 2>&1; then WAS_RUNNING=true; fi
        ;;
    *) printf '%s\n' '不支持的用户服务平台' >&2; exit 1 ;;
esac
[ ! -L "$APP_DIR" ] && [ ! -L "$CONFIG_DIR" ] || { printf '%s\n' '安装目录不能是符号链接' >&2; exit 1; }
# Diagnose before stopping the current version. Credentials/state are never copied to backups.
# Keep positional install arguments intact while passing only non-secret paths to diagnose.
"$PACKAGE_ROOT/runtime/bin/java" -jar "$PACKAGE_ROOT/link-agent.jar" diagnose \
    --state-dir "$STATE_DIR" --link-wss "$1" --tls-identity-p12 "$2" \
    --tls-password-file "$3" --allowed-targets-file "$4" >/dev/null
[ ! -d "$APP_DIR" ] || cp -RP "$APP_DIR" "$BACKUP/app"
[ ! -d "$CONFIG_DIR" ] || cp -RP "$CONFIG_DIR" "$BACKUP/config"
[ ! -f "$UNIT" ] || cp -P "$UNIT" "$BACKUP/unit"
[ ! -f "$PLIST" ] || cp -P "$PLIST" "$BACKUP/plist"
MUTATED=true
if [ "$WAS_RUNNING" = true ]; then stop_service; fi
if [ "$#" = 6 ]; then
    sh "$PACKAGE_ROOT/scripts/java-agent/install-user-service.sh" install "$PACKAGE_ROOT/link-agent.jar" "$1" "$2" "$3" "$4" "$6"
else
    sh "$PACKAGE_ROOT/scripts/java-agent/install-user-service.sh" install "$PACKAGE_ROOT/link-agent.jar" "$1" "$2" "$3" "$4"
fi
# A manager accepting a start request is not enough: check it remains running.
sleep 2
case "$OS" in
    Linux) systemctl --user is-active --quiet jlshell-link-agent.service ;;
    Darwin) launchctl print "gui/$(id -u)/com.jlshell.link.agent" | grep -q 'state = running' ;;
esac
install -m 600 "$5" "$APP_DIR/release.manifest.json"
install -m 600 "$(dirname "$5")/release.signature.json" "$APP_DIR/release.signature.json"
SUCCESS=true
printf '%s\n' 'Java Agent 服务已安装并通过进程检查；请继续核对 Website 在线状态。'
