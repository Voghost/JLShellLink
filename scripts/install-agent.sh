#!/bin/sh
set -eu

umask 077

WEBSITE_URL=${JLSHELL_LINK_WEBSITE_URL:-https://jlshell.oomn.net}
INSTALL_ROOT=${JLSHELL_LINK_INSTALL_ROOT:-"$HOME/.jlshell-link"}
BIN_DIR="$INSTALL_ROOT/bin"
LOG_DIR="$INSTALL_ROOT/logs"
IDENTITY_FILE="$INSTALL_ROOT/agent-identity.key"
AUTHORITY_FILE="$INSTALL_ROOT/authority.pb"
TOKEN_FILE="$INSTALL_ROOT/enrollment.token"
CREDENTIAL_FILE="$INSTALL_ROOT/agent.credential"
SERVICE_NAME=jlshell-link-agent
FORCED_PLATFORM=${JLSHELL_LINK_PLATFORM:-auto}

say() {
    printf '%s\n' "$*"
}

fail() {
    printf 'JLShell Link 安装失败: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "缺少命令: $1"
}

restore_tty() {
    if [ "${TTY_HIDDEN:-0}" = 1 ]; then
        stty echo </dev/tty 2>/dev/null || true
        TTY_HIDDEN=0
    fi
}

cleanup() {
    restore_tty
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT HUP INT TERM

require_command curl
require_command tar

if [ "$FORCED_PLATFORM" = linux ] || [ "$FORCED_PLATFORM" = macos ]; then
    PLATFORM=$FORCED_PLATFORM
else
    case "$(uname -s)" in
        Linux) PLATFORM=linux ;;
        Darwin) PLATFORM=macos ;;
        *) fail "当前一键脚本仅支持 Linux 和 macOS；Windows 请使用 PowerShell 安装器" ;;
    esac
fi

case "$(uname -m)" in
    x86_64|amd64)
        ARCH=x64
        ;;
    arm64|aarch64)
        ARCH=arm64
        ;;
    *)
        fail "暂不支持当前处理器架构: $(uname -m)"
        ;;
esac

if [ "$PLATFORM" = linux ] && [ "$ARCH" != x64 ]; then
    fail "当前 Runtime 尚未发布 Linux $ARCH 版本"
fi
if [ "$PLATFORM" = macos ] && [ "$ARCH" != arm64 ]; then
    fail "当前 Runtime 尚未发布 macOS $ARCH 版本"
fi

ARCHIVE="jlshell-link-${PLATFORM}-${ARCH}.tar.gz"
DOWNLOAD_ROOT="$WEBSITE_URL/api/v1/link/runtime/latest"
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jlshell-link.XXXXXX")

say "正在下载 JLShell Link Agent ($PLATFORM/$ARCH)..."
curl -fsSL "$DOWNLOAD_ROOT/$ARCHIVE" -o "$TEMP_DIR/$ARCHIVE"
curl -fsSL "$DOWNLOAD_ROOT/$ARCHIVE.sha256" -o "$TEMP_DIR/$ARCHIVE.sha256"

expected_sha=$(awk '{print $1; exit}' "$TEMP_DIR/$ARCHIVE.sha256")
case "$expected_sha" in
    ''|*[!0-9a-fA-F]*) fail "下载的 SHA-256 文件无效" ;;
esac
[ "${#expected_sha}" -eq 64 ] || fail "下载的 SHA-256 长度无效"

if command -v sha256sum >/dev/null 2>&1; then
    actual_sha=$(sha256sum "$TEMP_DIR/$ARCHIVE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual_sha=$(shasum -a 256 "$TEMP_DIR/$ARCHIVE" | awk '{print $1}')
else
    fail "缺少 sha256sum 或 shasum，无法校验安装包"
fi
[ "$actual_sha" = "$expected_sha" ] || fail "Agent 安装包 SHA-256 校验失败"

mkdir -p "$BIN_DIR" "$LOG_DIR"
chmod 700 "$INSTALL_ROOT" "$BIN_DIR" "$LOG_DIR"
tar -xzf "$TEMP_DIR/$ARCHIVE" -C "$TEMP_DIR"
[ -f "$TEMP_DIR/jlshell-agent" ] || fail "安装包中缺少 jlshell-agent"
install -m 700 "$TEMP_DIR/jlshell-agent" "$BIN_DIR/jlshell-agent"
curl -fsSL "$WEBSITE_URL/api/v1/link/ticket-authority" -o "$AUTHORITY_FILE"
chmod 600 "$AUTHORITY_FILE"

if [ ! -c /dev/tty ]; then
    fail "无法打开交互终端读取一次性注册密钥"
fi
printf '请输入 Website 生成的一次性 Agent 注册密钥: ' >/dev/tty
stty -echo </dev/tty
TTY_HIDDEN=1
IFS= read -r enrollment_token </dev/tty
restore_tty
printf '\n' >/dev/tty
[ -n "$enrollment_token" ] || fail "注册密钥不能为空"
printf '%s\n' "$enrollment_token" >"$TOKEN_FILE"
unset enrollment_token
chmod 600 "$TOKEN_FILE"

relay_json=$(curl -fsSL "$WEBSITE_URL/api/v1/link/agent/bootstrap")
relay_address=$(printf '%s' "$relay_json" | sed -n 's/.*"relayAddress"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
relay_peer=$(printf '%s' "$relay_json" | sed -n 's/.*"relayPeer"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -n "$relay_address" ] && [ -n "$relay_peer" ] \
    || fail "当前没有在线的官方 Relay，请稍后重试"

set -- \
    "$BIN_DIR/jlshell-agent" \
    --identity "$IDENTITY_FILE" \
    --authority-public "$AUTHORITY_FILE" \
    --listen /ip4/0.0.0.0/tcp/7001 \
    --listen /ip4/0.0.0.0/udp/7001/quic-v1 \
    --control-plane-url "$WEBSITE_URL" \
    --enrollment-token-file "$TOKEN_FILE" \
    --credential-file "$CREDENTIAL_FILE"

set -- "$@" --relay-address "$relay_address" --relay-peer "$relay_peer"

if [ "$PLATFORM" = linux ] && command -v systemctl >/dev/null 2>&1; then
    UNIT_DIR="$HOME/.config/systemd/user"
    UNIT_FILE="$UNIT_DIR/$SERVICE_NAME.service"
    mkdir -p "$UNIT_DIR"
    {
        printf '%s\n' '[Unit]'
        printf '%s\n' 'Description=JLShell Link Agent'
        printf '%s\n' 'After=network-online.target'
        printf '%s\n' 'Wants=network-online.target'
        printf '\n%s\n' '[Service]'
        printf '%s' 'ExecStart='
        printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
        shift
        for argument in "$@"; do
            printf " '%s'" "$(printf '%s' "$argument" | sed "s/'/'\\\\''/g")"
        done
        printf '\n%s\n' 'Restart=always'
        printf '%s\n' 'RestartSec=5'
        printf '%s\n' 'UMask=0077'
        printf '%s\n' 'NoNewPrivileges=true'
        printf '%s\n' 'PrivateTmp=true'
        printf '\n%s\n' '[Install]'
        printf '%s\n' 'WantedBy=default.target'
    } >"$UNIT_FILE"
    chmod 600 "$UNIT_FILE"
    systemctl --user daemon-reload || fail "无法重载 systemd 用户服务"
    systemctl --user enable --now "$SERVICE_NAME.service" || fail "无法启动 systemd 用户服务"
    SERVICE_KIND=systemd-user
elif [ "$PLATFORM" = macos ]; then
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.jlshell.link.agent.plist"
    mkdir -p "$PLIST_DIR"
    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        printf '%s\n' '<plist version="1.0"><dict>'
        printf '%s\n' '<key>Label</key><string>com.jlshell.link.agent</string>'
        printf '%s\n' '<key>ProgramArguments</key><array>'
        for argument in "$@"; do
            escaped=$(printf '%s' "$argument" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            printf '<string>%s</string>\n' "$escaped"
        done
        printf '%s\n' '</array>'
        printf '%s\n' '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>'
        printf '<key>StandardOutPath</key><string>%s</string>\n' "$LOG_DIR/agent.log"
        printf '<key>StandardErrorPath</key><string>%s</string>\n' "$LOG_DIR/agent-error.log"
        printf '%s\n' '</dict></plist>'
    } >"$PLIST_FILE"
    chmod 600 "$PLIST_FILE"
    launchctl bootout "gui/$(id -u)/com.jlshell.link.agent" >/dev/null 2>&1 || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST_FILE" || fail "无法启动 macOS LaunchAgent"
    SERVICE_KIND=launch-agent
else
    "$@" >>"$LOG_DIR/agent.log" 2>>"$LOG_DIR/agent-error.log" &
    printf '%s\n' "$!" >"$INSTALL_ROOT/agent.pid"
    SERVICE_KIND=background-process
fi

attempt=0
while [ "$attempt" -lt 20 ] && [ ! -s "$CREDENTIAL_FILE" ]; do
    sleep 1
    attempt=$((attempt + 1))
done

if [ ! -s "$CREDENTIAL_FILE" ]; then
    fail "Agent 未能在 20 秒内完成注册，请检查 $LOG_DIR 下的日志"
fi

say "JLShell Link Agent 安装并注册成功。"
say "目录: $INSTALL_ROOT"
say "服务: $SERVICE_KIND"
say "接下来请回到 Website，为该 Agent 添加允许访问的精确 IP 和端口。"
