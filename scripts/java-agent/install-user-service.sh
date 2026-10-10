#!/bin/sh
set -eu

ACTION=${1:-}
. "$(dirname "$0")/user-service-layout.sh"
umask 077
PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)

fail() { printf '安装失败：%s\n' "$*" >&2; exit 1; }
quote_shell() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
xml_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

case "$ACTION" in
    install)
        [ "$#" -ge 6 ] && [ "$#" -le 7 ] || fail \
            '用法: install-user-service.sh install <agent.jar> <wss-uri> <identity.p12> <password-file> <allowed-targets> [ticket-issuer]'
        JAR=$(cd "$(dirname "$2")" && pwd -P)/$(basename "$2")
        WSS_URI=$3
        TLS_IDENTITY=$(cd "$(dirname "$4")" && pwd -P)/$(basename "$4")
        TLS_PASSWORD=$(cd "$(dirname "$5")" && pwd -P)/$(basename "$5")
        ALLOWED_TARGETS=$(cd "$(dirname "$6")" && pwd -P)/$(basename "$6")
        TICKET_ISSUER=${7:-}
        [ -f "$JAR" ] && [ -f "$TLS_IDENTITY" ] && [ -f "$TLS_PASSWORD" ] \
            && [ -f "$ALLOWED_TARGETS" ] || fail 'JAR、TLS 文件或目标白名单不存在'
        case "$WSS_URI" in wss://*) ;; *) fail 'WSS 地址必须以 wss:// 开头' ;; esac
        case "$TICKET_ISSUER" in ''|https://*) ;; *) fail '票据签发者必须以 https:// 开头' ;; esac
        if [ -n "${JLSHELL_LINK_JAVA:-}" ]; then
            BUNDLED_JAVA=$JLSHELL_LINK_JAVA
            command -v "$BUNDLED_JAVA" >/dev/null 2>&1 || fail 'JLSHELL_LINK_JAVA 不可执行'
        elif [ -d "$PACKAGE_ROOT/runtime" ]; then
            [ -x "$PACKAGE_ROOT/runtime/bin/java" ] || fail '发布包内的 Java 21 runtime 不完整'
            BUNDLED_JAVA="$APP_DIR/runtime/bin/java"
        else
            BUNDLED_JAVA=${JLSHELL_LINK_JAVA:-java}
            command -v "$BUNDLED_JAVA" >/dev/null 2>&1 || fail '需要 Java 21；请使用包含 runtime 的发布包或设置 JLSHELL_LINK_JAVA'
        fi
        mkdir -p "$CONFIG_DIR" "$APP_DIR" "$STATE_DIR" "$LOG_DIR"
        chmod 700 "$CONFIG_DIR" "$APP_DIR" "$STATE_DIR" "$LOG_DIR"
        install -m 600 "$JAR" "$APP_DIR/link-agent.jar"
        if [ -d "$PACKAGE_ROOT/runtime" ]; then
            rm -rf "$APP_DIR/runtime.new"
            cp -R "$PACKAGE_ROOT/runtime" "$APP_DIR/runtime.new"
            rm -rf "$APP_DIR/runtime"
            mv "$APP_DIR/runtime.new" "$APP_DIR/runtime"
        fi
        {
            printf 'export JLSHELL_LINK_AGENT_JAR=%s\n' "$(quote_shell "$APP_DIR/link-agent.jar")"
            printf 'export JLSHELL_LINK_STATE_DIR=%s\n' "$(quote_shell "$STATE_DIR")"
            printf 'export JLSHELL_LINK_WSS_URI=%s\n' "$(quote_shell "$WSS_URI")"
            printf 'export JLSHELL_LINK_TLS_IDENTITY=%s\n' "$(quote_shell "$TLS_IDENTITY")"
            printf 'export JLSHELL_LINK_TLS_PASSWORD_FILE=%s\n' "$(quote_shell "$TLS_PASSWORD")"
            printf 'export JLSHELL_LINK_ALLOWED_TARGETS=%s\n' "$(quote_shell "$ALLOWED_TARGETS")"
            [ -z "$TICKET_ISSUER" ] || printf 'export JLSHELL_LINK_TICKET_ISSUER=%s\n' "$(quote_shell "$TICKET_ISSUER")"
            [ -z "${JLSHELL_LINK_STUN_SERVERS:-}" ] || \
                printf 'export JLSHELL_LINK_STUN_SERVERS=%s\n' "$(quote_shell "$JLSHELL_LINK_STUN_SERVERS")"
            printf 'export JAVA=%s\n' "$(quote_shell "$BUNDLED_JAVA")"
            [ -z "${JLSHELL_LINK_JAVA_TOOL_OPTIONS:-}" ] || \
                printf 'export JAVA_TOOL_OPTIONS=%s\n' "$(quote_shell "$JLSHELL_LINK_JAVA_TOOL_OPTIONS")"
        } >"$ENV_FILE"
        chmod 600 "$ENV_FILE"
        install -m 700 "$(dirname "$0")/run-agent.sh" "$APP_DIR/run-agent.sh"
        install -m 700 "$(dirname "$0")/stop-agent.sh" "$APP_DIR/stop-agent.sh"
        case "$(uname -s)" in
            Linux)
                command -v systemctl >/dev/null 2>&1 || fail '找不到 systemctl'
                UNIT_DIR="$CONFIG_DIR/systemd"
                mkdir -p "$UNIT_DIR"
                ENV_FILE_SYSTEMD=$(printf '%s' "$ENV_FILE" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g')
                APP_DIR_SYSTEMD=$(printf '%s' "$APP_DIR" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g')
                cat >"$UNIT_DIR/$UNIT_NAME.service" <<EOF
[Unit]
Description=JLShell Link Java Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="JLSHELL_LINK_AGENT_CONFIG=$ENV_FILE_SYSTEMD"
ExecStart="$APP_DIR_SYSTEMD/run-agent.sh"
ExecStop="$APP_DIR_SYSTEMD/stop-agent.sh"
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
KillSignal=SIGTERM
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=default.target
EOF
                chmod 600 "$UNIT_DIR/$UNIT_NAME.service"
                mkdir -p "$HOME/.config/systemd/user"
                ln -sfn "$UNIT_DIR/$UNIT_NAME.service" "$HOME/.config/systemd/user/$UNIT_NAME.service"
                systemctl --user daemon-reload
                systemctl --user enable --now "$UNIT_NAME.service"
                ;;
            Darwin)
                command -v launchctl >/dev/null 2>&1 || fail '找不到 launchctl'
                PLIST_DIR="$HOME/Library/LaunchAgents"
                mkdir -p "$PLIST_DIR" "$LOG_DIR"
                APP_DIR_XML=$(xml_escape "$APP_DIR")
                LOG_DIR_XML=$(xml_escape "$LOG_DIR")
                ENV_FILE_XML=$(xml_escape "$ENV_FILE")
                cat >"$PLIST_DIR/$PLIST_NAME.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$PLIST_NAME</string>
  <key>ProgramArguments</key><array><string>$APP_DIR_XML/run-agent.sh</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>JLSHELL_LINK_AGENT_CONFIG</key><string>$ENV_FILE_XML</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$LOG_DIR_XML/agent.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR_XML/agent-error.log</string>
</dict></plist>
EOF
                chmod 600 "$PLIST_DIR/$PLIST_NAME.plist"
                launchctl bootout "gui/$(id -u)/$PLIST_NAME" >/dev/null 2>&1 || true
                launchctl bootstrap "gui/$(id -u)" "$PLIST_DIR/$PLIST_NAME.plist"
                ;;
            *) fail '仅支持 Linux systemd-user 与 macOS LaunchAgent' ;;
        esac
        printf 'JLShell Link 用户服务已安装；凭据和 Agent 状态保存在 %s。\n' "$STATE_DIR"
        ;;
    uninstall)
        case "$(uname -s)" in
            Linux)
                systemctl --user disable --now "$UNIT_NAME.service" >/dev/null 2>&1 || true
                rm -f "$HOME/.config/systemd/user/$UNIT_NAME.service" "$CONFIG_DIR/systemd/$UNIT_NAME.service"
                systemctl --user daemon-reload >/dev/null 2>&1 || true
                ;;
            Darwin)
                launchctl bootout "gui/$(id -u)/$PLIST_NAME" >/dev/null 2>&1 || true
                rm -f "$HOME/Library/LaunchAgents/$PLIST_NAME.plist"
                ;;
            *) fail '仅支持 Linux systemd-user 与 macOS LaunchAgent' ;;
        esac
        rm -f "$ENV_FILE"
        printf '服务定义已移除；Agent 身份、凭据、JAR 和日志保留在 %s。\n' "$STATE_DIR"
        ;;
    status)
        case "$(uname -s)" in
            Linux) systemctl --user status --no-pager "$UNIT_NAME.service" ;;
            Darwin) launchctl print "gui/$(id -u)/$PLIST_NAME" ;;
            *) fail '仅支持 Linux systemd-user 与 macOS LaunchAgent' ;;
        esac
        ;;
    *) fail '用法: install-user-service.sh install|uninstall|status ...' ;;
esac
