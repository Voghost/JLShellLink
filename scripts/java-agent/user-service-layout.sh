#!/bin/sh
# Sourced only by installer/upgrade. Defaults preserve the existing plugin layout.
layout_fail() { printf '%s\n' '用户服务目录配置无效：独立安装需安全的绝对目录及独立实例名。' >&2; exit 1; }
if [ -n "${JLSHELL_LINK_INSTALL_ROOT:-}" ] || [ -n "${JLSHELL_LINK_SERVICE_INSTANCE:-}" ]; then
    case "${JLSHELL_LINK_INSTALL_ROOT:-}" in /*) ;; *) layout_fail ;; esac
    CONTROL=$(printf '%s' "$JLSHELL_LINK_INSTALL_ROOT" | LC_ALL=C tr -d '\040-\176')
    [ -z "$CONTROL" ] || layout_fail
    case "$JLSHELL_LINK_INSTALL_ROOT" in *'%'*|*'\'*) layout_fail ;; esac
    INSTANCE=${JLSHELL_LINK_SERVICE_INSTANCE:-}
    case "$INSTANCE" in ''|*[!a-z0-9-]*|-*) layout_fail ;; esac
    [ "${#INSTANCE}" -le 32 ] || layout_fail
    [ -d "$JLSHELL_LINK_INSTALL_ROOT" ] && [ ! -L "$JLSHELL_LINK_INSTALL_ROOT" ] \
        && [ -O "$JLSHELL_LINK_INSTALL_ROOT" ] || layout_fail
    INSTALL_ROOT=$(CDPATH= cd -- "$JLSHELL_LINK_INSTALL_ROOT" && pwd -P)
    # Require an explicit private root; do not chmod an arbitrary caller directory.
    ROOT_MODE=$(LC_ALL=C ls -ld "$INSTALL_ROOT" | cut -c1-10)
    [ "$ROOT_MODE" = drwx------ ] || layout_fail
    INSTANCE_FILE="$INSTALL_ROOT/.service-instance"
    if [ -e "$INSTANCE_FILE" ] || [ -L "$INSTANCE_FILE" ]; then
        [ -f "$INSTANCE_FILE" ] && [ ! -L "$INSTANCE_FILE" ] \
            && [ "$(cat "$INSTANCE_FILE")" = "$INSTANCE" ] || layout_fail
    fi
    CONFIG_DIR="$INSTALL_ROOT/config"
    APP_DIR="$INSTALL_ROOT/app"
    STATE_DIR="$INSTALL_ROOT/state"
    LOG_DIR="$INSTALL_ROOT/logs"
    UNIT_NAME="jlshell-link-agent-$INSTANCE"
    PLIST_NAME="com.jlshell.link.agent.$INSTANCE"
    BACKUP_PARENT="$INSTALL_ROOT"
    LOCK="$INSTALL_ROOT/.upgrade-lock"
else
    CONFIG_DIR="$HOME/.config/jlshell-link-agent"
    APP_DIR="$HOME/.local/lib/jlshell-link-agent"
    STATE_DIR="$HOME/.local/state/jlshell-link-agent"
    LOG_DIR="$HOME/.local/share/jlshell-link-agent/logs"
    UNIT_NAME=jlshell-link-agent
    PLIST_NAME=com.jlshell.link.agent
    BACKUP_PARENT="$HOME/.local/lib"
    LOCK="$BACKUP_PARENT/.jlshell-link-upgrade-lock"
fi
ENV_FILE="$CONFIG_DIR/agent.env"
UNIT="$HOME/.config/systemd/user/$UNIT_NAME.service"
PLIST="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"
for layout_directory in "$CONFIG_DIR" "$APP_DIR" "$STATE_DIR" "$LOG_DIR"; do
    [ ! -L "$layout_directory" ] || layout_fail
done
if [ -n "${INSTALL_ROOT:-}" ]; then
    # A reused name must not overwrite a different root's manager registration.
    if [ -e "$UNIT" ] || [ -L "$UNIT" ]; then
        [ -L "$UNIT" ] && [ "$UNIT" -ef "$CONFIG_DIR/systemd/$UNIT_NAME.service" ] || layout_fail
    fi
    if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then
        [ -f "$PLIST" ] && [ ! -L "$PLIST" ] || layout_fail
        EXPECTED_APP_XML=$(printf '%s' "$APP_DIR" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        grep -F -q "<string>$EXPECTED_APP_XML/run-agent.sh</string>" "$PLIST" || layout_fail
    fi
    if [ ! -e "$INSTANCE_FILE" ] && [ "${ACTION:-}" = install ]; then
        (umask 077; set -C; printf '%s\n' "$INSTANCE" >"$INSTANCE_FILE") || layout_fail
    fi
fi
