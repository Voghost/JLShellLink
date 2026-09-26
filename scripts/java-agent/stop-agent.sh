#!/bin/sh
set -eu

CONFIG_FILE=${JLSHELL_LINK_AGENT_CONFIG:-"${HOME:?}/.config/jlshell-link-agent/agent.env"}
if [ ! -f "$CONFIG_FILE" ] || [ -L "$CONFIG_FILE" ]; then
    printf '%s\n' 'JLShell Link Agent 配置必须是当前用户的普通文件' >&2
    exit 1
fi
. "$CONFIG_FILE"
exec "${JAVA:-java}" -jar "$JLSHELL_LINK_AGENT_JAR" stop --state-dir "$JLSHELL_LINK_STATE_DIR"
