#!/bin/sh
set -eu

STATE_DIR="${JLSHELL_RELAY_STATE_DIR:-/var/lib/jlshell-link}"
IDENTITY_FILE="${JLSHELL_RELAY_IDENTITY_FILE:-$STATE_DIR/relay-identity.key}"
CREDENTIAL_FILE="${JLSHELL_RELAY_CREDENTIAL_FILE:-$STATE_DIR/relay.credential}"
CONTROL_PLANE_URL="${JLSHELL_RELAY_CONTROL_PLANE_URL:-https://jlshell.oomn.net}"
RELAY_NAME="${JLSHELL_RELAY_NAME:-official-relay}"
RELAY_VERSION="${JLSHELL_RELAY_VERSION:-container}"
PUBLIC_ENDPOINT="${JLSHELL_RELAY_PUBLIC_ENDPOINT:-}"
RELAY_BIN="${JLSHELL_RELAY_BIN:-/usr/local/bin/jlshell-relay}"

log() {
  printf '%s\n' "[jlshell-relay] $*"
}

fail() {
  printf '%s\n' "[jlshell-relay] ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "缺少依赖命令: $1"
}

ensure_state() {
  umask 077
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
}

identity_value() {
  "$RELAY_BIN" --identity "$IDENTITY_FILE" --print-identity \
    | awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }'
}

register_relay() {
  require_command curl
  require_command jq
  : "${JLSHELL_RELAY_ADMIN_JWT:?首次注册必须设置 JLSHELL_RELAY_ADMIN_JWT}"
  [ -n "$PUBLIC_ENDPOINT" ] || fail "首次注册必须设置 JLSHELL_RELAY_PUBLIC_ENDPOINT，例如 /ip4/203.0.113.10/tcp/4001"
  case "$PUBLIC_ENDPOINT" in
    /ip4/*/tcp/*|/ip6/*/tcp/*) ;;
    *) fail "JLSHELL_RELAY_PUBLIC_ENDPOINT 必须是 /ip4 或 /ip6 的 TCP multiaddr" ;;
  esac

  ensure_state
  if [ -s "$CREDENTIAL_FILE" ]; then
    log "Relay 已有凭据，跳过重复注册"
    return 0
  fi

  public_key="$(identity_value RELAY_PUBLIC_KEY)"
  [ -n "$public_key" ] || fail "无法读取 Relay 公钥"
  challenge="$(curl -fsS --retry 3 --retry-delay 1 \
    -X POST "$CONTROL_PLANE_URL/api/admin/relay-nodes/challenges" \
    -H "Authorization: Bearer $JLSHELL_RELAY_ADMIN_JWT" \
    -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg publicKey "$public_key" '{publicKey:$publicKey}')")" \
    || fail "无法从 Website 获取 Relay challenge"
  challenge_id="$(printf '%s' "$challenge" | jq -er '.challengeId')" \
    || fail "Website challenge 响应缺少 challengeId"
  payload="$(printf '%s' "$challenge" | jq -er '.payload')" \
    || fail "Website challenge 响应缺少 payload"
  signature="$($RELAY_BIN --identity "$IDENTITY_FILE" --identity-proof "$payload" \
    | awk -F= '$1 == "RELAY_PROOF_SIGNATURE" { print substr($0, index($0, "=") + 1); exit }')"
  [ -n "$signature" ] || fail "无法生成 Relay challenge 签名"

  registration="$(curl -fsS --retry 3 --retry-delay 1 \
    -X POST "$CONTROL_PLANE_URL/api/admin/relay-nodes" \
    -H "Authorization: Bearer $JLSHELL_RELAY_ADMIN_JWT" \
    -H 'Content-Type: application/json' \
    --data "$(jq -cn \
      --arg name "$RELAY_NAME" \
      --arg publicKey "$public_key" \
      --arg endpoint "$PUBLIC_ENDPOINT" \
      --arg version "$RELAY_VERSION" \
      --arg challengeId "$challenge_id" \
      --arg proofSignature "$signature" \
      '{name:$name,publicKey:$publicKey,endpoint:$endpoint,version:$version,challengeId:$challengeId,proofSignature:$proofSignature}')")" \
    || fail "Website Relay 注册失败"
  credential="$(printf '%s' "$registration" | jq -er '.credential')" \
    || fail "Website 注册响应缺少 credential"
  temporary="$CREDENTIAL_FILE.tmp.$$"
  printf '%s\n' "$credential" > "$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$CREDENTIAL_FILE"
  log "Relay 注册成功，凭据已保存到 $CREDENTIAL_FILE"
}

run_relay() {
  ensure_state
  [ -s "$CREDENTIAL_FILE" ] || fail "Relay 尚未注册，请先执行 docker compose run --rm relay-bootstrap register"
  exec "$RELAY_BIN" \
    --identity "$IDENTITY_FILE" \
    --listen "${JLSHELL_RELAY_LISTEN_TCP:-/ip4/0.0.0.0/tcp/4001}" \
    --listen "${JLSHELL_RELAY_LISTEN_QUIC:-/ip4/0.0.0.0/udp/4001/quic-v1}" \
    --allow-public-listen \
    --control-plane-url "$CONTROL_PLANE_URL" \
    --credential-file "$CREDENTIAL_FILE"
}

case "${1:-run}" in
  register)
    register_relay
    ;;
  run)
    run_relay
    ;;
  *)
    exec "$@"
    ;;
esac
