#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SKIP: network namespace smoke test requires Linux" >&2
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "SKIP: rerun on an isolated test host with root/CAP_NET_ADMIN" >&2
  exit 0
fi

for command_name in ip python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "SKIP: missing required command: $command_name" >&2
    exit 0
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/.." && pwd)"
binary_dir="${JLSHELL_LINK_BIN_DIR:-$repository_root/target/debug}"
linkctl="$binary_dir/jlshell-linkctl"
relay_binary="$binary_dir/jlshell-relay"
agent_binary="$binary_dir/jlshell-agent"
connector_binary="$binary_dir/jlshell-connector"

for binary_path in "$linkctl" "$relay_binary" "$agent_binary" "$connector_binary"; do
  if [[ ! -x "$binary_path" ]]; then
    echo "ERROR: missing executable $binary_path; run cargo build --workspace first" >&2
    exit 1
  fi
done

smoke_dir="$(mktemp -d /tmp/jlshell-link-netns.XXXXXX)"
agent_namespace="jls-agent-$$"
connector_namespace="jls-connector-$$"
agent_host_veth="jlah$$"
agent_peer_veth="jlap$$"
connector_host_veth="jlch$$"
connector_peer_veth="jlcp$$"
relay_pid=""
agent_pid=""
connector_pid=""
echo_pid=""

cleanup() {
  for process_id in "$connector_pid" "$agent_pid" "$relay_pid" "$echo_pid"; do
    if [[ -n "$process_id" ]]; then
      kill "$process_id" 2>/dev/null || true
    fi
  done
  ip netns del "$agent_namespace" 2>/dev/null || true
  ip netns del "$connector_namespace" 2>/dev/null || true
  ip link del "$agent_host_veth" 2>/dev/null || true
  ip link del "$connector_host_veth" 2>/dev/null || true
  rm -rf -- "$smoke_dir"
}
trap cleanup EXIT INT TERM

wait_for_log() {
  local log_file="$1"
  local pattern="$2"
  for _ in $(seq 1 100); do
    if grep -q "$pattern" "$log_file" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "ERROR: timed out waiting for '$pattern' in $log_file" >&2
  if [[ -f "$log_file" ]]; then
    sed -n '1,200p' "$log_file" >&2
  fi
  return 1
}

ip netns add "$agent_namespace"
ip netns add "$connector_namespace"
ip link add "$agent_host_veth" type veth peer name "$agent_peer_veth"
ip link add "$connector_host_veth" type veth peer name "$connector_peer_veth"
ip link set "$agent_peer_veth" netns "$agent_namespace"
ip link set "$connector_peer_veth" netns "$connector_namespace"

ip addr add 10.231.1.1/24 dev "$agent_host_veth"
ip addr add 10.232.1.1/24 dev "$connector_host_veth"
ip link set "$agent_host_veth" up
ip link set "$connector_host_veth" up

ip netns exec "$agent_namespace" ip link set lo up
ip netns exec "$agent_namespace" ip link set "$agent_peer_veth" name eth0
ip netns exec "$agent_namespace" ip addr add 10.231.1.2/24 dev eth0
ip netns exec "$agent_namespace" ip link set eth0 up
ip netns exec "$agent_namespace" ip route add default via 10.231.1.1

ip netns exec "$connector_namespace" ip link set lo up
ip netns exec "$connector_namespace" ip link set "$connector_peer_veth" name eth0
ip netns exec "$connector_namespace" ip addr add 10.232.1.2/24 dev eth0
ip netns exec "$connector_namespace" ip link set eth0 up
ip netns exec "$connector_namespace" ip route add default via 10.232.1.1

"$linkctl" authority-init \
  --private-key "$smoke_dir/authority-private.json" \
  --public-key "$smoke_dir/authority-public.json" >/dev/null
relay_identity_output="$("$linkctl" identity-init --output "$smoke_dir/relay.key")"
agent_identity_output="$("$linkctl" identity-init --output "$smoke_dir/agent.key")"
connector_identity_output="$("$linkctl" identity-init --output "$smoke_dir/connector.key")"
relay_peer_id="$(sed -n 's/^PEER_ID=//p' <<<"$relay_identity_output")"
agent_peer_id="$(sed -n 's/^PEER_ID=//p' <<<"$agent_identity_output")"
connector_peer_id="$(sed -n 's/^PEER_ID=//p' <<<"$connector_identity_output")"

ip netns exec "$agent_namespace" python3 -c \
  'import socket; s=socket.socket(); s.bind(("127.0.0.1",9100)); s.listen(); c,_=s.accept(); d=c.recv(65536); c.sendall(d); c.shutdown(socket.SHUT_WR); c.close(); s.close()' \
  >"$smoke_dir/echo.log" 2>&1 &
echo_pid="$!"

"$relay_binary" \
  --identity "$smoke_dir/relay.key" \
  --listen /ip4/10.231.1.1/tcp/4101 \
  --allow-public-listen >"$smoke_dir/relay.log" 2>&1 &
relay_pid="$!"
wait_for_log "$smoke_dir/relay.log" 'LISTEN_ADDRESS='

ip netns exec "$agent_namespace" "$agent_binary" \
  --identity "$smoke_dir/agent.key" \
  --authority-public "$smoke_dir/authority-public.json" \
  --allow-target 127.0.0.1:9100 \
  --connect-policy relay-only \
  --relay-address /ip4/10.231.1.1/tcp/4101 \
  --relay-peer "$relay_peer_id" >"$smoke_dir/agent.log" 2>&1 &
agent_pid="$!"
wait_for_log "$smoke_dir/agent.log" '/p2p-circuit/'

"$linkctl" ticket-issue \
  --authority-private "$smoke_dir/authority-private.json" \
  --connector-peer "$connector_peer_id" \
  --agent-peer "$agent_peer_id" \
  --target 127.0.0.1:9100 \
  --output "$smoke_dir/ticket.pb" >/dev/null

ip netns exec "$connector_namespace" "$connector_binary" \
  --identity "$smoke_dir/connector.key" \
  --agent-peer "$agent_peer_id" \
  --connect-policy relay-only \
  --relay-address /ip4/10.231.1.1/tcp/4101 \
  --relay-peer "$relay_peer_id" \
  --ticket "$smoke_dir/ticket.pb" \
  --target 127.0.0.1:9100 \
  --local-bind 127.0.0.1:7200 >"$smoke_dir/connector.log" 2>&1 &
connector_pid="$!"
wait_for_log "$smoke_dir/connector.log" 'LISTEN_ADDRESS=127.0.0.1:7200'

ip netns exec "$connector_namespace" python3 -c \
  'import socket; p=b"jlshell-link-netns"*257; s=socket.create_connection(("127.0.0.1",7200)); s.sendall(p); s.shutdown(socket.SHUT_WR); d=b"";
while True:
 b=s.recv(4096)
 if not b: break
 d+=b
assert d==p, (len(d),len(p))'

wait "$connector_pid"
connector_pid=""
grep -q 'CONNECTION_PATH=Relay' "$smoke_dir/connector.log"
echo "LINUX_NETNS_RELAY_ECHO_OK"

