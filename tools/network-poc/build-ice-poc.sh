#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo 'Usage: build-ice-poc.sh <private-output-directory>' >&2
  exit 2
fi

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output_dir=$1
mkdir -p "$output_dir/classes" "$output_dir/lib"

(
  cd "$repo_dir"
  mvn -B -ntp -Pnetwork-poc-candidates -pl link-transport -am -DskipTests package
  mvn -B -ntp -Pnetwork-poc-candidates -pl link-transport -am dependency:copy-dependencies \
    -DincludeScope=test -DoutputDirectory="$output_dir/lib"
)

cp -R "$repo_dir/link-core/target/classes/." "$output_dir/classes/"
cp -R "$repo_dir/link-transport/target/classes/." "$output_dir/classes/"

javac --release 21 \
  -cp "$output_dir/classes:$output_dir/lib/*" \
  -d "$output_dir/classes" \
  "$repo_dir/tools/network-poc/JavaStunServer.java" \
  "$repo_dir/tools/network-poc/JavaTcpRelay.java" \
  "$repo_dir/tools/network-poc/JavaUdpPathProbe.java" \
  "$repo_dir/tools/network-poc/JavaWssRelayProbe.java" \
  "$repo_dir/tools/network-poc/JavaWssFallbackPeer.java" \
  "$repo_dir/tools/network-poc/JavaHttp2ConnectProbe.java" \
  "$repo_dir/tools/network-poc/JavaIceKcpHttp2Peer.java"

echo "Built Java 21 network POC in $output_dir"
