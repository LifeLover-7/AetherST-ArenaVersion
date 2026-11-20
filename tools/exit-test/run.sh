#!/usr/bin/env bash
# Linux x86-64, JDK 17, Go 1.23+. Only test dependencies are downloaded; no provider traffic.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
curl -fsSL --retry 2 https://github.com/SagerNet/sing-box/releases/download/v1.10.7/sing-box-1.10.7-linux-amd64.tar.gz -o core.tgz
sha256sum core.tgz
tar xzf core.tgz sing-box-1.10.7-linux-amd64/sing-box
export AETHER_TEST_SING_BOX="$tmp/sing-box-1.10.7-linux-amd64/sing-box"
cp "$root/tools/exit-test/peer/main.go" .
go mod init local.test/exit-peer
go get golang.zx2c4.com/wireguard/tun/netstack@v0.0.0-20250521234502-f333402bd9cb
go build -mod=mod -o peer .
export AETHER_TEST_WG_PEER="$tmp/peer"
cd "$root"
bash gradlew :composeApp:desktopTest -PskipAndroid=true --no-daemon
