#!/usr/bin/env bash
# Linux x86-64, JDK 17, Go 1.23+. Only test dependencies are downloaded; no provider traffic.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
curl -fsSL --retry 2 https://github.com/SagerNet/sing-box/releases/download/v1.10.7/sing-box-1.10.7-linux-amd64.tar.gz -o core.tgz
tar xzf core.tgz sing-box-1.10.7-linux-amd64/sing-box
export AETHER_TEST_SING_BOX="$tmp/sing-box-1.10.7-linux-amd64/sing-box"
cp "$root"/tools/exit-test/peer/*.go .
go mod init local.test/exit-peer
go get golang.zx2c4.com/wireguard/tun/netstack@v0.0.0-20250521234502-f333402bd9cb
go build -mod=mod -o peer .
export AETHER_TEST_WG_PEER="$tmp/peer"
cd "$root"
if ! bash gradlew :composeApp:testReleaseUnitTest --tests '*ExitTunnelTest' --tests '*WireGuardDataPlaneTest' --no-daemon 2>&1 | tee "$tmp/test.log"; then
    # Put the first build errors beside the test results in the check (also useful on headless runs).
    awk '/^e: |^> Task .*FAILED|^> Could not|^Execution failed for task|^Cannot locate tasks|^Task .*not found/ {if (n++ < 6) print "::error title=Loopback test build::" $0}' "$tmp/test.log"
    exit 1
fi
