#!/usr/bin/env bash
# Linux x86-64, JDK 17, Go 1.24. All test traffic stays on loopback.
set -Eeuo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
phase='prepare test tools'
trap 'echo "::error title=Loopback checks::$phase failed (line $LINENO)"' ERR
export GOTOOLCHAIN=local
if [[ -z ${AETHER_TEST_SING_BOX:-} ]]; then
    # Build only the features under test, from the version embedded in libsing-box.so.
    phase='build sing-box 1.10.7'
    GOBIN="$tmp" go install -tags with_wireguard,with_gvisor -ldflags=-checklinkname=0 github.com/sagernet/sing-box/cmd/sing-box@v1.10.7
    export AETHER_TEST_SING_BOX="$tmp/sing-box"
fi
if [[ -z ${AETHER_TEST_WG_PEER:-} ]]; then
    phase='build local WireGuard peer'
    (cd "$root/tools/exit-test/peer" && go build -mod=readonly -o "$tmp/peer" .)
    export AETHER_TEST_WG_PEER="$tmp/peer"
fi
phase='Shared transport tests'
cd "$root"
bash gradlew -p tools/exit-test test --no-daemon
