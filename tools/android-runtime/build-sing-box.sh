#!/usr/bin/env bash
# Rebuild the existing userspace exit (no new app library). Requires Go 1.24.x and an Android NDK.
set -euo pipefail
abi=$1; dest=$(realpath -m "$2"); mkdir -p "$(dirname "$dest")"
case $abi in arm64-v8a) arch=arm64; target=aarch64;; x86_64) arch=amd64; target=x86_64;; *) exit 2;; esac
ndk=${ANDROID_NDK_HOME:-$(find "${ANDROID_HOME:?}/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)}
cc="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/${target}-linux-android26-clang"; test -x "$cc"
module=github.com/sagernet/sing-box@v1.10.7
src=$(go mod download -json "$module" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Dir"])')
(cd "$src" && CGO_ENABLED=1 GOOS=android GOARCH="$arch" CC="$cc" go build -mod=readonly -trimpath -tags with_wireguard,with_gvisor \
  -ldflags='-s -w -checklinkname=0 -extldflags=-Wl,-z,max-page-size=16384' -o "$dest" ./cmd/sing-box)
readelf -lW "$dest" | python3 -c 'import sys; a=[int(l.split()[-1],16) for l in sys.stdin if l.lstrip().startswith("LOAD ")]; assert a and min(a)>=16384,a'
