#!/usr/bin/env bash
# Linux host, Android emulator. All generated trust material stays in ignored build directories.
set -euo pipefail
cd "$(dirname "$0")/../.."
out="$PWD/app/build/runtime-check"; mkdir -p "$out"/{res/raw,res/xml,assets,jni/x86_64}; umask 077
bash tools/android-runtime/build-sing-box.sh x86_64 "$out/jni/x86_64/libsing-box.so"
(cd tools/exit-test/peer && go build -mod=readonly -o "$out/device-peers" ./device)
cd "$out"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=Ephemeral emulator test CA' -days 2 -keyout ca.key -out res/raw/device_ca.pem
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=edge.fixture.test' -keyout leaf.key -out leaf.csr
printf '%s\n' 'basicConstraints=CA:FALSE' 'extendedKeyUsage=serverAuth,clientAuth' 'subjectAltName=DNS:edge.fixture.test,DNS:firefox.settings.services.mozilla.com,IP:1.1.1.1' > extensions
openssl x509 -req -in leaf.csr -CA res/raw/device_ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile extensions -out leaf.pem
# Only the emulator-specific debug variant consumes these resources. Release trusts system roots only.
cat > res/xml/network_security_config.xml <<'XML'
<network-security-config>
  <base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/></trust-anchors></base-config>
  <domain-config><domain>1.1.1.1</domain><domain>edge.fixture.test</domain><domain>firefox.settings.services.mozilla.com</domain><trust-anchors><certificates src="@raw/device_ca"/></trust-anchors></domain-config>
</network-security-config>
XML
cp leaf.pem leaf.key assets/
rm -f peers.json
./device-peers "$out" > fixture.log 2>&1 &
for i in {1..50}; do if test -s peers.json; then cp peers.json assets/; exit 0; fi; sleep 0.1; done
cat fixture.log; exit 1
