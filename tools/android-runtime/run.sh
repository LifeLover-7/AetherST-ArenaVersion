#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
pkg=io.github.immaghzbad.aetherst.runtimecheck
adb install -r "$(find app/build/outputs/apk/debug -name '*.apk' -print -quit)"
adb install -r "$(find app/build/outputs/apk/androidTest/debug -name '*.apk' -print -quit)"
adb shell appops set "$pkg" ACTIVATE_VPN allow
result=0
for test in listenerEvidence wgProton wgFirefox goolDirect classicGoolDirect mimDirect; do
  log="$RUNNER_TEMP/device-$test.txt"
  adb shell am instrument -w -r -e class "io.github.immaghzbad.aetherst.DeviceRoutingTest#$test" "$pkg.test/androidx.test.runner.AndroidJUnitRunner" | tee "$log"
  if grep -Fq 'OK (1 test)' "$log" && ! grep -q 'Error in\|shortMsg=\|FAILURES!!!' "$log"; then
    echo "::notice title=Android runtime::$test: PASS"
  else
    reason=$(grep -m1 -E 'AssertionError|Exception|shortMsg=|Error:' "$log" | cut -c1-2000 || true)
    echo "::error title=Android runtime::$test: ${reason:-instrumentation failed}"; result=1
  fi
done
exit "$result"
