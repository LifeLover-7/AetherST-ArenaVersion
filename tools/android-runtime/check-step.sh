#!/usr/bin/env bash
# Make the failing phase / compiler diagnostic available as a check annotation as well as in the log.
set -euo pipefail
phase=$1; shift
log=$(mktemp); trap 'rm -f "$log"' EXIT
if "$@" 2>&1 | tee "$log"; then exit 0; fi
python3 - "$log" "$phase" <<'PY'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines()
errors = [s for s in lines if s.startswith(('e: ', '* What went wrong:', '> ')) or 'error:' in s.lower()]
msg = '\n'.join((errors[-16:] if errors else lines[-18:]))[:3500]
print('::error title=' + sys.argv[2] + '::' + msg.replace('%', '%25').replace('\n', '%0A').replace('\r', '%0D'))
PY
exit 1
