#!/bin/sh
# OSCam -> TCMG interoperability check.
# OSCam runs as a CLIENT with one reader per TCMG protocol (newcamd / cccam / cs378x);
# a camd35 UDP request is injected so each reader really connects and asks TCMG for a CW.
# usage: OSCAM_BIN=/path/to/oscam [TCMG_BIN=build/tcmg] sh tools/oscam-interop/run.sh [provid-hex]
# needs: python3 + the "cryptography" module, a localhost-capable OSCam with newcamd, CCcam and camd35 modules.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
TCMG_BIN=${TCMG_BIN:-$ROOT/build/tcmg}
PROV=${1:-}
[ -x "${OSCAM_BIN:-}" ] || { echo "set OSCAM_BIN to an oscam binary" >&2; exit 2; }
[ -x "$TCMG_BIN" ] || { echo "missing $TCMG_BIN (run make first)" >&2; exit 2; }
T=${TMPDIR:-/tmp}/tcmg-oscam-interop-$$
mkdir -p "$T/tcmg" "$T/oscam"
PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 1; rm -rf "$T"' EXIT INT TERM

cat > "$T/tcmg/tcmg.conf" <<CFG
[global]
socket_timeout = 30
[webif]
enabled = 0
[newcamd]
port = 25050
key = 0102030405060708091011121314
[cccam]
port = 22200
[cs378x]
port = 27000
CFG
{
  echo '[account]'; echo 'user = test'; echo 'pwd = test'; echo 'enabled = 1'; echo 'group = 1'; echo 'caid = 0B00'
  echo 'max_connections = 0'
  [ -n "$PROV" ] && echo "ident = 0B00:$PROV"
} > "$T/tcmg/tcmg.users"
cat > "$T/tcmg/tcmg.readers" <<CFG
[reader]
label = source-emu
protocol = emu
enabled = 1
group = 1
caid = 0B00
sid_whitelist = 0064
ecmwhitelist = 00
ecmkey = 0B00=9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F
CFG
cat > "$T/oscam/oscam.conf" <<CFG
[global]
logfile = $T/oscam/oscam.log
[cs357x]
port = 22001
CFG
for n in 1 2 3; do printf '[account]\nuser = local%s\npwd = local\ngroup = %s\n\n' $n $n; done > "$T/oscam/oscam.user"
cat > "$T/oscam/oscam.server" <<CFG
[reader]
label = tcmg_newcamd
protocol = newcamd
device = 127.0.0.1,25050
key = 0102030405060708091011121314
user = test
password = test
group = 1
caid = 0B00
disablecrccws = 1

[reader]
label = tcmg_cccam
protocol = cccam
device = 127.0.0.1,22200
user = test
password = test
group = 2
caid = 0B00

[reader]
label = tcmg_cs378x
protocol = cs378x
device = 127.0.0.1,27000
user = test
password = test
group = 3
caid = 0B00
CFG
"$TCMG_BIN" -c "$T/tcmg" >"$T/tcmg.out" 2>&1 & PIDS="$PIDS $!"
sleep 2
"$OSCAM_BIN" -b -c "$T/oscam" >"$T/oscam.out" 2>&1 & PIDS="$PIDS $!"
sleep 4
fail=0
for pair in "local1 newcamd" "local2 cccam" "local3 cs378x"; do
  set -- $pair
  if python3 "$HERE/inject.py" "$1" 22001 ${PROV:-000000} >"$T/r.$2" 2>&1; then echo "[$2] PASS"; else echo "[$2] FAIL: $(cat "$T/r.$2")"; fail=1; fi
done
exit $fail
