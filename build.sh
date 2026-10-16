#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$ROOT_DIR/.tcmg-build"
TOOLCHAIN_DIR="$STATE_DIR/toolchains"
LOG_DIR="$STATE_DIR/logs"
VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"

[[ -f "$ROOT_DIR/Makefile" && -f "$ROOT_DIR/src/main.c" ]] || {
  echo "ERROR: run this script from the TCMG source tree" >&2
  exit 1
}

mkdir -p "$STATE_DIR" "$TOOLCHAIN_DIR" "$LOG_DIR"

DEVICES=()
TOOLCHAINS=()
DEVICE_CATALOG="$ROOT_DIR/catalog/devices.tsv"
TOOLCHAIN_CATALOG="$ROOT_DIR/catalog/toolchains.tsv"

TARGET=""
PLATFORM=""
ARCH=""
DESCRIPTION=""
CONF_DIR=""
PCSC=""
TOOLCHAIN=""
RELEASE=1
CLEAN=1
JOBS="auto"
CFLAGS_EXTRA=""
LDFLAGS_EXTRA=""
CC_EXPLICIT=""
CURRENT_CC=""
SAVE=1
PCSC_CFLAGS=""
PCSC_LIBS=""
PCSC_ENABLED=0
TC_RUNTIME_ROOT=""

say(){ printf '%s\n' "$*"; }
line(){ printf '%s\n' '------------------------------------------------------------'; }
ok(){ printf '  %-8s %s\n' OK "$*"; }
warn(){ printf '  %-8s %s\n' WARN "$*" >&2; }
err(){ printf '  %-8s %s\n' ERROR "$*" >&2; }

load_catalogs(){
  local row
  [[ -f "$DEVICE_CATALOG" ]] || { err "Device catalog missing: $DEVICE_CATALOG"; return 1; }
  [[ -f "$TOOLCHAIN_CATALOG" ]] || { err "Toolchain catalog missing: $TOOLCHAIN_CATALOG"; return 1; }
  while IFS= read -r row || [[ -n "$row" ]]; do
    [[ -z "$row" || "$row" == \#* ]] && continue
    DEVICES+=("$row")
  done < "$DEVICE_CATALOG"
  while IFS= read -r row || [[ -n "$row" ]]; do
    [[ -z "$row" || "$row" == \#* ]] && continue
    TOOLCHAINS+=("$row")
  done < "$TOOLCHAIN_CATALOG"
  [[ ${#DEVICES[@]} -gt 0 ]] || { err 'Device catalog is empty'; return 1; }
  [[ ${#TOOLCHAINS[@]} -gt 0 ]] || { err 'Toolchain catalog is empty'; return 1; }
}

load_catalogs || exit 1

TUI_ACTIVE=0
TUI_STTY=''

declare -a TUI_FAMILIES=()
declare -A TUI_FAMILY_ROWS=()
declare -A TUI_FAMILY_COUNTS=()
declare -a TUI_ROWS=()

_tui_family_for_row(){
  local row="$1" name platform arch description conf pcsc tc s
  IFS='|' read -r name platform arch description conf pcsc tc <<< "$row"
  s="${name,,} ${description,,}"

  case "$name" in
    platform-*|profile-*) printf '%s\n' 'Build Profiles'; return ;;
  esac

  case "$s" in
    *windows*|*macos*) printf '%s\n' 'Windows / macOS'; return ;;
    *forever*) printf '%s\n' 'Forever'; return ;;
    *novaler*) printf '%s\n' 'Novaler'; return ;;
    *multibox*|*maxytec*) printf '%s\n' 'MaXytec / MultiBox'; return ;;
    *dreambox*|*dreamone*|*dreamtwo*) printf '%s\n' 'Dreambox'; return ;;
    *vuplus*|*'vu+'*|vuuno*|vuzero*|vuduo*|vusolo*|vuultimo*|vusolo4k*) printf '%s\n' 'Vu+'; return ;;
    *formuler*) printf '%s\n' 'Formuler'; return ;;
    gb*|*gigablue*) printf '%s\n' 'GigaBlue'; return ;;
    et*|e3hd|e4hd|*xtrend*) printf '%s\n' 'Xtrend / ET'; return ;;
    h[0-9]*|hd[0-9]*|hzero|*zgemma*) printf '%s\n' 'Zgemma / H-Series'; return ;;
    *mutant*|*'ax/mutant'*|*' ax '*) printf '%s\n' 'Mutant / AX'; return ;;
    *edision*|osmini*|osmega|osmio*|*'os mio'*) printf '%s\n' 'Edision'; return ;;
    *qnap*) printf '%s\n' 'QNAP'; return ;;
    *synology*) printf '%s\n' 'Synology'; return ;;
    *raspberry*|rpi-*) printf '%s\n' 'Raspberry Pi'; return ;;
    *fritz*|*'fritz!box'*) printf '%s\n' 'FRITZ!Box'; return ;;
    *ubiquiti*|*ubnt*) printf '%s\n' 'Ubiquiti'; return ;;
    *openwrt*) printf '%s\n' 'OpenWrt / Routers'; return ;;
    *openembedded*|*'oe20'*|*'openpli'*) printf '%s\n' 'OpenEmbedded / OpenPLi'; return ;;
    *coolstream*|*cool2*) printf '%s\n' 'COOLSTREAM'; return ;;
    *dbox*|*ppcold*) printf '%s\n' 'DBox'; return ;;
    *sh4*) printf '%s\n' 'SH4'; return ;;
    *native*|tubox|generic-*|bootlin-*) printf '%s\n' 'Generic / Development'; return ;;
  esac

  case "$arch" in
    arm|armv5|armv6|armv7|aarch64) printf '%s\n' 'Generic ARM / AArch64'; return ;;
    mips|mipsel|mips32el|mips64) printf '%s\n' 'Generic MIPS'; return ;;
    powerpc) printf '%s\n' 'Generic PowerPC'; return ;;
    csky) printf '%s\n' 'C-SKY'; return ;;
    *) printf '%s\n' 'Other STB'; return ;;
  esac
}

_tui_build_families(){
  local row fam
  TUI_FAMILIES=()
  TUI_FAMILY_ROWS=()
  TUI_FAMILY_COUNTS=()
  for row in "${DEVICES[@]}"; do
    fam="$(_tui_family_for_row "$row")"
    if [[ -z "${TUI_FAMILY_COUNTS[$fam]+x}" ]]; then
      TUI_FAMILIES+=("$fam")
      TUI_FAMILY_COUNTS[$fam]=0
      TUI_FAMILY_ROWS[$fam]=''
    fi
    TUI_FAMILY_COUNTS[$fam]=$((TUI_FAMILY_COUNTS[$fam]+1))
    TUI_FAMILY_ROWS[$fam]+="$row"$'\n'
  done
}

_tui_lines(){
  local n="$(tput lines 2>/dev/null || printf '24')"
  [[ "$n" =~ ^[0-9]+$ ]] || n=24
  (( n < 16 )) && n=16
  printf '%s' "$n"
}

_tui_cols(){
  local n="$(tput cols 2>/dev/null || printf '90')"
  [[ "$n" =~ ^[0-9]+$ ]] || n=90
  (( n < 70 )) && n=70
  printf '%s' "$n"
}

_tui_trim(){
  local text="$1" width="$2"
  (( width < 8 )) && width=8
  if (( ${#text} > width )); then
    printf '%.*s...' "$((width-3))" "$text"
  else
    printf '%s' "$text"
  fi
}

_tui_start(){
  [[ "$TUI_ACTIVE" == 1 ]] && return 0
  TUI_STTY="$(stty -g 2>/dev/null || true)"
  stty -echo -icanon min 1 time 0 2>/dev/null || return 1
  printf '\033[?25l'
  TUI_ACTIVE=1
}

_tui_stop(){
  [[ "$TUI_ACTIVE" == 1 ]] || return 0
  printf '\033[?25h\033[0m\n'
  [[ -n "$TUI_STTY" ]] && stty "$TUI_STTY" 2>/dev/null || stty sane 2>/dev/null || true
  TUI_ACTIVE=0
}

_tui_pause(){
  local prompt="${1:-Press Enter to return to the TUI...}"
  _tui_stop
  printf '%s' "$prompt"
  read -r _
  _tui_start
}

_tui_key(){
  local k rest
  IFS= read -rsN1 k || return 1
  if [[ "$k" == $'\e' ]]; then
    rest=''
    IFS= read -rsN2 -t 0.05 rest || true
    k+="$rest"
  fi
  case "$k" in
    $'\e[A'|k) printf 'up' ;;
    $'\e[B'|j) printf 'down' ;;
    $'\e[C'|l) printf 'right' ;;
    $'\e[D'|h) printf 'left' ;;
    $'\e[H'|g) printf 'home' ;;
    $'\e[F'|G) printf 'end' ;;
    $'\e[5~') printf 'pageup' ;;
    $'\e[6~') printf 'pagedown' ;;
    $'\e') printf 'back' ;;
    $'\n'|$'\r') printf 'enter' ;;
    q|Q) printf 'quit' ;;
    b|B) printf 'back' ;;
    *) printf '%s' "$k" ;;
  esac
}

_tui_header(){
  local title="$1" detail="${2:-}"
  printf '\033[H\033[2J'
  printf ' TCMG %s  |  build TUI\n' "$VERSION"
  printf ' %s\n' "$title"
  [[ -n "$detail" ]] && printf ' %s\n' "$detail"
  printf '%s\n' '------------------------------------------------------------'
}

_tui_family_menu(){
  _tui_build_families
  _tui_start || return 1
  local pos=0 total=${#TUI_FAMILIES[@]} key lines max_rows start end i fam mark
  while :; do
    lines="$(_tui_lines)"
    max_rows=$((lines-8)); (( max_rows < 5 )) && max_rows=5
    start=0
    (( pos >= max_rows )) && start=$((pos-max_rows+1))
    end=$((start+max_rows)); (( end > total )) && end=$total

    _tui_header 'Select device family' "$total families / ${#DEVICES[@]} profiles"
    for ((i=start;i<end;i++)); do
      fam="${TUI_FAMILIES[$i]}"
      mark=' '
      [[ "$i" == "$pos" ]] && mark='>'
      printf ' %s %-28s %4d devices\n' "$mark" "$fam" "${TUI_FAMILY_COUNTS[$fam]}"
    done
    printf '\n ↑↓ select   Enter open   PgUp/PgDn   Home/End   q quit\n'

    key="$(_tui_key)"
    case "$key" in
      up) ((pos>0)) && pos=$((pos-1));;
      down) ((pos<total-1)) && pos=$((pos+1));;
      home) pos=0;; end) pos=$((total-1));;
      pageup) pos=$((pos-max_rows)); ((pos<0)) && pos=0;;
      pagedown) pos=$((pos+max_rows)); ((pos>total-1)) && pos=$((total-1));;
      enter) TUI_RESULT="${TUI_FAMILIES[$pos]}"; return 0;;
      back|quit) TUI_RESULT=''; return 1;;
    esac
  done
}

_tui_device_menu(){
  local family="$1"
  mapfile -t TUI_ROWS < <(printf '%s' "${TUI_FAMILY_ROWS[$family]}" | sed '/^$/d')
  local total=${#TUI_ROWS[@]}
  (( total > 0 )) || return 1
  local pos=0 key lines max_rows start end i name platform arch desc conf pcsc tc mark width
  while :; do
    lines="$(_tui_lines)"
    max_rows=$((lines-13)); (( max_rows < 4 )) && max_rows=4
    start=0
    (( pos >= max_rows )) && start=$((pos-max_rows+1))
    end=$((start+max_rows)); (( end > total )) && end=$total
    IFS='|' read -r name platform arch desc conf pcsc tc <<< "${TUI_ROWS[$pos]}"
    width=$(( $(_tui_cols) - 18 )); (( width < 24 )) && width=24

    _tui_header "$family" "$total devices"
    printf ' Selected: %s\n' "$desc"
    printf ' ID=%s  arch=%s  pcsc=%s\n\n' "$name" "$arch" "$pcsc"
    for ((i=start;i<end;i++)); do
      IFS='|' read -r name platform arch desc conf pcsc tc <<< "${TUI_ROWS[$i]}"
      mark=' '
      [[ "$i" == "$pos" ]] && mark='>'
      printf ' %s %3d  %s\n' "$mark" "$((i+1))" "$(_tui_trim "$desc" "$width")"
    done
    printf '\n ↑↓ select   Enter actions   b back   q quit\n'

    key="$(_tui_key)"
    case "$key" in
      up) ((pos>0)) && pos=$((pos-1));;
      down) ((pos<total-1)) && pos=$((pos+1));;
      home) pos=0;; end) pos=$((total-1));;
      pageup) pos=$((pos-max_rows)); ((pos<0)) && pos=0;;
      pagedown) pos=$((pos+max_rows)); ((pos>total-1)) && pos=$((total-1));;
      enter) TUI_RESULT="${TUI_ROWS[$pos]}"; return 0;;
      back) return 2;;
      quit) TUI_RESULT=''; return 1;;
    esac
  done
}

_tui_action_menu(){
  local row="$1" action=0 key name platform arch desc conf pcsc tc
  IFS='|' read -r name platform arch desc conf pcsc tc <<< "$row"
  local -a actions=('Build' 'Edit configuration' 'Toolchain' 'Clean build' 'Back')
  local n=${#actions[@]} i mark
  while :; do
    _tui_header "$desc" "Device: $name"
    printf ' platform   %s\n arch        %s\n config      %s\n pcsc        %s\n toolchain   %s\n\n' "$platform" "$arch" "$conf" "$pcsc" "$tc"
    for ((i=0;i<n;i++)); do
      mark=' '
      [[ "$i" == "$action" ]] && mark='>'
      printf ' %s %d  %s\n' "$mark" "$((i+1))" "${actions[$i]}"
    done
    printf '\n ↑↓ select   Enter run   b back   q quit\n'
    key="$(_tui_key)"
    case "$key" in
      up) ((action>0)) && action=$((action-1));;
      down) ((action<n-1)) && action=$((action+1));;
      home) action=0;; end) action=$((n-1));;
      enter)
        case "$action" in
          0) TUI_RESULT='build';;
          1) TUI_RESULT='config';;
          2) TUI_RESULT='toolchain';;
          3) TUI_RESULT='clean';;
          4) TUI_RESULT='back';;
        esac
        return 0;;
      back) TUI_RESULT='back'; return 0;;
      quit) TUI_RESULT='quit'; return 0;;
    esac
  done
}

run_tui(){
  local family row action rc
  while :; do
    _tui_family_menu || { _tui_stop; return 0; }
    family="$TUI_RESULT"
    while :; do
      if _tui_device_menu "$family"; then
        rc=0
      else
        rc=$?
      fi
      [[ "$rc" == 1 ]] && { _tui_stop; return 0; }
      [[ "$rc" == 2 ]] && break
      row="$TUI_RESULT"
      while :; do
        _tui_action_menu "$row"
        action="$TUI_RESULT"
        case "$action" in
          back) break;;
          quit) _tui_stop; return 0;;
          build)
            load_defaults "$row"
            save_state
            _tui_stop
            if build_device; then
              rc=0
            else
              rc=$?
            fi
            printf '\n'
            _tui_pause
            [[ "$rc" != 0 ]] && return "$rc"
            ;;
          config)
            load_defaults "$row"
            _tui_stop
            if interactive; then
              rc=0
            else
              rc=$?
            fi
            save_state
            _tui_start || return 1
            ;;
          toolchain)
            load_defaults "$row"
            _tui_stop
            if [[ "$TOOLCHAIN" == native ]]; then
              ok 'Native compiler - nothing to download'
              rc=0
            elif [[ "$TOOLCHAIN" == manual ]]; then
              err 'Manual toolchain: use --toolchain-dir /path/to/sdk'
              rc=1
            else
              if fetch_toolchain "$TOOLCHAIN"; then
                rc=0
              else
                rc=$?
              fi
            fi
            _tui_pause
            [[ "$rc" != 0 ]] && return "$rc"
            ;;
          clean)
            load_defaults "$row"
            _tui_stop
            if clean_device; then
              rc=0
            else
              rc=$?
            fi
            _tui_pause
            [[ "$rc" != 0 ]] && return "$rc"
            ;;
        esac
      done
    done
  done
}

FZF_RESULT=''
FZF_FAMILY_LINES=()
FZF_DEVICE_LINES=()

_fzf_build_family_lines(){
  local row fam
  _tui_build_families
  FZF_FAMILY_LINES=()
  for fam in "${TUI_FAMILIES[@]}"; do
    FZF_FAMILY_LINES+=("${fam}|${TUI_FAMILY_COUNTS[$fam]}")
  done
}

_fzf_device_line(){
  local row="$1" name platform arch description conf pcsc tc
  IFS='|' read -r name platform arch description conf pcsc tc <<< "$row"
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$name" "$arch" "$pcsc" "$description" "$platform" "$conf" "$tc"
}

_fzf_select_device(){
  local family="$1" row selected name arch pcsc description platform conf tc
  mapfile -t FZF_DEVICE_LINES < <(
    printf '%s' "${TUI_FAMILY_ROWS[$family]}" |
      while IFS= read -r row; do
        [[ -n "$row" ]] || continue
        _fzf_device_line "$row"
      done
  )
  ((${#FZF_DEVICE_LINES[@]} > 0)) || return 1

  selected="$(printf '%s\n' "${FZF_DEVICE_LINES[@]}" | fzf \
    --height=78% --layout=reverse --border=rounded --cycle \
    --prompt='Device > ' --header="${family}  ·  Type to fuzzy-search  ·  Enter select  ·  Esc back" \
    --delimiter='[|]' --with-nth='1,2,3,4' --nth='1,2,3,4' --scheme=history \
    --preview='printf "Device: %s\\nArchitecture: %s\\nPC/SC: %s\\nPlatform: %s\\nConfig: %s\\nToolchain: %s\\n\\n%s\\n" {1} {2} {3} {5} {6} {7} {4}' \
    --preview-window='right:42%:wrap' || true)"
  [[ -n "$selected" ]] || return 1
  name="${selected%%|*}"
  [[ -n "$name" ]] || return 1
  FZF_RESULT="$(find_device "$name" || true)"
  [[ -n "$FZF_RESULT" ]] || return 1
  return 0
}

_fzf_search_all_devices(){
  local row selected name
  FZF_DEVICE_LINES=()
  for row in "${DEVICES[@]}"; do
    FZF_DEVICE_LINES+=("$(_fzf_device_line "$row")")
  done
  selected="$(printf '%s\n' "${FZF_DEVICE_LINES[@]}" | fzf \
    --height=88% --layout=reverse --border=rounded --cycle \
    --prompt='Search > ' --header='All devices  ·  Fuzzy search across the complete catalog  ·  Enter select  ·  Esc back' \
    --delimiter='[|]' --with-nth='1,2,3,4' --nth='1,2,3,4' --scheme=history \
    --preview='printf "Device: %s\\nArchitecture: %s\\nPC/SC: %s\\nPlatform: %s\\nConfig: %s\\nToolchain: %s\\n\\n%s\\n" {1} {2} {3} {5} {6} {7} {4}' \
    --preview-window='right:42%:wrap' || true)"
  [[ -n "$selected" ]] || return 1
  name="${selected%%|*}"
  FZF_RESULT="$(find_device "$name" || true)"
  [[ -n "$FZF_RESULT" ]] || return 1
  return 0
}

_fzf_select_action(){
  local device="$1" name platform arch desc conf pcsc tc
  IFS='|' read -r name platform arch desc conf pcsc tc <<< "$device"
  local selected
  selected="$(printf '%s\n' \
    'Build' \
    'Edit configuration' \
    'Toolchain' \
    'Clean build' \
    'Back to devices' \
    | fzf \
    --height=48% --layout=reverse --border=rounded --prompt='Action > ' \
    --header="${desc}  ·  ${arch}  ·  PC/SC ${pcsc}" \
    --no-multi --info=inline --pointer='▶' --marker='✓' \
    --preview-window='right:1%:hidden' || true)"
  [[ -n "$selected" ]] || return 1
  case "$selected" in
    Build) FZF_RESULT='build';;
    'Edit configuration') FZF_RESULT='config';;
    Toolchain) FZF_RESULT='toolchain';;
    'Clean build') FZF_RESULT='clean';;
    'Back to devices') FZF_RESULT='back';;
    *) return 1;;
  esac
  return 0
}

_fzf_wait(){
  local prompt="${1:-Press Enter to continue...}"
  printf '\n%s' "$prompt"
  IFS= read -r _ || true
}

run_fzf(){
  command -v fzf >/dev/null 2>&1 || return 2
  [[ -t 0 && -t 1 ]] || return 2

  local family row action rc
  _fzf_build_family_lines

  while :; do
    local family_lines=( '[ Search all devices ]|0' "${FZF_FAMILY_LINES[@]}" )
    family="$(printf '%s\n' "${family_lines[@]}" | fzf \
      --height=78% --layout=reverse --border=rounded --cycle \
      --prompt='TCMG > ' --header="TCMG ${VERSION}  ·  ${#DEVICES[@]} devices  ·  Fuzzy search  ·  Enter select  ·  Esc quit" \
      --delimiter='[|]' --with-nth='1,2' --scheme=history \
      --preview='printf "Selection: %s\\nDevices: %s\\n" {1} {2}' \
      --preview-window='right:30%:wrap' || true)"
    [[ -n "$family" ]] || return 0

    if [[ "$family" == '[ Search all devices ]|0' ]]; then
      _fzf_search_all_devices || continue
      row="$FZF_RESULT"
    else
      family="${family%%|*}"
      if ! _fzf_select_device "$family"; then
        continue
      fi
      row="$FZF_RESULT"
    fi

    while :; do
      if ! _fzf_select_action "$row"; then
        break
      fi
      action="$FZF_RESULT"
      case "$action" in
        back)
          break
          ;;
        build)
          load_defaults "$row"
          save_state
          if build_device; then
            rc=0
          else
            rc=$?
          fi
          _fzf_wait
          [[ "$rc" == 0 ]] || return "$rc"
          ;;
        config)
          load_defaults "$row"
          if interactive; then
            rc=0
          else
            rc=$?
          fi
          save_state
          (( rc == 0 )) && { printf '\n'; ok "Configuration saved for $(device_label "$TARGET")"; show_config; }
          _fzf_wait
          [[ "$rc" == 0 ]] || return "$rc"
          ;;
        toolchain)
          load_defaults "$row"
          if [[ "$TOOLCHAIN" == native ]]; then
            ok 'Native compiler - nothing to download'
            rc=0
          elif [[ "$TOOLCHAIN" == manual ]]; then
            err 'Manual toolchain: use --toolchain-dir /path/to/sdk'
            rc=1
          else
            if fetch_toolchain "$TOOLCHAIN"; then rc=0; else rc=$?; fi
          fi
          _fzf_wait
          [[ "$rc" == 0 ]] || return "$rc"
          ;;
        clean)
          load_defaults "$row"
          if clean_device; then rc=0; else rc=$?; fi
          _fzf_wait
          [[ "$rc" == 0 ]] || return "$rc"
          ;;
      esac
    done
  done
}

usage(){
  cat <<'TXT'
TCMG $VERSION - simple device builder

  ./build.sh                 Interactive build wizard (fzf, with TUI fallback)
  ./build.sh list            List devices
  ./build.sh plan <device>   Show saved settings
  ./build.sh config <device> Edit settings and save
  ./build.sh build <device> Build one device
  ./build.sh toolchain <device> Download/prepare its toolchain
  ./build.sh clean <device> Clean only that device
  ./build.sh self-test       Test the builder itself

Interactive UI:
  TCMG_UI=auto|fzf|tui
  Examples: TCMG_UI=fzf ./build.sh
            ./build.sh wizard --ui fzf
            ./build.sh wizard --ui tui

The fzf wizard provides fuzzy search across all devices, grouped families,
device previews, and Build/Edit/Toolchain/Clean actions.
  ./build.sh check           Check the builder environment

Build options:
  --pcsc auto|on|off
  --release / --debug
  --clean / --no-clean
  --jobs auto|N
  --confdir DIR
  --cflags TEXT
  --ldflags TEXT
  --cc PATH
  --toolchain-dir DIR       Manual SDK/toolchain root

Cross Linux targets default to PC/SC on. The builder prepares a target-side
static libpcsclite client automatically under the selected toolchain.
  --no-save

Nothing is shared between device builds except the source tree. Each device
gets its own build/<device>/ directory and its own saved state.
TXT
}

bool(){ case "${1:-}" in 1|on|yes|true|ON|YES|TRUE) echo 1;; 0|off|no|false|OFF|NO|FALSE) echo 0;; *) return 1;; esac; }

find_device(){
  local wanted="$1" row name
  for row in "${DEVICES[@]}"; do
    IFS='|' read -r name _ <<< "$row"
    if [[ "$name" == "$wanted" ]]; then printf '%s\n' "$row"; return 0; fi
  done
  return 1
}

find_toolchain(){
  local wanted="$1" row name
  for row in "${TOOLCHAINS[@]}"; do
    IFS='|' read -r name _ <<< "$row"
    if [[ "$name" == "$wanted" ]]; then printf '%s\n' "$row"; return 0; fi
  done
  return 1
}

state_file(){ printf '%s/%s.conf\n' "$STATE_DIR" "$1"; }

load_catalog_defaults(){
  local row="$1" catalog_name
  IFS='|' read -r catalog_name PLATFORM ARCH DESCRIPTION CONF_DIR PCSC TOOLCHAIN <<< "$row"
  TARGET="$catalog_name"
  RELEASE=1
  CLEAN=1
  JOBS=auto
  CFLAGS_EXTRA=""
  LDFLAGS_EXTRA=""
  CC_EXPLICIT=""
}

has_saved_state(){
  [[ -f "$(state_file "$TARGET")" ]]
}

load_defaults(){
  local row="$1" catalog_name
  load_catalog_defaults "$row"
  IFS='|' read -r catalog_name _ <<< "$row"
  local state
  state="$(state_file "$catalog_name")"
  if [[ -f "$state" ]]; then
    source "$state"
    TARGET="$catalog_name"
  fi
  if [[ "$catalog_name" == "windows-x64" ]]; then
    case "$CONF_DIR" in
      'C:/ProgramData/TCMG'|'C:\ProgramData\TCMG')
        CONF_DIR="./"
        warn "Migrated Windows config directory to ./"
        ;;
    esac
  fi
}

save_state(){
  [[ "$SAVE" == 1 ]] || return 0
  local f tmp
  f="$(state_file "$TARGET")"; tmp="$f.tmp.$$"
  {
    printf 'PCSC=%q\n' "$PCSC"
    printf 'RELEASE=%q\n' "$RELEASE"
    printf 'CLEAN=%q\n' "$CLEAN"
    printf 'JOBS=%q\n' "$JOBS"
    printf 'CONF_DIR=%q\n' "$CONF_DIR"
    printf 'CFLAGS_EXTRA=%q\n' "$CFLAGS_EXTRA"
    printf 'LDFLAGS_EXTRA=%q\n' "$LDFLAGS_EXTRA"
    printf 'CC_EXPLICIT=%q\n' "$CC_EXPLICIT"
  } > "$tmp"
  mv -f "$tmp" "$f"
}

device_label(){
  local row name platform arch description conf pcsc tc
  row="$(find_device "$1" 2>/dev/null || true)"
  if [[ -n "$row" ]]; then
    IFS='|' read -r name platform arch description conf pcsc tc <<< "$row"
    [[ -n "$description" ]] && { printf '%s' "$description"; return 0; }
  fi
  printf '%s' "$1"
}

show_devices(){
  local i=1 row name label
  echo
  printf '%s\n' "TCMG $VERSION devices (${#DEVICES[@]})"
  line
  for row in "${DEVICES[@]}"; do
    IFS='|' read -r name _ <<< "$row"
    label="$(device_label "$name")"
    printf '  %2d) %s\n' "$i" "$label"
    i=$((i + 1))
  done
  echo
}

show_config(){
  line
  printf '%-20s %s\n' Device "$(device_label "$TARGET")"
  printf '%-20s %s\n' ID "$TARGET"
  printf '%-20s %s\n' Platform "$PLATFORM"
  printf '%-20s %s\n' Architecture "$ARCH"
  printf '%-20s %s\n' 'Config directory' "$CONF_DIR"
  printf '%-20s %s\n' Toolchain "$TOOLCHAIN"
  printf '%-20s %s\n' 'PC/SC' "$PCSC"
  printf '%-20s %s\n' 'Build' "$([[ "$RELEASE" == 1 ]] && echo Release || echo Debug)"
  printf '%-20s %s\n' Clean "$CLEAN"
  printf '%-20s %s\n' Jobs "$JOBS"
  printf '%-20s %s\n' Compiler "${CC_EXPLICIT:-auto}"
  printf '%-20s %s\n' CFLAGS "${CFLAGS_EXTRA:-<none>}"
  printf '%-20s %s\n' LDFLAGS "${LDFLAGS_EXTRA:-<none>}"
  line
}

show_profile(){
  local row="$1"
  load_defaults "$row"
  echo
  printf '%s\n' "Profile — $(device_label "$TARGET")"
  show_config
}

choose_device(){
  show_devices
  local n row choice total=${#DEVICES[@]}
  read -r -p "Select device [1-$total]: " choice
  [[ "$choice" =~ ^[0-9]+$ ]] || { err 'Invalid device'; exit 1; }
  n=1
  for row in "${DEVICES[@]}"; do
    if [[ "$n" == "$choice" ]]; then
      load_catalog_defaults "$row"
      CHOSEN_ROW="$row"
      return 0
    fi
    n=$((n + 1))
  done
  err 'Invalid device'; exit 1
}

jobs_num(){
  if [[ "$JOBS" == auto ]]; then
    command -v nproc >/dev/null 2>&1 && nproc || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2
  else
    echo "$JOBS"
  fi
}

need(){ command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; return 1; }; }

probe_compiler(){
  local cc="$1" probe
  if [[ ! -x "$cc" ]]; then
    err "Compiler is not executable: $cc"
    return 1
  fi
  if ! probe="$($cc -dumpmachine 2>/dev/null)"; then
    err "Compiler exists but cannot execute: $cc"
    if command -v file >/dev/null 2>&1; then file "$cc" >&2 || true; fi
    if command -v readelf >/dev/null 2>&1; then
      readelf -l "$cc" 2>/dev/null | grep -F 'Requesting program interpreter' >&2 || true
    fi
    err "This is usually a relocated/missing SDK loader problem, not a C source error."
    return 1
  fi
  if [[ -n "$probe" ]]; then
    ok "Compiler probe: $probe" >&2
  else
    ok "Compiler executable probe passed" >&2
  fi
}

ensure_legacy_sdk_alias(){
  local root="$1" cc="$2" interp legacy_root host_subdir real_root current
  [[ -f "$cc" ]] || return 0
  command -v readelf >/dev/null 2>&1 || return 0
  interp="$(readelf -l "$cc" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \([^]]*\).*/\1/p' | head -n1)"
  [[ -n "$interp" ]] || return 0
  case "$interp" in
    */sysroots/x86_64-*/lib/ld-linux-x86-64.so.2)
      host_subdir="${interp#*/sysroots/}"
      legacy_root="${interp%/sysroots/${host_subdir}}"
      ;;
    *)
      return 0
      ;;
  esac
  [[ -n "$legacy_root" && "$legacy_root" != "/" ]] || return 0
  real_root="$(readlink -f "$root" 2>/dev/null || printf '%s' "$root")"
  if [[ -L "$legacy_root" ]]; then
    current="$(readlink -f "$legacy_root" 2>/dev/null || true)"
    [[ "$current" == "$real_root" ]] && return 0
    rm -f "$legacy_root"
  elif [[ -e "$legacy_root" ]]; then
    current="$(readlink -f "$legacy_root" 2>/dev/null || true)"
    if [[ "$current" == "$real_root" ]]; then
      return 0
    fi
    err "SDK expects legacy prefix $legacy_root, but it already exists and is not this toolchain"
    err "Remove/rename that directory or use --toolchain-dir with an SDK already installed there"
    return 1
  fi
  mkdir -p "$(dirname "$legacy_root")"
  ln -s "$real_root" "$legacy_root"
  ok "Legacy SDK alias: $legacy_root -> $real_root" >&2
}

normalize_oe_toolchain(){
  local root="$1" prefix="$2" host_bin d cc found
  [[ -d "$root" ]] || return 0
  found="$(locate_cross_gcc "$root" "$prefix" 2>/dev/null || true)"
  [[ -n "$found" ]] || return 0
  cc="${found#*|}"
  ensure_legacy_sdk_alias "$root" "$cc" || return 1
  if [[ -n "$prefix" && ! -x "$root/bin/${prefix}gcc" && -d "$root/sysroots" ]]; then
    host_bin=""
    while IFS= read -r -d '' d; do
      if [[ -x "$d/${prefix}gcc" ]]; then
        host_bin="$d"
        break
      fi
    done < <(find -L "$root/sysroots" -type d -path "*/usr/bin/${prefix%?}" -print0 2>/dev/null)
    if [[ -n "$host_bin" ]]; then
      rm -f "$root/bin" 2>/dev/null || true
      ln -s "${host_bin#"$root/"}" "$root/bin" 2>/dev/null || true
    fi
  fi
}

toolchain_cache_root(){ printf '%s/%s\n' "$TOOLCHAIN_DIR" "$1"; }
toolchain_runtime_root(){ printf '%s/extract\n' "$(toolchain_cache_root "$1")"; }

materialize_toolchain(){
  local tc="$1" cache root archive row name desc arch url sha prefix sysrel cflags ldflags
  row="$(find_toolchain "$tc" || true)"; [[ -n "$row" ]] || { err "No managed toolchain for $tc"; return 1; }
  IFS='|' read -r name desc arch url sha prefix sysrel cflags ldflags <<< "$row"
  cache="$(toolchain_cache_root "$tc")"
  archive="$cache/toolchain.archive"
  root="$(toolchain_runtime_root "$tc")"
  [[ -f "$archive" ]] || { err "Cached toolchain archive missing: $archive"; return 1; }
  need sha256sum || return 1
  if ! printf '%s  %s\n' "$sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
    err "Cached toolchain SHA-256 mismatch: $archive"
    return 1
  fi
  mkdir -p "$cache"
  rm -rf "$root"
  mkdir -p "$root"
  case "$url" in
    *.tar.bz2) tar -xjf "$archive" -C "$root" || { err "Extract failed: $tc"; return 1; };;
    *.tar.xz)  tar -xJf "$archive" -C "$root" || { err "Extract failed: $tc"; return 1; };;
    *.tar.gz)  tar -xzf "$archive" -C "$root" || { err "Extract failed: $tc"; return 1; };;
    *)         tar -xf "$archive" -C "$root" || { err "Extract failed: $tc"; return 1; };;
  esac
  normalize_oe_toolchain "$root" "$prefix" || return 1
  printf '%s\n' "$root" > "$cache/root.path"
}

cross_pcsc_root(){
  local root=""
  if [[ "$TOOLCHAIN" == manual ]]; then
    root="$(cat "$STATE_DIR/manual-toolchain-$TARGET.path" 2>/dev/null || true)"
  else
    root="$(cat "$(toolchain_cache_root "$TOOLCHAIN")/root.path" 2>/dev/null || true)"
    [[ -n "$root" ]] || root="$(toolchain_runtime_root "$TOOLCHAIN")"
  fi
  [[ -n "$root" ]] && printf '%s\n' "$root"
}

pcsc_header_probe(){
  local cc="$1"
  local flags="${2:-}"
  printf '#include <PCSC/winscard.h>\n#include <PCSC/wintypes.h>\nint tcmg_pcsc_probe;\n' |
    "$cc" $TC_CFLAGS $flags -E -x c - >/dev/null 2>&1
}

existing_cross_pcsc(){
  local tcroot="${1:-$(cross_pcsc_root)}" sysroot="${2:-${TC_SYSROOT:-}}" inc lib
  PCSC_CFLAGS=""
  PCSC_LIBS=""
  if [[ -f "$tcroot/pcsc-libs/include/PCSC/winscard.h" &&
        -f "$tcroot/pcsc-libs/include/PCSC/wintypes.h" &&
        -f "$tcroot/pcsc-libs/include/PCSC/pcsclite.h" &&
        -f "$tcroot/pcsc-libs/lib/libpcsclite.a" ]]; then
    PCSC_CFLAGS="-I$tcroot/pcsc-libs/include -I$tcroot/pcsc-libs/include/PCSC"
    PCSC_LIBS="-L$tcroot/pcsc-libs/lib -lpcsclite -ldl"
    return 0
  fi
  if [[ -n "$sysroot" ]]; then
    for inc in "$sysroot/usr/include" "$sysroot/include"; do
      [[ -f "$inc/PCSC/winscard.h" ]] || continue
      [[ -f "$inc/PCSC/wintypes.h" ]] || continue
      [[ -f "$inc/PCSC/pcsclite.h" ]] || continue
      for lib in "$sysroot/usr/lib" "$sysroot/usr/lib64" "$sysroot/lib" "$sysroot/lib64"; do
        if [[ -f "$lib/libpcsclite.a" || -f "$lib/libpcsclite.so" ]]; then
          PCSC_CFLAGS="-I$inc -I$inc/PCSC"
          PCSC_LIBS="-L$lib -lpcsclite -ldl"
          return 0
        fi
      done
    done
  fi
  return 1
}

prepare_cross_pcsc(){
  local cc="$1" jobs="$2" tcroot prefix cache build src_root archive cc_base host
  local cflags ldflags lib candidate h
  tcroot="$(cross_pcsc_root)"
  [[ -n "$tcroot" && -d "$tcroot" ]] || { err "PCSC: toolchain root is missing"; return 1; }

  prefix="$tcroot/pcsc-libs"
  cache="$tcroot/pcsc-cache"
  build="$tcroot/pcsc-build"
  src_root="$build/src"
  archive="$cache/PCSC-1.9.5.tar.gz"
  mkdir -p "$prefix" "$cache" "$build"

  if [[ -f "$prefix/include/PCSC/winscard.h" &&
        -f "$prefix/include/PCSC/wintypes.h" &&
        -f "$prefix/include/PCSC/pcsclite.h" &&
        -f "$prefix/lib/libpcsclite.a" ]]; then
    PCSC_CFLAGS="-I$prefix/include -I$prefix/include/PCSC"
    PCSC_LIBS="-L$prefix/lib -lpcsclite -ldl"
    ok "PC/SC ready: $prefix"
    return 0
  fi

  need curl || return 1
  need tar || return 1
  need make || return 1

  if [[ -f "$archive" ]] && tar -tzf "$archive" >/dev/null 2>&1; then
    ok "PC/SC source cache: PCSC 1.9.5"
  else
    rm -f "$archive"
    say "  Downloading PC/SC source: PCSC 1.9.5"
    curl -fL --retry 3 --connect-timeout 20 --max-time 1800 \
      -o "$archive" \
      "https://github.com/LudovicRousseau/PCSC/archive/refs/tags/1.9.5.tar.gz" || {
        rm -f "$archive"
        err "PCSC source download failed"
        return 1
      }
    tar -tzf "$archive" >/dev/null 2>&1 || {
      rm -f "$archive"
      err "downloaded PCSC source archive is invalid"
      return 1
    }
  fi
  rm -rf "$src_root"
  mkdir -p "$src_root"
  tar -xzf "$archive" -C "$src_root" --strip-components=1 || { err "cannot extract pcsc-lite source"; return 1; }

  cc_base="$(basename "$cc")"
  host="${cc_base%-gcc}"
  [[ -n "$host" && "$host" != "$cc_base" ]] || { err "cannot derive PC/SC target from compiler: $cc"; return 1; }

  export CC="$cc"
  export CXX="${CC%-gcc}-g++"
  export AR="${CC%-gcc}-ar"
  export RANLIB="${CC%-gcc}-ranlib"
  export STRIP="${CC%-gcc}-strip"

  cflags="${PCSC_BUILD_CFLAGS:-${TC_CFLAGS:-}}"
  ldflags="${PCSC_BUILD_LDFLAGS:-${TC_LDFLAGS:-}}"
  if [[ -z "$cflags" && -n "$TC_SYSROOT" && -d "$TC_SYSROOT" ]]; then
    cflags="--sysroot=$TC_SYSROOT"
  fi
  if [[ -z "$ldflags" && -n "$TC_SYSROOT" && -d "$TC_SYSROOT" ]]; then
    ldflags="--sysroot=$TC_SYSROOT"
  fi

  if !(
    cd "$src_root"
    if [[ -x ./bootstrap ]]; then
      ./bootstrap >"$build/bootstrap.log" 2>&1
    else
      command -v autoreconf >/dev/null 2>&1 || exit 1
      autoreconf -fi >"$build/autoreconf.log" 2>&1
    fi
    ./configure \
      --build="$(./config.guess 2>/dev/null || printf '%s' x86_64-pc-linux-gnu)" \
      --host="$host" \
      --prefix=/usr \
      --enable-static \
      --disable-shared \
      --disable-libudev \
      --disable-libsystemd \
      --disable-polkit \
      --disable-libusb \
      CFLAGS="$cflags" \
      LDFLAGS="$ldflags" >"$build/configure.log" 2>&1
    make -C src -j"$jobs" libpcsclite.la >"$build/make.log" 2>&1
  ); then
    [[ -f "$build/bootstrap.log" ]] && tail -n 60 "$build/bootstrap.log" >&2 || true
    [[ -f "$build/autoreconf.log" ]] && tail -n 60 "$build/autoreconf.log" >&2 || true
    [[ -f "$build/configure.log" ]] && tail -n 120 "$build/configure.log" >&2 || true
    [[ -f "$build/make.log" ]] && tail -n 160 "$build/make.log" >&2 || true
    err "PCSC client build failed"
    return 1
  fi

  lib=""
  for candidate in "$src_root/src/.libs/libpcsclite.a" "$src_root/.libs/libpcsclite.a"; do
    if [[ -f "$candidate" ]]; then lib="$candidate"; break; fi
  done
  [[ -n "$lib" ]] || { err "PCSC build produced no libpcsclite.a"; return 1; }

  mkdir -p "$prefix/include/PCSC" "$prefix/lib/pkgconfig"
  for h in "$src_root"/src/PCSC/*.h; do
    [[ -f "$h" ]] || continue
    cp -f "$h" "$prefix/include/PCSC/"
  done
  cp -f "$lib" "$prefix/lib/libpcsclite.a"

  [[ -f "$prefix/include/PCSC/winscard.h" &&
     -f "$prefix/include/PCSC/wintypes.h" &&
     -f "$prefix/include/PCSC/pcsclite.h" ]] || { err "PC/SC headers were not installed"; return 1; }

  cat >"$prefix/lib/pkgconfig/libpcsclite.pc" <<EOF
prefix=$prefix
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libpcsclite
Description: PC/SC Lite client library
Version: 1.9.5
Cflags: -I\${includedir}
Libs: -L\${libdir} -lpcsclite
Libs.private: -pthread -ldl
EOF

  rm -rf "$build"
  PCSC_CFLAGS="-I$prefix/include -I$prefix/include/PCSC"
  PCSC_LIBS="-L$prefix/lib -lpcsclite -ldl"
  echo "PC/SC: ready at $prefix"
}

locate_cross_gcc(){
  local root="$1" prefer_prefix="${2:-}" cc=""
  if [[ -n "$prefer_prefix" ]]; then
    [[ -x "$root/bin/${prefer_prefix}gcc" ]] && cc="$root/bin/${prefer_prefix}gcc"
    if [[ -z "$cc" && -d "$root/sysroots" ]]; then
      while IFS= read -r -d '' d; do
        if [[ -x "$d/${prefer_prefix}gcc" ]]; then cc="$d/${prefer_prefix}gcc"; break; fi
      done < <(find -L "$root/sysroots" -type d -path "*/usr/bin/${prefer_prefix%?}" -print0 2>/dev/null)
    fi
    if [[ -z "$cc" ]]; then
      cc="$(find -L "$root" -type f -path '*/bin/'"$prefer_prefix"'gcc' -perm -111 -print -quit 2>/dev/null || true)"
    fi
  fi
  if [[ -z "$cc" ]]; then
    cc="$(find -L "$root" -type f -path '*/bin/*-gcc' -perm -111 -print -quit 2>/dev/null || true)"
  fi
  [[ -n "$cc" ]] || return 1
  local base prefix
  base="$(basename "$cc")"
  prefix="${base%gcc}"
  printf '%s|%s\n' "$prefix" "$cc"
}

find_installed_toolchain(){
  local tc="$1" cache root row name desc arch url sha prefix sysrel cflags ldflags cc sysroot found
  row="$(find_toolchain "$tc" || true)"; [[ -n "$row" ]] || return 1
  IFS='|' read -r name desc arch url sha prefix sysrel cflags ldflags <<< "$row"
  cache="$(toolchain_cache_root "$tc")"
  root="$(cat "$cache/root.path" 2>/dev/null || true)"
  if [[ -z "$root" || ! -d "$root" ]]; then
    root="$(toolchain_runtime_root "$tc")"
    [[ -f "$cache/toolchain.archive" || -f "$cache/toolchain.tar.xz" ]] || return 1
    materialize_toolchain "$tc" >/dev/null || return 1
  fi
  normalize_oe_toolchain "$root" "$prefix" >/dev/null || return 1
  found="$(locate_cross_gcc "$root" "$prefix" || true)"; [[ -n "$found" ]] || return 1
  cc="${found#*|}"
  if [[ -d "$root/$sysrel" ]]; then
    sysroot="$root/$sysrel"
  else
    sysroot="$($cc -print-sysroot 2>/dev/null || true)"
  fi
  if [[ -n "$sysrel" && -d "$root/$sysrel" ]]; then
    sysroot="$root/$sysrel"
  fi
  printf '%s|%s|%s\n' "$root" "$cc" "$sysroot"
}

fetch_toolchain(){
  local tc="$1" row name desc arch url sha prefix sysrel cflags ldflags cache archive tmp_archive
  row="$(find_toolchain "$tc" || true)"; [[ -n "$row" ]] || { err "No managed toolchain for $tc"; return 1; }
  IFS='|' read -r name desc arch url sha prefix sysrel cflags ldflags <<< "$row"
  [[ -n "$url" && -n "$sha" ]] || { err "$tc has no managed download. Use --toolchain-dir for this device."; return 1; }
  need curl || return 1
  need sha256sum || return 1
  need tar || return 1
  cache="$(toolchain_cache_root "$tc")"
  mkdir -p "$cache"
  archive="$cache/toolchain.archive"

  if [[ -f "$archive" ]] && printf '%s  %s\n' "$sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
    ok "Using verified toolchain archive: $tc"
  else
    rm -f "$archive"
    tmp_archive="$archive.part.$$"
    rm -f "$tmp_archive"
    echo "  Downloading: $tc" >&2
    echo "  URL: $url" >&2
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 0 --progress-bar -o "$tmp_archive" "$url"; then
      rm -f "$tmp_archive"
      err "Toolchain download failed: $tc"
      return 1
    fi
    if ! printf '%s  %s\n' "$sha" "$tmp_archive" | sha256sum -c - >/dev/null 2>&1; then
      rm -f "$tmp_archive"
      err "Downloaded toolchain SHA-256 mismatch: $tc"
      return 1
    fi
    mv -f "$tmp_archive" "$archive"
    ok "Toolchain archive ready: $tc"
  fi

  materialize_toolchain "$tc" || return 1
  local info cc
  info="$(find_installed_toolchain "$tc")" || return 1
  cc="$(cut -d'|' -f2 <<< "$info")"
  printf '%s\n' "$cc" > "$cache/compiler.path"
  ok "Toolchain ready: $tc"
  ok "Compiler: $cc"
}

manual_toolchain(){
  local dir="$1" cc
  [[ -d "$dir" ]] || { err "Toolchain directory not found: $dir"; return 1; }
  printf '%s\n' "$dir" > "$STATE_DIR/manual-toolchain-$TARGET.path"
  cc="$(find -L "$dir" -type f -name '*-gcc' -perm -111 -print -quit 2>/dev/null || true)"
  [[ -n "$cc" ]] || { err "No cross gcc found under $dir (searched following symlinks too)"; return 1; }
  printf '%s\n' "$cc" > "$STATE_DIR/manual-toolchain-$TARGET.compiler"
  ok "Using manual toolchain: $dir"
  ok "Compiler: $cc"
}

resolve_compiler(){
  local tc_info tcdir cc sysroot
  if [[ -n "$CC_EXPLICIT" ]]; then
    cc="$CC_EXPLICIT"
  elif [[ "$TOOLCHAIN" == native ]]; then
    case "$PLATFORM" in
      linux) cc="${CC:-gcc}";;
      windows) cc="x86_64-w64-mingw32-gcc";;
      macos) cc="cc";;
    esac
  elif [[ "$TOOLCHAIN" == manual ]]; then
    cc="$(cat "$STATE_DIR/manual-toolchain-$TARGET.compiler" 2>/dev/null || true)"
    [[ -n "$cc" ]] || {
      err "No manual toolchain selected for $TARGET. Use:"
      echo "  ./build.sh config $TARGET --toolchain-dir /path/to/sdk" >&2
      return 1
    }
  else
    tc_info="$(find_installed_toolchain "$TOOLCHAIN" || true)"
    if [[ -z "$tc_info" ]]; then
      echo "  Toolchain '$TOOLCHAIN' is not installed; downloading it now." >&2
      fetch_toolchain "$TOOLCHAIN" >&2 || return 1
      tc_info="$(find_installed_toolchain "$TOOLCHAIN" || true)"
    fi
    [[ -n "$tc_info" ]] || { err "Could not resolve managed toolchain '$TOOLCHAIN'"; return 1; }
    IFS='|' read -r tcdir cc sysroot <<< "$tc_info"
  fi
  if [[ "$cc" == */* ]]; then
    [[ -x "$cc" ]] || { err "Compiler not executable: $cc"; return 1; }
  else
    command -v "$cc" >/dev/null 2>&1 || { err "Compiler not found: $cc"; return 1; }
    cc="$(command -v "$cc")"
  fi
  if [[ "$TOOLCHAIN" != native || "$PLATFORM" == linux ]]; then
    probe_compiler "$cc" || return 1
  fi
  printf '%s\n' "$cc"
}

validate_arch(){
  local cc="$1" target
  [[ "$PLATFORM" == linux ]] || return 0
  [[ "$TOOLCHAIN" == native ]] && return 0
  target="$($cc -dumpmachine 2>/dev/null || true)"
  [[ -n "$target" ]] || { err "Compiler target probe failed: $cc"; return 1; }
  case "$ARCH" in
    arm|armv5|armv6|armv7) [[ "$target" == arm*-* || "$target" == arm*linux* ]] || { err "Wrong compiler target: $target (need $ARCH)"; return 1; };;
    aarch64) [[ "$target" == aarch64-* || "$target" == aarch64* ]] || { err "Wrong compiler target: $target (need AArch64)"; return 1; };;
    mipsel|mips32el) [[ "$target" == mipsel-* || "$target" == mipsel* ]] || { err "Wrong compiler target: $target (need MIPSel)"; return 1; };;
    mips) [[ "$target" == mips-* || ("$target" == mips* && "$target" != mipsel*) ]] || { err "Wrong compiler target: $target (need MIPS)"; return 1; };;
    mips64) [[ "$target" == mips64-* || "$target" == mips64* ]] || { err "Wrong compiler target: $target (need MIPS64)"; return 1; };;
    powerpc) [[ "$target" == powerpc-* || "$target" == powerpc* ]] || { err "Wrong compiler target: $target (need PowerPC)"; return 1; };;
    sh4) [[ "$target" == sh4-* || "$target" == sh4* ]] || { err "Wrong compiler target: $target (need SH4)"; return 1; };;
    csky) [[ "$target" == csky-* || "$target" == csky* ]] || { err "Wrong compiler target: $target (need C-SKY)"; return 1; };;
    x86) [[ "$target" == i[3-6]86-* || "$target" == i[3-6]86* || "$target" == x86-* ]] || { err "Wrong compiler target: $target (need x86)"; return 1; };;
    x86_64) [[ "$target" == x86_64-* || "$target" == x86_64* ]] || { err "Wrong compiler target: $target (need x86_64)"; return 1; };;
    *) warn "No strict architecture matcher for $ARCH (compiler: $target)";;
  esac
  ok "Compiler target: $target"
}

arch_runtime_ldflags(){
  if [[ "$ARCH" == "sh4" && "$TOOLCHAIN" == "sh4" ]]; then
    printf '%s' ''
    return 0
  fi
  case "$ARCH" in
    mipsel|mips32el|sh4)
      local cc="${1:-${CURRENT_CC:-}}" atomic_archive=""
      if [[ -n "$cc" && -x "$cc" ]]; then
        atomic_archive="$($cc -print-file-name=libatomic.a 2>/dev/null || true)"
      fi
      if [[ -n "$atomic_archive" && "$atomic_archive" != "libatomic.a" && -f "$atomic_archive" ]]; then
        printf '%s' '-Wl,-Bstatic -latomic -Wl,-Bdynamic'
      else
        printf '%s' '-latomic'
      fi
      ;;
    *) printf '%s' '';;
  esac
}

toolchain_flags(){
  TC_CFLAGS=""; TC_LDFLAGS=""; TC_SYSROOT=""; TC_RUNTIME_ROOT=""
  [[ "$TOOLCHAIN" == native || "$TOOLCHAIN" == manual ]] && return 0
  local row name desc arch url sha prefix sysrel cflags ldflags info cc builtin_sysroot
  row="$(find_toolchain "$TOOLCHAIN")"
  IFS='|' read -r name desc arch url sha prefix sysrel cflags ldflags <<< "$row"
  info="$(find_installed_toolchain "$TOOLCHAIN")"
  TC_RUNTIME_ROOT="$(cut -d'|' -f1 <<< "$info")"
  cc="$(cut -d'|' -f2 <<< "$info")"
  TC_CFLAGS="$cflags"
  TC_LDFLAGS="$ldflags"

  local runtime_ldflags
  runtime_ldflags="$(arch_runtime_ldflags "$cc")"
  if [[ -n "$runtime_ldflags" ]]; then
    TC_LDFLAGS="${TC_LDFLAGS:+$TC_LDFLAGS }$runtime_ldflags"
  fi

  builtin_sysroot="$($cc -print-sysroot 2>/dev/null || true)"
  if [[ -n "$builtin_sysroot" && -d "$builtin_sysroot" ]]; then
    TC_SYSROOT="$builtin_sysroot"
  elif [[ -n "$sysrel" && -d "$TC_RUNTIME_ROOT/$sysrel" ]]; then
    TC_SYSROOT="$TC_RUNTIME_ROOT/$sysrel"
    TC_CFLAGS="${TC_CFLAGS:+$TC_CFLAGS }--sysroot=$TC_SYSROOT"
    TC_LDFLAGS="${TC_LDFLAGS:+$TC_LDFLAGS }--sysroot=$TC_SYSROOT"
  fi
}

pcsc_flag(){
  PCSC_CFLAGS=""
  PCSC_LIBS=""
  PCSC_ENABLED=0
  case "$PCSC" in
    off) return 0;;
    on)
      if [[ "$PLATFORM" == linux ]]; then
        if [[ "$TOOLCHAIN" == native ]]; then
          if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcsclite; then
            PCSC_CFLAGS="$(pkg-config --cflags libpcsclite)"
            PCSC_LIBS="$(pkg-config --libs libpcsclite)"
          fi
          [[ -n "$PCSC_LIBS" ]] || PCSC_LIBS="-lpcsclite"
        else
          if ! existing_cross_pcsc "$TC_RUNTIME_ROOT" "$TC_SYSROOT" ||
             ! pcsc_header_probe "$CURRENT_CC" "$PCSC_CFLAGS"; then
            prepare_cross_pcsc "$CURRENT_CC" "$(jobs_num)" || return 1
            pcsc_header_probe "$CURRENT_CC" "$PCSC_CFLAGS" || {
              err "PC/SC headers are not usable after preparing target libpcsclite"
              return 1
            }
          fi
        fi
      fi
      PCSC_ENABLED=1
      return 0;;
    auto)
      if [[ "$PLATFORM" == linux && "$TOOLCHAIN" == native ]]; then
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcsclite; then
          PCSC_ENABLED=1
        fi
      elif [[ "$PLATFORM" == linux && "$TOOLCHAIN" != native ]]; then
        if existing_cross_pcsc "$TC_RUNTIME_ROOT" "$TC_SYSROOT" &&
           pcsc_header_probe "$CURRENT_CC" "$PCSC_CFLAGS"; then
          PCSC_ENABLED=1
        fi
      elif [[ "$PLATFORM" != linux ]]; then
        PCSC_ENABLED=1
      fi
      return 0;;
    *) err 'PCSC must be auto/on/off'; return 1;;
  esac
}

normalize_menu_choice(){
  local value="$1"
  value="${value//$'\r'/}"
  value="${value#${value%%[![:space:]]*}}"
  value="${value%${value##*[![:space:]]}}"
  printf '%s' "$value"
}

normalize_pcsc(){
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    auto|on|off) printf '%s\n' "$value";;
    *) err 'PCSC must be auto, on or off'; return 1;;
  esac
}

validate_jobs(){
  [[ "$JOBS" == auto || "$JOBS" =~ ^[1-9][0-9]*$ ]] || { err 'Jobs must be auto or a positive integer'; return 1; }
}

validate_settings(){
  PCSC="$(normalize_pcsc "$PCSC")" || return 1
  validate_jobs || return 1
  [[ "$RELEASE" == 0 || "$RELEASE" == 1 ]] || { err 'Build mode must be release or debug'; return 1; }
  [[ "$CLEAN" == 0 || "$CLEAN" == 1 ]] || { err 'Clean mode must be enabled or disabled'; return 1; }
}

interactive(){
  local ans
  echo
  line; echo "Edit configuration: $(device_label "$TARGET")"; echo "$DESCRIPTION"; line
  read -r -p "Release build? [Y/n] " ans
  if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then RELEASE=1; else RELEASE=0; fi
  read -r -p "PCSC [auto/on/off] [$PCSC]: " ans
  if [[ -n "$ans" ]]; then PCSC="$ans"; fi
  PCSC="$(normalize_pcsc "$PCSC")" || return 1
  read -r -p "Clean before build? [Y/n] " ans
  if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then CLEAN=1; else CLEAN=0; fi
  read -r -p "Jobs [auto/$JOBS]: " ans
  if [[ -n "$ans" ]]; then JOBS="$ans"; fi
  validate_jobs || return 1
  read -r -p "Config directory [$CONF_DIR]: " ans
  if [[ -n "$ans" ]]; then CONF_DIR="$ans"; fi
  if [[ "$TOOLCHAIN" == manual ]]; then
    read -r -p "Toolchain directory [none]: " ans
    [[ -n "$ans" ]] && manual_toolchain "$ans"
  fi
  read -r -p "Extra CFLAGS [none]: " ans; CFLAGS_EXTRA="$ans"
  read -r -p "Extra LDFLAGS [none]: " ans; LDFLAGS_EXTRA="$ans"
}

interactive_menu(){
  local row="$1" action normalized
  show_profile "$row"
  while :; do
    echo
    read -r -p '[1=Build, 2=Edit]: ' action
    normalized="$(normalize_menu_choice "$action")"
    case "${normalized:-1}" in
      1)
        save_state
        build_device
        return $?
        ;;
      2)
        interactive
        save_state
        echo
        ok "Configuration saved for $(device_label "$TARGET")"
        show_config
        return 0
        ;;
      *)
        err 'Invalid choice. Enter 1 to build or 2 to edit configuration.'
        ;;
    esac
  done
}

build_device(){
  local cc pcsc_enabled jobs build_dir stamp log builtin_inc asset_rev
  PCSC_CFLAGS=""
  PCSC_LIBS=""
  cc="$(resolve_compiler)" || return 1
  CURRENT_CC="$cc"
  validate_arch "$cc" || return 1
  toolchain_flags
  pcsc_flag || return 1
  pcsc_enabled="$PCSC_ENABLED"

  if [[ "$PLATFORM" == linux && "$TOOLCHAIN" != native ]]; then
    builtin_inc="$($cc -print-file-name=include 2>/dev/null || true)"
    if [[ -z "$builtin_inc" || "$builtin_inc" == include || ! -f "$builtin_inc/stddef.h" ]]; then
      err "Cross GCC builtin headers are not usable"
      err "Compiler: $cc"
      err "GCC include: ${builtin_inc:-<none>}"
      return 1
    fi
    if ! printf '#include <stddef.h>\nint tcmg_header_probe;\n' | "$cc" $TC_CFLAGS -E -x c - >/dev/null 2>&1; then
      err "Cross GCC cannot preprocess stddef.h with the selected sysroot"
      return 1
    fi
    ok "GCC headers: stddef.h"
    if [[ "$pcsc_enabled" == 1 ]]; then
      if ! printf '#include <PCSC/winscard.h>\nint tcmg_pcsc_probe;\n' | "$cc" $TC_CFLAGS $PCSC_CFLAGS -E -x c - >/dev/null 2>&1; then
        err "PC/SC headers are not usable with the selected cross compiler"
        return 1
      fi
      ok "PC/SC headers: winscard.h"
    fi
  fi
  jobs="$(jobs_num)"
  build_dir="build/$TARGET"
  [[ "$CLEAN" == 1 ]] && make BUILD_DIR="$build_dir" clean >/dev/null 2>&1 || true
  stamp="$(date +%Y%m%d-%H%M%S)"
  asset_rev="$(date +%Y%m%d%H%M%S)"
  log="$LOG_DIR/${TARGET}-${stamp}.log"
  echo
  line
  echo "Building TCMG $VERSION — $TARGET"
  show_config
  echo "Compiler: $cc"
  echo "Output  : $build_dir/tcmg-$VERSION-$TARGET"
  if [[ "$ARCH" == "sh4" || "$ARCH" == "mipsel" || "$ARCH" == "mips32el" ]]; then
    if [[ "$TOOLCHAIN" == "sh4" ]]; then
      echo "Compatibility: legacy SH4/GCC (gnu99 + GCC sync atomics)"
      echo "Runtime  : -lrt (legacy glibc clock_gettime)"
    else
      echo "Runtime  : -latomic (static when available)"
    fi
  fi
  [[ "$pcsc_enabled" == 1 && "$PLATFORM" == linux && "$TOOLCHAIN" != native ]] && {
    echo "PCSC CFLAGS: $PCSC_CFLAGS"
    echo "PCSC LIBS  : $PCSC_LIBS"
  }
  line
  local args=("BUILD_DIR=$build_dir" "RELEASE=$RELEASE" "TCMG_TARGET_OS=$PLATFORM" "TCMG_TARGET_ARCH=$ARCH" "TCMG_TARGET_NAME=tcmg-$VERSION-$TARGET" "TCMG_DEVICE_NAME=$TARGET" "TCMG_PCSC=$pcsc_enabled" "CC=$cc" "TCMG_CONF_DIR=$CONF_DIR" "TCMG_ASSET_REV=$asset_rev")
  if [[ "$TOOLCHAIN" == "sh4" ]]; then
    args+=("TCMG_LEGACY_SH4=1")
  fi
  [[ -n "$CFLAGS_EXTRA" ]] && args+=("CFLAGS_EXTRA=$CFLAGS_EXTRA")
  [[ -n "$PCSC_CFLAGS" ]] && args+=("PCSC_CFLAGS=$PCSC_CFLAGS")
  [[ -n "$PCSC_LIBS" ]] && args+=("PCSC_LIBS=$PCSC_LIBS")
  local cflags="$TC_CFLAGS $CFLAGS_EXTRA" ldflags="$TC_LDFLAGS $LDFLAGS_EXTRA"
  if [[ "$ARCH" == "sh4" && "$TOOLCHAIN" == "sh4" ]]; then
    ldflags="$(sed -E 's/(^|[[:space:]])-Wl,-Bstatic[[:space:]]+-latomic[[:space:]]+-Wl,-Bdynamic([[:space:]]|$)/ /g; s/(^|[[:space:]])-latomic([[:space:]]|$)/ /g; s/[[:space:]]+/ /g; s/^ | $//g' <<< "$ldflags")"
  else
    case " $ldflags " in
      *" -latomic "*) ;;
      *)
        case "$ARCH" in
          mipsel|mips32el|sh4) ldflags="${ldflags:+$ldflags }-latomic" ;;
        esac
        ;;
    esac
  fi
  [[ -n "$cflags" ]] && args+=("TCMG_ARCH_FLAGS=$cflags")
  [[ -n "$ldflags" ]] && args+=("TCMG_ARCH_LDFLAGS=$ldflags")
  if ! make -j"$jobs" "${args[@]}" >"$log" 2>&1; then
    err "Build failed"
    tail -n 100 "$log" >&2
    echo "Log: $log" >&2
    return 1
  fi
  local output_bin="$build_dir/tcmg-$VERSION-$TARGET"
  if [[ ! -f "$output_bin" ]]; then
    err "Build reported success but output is missing: $output_bin"
    return 1
  fi
  if ! grep -aFq "tcmg v$VERSION ($TARGET)" "$output_bin" 2>/dev/null; then
    err "Build output does not contain the expected embedded version/device banner: tcmg v$VERSION ($TARGET)"
    return 1
  fi
  ok "Embedded identity: tcmg v$VERSION ($TARGET)"
  if [[ "$ARCH" == "sh4" || "$ARCH" == "mipsel" || "$ARCH" == "mips32el" ]]; then
    if command -v readelf >/dev/null 2>&1 && [[ -f "$output_bin" ]]; then
      if readelf -d "$output_bin" 2>/dev/null | grep -q 'libatomic\.so'; then
        err "Build produced a dynamic libatomic dependency: $output_bin"
        err "The selected cross toolchain does not provide a static libatomic archive."
        return 1
      fi
      ok "Atomic runtime: static (no libatomic.so dependency)"
    fi
  fi
  ok "Build complete: $output_bin"
  echo "Log: $log"
}

clean_device(){
  make BUILD_DIR="build/$TARGET" clean
  rm -f "$LOG_DIR/${TARGET}-"*.log 2>/dev/null || true
}

check_env(){
  local bad=0 c
  for c in bash make awk sed grep find; do command -v "$c" >/dev/null 2>&1 || { err "Missing command: $c"; bad=1; }; done
  [[ -f "$ROOT_DIR/Makefile" ]] || { err 'Makefile missing'; bad=1; }
  [[ -f "$ROOT_DIR/src/main.c" ]] || { err 'src/main.c missing'; bad=1; }
  if [[ "$bad" == 0 ]]; then ok 'Builder environment'; fi
  return "$bad"
}

self_test(){
  local tmp="$STATE_DIR/self-test.$$" row name i
  mkdir -p "$tmp"
  trap 'rm -rf "$tmp"' RETURN
  [[ ${#DEVICES[@]} -ge 200 ]] || { err "device catalog unexpectedly small: ${#DEVICES[@]}"; return 1; }
  [[ ${#TOOLCHAINS[@]} -ge 80 ]] || { err "toolchain catalog too small: ${#TOOLCHAINS[@]}"; return 1; }
  declare -F run_fzf >/dev/null 2>&1 || { err 'fzf wizard function missing'; return 1; }
  [[ "$(find_device generic-linux)" == generic-linux\|linux\|native* ]] || { err 'device catalog failed'; return 1; }
  [[ "$(find_toolchain vuplus4k_armv7)" == vuplus4k_armv7\|* ]] || { err 'SimpleBuild4 Vu+ toolchain catalog failed'; return 1; }
  [[ "$(find_device dreambox-dm800se)" == dreambox-dm800se\|linux\|mipsel\|* ]] || { err 'Dreambox DM800SE device catalog failed'; return 1; }
  [[ "$(find_device novaler4kpro)" == novaler4kpro\|linux\|aarch64\|* ]] || { err 'Novaler 4K PRO device catalog failed'; return 1; }
  [[ "$(find_device vuuno4k)" == vuuno4k\|linux\|armv7\|* ]] || { err 'Vu+ device catalog failed'; return 1; }
  [[ "$(find_device dm800sev2)" == dm800sev2\|linux\|mipsel\|* ]] || { err 'Dreambox DM800SE v2 catalog failed'; return 1; }
  [[ "$(find_device dreambox-dm520)" == dreambox-dm520\|linux\|mipsel\|* ]] || { err 'Dreambox DM520 device catalog failed'; return 1; }
  [[ "$(find_device dreambox-dm7080)" == dreambox-dm7080\|linux\|mipsel\|* ]] || { err 'Dreambox DM7080 device catalog failed'; return 1; }
  [[ "$(find_device dreambox-dm820)" == dreambox-dm820\|linux\|mipsel\|* ]] || { err 'Dreambox DM820 device catalog failed'; return 1; }
  [[ "$(find_device forever-7878)" == forever-7878\|linux\|sh4\|* ]] || { err 'Forever 7878 device catalog failed'; return 1; }
  [[ "$(find_toolchain sh4)" == sh4\|* ]] || { err 'Legacy SH4 toolchain catalog failed'; return 1; }
  [[ "$(find_toolchain dream_mipsel)" == dream_mipsel\|* ]] || { err 'Dreambox legacy MIPSel toolchain catalog failed'; return 1; }
  [[ "$(find_toolchain bootlin_aarch64_2018)" == bootlin_aarch64_2018\|* ]] || { err 'Bootlin AArch64 toolchain catalog failed'; return 1; }
  [[ "$(find_toolchain bootlin_armv7_2018)" == bootlin_armv7_2018\|* ]] || { err 'Bootlin ARMv7 toolchain catalog failed'; return 1; }
  [[ "$(find_toolchain bootlin_mipsel_2018)" == bootlin_mipsel_2018\|* ]] || { err 'Bootlin MIPSel toolchain catalog failed'; return 1; }
  [[ "$(find_toolchain bootlin_powerpc_2018)" == bootlin_powerpc_2018\|* ]] || { err 'Bootlin PowerPC toolchain catalog failed'; return 1; }
  [[ "$(normalize_menu_choice $' 2\r ')" == 2 ]] || { err 'Interactive menu choice normalization failed'; return 1; }
  local tcrow tcname tcdesc tcarch tcurl tcsha tcpfx tcsys tccf tcaf
  for tcname in bootlin_aarch64_2018 bootlin_armv7_2018 bootlin_mipsel_2018 bootlin_powerpc_2018; do
    tcrow="$(find_toolchain "$tcname")"
    IFS='|' read -r tcname tcdesc tcarch tcurl tcsha tcpfx tcsys tccf tcaf <<< "$tcrow"
    [[ "$tcurl" == https://toolchains.bootlin.com/* ]] || { err "Bootlin URL invalid for $tcname"; return 1; }
    [[ "$tcurl" == *.tar.bz2 ]] || { err "Bootlin archive format invalid for $tcname"; return 1; }
    [[ "$tcsha" =~ ^[0-9a-fA-F]{64}$ ]] || { err "Bootlin SHA-256 invalid for $tcname"; return 1; }
  done
  ARCH=powerpc
  [[ "$(arch_runtime_ldflags)" == '' ]] || { err 'PowerPC should not inherit MIPSel -latomic'; return 1; }
  ARCH=mipsel
  [[ "$(arch_runtime_ldflags)" == '-latomic' ]] || { err 'MIPSel runtime linker flags missing -latomic'; return 1; }
  ARCH=sh4
  local sh4_runtime_flags="$(arch_runtime_ldflags "${CURRENT_CC:-}")"
  [[ " $sh4_runtime_flags " == *" -latomic "* ]] || { err 'SH4 runtime linker flags missing -latomic'; return 1; }
  local sh4_ldflags="${TC_LDFLAGS:-} ${LDFLAGS_EXTRA:-}"
  case " $sh4_ldflags " in
    *" -latomic "*) ;;
    *) sh4_ldflags="${sh4_ldflags:+$sh4_ldflags }-latomic" ;;
  esac
  [[ " $sh4_ldflags " == *" -latomic "* ]] || { err 'SH4 generic final linker flags do not contain -latomic'; return 1; }
  local legacy_sh4_ldflags
  legacy_sh4_ldflags="$(ARCH=sh4 TOOLCHAIN=sh4 arch_runtime_ldflags 2>/dev/null || true)"
  [[ -z "$legacy_sh4_ldflags" ]] || { err 'Legacy SH4 must not link -latomic'; return 1; }
  local legacy_sh4_makefile_flags
  legacy_sh4_makefile_flags="$(make -s -n BUILD_DIR=/tmp/tcmg-selftest TCMG_TARGET_OS=linux TCMG_TARGET_ARCH=sh4 TCMG_TARGET_NAME=tcmg-selftest TCMG_PCSC=0 TCMG_LEGACY_SH4=1 2>/dev/null | grep -E '\-o /tmp/tcmg-selftest/tcmg-selftest' | tail -n1 || true)"
  [[ " $legacy_sh4_makefile_flags " == *" -lrt "* ]] || { err 'Legacy SH4 final linker flags missing -lrt'; return 1; }
  [[ " $legacy_sh4_makefile_flags " != *" -latomic "* ]] || { err 'Legacy SH4 final linker flags must not contain -latomic'; return 1; }
  [[ -f "$ROOT_DIR/src/legacy_sh4/legacy_preinclude.h" ]] || { err 'Legacy SH4 preinclude missing'; return 1; }
  [[ -f "$ROOT_DIR/src/legacy_sh4/stdatomic.h" ]] || { err 'Legacy SH4 stdatomic compatibility header missing'; return 1; }
  ARCH=native
  [[ -z "$(arch_runtime_ldflags)" ]] || { err 'Native targets should not force -latomic'; return 1; }
  local winrow wname wplatform warch wdesc wconf wpcsc wtc
  winrow="$(find_device windows-x64)"
  IFS='|' read -r wname wplatform warch wdesc wconf wpcsc wtc <<< "$winrow"
  [[ "$wconf" == './' ]] || { err "Windows default config directory is not ./ (got: $wconf)"; return 1; }
  TARGET=generic-linux; PLATFORM=linux; ARCH=native; DESCRIPTION=x; CONF_DIR=/tmp; PCSC=off; TOOLCHAIN=native; RELEASE=1; CLEAN=1; JOBS=1; CFLAGS_EXTRA=; LDFLAGS_EXTRA=; CC_EXPLICIT=;
  SAVE=1; save_state >/dev/null
  [[ -f "$(state_file generic-linux)" ]] || { err 'state persistence failed'; return 1; }
  [[ "$(find "${TOOLCHAIN_DIR}" -maxdepth 2 -type f -name '*.tmp*' 2>/dev/null | wc -l)" == 0 ]] || { err 'temporary toolchain files remain'; return 1; }
  ok 'Self-test passed'; return 0
}

parse_options(){
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pcsc) PCSC="${2:?missing value for --pcsc}"; shift 2;;
      --release) RELEASE=1; shift;;
      --debug) RELEASE=0; shift;;
      --clean) CLEAN=1; shift;;
      --no-clean) CLEAN=0; shift;;
      --jobs) JOBS="${2:?missing value for --jobs}"; shift 2;;
      --confdir) CONF_DIR="${2:?missing value for --confdir}"; shift 2;;
      --cflags) CFLAGS_EXTRA="${2:?missing value for --cflags}"; shift 2;;
      --ldflags) LDFLAGS_EXTRA="${2:?missing value for --ldflags}"; shift 2;;
      --cc) CC_EXPLICIT="${2:?missing value for --cc}"; shift 2;;
      --toolchain-dir) MANUAL_TC_DIR="${2:?missing value for --toolchain-dir}"; shift 2;;
      --no-save) SAVE=0; shift;;
      --help|-h) usage; exit 0;;
      *) err "Unknown option: $1"; usage; exit 1;;
    esac
  done
  validate_settings
}

COMMAND="${1:-wizard}"
shift || true
MANUAL_TC_DIR=""
DEVICE_ARG=""
UI_MODE="${TCMG_UI:-auto}"

run_interactive_ui(){
  local mode="$UI_MODE" rc
  case "$mode" in
    auto)
      if declare -F run_fzf >/dev/null 2>&1 && command -v fzf >/dev/null 2>&1 && [[ -t 0 && -t 1 ]]; then
        if run_fzf; then
          return 0
        else
          rc=$?
        fi
        [[ "$rc" == 2 ]] || return "$rc"
      fi
      if declare -F run_tui >/dev/null 2>&1 && [[ -t 0 && -t 1 ]]; then
        run_tui
        return $?
      fi
      choose_device
      interactive_menu "$CHOSEN_ROW"
      return $?
      ;;
    fzf)
      if ! declare -F run_fzf >/dev/null 2>&1 || ! command -v fzf >/dev/null 2>&1 || [[ ! -t 0 || ! -t 1 ]]; then
        err 'fzf UI requires an interactive terminal and the fzf command'
        err 'Use TCMG_UI=tui or run without TCMG_UI=fzf'
        return 1
      fi
      if run_fzf; then
        return 0
      else
        return $?
      fi
      ;;
    tui)
      if declare -F run_tui >/dev/null 2>&1 && [[ -t 0 && -t 1 ]]; then
        run_tui
        return $?
      fi
      choose_device
      interactive_menu "$CHOSEN_ROW"
      return $?
      ;;
    *)
      err 'TCMG_UI must be auto, fzf, or tui'
      return 1
      ;;
  esac
}

case "$COMMAND" in
  ''|wizard|menu)
    if [[ "${1:-}" == --ui ]]; then
      UI_MODE="${2:-}"
      shift 2
    elif [[ "${1:-}" == --ui=* ]]; then
      UI_MODE="${1#--ui=}"
      shift
    fi
    run_interactive_ui
    exit $?;;
  list)
    show_devices; exit 0;;
  check|doctor)
    check_env; exit $?;;
  self-test)
    check_env && self_test; exit $?;;
  plan|config|build|toolchain|clean|test|strict)
    if [[ $# -gt 0 && "$1" != --* ]]; then DEVICE_ARG="$1"; shift; fi
    ;;
  help|-h|--help)
    usage; exit 0;;
  *)
    if find_device "$COMMAND" >/dev/null 2>&1; then
      DEVICE_ARG="$COMMAND"
      COMMAND=build
    else
      err "Unknown command/device: $COMMAND"; usage; exit 1
    fi
    ;;
esac

if [[ -z "$DEVICE_ARG" ]]; then
  show_devices
  read -r -p "Select device [1-${#DEVICES[@]}]: " n
  [[ "$n" =~ ^[0-9]+$ ]] || { err 'Invalid device'; exit 1; }
  i=1
  for row in "${DEVICES[@]}"; do
    if [[ "$i" == "$n" ]]; then DEVICE_ARG="${row%%|*}"; break; fi
    i=$((i + 1))
  done
fi

row="$(find_device "$DEVICE_ARG" || true)"
[[ -n "$row" ]] || { err "Unknown device '$DEVICE_ARG'"; exit 1; }
load_defaults "$row"
parse_options "$@"

if [[ -n "$MANUAL_TC_DIR" ]]; then manual_toolchain "$MANUAL_TC_DIR"; fi

case "$COMMAND" in
  plan)
    show_config
    if has_saved_state; then echo 'Saved configuration: yes'; else echo 'Saved configuration: no'; fi
    ;;
  config)
    interactive
    [[ -n "$MANUAL_TC_DIR" ]] && manual_toolchain "$MANUAL_TC_DIR"
    save_state
    show_config;;
  toolchain)
    if [[ "$TOOLCHAIN" == native ]]; then
      ok 'Native compiler - nothing to download'
    elif [[ "$TOOLCHAIN" == manual ]]; then
      [[ -n "$MANUAL_TC_DIR" ]] || { err 'This device needs --toolchain-dir /path/to/sdk'; exit 1; }
    else
      fetch_toolchain "$TOOLCHAIN"
    fi;;
  build)
    save_state
    build_device;;
  clean)
    clean_device;;
  test)
    save_state
    make BUILD_DIR="build/$TARGET" RELEASE="$RELEASE" TCMG_TARGET_OS="$PLATFORM" TCMG_TARGET_NAME=tcmg TCMG_PCSC=0 test;;
  strict)
    save_state
    make BUILD_DIR="build/$TARGET" RELEASE=0 TCMG_TARGET_OS="$PLATFORM" TCMG_TARGET_NAME=tcmg TCMG_PCSC=0 TCMG_STRICT=1;;
esac
