#!/usr/bin/env bash
#
# protection one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/AnAverageBeing/protection/main/install.sh | sudo bash
#
# Downloads the prebuilt static binary for your architecture, installs the
# systemd unit, then INTERACTIVELY asks a few important questions (installation
# name, protection mode, Discord alerts) and writes a starter config in safe
# dry-run mode. Everything else is tunable later in the config file.
#
set -euo pipefail

REPO="AnAverageBeing/protection"
PREFIX="${PREFIX:-/usr/local}"
BIN_DEST="$PREFIX/bin/protection"
CONFIG_DIR="/etc/protection"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
UNIT_DEST="/etc/systemd/system/protection.service"
RAW="https://raw.githubusercontent.com/$REPO/main"

c_grn='\033[0;32m'; c_yel='\033[1;33m'; c_blu='\033[0;34m'; c_red='\033[0;31m'; c_dim='\033[0;90m'; c_off='\033[0m'
say()  { printf "${c_blu}==>${c_off} %s\n" "$*"; }
ok()   { printf "  ${c_grn}ok${c_off} %s\n" "$*"; }
warn() { printf "  ${c_yel}! ${c_off} %s\n" "$*"; }
die()  { printf "${c_red}error:${c_off} %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (try: curl -fsSL $RAW/install.sh | sudo bash)"
command -v curl >/dev/null 2>&1 || die "curl is required"

# --- a tty we can prompt on, even when piped through curl|bash ----------------
TTY=""
if [[ -r /dev/tty ]]; then TTY=/dev/tty; fi
ask() { # ask <var> <prompt> <default>
  local __var="$1" __prompt="$2" __default="$3" __reply=""
  if [[ -z "$TTY" ]]; then printf -v "$__var" '%s' "$__default"; return; fi
  if [[ -n "$__default" ]]; then
    printf "${c_blu}?${c_off} %s ${c_dim}[%s]${c_off}: " "$__prompt" "$__default" > "$TTY"
  else
    printf "${c_blu}?${c_off} %s: " "$__prompt" > "$TTY"
  fi
  read -r __reply < "$TTY" || true
  printf -v "$__var" '%s' "${__reply:-$__default}"
}

# --- detect architecture ------------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
ASSET="protection-linux-$ARCH"
say "Installing protection ($ASSET)"

# --- download binary ----------------------------------------------------------
URL="https://github.com/$REPO/releases/latest/download/$ASSET"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP" || die "failed to download $URL"
install -Dm0755 "$TMP" "$BIN_DEST"
ok "binary -> $BIN_DEST ($("$BIN_DEST" version 2>/dev/null || echo unknown))"

# --- systemd unit -------------------------------------------------------------
if curl -fsSL "$RAW/packaging/protection.service" -o "$UNIT_DEST"; then
  ok "systemd unit -> $UNIT_DEST"
else
  warn "could not fetch systemd unit (continuing)"
fi

# --- state directories --------------------------------------------------------
mkdir -p /var/lib/protection/quarantine && chmod 700 /var/lib/protection/quarantine
ok "state dir -> /var/lib/protection"

# --- interactive configuration ------------------------------------------------
if [[ -f "$CONFIG_FILE" ]]; then
  warn "$CONFIG_FILE already exists; left untouched"
else
  # sensible default name: hostname, else primary IP, else Protection
  DEF_NAME="$(hostname 2>/dev/null || true)"
  [[ -z "$DEF_NAME" ]] && DEF_NAME="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$DEF_NAME" ]] && DEF_NAME="Protection"

  echo
  say "Quick setup ${c_dim}(everything here is editable later in $CONFIG_FILE)${c_off}"

  ask NAME    "Name this installation"                  "$DEF_NAME"
  ask MODE    "Protect what? (server / docker / both)"  "both"
  case "$MODE" in server|docker|both) ;; *) MODE="both" ;; esac
  ask DISCORD "Discord webhook URL for alerts (blank to skip)" ""

  PTERO_URL=""; PTERO_KEY=""
  if [[ "$MODE" != "server" ]]; then
    ask USE_PTERO "Using Pterodactyl? auto-suspend abusive servers (y/N)" "N"
    if [[ "$USE_PTERO" =~ ^[Yy] ]]; then
      ask PTERO_URL "  Panel URL (e.g. https://panel.example.com)" ""
      ask PTERO_KEY "  Application API key (ptla_...)" ""
    fi
  fi

  ask ARM "Arm enforcement now? 'no' keeps safe dry-run mode (y/N)" "N"
  DRY="true"; [[ "$ARM" =~ ^[Yy] ]] && DRY="false"

  mkdir -p "$CONFIG_DIR"
  ARGS=(config init "$CONFIG_FILE" --name "$NAME" --mode "$MODE" --dry-run "$DRY")
  [[ -n "$DISCORD"   ]] && ARGS+=(--discord-webhook "$DISCORD")
  [[ -n "$PTERO_URL" && -n "$PTERO_KEY" ]] && ARGS+=(--pterodactyl-url "$PTERO_URL" --pterodactyl-key "$PTERO_KEY")
  "$BIN_DEST" "${ARGS[@]}" >/dev/null
  ok "config -> $CONFIG_FILE  (name='$NAME', mode=$MODE, dry_run=$DRY)"
fi

# --- enable service -----------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [[ -f "$UNIT_DEST" ]]; then
  systemctl daemon-reload
  systemctl enable --now protection >/dev/null 2>&1 && ok "service enabled & started" || warn "could not auto-start service"
fi

printf "\n${c_grn}protection is installed.${c_off}\n"
cat <<EOF

Next:
  protection status                # config + docker connectivity
  protection test-alert            # verify your alert channels
  protection scan                  # one-off scan (no enforcement)
  journalctl -u protection -f      # live activity

Edit $CONFIG_FILE to fine-tune thresholds, signatures and rules.
When confident, set dry_run: false and: systemctl restart protection
EOF
