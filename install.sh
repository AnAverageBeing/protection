#!/usr/bin/env bash
#
# protection one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/AnAverageBeing/protection/main/install.sh | sudo bash
#
# Downloads the prebuilt static binary for your architecture from the latest
# GitHub release, installs the systemd unit, creates a starter config (in
# dry-run mode) and enables the service. No Go toolchain required.
#
set -euo pipefail

REPO="AnAverageBeing/protection"
PREFIX="${PREFIX:-/usr/local}"
BIN_DEST="$PREFIX/bin/protection"
CONFIG_DIR="/etc/protection"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
UNIT_DEST="/etc/systemd/system/protection.service"
RAW="https://raw.githubusercontent.com/$REPO/main"

c_green='\033[0;32m'; c_yellow='\033[1;33m'; c_blue='\033[0;34m'; c_red='\033[0;31m'; c_off='\033[0m'
say()  { printf "${c_blue}==>${c_off} %s\n" "$*"; }
ok()   { printf "${c_green}  ok${c_off} %s\n" "$*"; }
warn() { printf "${c_yellow}  ! ${c_off} %s\n" "$*"; }
die()  { printf "${c_red}error:${c_off} %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (try: curl -fsSL $RAW/install.sh | sudo bash)"
command -v curl >/dev/null 2>&1 || die "curl is required"

# --- detect architecture -----------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64)         ARCH=amd64 ;;
  aarch64|arm64)        ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
ASSET="protection-linux-$ARCH"
say "Installing protection ($ASSET)"

# --- download binary ---------------------------------------------------------
URL="https://github.com/$REPO/releases/latest/download/$ASSET"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
if ! curl -fsSL "$URL" -o "$TMP"; then
  die "failed to download $URL"
fi
install -Dm0755 "$TMP" "$BIN_DEST"
ok "binary -> $BIN_DEST"

# --- systemd unit ------------------------------------------------------------
if curl -fsSL "$RAW/packaging/protection.service" -o "$UNIT_DEST"; then
  ok "systemd unit -> $UNIT_DEST"
else
  warn "could not fetch systemd unit (continuing without it)"
fi

# --- state directories -------------------------------------------------------
mkdir -p /var/lib/protection/quarantine
chmod 700 /var/lib/protection/quarantine
ok "state dir -> /var/lib/protection"

# --- configuration -----------------------------------------------------------
if [[ -f "$CONFIG_FILE" ]]; then
  warn "$CONFIG_FILE already exists; left untouched"
else
  mkdir -p "$CONFIG_DIR"
  "$BIN_DEST" config init "$CONFIG_FILE" >/dev/null
  ok "starter config -> $CONFIG_FILE (dry-run mode)"
fi

# --- enable service ----------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [[ -f "$UNIT_DEST" ]]; then
  systemctl daemon-reload
  systemctl enable --now protection >/dev/null 2>&1 || warn "could not auto-start service"
  ok "service enabled"
fi

cat <<EOF

$(printf "${c_green}protection installed.${c_off}")  Version: $("$BIN_DEST" version 2>/dev/null || echo unknown)

Next steps:
  1. Edit ${CONFIG_FILE}  — add your Discord/email/webhook alerts (keep dry_run: true)
  2. protection test-alert            # verify alert channels
  3. journalctl -u protection -f      # watch what it WOULD do
  4. When confident, set dry_run: false then: systemctl restart protection

Useful commands:
  protection status        # config + docker connectivity
  protection scan          # one-off scan, no enforcement
EOF
