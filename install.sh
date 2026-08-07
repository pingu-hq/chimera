#!/usr/bin/env bash
# install the latest chimera release into prefix/bin.

set -euo pipefail

PREFIX="${1:-${PREFIX:-/usr/local}}"
BIN_DIR="$PREFIX/bin"
RELEASE_URL="https://github.com/pingu-hq/chimera/releases/latest/download"
TEMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

c_log() { printf '\033[1;36m[chimera]\033[0m %s\n' "$*"; }
c_err() { printf '\033[1;31m[chimera]\033[0m error: %s\n' "$*" >&2; }

if ! command -v curl >/dev/null 2>&1; then
    c_err "curl is required to download the release"
    exit 1
fi

download() {
    local name="$1"
    c_log "downloading $name"
    curl --fail --location --silent --show-error \
        "$RELEASE_URL/$name" \
        --output "$TEMP_DIR/$name"
}

download chimera-x86_64
download chi-x86_64

mkdir -p "$BIN_DIR"
install -m 0755 "$TEMP_DIR/chimera-x86_64" "$BIN_DIR/chimera"
install -m 0755 "$TEMP_DIR/chi-x86_64" "$BIN_DIR/chi"

c_log "installed $BIN_DIR/chimera"
c_log "installed $BIN_DIR/chi"
c_log "try: chimera help"
