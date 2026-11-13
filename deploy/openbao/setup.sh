#!/bin/bash
# One-time setup of the license signing key in OpenBao (README-SERVER.md). Run it as the OpenBao operator, with BAO_ADDR and BAO_TOKEN (an admin token, NOT the server's) in the environment.
#   BAO_ADDR=https://127.0.0.1:8200 BAO_TOKEN=... ./deploy/openbao/setup.sh [--token-file /etc/asix-vendor/bao.token] [--key asix-license] [--mount transit]
# It: enables the transit engine, creates an Ed25519 key that CANNOT be exported or backed up in plain text, loads the sign-only policy, and writes a renewable token for the vendor server
# (mode 600) to --token-file. Safe to run again: an existing key is left alone.
set -euo pipefail
BAO="${BAO_BIN:-bao}"; KEY="asix-license"; MOUNT="transit"; TOKEN_FILE=""
while [ $# -gt 0 ]; do case "$1" in --key) KEY="$2"; shift 2;; --mount) MOUNT="$2"; shift 2;; --token-file) TOKEN_FILE="$2"; shift 2;; -h|--help) sed -n 2,8p "$0"; exit 0;; *) echo "unknown option $1" >&2; exit 2;; esac; done
[[ "$KEY" =~ ^[A-Za-z0-9._-]{1,60}$ ]] || { echo "ERROR: bad --key" >&2; exit 2; }
[[ "$MOUNT" =~ ^[A-Za-z0-9._-]{1,40}$ ]] || { echo "ERROR: bad --mount" >&2; exit 2; }
: "${BAO_ADDR:?set BAO_ADDR}"; : "${BAO_TOKEN:?set BAO_TOKEN (an admin token)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0; "$BAO" status >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { [ "$rc" -eq 2 ] && echo "ERROR: OpenBao at $BAO_ADDR is sealed: unseal it first." >&2 || echo "ERROR: cannot reach OpenBao at $BAO_ADDR (or the bao command is not installed)." >&2; exit 1; }

LIST="$("$BAO" secrets list -format=json)"; if ! grep -q "\"$MOUNT/\"" <<<"$LIST"; then "$BAO" secrets enable -path="$MOUNT" transit >/dev/null; echo "Enabled the transit engine at $MOUNT/"; fi
if "$BAO" read "$MOUNT/keys/$KEY" >/dev/null 2>&1; then echo "The key $KEY already exists: left alone."
else "$BAO" write -f "$MOUNT/keys/$KEY" type=ed25519 exportable=false allow_plaintext_backup=false >/dev/null; echo "Created the Ed25519 key $KEY (not exportable, no plain-text backup)."; fi
sed -e "s#transit/sign/asix-license#$MOUNT/sign/$KEY#" -e "s#transit/keys/asix-license#$MOUNT/keys/$KEY#" "$HERE/asix-sign.hcl" | "$BAO" policy write asix-sign - >/dev/null; echo "Loaded the policy asix-sign."
if [ -n "$TOKEN_FILE" ]; then
  umask 077; TOKEN="$("$BAO" token create -policy=asix-sign -orphan -period=768h -display-name=asix-vendor-server -format=json | python3 -c 'import json,sys;print(json.load(sys.stdin)["auth"]["client_token"])')"
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"; echo "Wrote the server's token to $TOKEN_FILE (mode 600). It renews itself while the server runs; make a new one if the server is off for over 32 days."
fi
echo; echo "The public key (for the ASIX product) is shown by:  node server/index.js signer-info"
