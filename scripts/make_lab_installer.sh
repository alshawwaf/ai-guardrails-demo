#!/usr/bin/env bash
# Build dist/aiguard-lab-install.sh: scripts/lab_install.sh with this repository
# embedded (no git history, tests, local data, settings, keys or certificates).
#
#   ./scripts/make_lab_installer.sh        then copy dist/aiguard-lab-install.sh to the lab host
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
BASE="$(basename "$ROOT")"
OUT="$ROOT/dist/aiguard-lab-install.sh"
MARKER="__AIGUARD_PAYLOAD_BELOW__"
mkdir -p "$ROOT/dist"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Scripts with Windows line endings (a CRLF checkout) do not run on the lab host or in the image.
CRLF="$(grep -l "$(printf '\r')" "$ROOT"/scripts/*.sh 2>/dev/null || true)"
if [ -n "$CRLF" ]; then
  echo "Refusing to build: these scripts have Windows (CRLF) line endings:" >&2
  echo "$CRLF" >&2
  echo "Fix: git config core.autocrlf input && git checkout -- scripts/   (or: sed -i 's/\\r\$//' FILE)" >&2
  exit 1
fi

# bsdtar (macOS) vs GNU tar: no macOS metadata, and files owned by root:root in the archive
# (the installer also extracts with --no-same-owner).
TAR_FLAGS=()
if tar --version 2>/dev/null | grep -i bsdtar >/dev/null; then
  TAR_FLAGS+=(--no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname root)
else
  TAR_FLAGS+=(--owner=0 --group=0 --numeric-owner)
fi
# .env.* holds local settings (.env.local, .env.prod, ...): excluded, then .env.example is added back.
( cd "$ROOT/.." && COPYFILE_DISABLE=1 tar cf "$TMP/kit.tar" ${TAR_FLAGS[@]+"${TAR_FLAGS[@]}"} \
    --exclude='.git' --exclude='__pycache__' --exclude='.pytest_cache' --exclude='.DS_Store' \
    --exclude='.venv' --exclude='venv' --exclude='node_modules' --exclude='.aiguard' \
    --exclude="$BASE/dist" --exclude="$BASE/tests" --exclude="$BASE/tmp" \
    --exclude="$BASE/instance" --exclude="$BASE/logs" \
    --exclude="$BASE/backups" --exclude="$BASE/models_cache" \
    --exclude='.env' --exclude='.env.*' --exclude='*.crt' --exclude='*.pem' --exclude='*.key' \
    --exclude='*.p12' --exclude='*.pfx' --exclude='*.jks' --exclude='id_rsa*' --exclude='id_ed25519*' \
    "$BASE" )
if [ -f "$ROOT/.env.example" ]; then
  ( cd "$ROOT/.." && COPYFILE_DISABLE=1 tar rf "$TMP/kit.tar" ${TAR_FLAGS[@]+"${TAR_FLAGS[@]}"} "$BASE/.env.example" )
fi

# The embedded folder must be called ai-guardrails-demo (the installer expects it).
if [ "$BASE" != "ai-guardrails-demo" ]; then
  mkdir "$TMP/x" && tar xf "$TMP/kit.tar" -C "$TMP/x" && mv "$TMP/x/$BASE" "$TMP/x/ai-guardrails-demo"
  ( cd "$TMP/x" && COPYFILE_DISABLE=1 tar cf "$TMP/kit.tar" ${TAR_FLAGS[@]+"${TAR_FLAGS[@]}"} ai-guardrails-demo )
fi
gzip -n -9 "$TMP/kit.tar"; mv "$TMP/kit.tar.gz" "$TMP/kit.tgz"

tar tzf "$TMP/kit.tgz" >"$TMP/list"
if grep -E '(^|/)\.env(\.[^/]*)?$|\.(pem|key|crt|p12|pfx|jks)$|(^|/)id_(rsa|ed25519)|^ai-guardrails-demo/(instance|logs|tests|dist|backups|models_cache)(/|$)|(^|/)(\.git|\.aiguard)(/|$)' "$TMP/list" \
     | grep -vx 'ai-guardrails-demo/\.env\.example'; then
  echo "Refusing to build: the archive would contain settings, keys, tests or local data (listed above)." >&2
  exit 1
fi
grep -qx 'ai-guardrails-demo/app.py' "$TMP/list" || { echo "Refusing to build: app.py is not in the archive." >&2; exit 1; }

# script part with LF line endings and a final newline, so the marker is a line of its own
{ awk '{ sub(/\r$/, ""); print }' "$ROOT/scripts/lab_install.sh"; echo "$MARKER"; openssl base64 -e -in "$TMP/kit.tgz"; } >"$TMP/out.sh"

# self-check: unpack the payload the way the installer does
LINE="$(awk -v m="$MARKER" '$0 == m { print NR; exit }' "$TMP/out.sh")"
tail -n +"$((LINE + 1))" "$TMP/out.sh" | openssl base64 -d | tar tzf - | grep -x 'ai-guardrails-demo/app.py' >/dev/null \
  || { echo "Refusing to build: the embedded payload does not unpack." >&2; exit 1; }
head -n "$((LINE - 1))" "$TMP/out.sh" | bash -n || { echo "Refusing to build: the installer has a syntax error." >&2; exit 1; }

chmod +x "$TMP/out.sh"
mv -f "$TMP/out.sh" "$OUT"
SUM="$( (sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT") | cut -d' ' -f1)"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"
echo "SHA-256 $SUM"
