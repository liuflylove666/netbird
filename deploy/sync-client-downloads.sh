#!/usr/bin/env bash
# Sync NetBird client installers into a local directory for NB_CLIENT_DOWNLOADS_DIR
# (layout compatible with the dashboard when "Use management server for install downloads" is on).
#
# Usage (repository root):
#   chmod +x deploy/sync-client-downloads.sh
#   ./deploy/sync-client-downloads.sh ./deploy/client-downloads
#
# --- NETBIRD_CLIENT_VERSION (optional) -----------------------------------------
# Controls which client release is downloaded from GitHub (TAG=vX.Y.Z) and which
# paths on pkgs.netbird.io are implied for versioned assets.
#
# When SET (recommended for production / version parity with your server):
#   - Value is a semver string: "0.68.1" or "v0.68.1" (a leading "v" is stripped).
#   - Example — one shot:
#       NETBIRD_CLIENT_VERSION=0.68.1 ./deploy/sync-client-downloads.sh ./deploy/client-downloads
#   - Example — same shell session (e.g. in CI or a deploy script):
#       export NETBIRD_CLIENT_VERSION=0.68.1
#       ./deploy/sync-client-downloads.sh ./deploy/client-downloads
#   - Pick the same version as your self-hosted management / combined image or the
#     dashboard "Management" version (Settings / about) so installers match the server.
#
# When UNSET:
#   - Version is read from: https://pkgs.netbird.io/releases/latest/version
#   - That tracks NetBird's latest published client, which may be NEWER than your
#     running server — fine for testing; for stable fleets prefer NETBIRD_CLIENT_VERSION.
#
# --- Mobile (optional; separate from NETBIRD_CLIENT_VERSION) --------------------
# The main github.com/netbirdio/netbird release does NOT ship .apk or .ipa. Android
# builds are published from https://github.com/netbirdio/android-client/releases
# under names like netbird-v0.4.1.apk (app semver, unrelated to agent 0.68.x).
#
#   NETBIRD_ANDROID_CLIENT_VERSION=0.4.1  — download that tag from android-client
#   NETBIRD_ANDROID_APK_URL=https://.../file.apk  — explicit URL (overrides version)
#   NETBIRD_IOS_IPA_URL=https://.../netbird.ipa   — iOS is not on GitHub releases;
#                                                   set this if you host an in-house IPA.
#
# After sync + docker compose:
#   - Mount DEST read-only at /var/lib/netbird/downloads
#   - Set NB_CLIENT_DOWNLOADS_DIR=/var/lib/netbird/downloads on netbird-server
#   - Enable the setting in Dashboard → Settings → Clients

set -euo pipefail

PKGS="${PKGS_BASE:-https://pkgs.netbird.io}"
GH="https://github.com/netbirdio/netbird/releases/download"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-"$REPO_ROOT/deploy/client-downloads"}"

log() { echo "[sync-client-downloads] $*"; }

need_curl() {
  command -v curl >/dev/null 2>&1 || {
    log "error: curl is required"
    exit 1
  }
}

fetch() {
  local url="$1" out="$2"
  mkdir -p "$(dirname "$out")"
  log "GET $url -> $out"
  if [[ -n "${GITHUB_TOKEN:-}" ]] && [[ "$url" == *"github.com"* ]]; then
    curl -fSL --retry 3 --connect-timeout 30 \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      "$url" -o "$out"
  else
    curl -fSL --retry 3 --connect-timeout 30 "$url" -o "$out"
  fi
}

# Like fetch but does not abort the script on 404 / network errors.
fetch_optional() {
  local url="$1" out="$2"
  mkdir -p "$(dirname "$out")" 2>/dev/null || true
  log "GET (optional) $url -> $out"
  if [[ -n "${GITHUB_TOKEN:-}" ]] && [[ "$url" == *"github.com"* ]]; then
    if curl -fSL --retry 2 --connect-timeout 30 \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      "$url" -o "$out" 2>/dev/null; then
      return 0
    fi
  else
    if curl -fSL --retry 2 --connect-timeout 30 "$url" -o "$out" 2>/dev/null; then
      return 0
    fi
  fi
  rm -f "$out" 2>/dev/null || true
  log "skip (not found or failed): $url"
  return 0
}

need_curl

if [[ -n "${NETBIRD_CLIENT_VERSION:-}" ]]; then
  V="${NETBIRD_CLIENT_VERSION#v}"
  log "version source: NETBIRD_CLIENT_VERSION=${NETBIRD_CLIENT_VERSION} (normalized to ${V})"
else
  log "NETBIRD_CLIENT_VERSION unset — fetching latest from $PKGS/releases/latest/version (set NETBIRD_CLIENT_VERSION to pin, e.g. 0.68.1)"
  V="$(curl -fsSL "$PKGS/releases/latest/version" | tr -d '[:space:]\r')"
fi

if [[ -z "$V" ]]; then
  log "error: empty version"
  exit 1
fi

TAG="v${V}"
log "using NetBird client version ${V} (GitHub tag ${TAG}), destination: ${DEST}"

mkdir -p "$DEST"/{windows/x64,windows/arm64,windows/msi/x64,windows/msi/arm64,macos,debian,android,ios}

if fetch_optional "$PKGS/install.sh" "$DEST/install.sh"; then
  :
elif [[ -f "$REPO_ROOT/release_files/install.sh" ]]; then
  log "fallback: copy release_files/install.sh (script still references official pkgs for apt)"
  cp -f "$REPO_ROOT/release_files/install.sh" "$DEST/install.sh"
else
  log "error: could not obtain install.sh"
  exit 1
fi

fetch "$PKGS/debian/public.key" "$DEST/debian/public.key"

fetch "$PKGS/windows/x64" "$DEST/windows/x64/netbird.exe"
fetch "$PKGS/windows/arm64" "$DEST/windows/arm64/netbird.exe"
fetch "$PKGS/windows/msi/x64" "$DEST/windows/msi/x64/netbird.msi"
fetch "$PKGS/windows/msi/arm64" "$DEST/windows/msi/arm64/netbird.msi"

# Dashboard macOS link is {base}/macos/universal (no extension).
if fetch_optional "$PKGS/macos/universal" "$DEST/macos/universal"; then
  :
elif fetch_optional "$PKGS/macos/amd64" "$DEST/macos/universal"; then
  log "note: used pkgs macos/amd64 saved as macos/universal"
elif fetch_optional "$PKGS/macos/arm64" "$DEST/macos/universal"; then
  log "note: used pkgs macos/arm64 saved as macos/universal"
else
  log "warning: could not download macos/universal from pkgs; place a pkg manually at macos/universal"
fi

# Extra GitHub assets (optional; names match client updater on Windows).
fetch_optional "$GH/${TAG}/netbird_installer_${V}_windows_amd64.msi" \
  "$DEST/windows/msi/x64/netbird_installer_${V}_windows_amd64.msi"
fetch_optional "$GH/${TAG}/netbird_installer_${V}_windows_arm64.msi" \
  "$DEST/windows/msi/arm64/netbird_installer_${V}_windows_arm64.msi"
fetch_optional "$GH/${TAG}/netbird_installer_${V}_windows_amd64.exe" \
  "$DEST/windows/x64/netbird_installer_${V}_windows_amd64.exe"
fetch_optional "$GH/${TAG}/netbird_installer_${V}_windows_arm64.exe" \
  "$DEST/windows/arm64/netbird_installer_${V}_windows_arm64.exe"
fetch_optional "$GH/${TAG}/netbird_${V}_darwin_amd64.pkg" "$DEST/macos/netbird_${V}_darwin_amd64.pkg"
fetch_optional "$GH/${TAG}/netbird_${V}_darwin_arm64.pkg" "$DEST/macos/netbird_${V}_darwin_arm64.pkg"

# Mobile: see script header — not on netbirdio/netbird releases.
ANDROID_OUT="$DEST/android/netbird.apk"
IOS_OUT="$DEST/ios/netbird.ipa"
if [[ -n "${NETBIRD_ANDROID_APK_URL:-}" ]]; then
  fetch_optional "$NETBIRD_ANDROID_APK_URL" "$ANDROID_OUT"
elif [[ -n "${NETBIRD_ANDROID_CLIENT_VERSION:-}" ]]; then
  AV="${NETBIRD_ANDROID_CLIENT_VERSION#v}"
  ATAG="v${AV}"
  fetch_optional "https://github.com/netbirdio/android-client/releases/download/${ATAG}/netbird-${ATAG}.apk" \
    "$ANDROID_OUT"
fi
if [[ -n "${NETBIRD_IOS_IPA_URL:-}" ]]; then
  fetch_optional "$NETBIRD_IOS_IPA_URL" "$IOS_OUT"
fi

log "done. Sample of files under $DEST:"
find "$DEST" -type f | sed "s|^$DEST/||" | sort | head -200

cat <<EOF

Next steps:
  1. In deploy/docker-compose.yml add a read-only mount and env on netbird-server, e.g.:
       volumes:
         - ${DEST}:/var/lib/netbird/downloads:ro
       environment:
         NB_CLIENT_DOWNLOADS_DIR: /var/lib/netbird/downloads
  2. docker compose up -d --build
  3. Dashboard → Settings → Clients → enable "Use management server for install downloads".

Debian/Ubuntu full apt mirror (dists/, pool/) is large and not included; use official pkgs for apt,
or mirror separately (apt-mirror / rsync) if you need fully offline apt.
EOF
