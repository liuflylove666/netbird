#!/usr/bin/env bash
# Programmatically log in to embedded Dex (LDAP connector) as the LDAP admin,
# get a JWT, then create a reusable setup key via the NetBird REST API.
# Prints the setup key to stdout (any other output goes to stderr).
#
# Defaults match deploy/config.yaml + deploy/ldap-init.ldif.
# Override via env vars:
#   EMAIL, PASSWORD, CONNECTOR_ID, CLIENT_ID, REDIRECT, ISSUER, API_BASE, KEY_NAME
#
# Example usage from deploy/ directory:
#   ./scripts/bootstrap-setup-key.sh > /tmp/key && echo "NB_SETUP_KEY=$(cat /tmp/key)" > peer.env

set -euo pipefail

CLIENT_ID="${CLIENT_ID:-netbird-cli}"
REDIRECT="${REDIRECT:-http://localhost:53000/}"
EMAIL="${EMAIL:-ldapadmin@example.org}"
PASSWORD="${PASSWORD:-LdapAdmin@123}"
CONNECTOR_ID="${CONNECTOR_ID:-openldap}"
ISSUER="${ISSUER:-http://localhost/oauth2}"
API_BASE="${API_BASE:-http://localhost/api}"
KEY_NAME="${KEY_NAME:-docker-router}"

COOKIE=$(mktemp)
trap 'rm -f "$COOKIE"' EXIT

PKCE="cli-pkce-verifier-$(openssl rand -hex 16 2>/dev/null || echo 1234567890abcdef)"
STATE="state-$(openssl rand -hex 8 2>/dev/null || echo 12345678)"

AUTH_URL="${ISSUER}/auth?client_id=${CLIENT_ID}&response_type=code&redirect_uri=$(printf %s "$REDIRECT" | jq -sRr @uri)&scope=openid+profile+email+groups&state=${STATE}&code_challenge_method=plain&code_challenge=${PKCE}&connector_id=${CONNECTOR_ID}"

LOGIN_PAGE=$(curl -sS -L -c "$COOKIE" -b "$COOKIE" "$AUTH_URL")

FORM_ACTION=$(printf '%s' "$LOGIN_PAGE" \
  | grep -oE '<form[^>]+action="[^"]+"' \
  | head -1 \
  | sed -E 's/.*action="([^"]+)".*/\1/' \
  | sed 's/&amp;/\&/g')
[[ -z "$FORM_ACTION" ]] && { echo "ERR: could not find login form action" >&2; exit 1; }

LOGIN_HEADERS=$(curl -sS -c "$COOKIE" -b "$COOKIE" -D - -o /dev/null \
  --data-urlencode "login=${EMAIL}" \
  --data-urlencode "password=${PASSWORD}" \
  "http://localhost${FORM_ACTION}")

NEXT=$(printf '%s' "$LOGIN_HEADERS" | grep -i '^location:' | tail -1 | awk '{print $2}' | tr -d '\r')
[[ -z "$NEXT" ]] && { echo "ERR: login did not redirect (bad credentials?)" >&2; exit 1; }

CODE=""
for _ in 1 2 3 4 5; do
  if [[ "$NEXT" == "$REDIRECT"* ]]; then
    CODE=$(printf '%s' "$NEXT" | sed -nE 's/.*[?&]code=([^&]+).*/\1/p')
    break
  fi
  if [[ "$NEXT" == /* ]]; then NEXT="http://localhost${NEXT}"; fi
  HEADERS=$(curl -sS -c "$COOKIE" -b "$COOKIE" -D - -o /dev/null "$NEXT")
  NEXT=$(printf '%s' "$HEADERS" | grep -i '^location:' | tail -1 | awk '{print $2}' | tr -d '\r')
  [[ -z "$NEXT" ]] && break
done
[[ -z "$CODE" ]] && { echo "ERR: failed to obtain auth code (last URL: $NEXT)" >&2; exit 1; }

TOKEN_JSON=$(curl -sS -X POST "${ISSUER}/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=${REDIRECT}" \
  --data-urlencode "code_verifier=${PKCE}")

TOKEN=$(printf '%s' "$TOKEN_JSON" | jq -r '.access_token // .id_token // empty')
[[ -z "$TOKEN" ]] && { echo "ERR: token exchange failed: $TOKEN_JSON" >&2; exit 1; }

KEY_JSON=$(curl -sS -X POST "${API_BASE}/setup-keys" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"${KEY_NAME}\",\"type\":\"reusable\",\"expires_in\":31536000,\"usage_limit\":0,\"auto_groups\":[],\"ephemeral\":false}")

KEY=$(printf '%s' "$KEY_JSON" | jq -r '.key // empty')
[[ -z "$KEY" ]] && { echo "ERR: setup key creation failed: $KEY_JSON" >&2; exit 1; }

printf '%s\n' "$KEY"
