#!/usr/bin/env bash
# Uploads the plugin jar to a Jira instance through the UPM REST API and waits
# until the plugin reports enabled.
# Usage: it/install-plugin.sh <jar>
# Auth: JIRA_PAT (Bearer, preferred once the plugin blocks Basic auth) or
#       JIRA_ADMIN_USER / JIRA_ADMIN_PASS (Basic).
set -euo pipefail
jar="$1"
base="${JIRA_BASE_URL:-http://localhost:18080}"
key="de.netresearch.jira.jira-mfa-plugin"
if [[ -n "${JIRA_PAT:-}" ]]; then
  auth=(-H "Authorization: Bearer ${JIRA_PAT}")
else
  auth=(-u "${JIRA_ADMIN_USER:-admin}:${JIRA_ADMIN_PASS:-admin-Pass-4886}")
fi
hdr="$(mktemp)"
trap 'rm -f "$hdr"' EXIT
curl -sS -o /dev/null -D "$hdr" "${auth[@]}" -H 'Accept: application/vnd.atl.plugins.installed+json' "$base/rest/plugins/1.0/?os_authType=basic"
token="$(awk 'tolower($1)=="upm-token:" {print $2}' "$hdr" | tr -d '\r')"
if [[ -z "$token" ]]; then
  echo "no UPM token received" >&2
  exit 1
fi
code="$(curl -sS -o /dev/null -w '%{http_code}' "${auth[@]}" -H 'Accept: application/json' \
  -F "plugin=@${jar};type=application/java-archive" "$base/rest/plugins/1.0/?token=${token}")"
if [[ "$code" != 202 ]]; then
  echo "upload answered HTTP $code" >&2
  exit 1
fi
for _ in $(seq 1 60); do
  state="$(curl -sS "${auth[@]}" "$base/rest/plugins/1.0/${key}-key" | jq -r '"\(.enabled) \(.version)"' 2>/dev/null || true)"
  if [[ "$state" == true* ]]; then
    echo "installed and enabled: $state"
    exit 0
  fi
  sleep 2
done
echo "plugin not enabled after upload (last state: ${state:-none})" >&2
exit 1
