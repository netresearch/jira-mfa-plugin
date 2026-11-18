#!/usr/bin/env bash
# Uploads the plugin jar to a Jira instance through the UPM REST API and waits
# until the plugin reports enabled in the jar's version. An update over an
# installed version otherwise reads the old plugin, still enabled, as done.
# Usage: it/install-plugin.sh <jar>
# Auth: JIRA_PAT (personal access token of an administrator), or
#       JIRA_ADMIN_USER / JIRA_ADMIN_PASS (Basic). UPM issues its upload token to
#       a personal access token only on a request with os_authType=any (with
#       os_authType=basic it does not). Once the plugin is active it refuses Basic
#       for enforced administrators, so use JIRA_PAT there.
set -euo pipefail
jar="$1"
base="${JIRA_BASE_URL:-http://localhost:18080}"
key="de.netresearch.jira.jira-mfa-plugin"
want="$(unzip -p "$jar" atlassian-plugin.xml | yq -p xml -oy '.atlassian-plugin.plugin-info.version')"
if [[ -z "$want" || "$want" == null ]]; then
  echo "no plugin version found in $jar" >&2
  exit 1
fi
if [[ -n "${JIRA_PAT:-}" ]]; then
  auth=(-H "Authorization: Bearer ${JIRA_PAT}")
else
  auth=(-u "${JIRA_ADMIN_USER:-admin}:${JIRA_ADMIN_PASS:-admin-Pass-4886}")
fi
hdr="$(mktemp)"
trap 'rm -f "$hdr"' EXIT
curl -sS -o /dev/null -D "$hdr" "${auth[@]}" -H 'Accept: application/vnd.atl.plugins.installed+json' "$base/rest/plugins/1.0/?os_authType=any"
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
  # the plugin list, not .../<key>-key: that one answers a personal access token with an empty body
  state="$(curl -sS "${auth[@]}" -H 'Accept: application/vnd.atl.plugins.installed+json' "$base/rest/plugins/1.0/" \
    | jq -r --arg k "$key" '.plugins[] | select(.key == $k) | "\(.enabled) \(.version)"' 2>/dev/null || true)"
  if [[ "$state" == "true $want" ]]; then
    echo "installed and enabled: $state"
    exit 0
  fi
  sleep 2
done
echo "plugin $want not enabled after upload (last state: ${state:-none})" >&2
exit 1
