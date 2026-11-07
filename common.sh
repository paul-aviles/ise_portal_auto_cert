#!/usr/bin/env bash
# Shared functions for Cisco ISE Let's Encrypt automation.
set -Eeuo pipefail

# Cisco ISE Let's Encrypt ACME script
# Author:  Paul Aviles
# Created: 10-21-2026
# Version: 0.1.0
# License: MIT 

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/config.sh}"
[[ -r "$CONFIG_FILE" ]] || { echo "[ERROR] Cannot read config: $CONFIG_FILE" >&2; exit 1; }
source "$CONFIG_FILE"

DEBUG=false
DRY_RUN=false
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ise-le.XXXXXXXX")"
chmod 700 "$TMP_DIR"
CRED=""

# Diagnostics go to stderr. Stdout is reserved for return values.
log()  { printf '[INFO]  %s\n' "$*" >&2; }
warn() { printf '[WARN]  %s\n' "$*" >&2; }
err()  { printf '[ERROR] %s\n' "$*" >&2; }
dbg()  { [[ "$DEBUG" == true ]] && printf '[DEBUG] %s\n' "$*" >&2 || true; }

cleanup_common() {
  CRED=""
  [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"
}
trap cleanup_common EXIT

need_cmds() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || {
      err "Missing dependency: $c"
      return 1
    }
  done
}

new_tmp() {
  local f
  f="$(mktemp "${TMP_DIR}/file.XXXXXXXX")"
  chmod 600 "$f"
  printf '%s' "$f"
}

get_credentials() {
  local host="$1"
  [[ -r "$NETRC_FILE" ]] || {
    err "NETRC_FILE is not readable: $NETRC_FILE"
    return 1
  }

  if ! awk -v h="$host" '
    $1=="machine" && $2==h { found=1 }
    END { exit(found ? 0 : 1) }
  ' "$NETRC_FILE"; then
    err "No machine entry for ${host} in ${NETRC_FILE}"
    return 1
  fi
}

# Build a CA bundle from system roots plus persistent self-signed ISE pins.
declare -Ag ISE_API_TLS_READY=()

prepare_ise_api_trust() {
  local host="$1"
  local bundle="${ISE_CA_PEM:-}"
  local system_bundle="${ISE_SYSTEM_CA_BUNDLE:-}"
  local pin_dir="${ISE_API_PIN_DIR:-}"
  local captured subject issuer fp pin_file tmp pin_count=0

  [[ "${AUTO_CAPTURE_ISE_CERT:-false}" == true ]] || return 0

  [[ -n "$bundle" && -n "$pin_dir" ]] || {
    err "AUTO_CAPTURE_ISE_CERT=true requires ISE_CA_PEM and ISE_API_PIN_DIR."
    return 1
  }

  [[ "${ISE_API_TLS_READY[$host]:-false}" == true ]] && return 0

  if [[ -z "$system_bundle" ]]; then
    for candidate in \
      /etc/ssl/certs/ca-certificates.crt \
      /etc/pki/tls/certs/ca-bundle.crt; do
      if [[ -r "$candidate" ]]; then
        system_bundle="$candidate"
        break
      fi
    done
  fi

  [[ -n "$system_bundle" && -r "$system_bundle" ]] || {
    err "Cannot locate the system CA bundle. Set ISE_SYSTEM_CA_BUNDLE in config.sh."
    return 1
  }

  mkdir -p -- "$(dirname -- "$bundle")" "$pin_dir"
  chmod 700 "$pin_dir"

  # Capture the currently presented HTTPS leaf certificate.
  captured="$(new_tmp)"

  if openssl s_client \
      -connect "${host}:443" \
      -servername "$host" \
      -showcerts </dev/null 2>/dev/null |
      openssl x509 -out "$captured" 2>/dev/null; then

    if openssl x509 -in "$captured" -noout >/dev/null 2>&1; then
      subject="$(openssl x509 -in "$captured" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
      issuer="$(openssl x509 -in "$captured" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"

      if [[ "$subject" == "$issuer" ]]; then
        openssl x509 -in "$captured" -checkhost "$host" -noout >/dev/null 2>&1 || {
          err "ISE self-signed certificate does not cover ${host}; refusing to trust it."
          return 1
        }

        openssl verify \
          -CAfile "$captured" \
          -verify_hostname "$host" \
          "$captured" >/dev/null 2>&1 || {
          err "ISE self-signed certificate failed verification; refusing to trust it."
          return 1
        }

        fp="$(cert_fingerprint "$captured")"
        pin_file="${pin_dir}/${fp}.pem"

        if [[ ! -s "$pin_file" ]]; then
          install -m 600 "$captured" "$pin_file"
          log "Automatically pinned self-signed ISE HTTPS certificate for ${host}; SHA256=${fp}."
        else
          dbg "Self-signed ISE HTTPS certificate already pinned for ${host}; SHA256=${fp}."
        fi
      else
        dbg "ISE HTTPS certificate on ${host} is CA-issued; no leaf pin required."
      fi
    else
      dbg "No parseable HTTPS leaf certificate was returned by ${host}."
    fi
  else
    dbg "Could not inspect live HTTPS certificate from ${host}; using existing pins and system roots."
  fi

  # Rebuild the bundle with the system roots and all pinned certificates.
  tmp="$(new_tmp)"
  cp -- "$system_bundle" "$tmp"

  for pin_file in "$pin_dir"/*.pem; do
    [[ -f "$pin_file" ]] || continue
    cat "$pin_file" >> "$tmp"
    ((pin_count+=1))
  done

  chmod 600 "$tmp"
  mv -f -- "$tmp" "$bundle"
  chmod 600 "$bundle"

  dbg "ISE API TLS bundle prepared for ${host}: ${bundle}; OS roots plus ${pin_count} pinned certificate(s)."
  ISE_API_TLS_READY["$host"]=true
}

curl_common_args() {
  local host="$1"

  prepare_ise_api_trust "$host"

  CURL_ARGS=(
    -sS
    --connect-timeout "$CURL_CONNECT_TIMEOUT"
    --max-time "$CURL_MAX_TIME"
    --retry "$CURL_RETRY_COUNT"
    --retry-delay 2
    --netrc-file "$NETRC_FILE"
    -H "Accept: application/json"
  )

  if [[ -n "${ISE_CA_PEM:-}" ]]; then
    [[ -r "$ISE_CA_PEM" ]] || {
      err "ISE_CA_PEM is set but unreadable: $ISE_CA_PEM"
      return 1
    }
    CURL_ARGS+=(--cacert "$ISE_CA_PEM")
  fi

  dbg "TLS verification enabled; CA source: ${ISE_CA_PEM:-system trust store}"
  dbg "API authentication uses protected netrc entry for ${host}"
}

api_request() {
  # api_request HOST METHOD URL [PAYLOAD_FILE] [RESPONSE_FILE]
  local host="$1"
  local method="$2"
  local url="$3"
  local payload="${4:-}"
  local response="${5:-}"
  local http rc

  response="${response:-$(new_tmp)}"

  curl_common_args "$host"

  local args=(
    "${CURL_ARGS[@]}"
    -o "$response"
    -w '%{http_code}'
    -X "$method"
  )

  [[ -n "$payload" ]] &&
    args+=(-H "Content-Type: application/json" --data-binary "@$payload")

  dbg "HTTP ${method} ${url}"

  set +e
  http="$(curl "${args[@]}" "$url")"
  rc=$?
  set -e

  dbg "curl exit=${rc}; HTTP=${http:-000}; response_bytes=$(wc -c < "$response" | tr -d ' ')"

  if [[ "$rc" -ne 0 ]]; then
    err "curl failed for ${method} ${url} (exit ${rc})"
    return 1
  fi

#  if [[ ! "$http" =~ ^2[0-9][0-9]$ ]]; then
#    err "ISE API returned HTTP ${http} for ${method} ${url}"
#
#    if jq -e . "$response" >/dev/null 2>&1; then
#      jq -r '.message // .response.message // "No API error message"' "$response" >&2
#    fi
#
#    return 1
#  fi

    if [[ ! "$http" =~ ^2[0-9][0-9]$ ]]; then
    err "ISE API returned HTTP ${http} for ${method} ${url}"

    if [[ -s "$response" ]]; then
      if jq -e . "$response" >/dev/null 2>&1; then
        jq -c . "$response" >&2
      else
        err "ISE API response body:"
        sed -n '1,40p' "$response" >&2
      fi
    else
      err "ISE API returned an empty response body."
    fi

    return 1
  fi

  printf '%s\n' "$response"
}

cert_fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 |
    cut -d= -f2 |
    tr -d ':' |
    tr '[:lower:]' '[:upper:]'
}

cert_subject_cn() {
  openssl x509 -in "$1" -noout -subject -nameopt RFC2253 |
    sed -n 's/.*CN=\([^,]*\).*/\1/p'
}

cert_is_ca() {
  openssl x509 -in "$1" -noout -ext basicConstraints 2>/dev/null |
    grep -q 'CA:TRUE'
}

extract_pem_certs() {
  local input="$1"
  local current=""
  local line
  local -a files=()

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
      current="$(new_tmp)"
      files+=("$current")
    fi

    [[ -n "$current" ]] && printf '%s\n' "$line" >> "$current"

    if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
      current=""
    fi
  done < "$input"

  ((${#files[@]} > 0)) || {
    err "No PEM certificates found in $input"
    return 1
  }

  printf '%s\n' "${files[@]}"
}

trusted_list_url() {
  printf 'https://%s/api/v1/certs/trusted-certificate?size=1000&page=1' "$1"
}

find_trusted_by_fp() {
  local json="$1"
  local fp="$2"

  jq -c --arg fp "$fp" '
    [
      .response[]? |
      select(
        ((.sha256Fingerprint // "") |
        gsub(":";"") |
        ascii_upcase) == $fp
      )
    ][0] // empty
  ' "$json"
}

ensure_ca_trusted() {
  # ensure_ca_trusted HOST PEM FRIENDLY_NAME DESCRIPTION
  local host="$1"
  local pem="$2"
  local name="$3"
  local description="$4"

  local fp list_file match id detail_file payload response_file
  fp="$(cert_fingerprint "$pem")"

  log "Trusted CA check: ${name}; SHA256=${fp}"

  list_file="$(api_request "$host" GET "$(trusted_list_url "$host")")" || return 1
  match="$(find_trusted_by_fp "$list_file" "$fp")"

  if [[ -n "$match" ]]; then
    id="$(jq -r '.id // empty' <<<"$match")"

    [[ -n "$id" ]] || {
      err "Trusted certificate matched by fingerprint but has no ID."
      return 1
    }

    log "CA already exists in ISE (ID ${id}); checking trust flags."

    detail_file="$(api_request "$host" GET \
      "https://${host}/api/v1/certs/trusted-certificate/${id}")" || return 1

    local current
    current="$(jq -r '
      (.response.trustedFor // "")
      | split(",")
      | map(gsub("^\\s+|\\s+$"; ""))
      | [
          (index("Infrastructure") != null),
          (index("Endpoints") != null),
          (index("AdminAuth") != null),
          (index("Cisco Services") != null)
        ]
      | map(tostring) | join(",")
    ' "$detail_file")"

    local desired="${TRUST_FOR_ISE_AUTH},${TRUST_FOR_CLIENT_AUTH},${TRUST_FOR_CERTIFICATE_BASED_ADMIN_AUTH},${TRUST_FOR_CISCO_SERVICES_AUTH}"

    if [[ "$current" == "$desired" ]]; then
      log "CA trust settings already match."
      return 0
    fi

    warn "Existing CA trust settings differ (current=${current}; desired=${desired})."

    payload="$(new_tmp)"

    jq -n \
      --arg name "$(jq -r '.response.friendlyName // empty' "$detail_file")" \
      --arg description "$description" \
      --argjson ise "$TRUST_FOR_ISE_AUTH" \
      --argjson client "$TRUST_FOR_CLIENT_AUTH" \
      --argjson admin "$TRUST_FOR_CERTIFICATE_BASED_ADMIN_AUTH" \
      --argjson cisco "$TRUST_FOR_CISCO_SERVICES_AUTH" \
      '{
        name:$name,
        description:$description,
        trustForIseAuth:$ise,
        trustForClientAuth:$client,
        trustForCertificateBasedAdminAuth:$admin,
        trustForCiscoServicesAuth:$cisco
      }' > "$payload"

    if [[ "$DRY_RUN" == true ]]; then
      log "(dry-run) Would PUT updated trust flags for CA ID ${id}; no change made."
      return 0
    fi

    response_file="$(api_request "$host" PUT \
      "https://${host}/api/v1/certs/trusted-certificate/${id}" \
      "$payload")" || return 1

    log "Updated trust settings for CA ID ${id}."
    return 0
  fi

  payload="$(new_tmp)"

  jq -n \
    --arg name "$name" \
    --arg description "$description" \
    --rawfile data "$pem" \
    --argjson ise "$TRUST_FOR_ISE_AUTH" \
    --argjson client "$TRUST_FOR_CLIENT_AUTH" \
    --argjson admin "$TRUST_FOR_CERTIFICATE_BASED_ADMIN_AUTH" \
    --argjson cisco "$TRUST_FOR_CISCO_SERVICES_AUTH" \
    '{
      name:$name,
      description:$description,
      data:$data,
      allowBasicConstraintCAFalse:false,
      allowOutOfDateCert:false,
      allowSHA1Certificates:false,
      allowMultipleCNCert:false,
      validateCertificateExtensions:true,
      trustForIseAuth:$ise,
      trustForClientAuth:$client,
      trustForCertificateBasedAdminAuth:$admin,
      trustForCiscoServicesAuth:$cisco
    }' > "$payload"

  jq -e . "$payload" >/dev/null

  if [[ "$DEBUG" == true ]]; then
    cp "$payload" /tmp/ise-ca-import-payload.json
    chmod 600 /tmp/ise-ca-import-payload.json
    log "Saved diagnostic payload to /tmp/ise-ca-import-payload.json"
  fi

  if [[ "$DRY_RUN" == true ]]; then
    log "(dry-run) CA not present; would POST trusted certificate '${name}'."
    return 0
  fi

  if [[ "$DEBUG" == true ]]; then
    jq 'del(.data)' "$payload" >&2
    jq -r '.data' "$payload" | openssl x509 -noout -subject -issuer -dates
  fi

  response_file="$(api_request "$host" POST \
    "https://${host}/api/v1/certs/trusted-certificate/import" \
    "$payload")" || return 1

  local status
  status="$(jq -r '.response.status // empty' "$response_file")"

  if [[ -n "$status" && "${status,,}" != "success" ]]; then
    err "ISE did not confirm CA import: $(jq -r '.response.message // "unknown error"' "$response_file")"
    return 1
  fi

  log "Imported trusted CA '${name}' (HTTP success)."
}