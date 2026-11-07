#!/usr/bin/env bash
# Cisco ISE 3.5 Let's Encrypt system certificate importer.
# Supports standalone now and multiple node-specific perhaps, needs validation.

# Cisco ISE Let's Encrypt ACME script
# Author:  Paul Aviles
# Created: 10-21-2026
# Version: 0.1.0
# License: MIT

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<'EOF'
Usage: ISE_LE_Import.sh [--debug] [--dry-run] [--allow-admin-restart]
  --dry-run              Validate local certs and perform read-only ISE API checks.
                         No POST, PUT, or DELETE requests are sent.
  --debug                Detailed safe execution logging (never dumps secrets/payloads).
  --allow-admin-restart  Explicitly authorize Admin role activation/restart.
EOF
}

ALLOW_ADMIN_CLI=false
while (($#)); do
  case "$1" in
    --debug) DEBUG=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --allow-admin-restart) ALLOW_ADMIN_CLI=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

need_cmds curl openssl jq awk sed grep cut tr mktemp date wc
[[ -n "${PRIVATE_KEY_PASS:-}" ]] || PRIVATE_KEY_PASS="${ISE_PRIVATE_KEY_PASS:-}"
[[ -n "$PRIVATE_KEY_PASS" ]] || { err "Set PRIVATE_KEY_PASS in config.sh or ISE_PRIVATE_KEY_PASS in the environment."; exit 1; }

if [[ "$DRY_RUN" != true && "$ENABLE_ADMIN_ROLE" == true && "$ALLOW_ADMIN_ROLE_ACTIVATION" != true && "$ALLOW_ADMIN_CLI" != true ]]; then
  err "Admin role is enabled but activation is not authorized."
  err "Review the ISE application-server restart impact, then set ALLOW_ADMIN_ROLE_ACTIVATION=true or pass --allow-admin-restart."
  exit 1
fi

# ISE import API schema supports these roles; SAML and NativeIPSec are deliberately false/absent.
if [[ "$ENABLE_PORTAL_ROLE" == true && -z "$PORTAL_GROUP_TAG" ]]; then
  err "PORTAL_GROUP_TAG is required when Portal role is enabled."
  exit 1
fi

# Validate role trust dependencies in config.
[[ "$TRUST_FOR_CLIENT_AUTH" != true || "$TRUST_FOR_ISE_AUTH" == true ]] || { err "ClientAuth trust requires IseAuth trust."; exit 1; }
[[ "$TRUST_FOR_CERTIFICATE_BASED_ADMIN_AUTH" != true || ( "$TRUST_FOR_ISE_AUTH" == true && "$TRUST_FOR_CLIENT_AUTH" == true ) ]] || {
  err "Certificate-based admin trust requires both IseAuth and ClientAuth trust."; exit 1;
}

log "Cisco ISE 3.5 Let's Encrypt import starting."
dbg "Mode: debug=${DEBUG}; dry_run=${DRY_RUN}; truststore_host=${ISE_TRUSTSTORE_HOST}"
dbg "Supported roles: admin=${ENABLE_ADMIN_ROLE}, eap=${ENABLE_EAP_ROLE}, radius=${ENABLE_RADIUS_ROLE}, tacacs=${ENABLE_TACACS_ROLE}, pxgrid=${ENABLE_PXGRID_ROLE}, ims=${ENABLE_IMS_ROLE}, portal=${ENABLE_PORTAL_ROLE}; saml=false; NativeIPSec=excluded"

# Trusted CA prerequisites are deployment-wide and are checked/imported on PAN.
first_node_host="${ISE_TRUSTSTORE_HOST}"
get_credentials "$first_node_host"

node_index=0
for entry in "${ISE_NODES[@]}"; do
  IFS='|' read -r host live_dir <<<"$entry"
  [[ -n "$host" && -n "$live_dir" ]] || { err "Invalid ISE_NODES entry: expected host|live-directory"; exit 1; }
  fullchain="${live_dir}/fullchain.pem"
  privkey="${live_dir}/privkey.pem"
  [[ -r "$fullchain" ]] || { err "Cannot read certificate chain: $fullchain"; exit 1; }
  [[ -r "$privkey" ]] || { err "Cannot read private key: $privkey"; exit 1; }
  get_credentials "$host"

  log "Validating node ${host} (lineage ${live_dir})."
  certs_text="$(extract_pem_certs "$fullchain")"
  mapfile -t certs <<<"$certs_text"
  ((${#certs[@]} >= 1)) || { err "No certificate found in $fullchain"; exit 1; }
  leaf="${certs[0]}"
  openssl x509 -in "$leaf" -noout >/dev/null
  # Verify the leaf-to-issuer chain using the operating system CA store.
  # The intermediate certificates are taken from Certbot's fullchain.pem.
  intermediate_bundle="$(new_tmp)"
  : > "$intermediate_bundle"
  for chain_cert in "${certs[@]:1}"; do
    openssl x509 -in "$chain_cert" -noout >/dev/null
    if cert_is_ca "$chain_cert"; then cat "$chain_cert" >> "$intermediate_bundle"; fi
  done
  if [[ -s "$intermediate_bundle" ]]; then
    openssl verify -purpose sslserver -verify_hostname "$host" \
      -untrusted "$intermediate_bundle" "$leaf" >/dev/null || {
        err "Certificate chain validation failed for ${host} using the system CA trust store."
        exit 1
      }
  else
    openssl verify -purpose sslserver -verify_hostname "$host" "$leaf" >/dev/null || {
      err "Certificate chain validation failed for ${host} using the system CA trust store."
      exit 1
    }
  fi
  log "OpenSSL chain verification passed against the system CA trust store."
  openssl pkey -in "$privkey" -noout >/dev/null 2>&1 || { err "Private key is not readable/valid: $privkey"; exit 1; }
  openssl x509 -in "$leaf" -checkend 0 -noout >/dev/null || { err "Leaf certificate is expired."; exit 1; }
  openssl x509 -in "$leaf" -checkhost "$host" -noout >/dev/null 2>&1 || { err "Leaf certificate SAN/CN does not cover ${host}."; exit 1; }

  cert_pub="$(openssl x509 -in "$leaf" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)"
  key_pub="$(openssl pkey -in "$privkey" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)"
  [[ "$cert_pub" == "$key_pub" ]] || { err "Certificate and private key do not match for ${host}."; exit 1; }

  eku="$(openssl x509 -in "$leaf" -noout -ext extendedKeyUsage 2>/dev/null || true)"
  if [[ "$ENABLE_ADMIN_ROLE" == true || "$ENABLE_EAP_ROLE" == true || "$ENABLE_PORTAL_ROLE" == true || "$ENABLE_PXGRID_ROLE" == true || "$ENABLE_TACACS_ROLE" == true || "$ENABLE_RADIUS_ROLE" == true ]]; then
    grep -qi 'TLS Web Server Authentication' <<<"$eku" || { err "Certificate lacks TLS Web Server Authentication EKU required by requested roles."; exit 1; }
  fi

  # Client Authentication EKU is required for pxGrid (mTLS) and IMS (ISE 3.5 mTLS).
  # Admin, EAP, Portal, RADIUS DTLS, and TACACS are server-authentication roles.
  if [[ "$ENABLE_PXGRID_ROLE" == true || "$ENABLE_IMS_ROLE" == true ]]; then
    grep -qi 'TLS Web Client Authentication' <<<"$eku" || { err "Certificate lacks TLS Web Client Authentication EKU required by pxGrid and/or ISE Messaging Service."; exit 1; }
  fi

  log "Leaf subject: $(openssl x509 -in "$leaf" -noout -subject)"
  log "Leaf issuer:  $(openssl x509 -in "$leaf" -noout -issuer)"
  log "Leaf SHA256:  $(cert_fingerprint "$leaf")"
  log "Certificate/key match and hostname validation passed."

  # Check whether this exact leaf certificate is already installed.
  # This is deliberately before CA trust checks, key encryption, and payload
  # generation. Presence does not, by itself, prove that roles are correct, not checking for that!
  leaf_fp="$(cert_fingerprint "$leaf")"
  system_list="$(api_request "$host" GET \
    "https://${host}/api/v1/certs/system-certificate/${host}")"

  existing="$(jq -c --arg fp "$leaf_fp" \
    '[.response[]? |
      select(((.sha256Fingerprint // "") |
        gsub(":";"") | ascii_upcase) == $fp)][0] // empty' \
    "$system_list")"

  existing_id=""
  if [[ -n "$existing" ]]; then
    existing_id="$(jq -r '.id // empty' <<<"$existing")"
    [[ -n "$existing_id" ]] || {
      err "Certificate fingerprint matched, but ISE returned no certificate ID."
      exit 1
    }
    log "Exact certificate fingerprint already exists on ${host} (ID ${existing_id})."
  else
    log "Certificate fingerprint is not installed on ${host}."
  fi

  # Ensure root and intermediate chain is trusted before system cert import.
  root_args=(--chain-file "$fullchain" --host "$ISE_TRUSTSTORE_HOST")
  [[ "$DEBUG" == true ]] && root_args+=(--debug)
  [[ "$DRY_RUN" == true ]] && root_args+=(--dry-run)
  log "Checking Let's Encrypt root and intermediate CA trust."
  bash "${SCRIPT_DIR}/check-letsencrypt-root.sh" "${root_args[@]}"

  # Prevent duplicate system-certificate imports.
  # CA trust reconciliation has already completed above.
  if [[ -n "$existing_id" ]]; then
      log "Exact certificate already exists on ${host} (ID ${existing_id})."
      log "Skipping system-certificate import; no changes required."
      ((node_index+=1))
      continue
  fi

  # Encrypt key for ISE API. OpenSSL output and passphrase never enter debug logs.
  encrypted_key="$(new_tmp)"
  umask 077
  openssl pkcs8 -topk8 -in "$privkey" -out "$encrypted_key" -passout fd:3 3<<<"$PRIVATE_KEY_PASS" >/dev/null 2>&1
  chmod 600 "$encrypted_key"

  payload="$(new_tmp)"
  friendly="${FRIENDLY_NAME_PREFIX} ${host} $(date '+%Y-%m-%d %H:%M:%S')"
  ISE_IMPORT_PASSWORD="$PRIVATE_KEY_PASS" jq -n \
    --arg name "$friendly" \
    --rawfile data "$leaf" \
    --rawfile privateKeyData "$encrypted_key" \
    --arg portalGroupTag "$PORTAL_GROUP_TAG" \
    --argjson admin "$ENABLE_ADMIN_ROLE" \
    --argjson eap "$ENABLE_EAP_ROLE" \
    --argjson radius "$ENABLE_RADIUS_ROLE" \
    --argjson tacacs "$ENABLE_TACACS_ROLE" \
    --argjson pxgrid "$ENABLE_PXGRID_ROLE" \
    --argjson ims "$ENABLE_IMS_ROLE" \
    --argjson portal "$ENABLE_PORTAL_ROLE" \
    --argjson replace "$ALLOW_REPLACEMENT_OF_CERTIFICATES" \
    --argjson replacePortal "$ALLOW_REPLACEMENT_OF_PORTAL_GROUP_TAG" \
    --argjson roleTransfer "$ALLOW_ROLE_TRANSFER_FOR_SAME_SUBJECT" \
    --argjson portalTransfer "$ALLOW_PORTAL_TAG_TRANSFER_FOR_SAME_SUBJECT" \
    '{
      name:$name, password:env.ISE_IMPORT_PASSWORD, data:$data, privateKeyData:$privateKeyData,
      allowOutOfDateCert:false, allowSHA1Certificates:false,
      allowExtendedValidity:false, allowReplacementOfCertificates:$replace,
      allowReplacementOfPortalGroupTag:$replacePortal,
      allowRoleTransferForSameSubject:$roleTransfer,
      allowPortalTagTransferForSameSubject:$portalTransfer,
      allowWildCardCertificates:false, validateCertificateExtensions:false,
      admin:$admin, eap:$eap, radius:$radius, tacacs:$tacacs,
      pxgrid:$pxgrid, ims:$ims, saml:false, portal:$portal,
      portalGroupTag:$portalGroupTag
    }' > "$payload"
  jq -e . "$payload" >/dev/null
  dbg "Import payload generated; bytes=$(wc -c < "$payload" | tr -d ' '); sensitive fields redacted."
  dbg "Role assignments: admin=${ENABLE_ADMIN_ROLE}, eap=${ENABLE_EAP_ROLE}, radius=${ENABLE_RADIUS_ROLE}, tacacs=${ENABLE_TACACS_ROLE}, pxgrid=${ENABLE_PXGRID_ROLE}, ims=${ENABLE_IMS_ROLE}, portal=${ENABLE_PORTAL_ROLE}, saml=false."

  #  Read-only preflight: retrieve current node certificates and detect exact duplicate.
  if [[ "$DRY_RUN" == true ]]; then
    log "(dry-run) Would POST system certificate to https://${host}/api/v1/certs/system-certificate/import."
    log "(dry-run) Payload validation passed; no POST/PUT/DELETE requests were sent."
  else
    response="$(api_request "$host" POST "https://${host}/api/v1/certs/system-certificate/import" "$payload")"
    api_status="$(jq -r '.response.status // empty' "$response")"
    api_message="$(jq -r '.response.message // empty' "$response")"
    api_id="$(jq -r '.response.id // empty' "$response")"
    if [[ -n "$api_status" && "${api_status,,}" != "success" ]]; then
      err "ISE did not confirm system certificate import: ${api_message:-unknown error}"
      exit 1
    fi
    log "System certificate import accepted on ${host}; ID=${api_id:-not returned}; message=${api_message:-not returned}"

    # Verify the new fingerprint is visible after import.
    verify_list="$(api_request "$host" GET "https://${host}/api/v1/certs/system-certificate/${host}")"
    jq -e --arg fp "$leaf_fp" '.response[]? | select(((.sha256Fingerprint // "")|gsub(":";"")|ascii_upcase)==$fp)' "$verify_list" >/dev/null || {
      err "Import API returned success but the certificate fingerprint is not visible in the system-certificate list."
      exit 1
    }
    log "Post-import verification passed for ${host}."
  fi
  ((node_index+=1))
done

log "Completed processing ${node_index} ISE node(s)."
[[ "$DRY_RUN" == true ]] && log "Dry-run finished: no certificate changes were made."
