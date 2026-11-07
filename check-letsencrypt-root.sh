#!/usr/bin/env bash
# Import ISRG Root X1 and every CA intermediate from a Certbot fullchain.
# Safe to run standalone; --dry-run performs GETs only.

# Cisco ISE Let's Encrypt ACME script
# Author:  Paul Aviles
# Created: 10-21-2026
# Version: 0.1.0
# License: MIT 

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/common.sh"

CHAIN_FILE=""
ROOT_URL="https://letsencrypt.org/certs/isrgrootx1.pem"
ROOT_FRIENDLY_NAME="Lets Encrypt ISRG Root X1 Trusted Root Certificate"

usage() { echo "Usage: $0 --chain-file FULLCHAIN.pem [--host ISE-FQDN] [--debug] [--dry-run]"; }

HOST="${ISE_TRUSTSTORE_HOST}"
while (($#)); do
  case "$1" in
    --chain-file) CHAIN_FILE="${2:?missing chain file}"; shift 2 ;;
    --host) HOST="${2:?missing host}"; shift 2 ;;
    --debug) DEBUG=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

need_cmds curl openssl jq awk sed grep cut tr mktemp
[[ -r "$CHAIN_FILE" ]] || { err "Cannot read fullchain: $CHAIN_FILE"; exit 1; }
get_credentials "$HOST"

ROOT_PEM="$(new_tmp)"
log "Downloading ISRG Root X1 from ${ROOT_URL}"
curl -fsS --connect-timeout 15 --max-time 60 -o "$ROOT_PEM" "$ROOT_URL"
openssl x509 -in "$ROOT_PEM" -noout >/dev/null
cert_is_ca "$ROOT_PEM" || { err "Downloaded ISRG Root X1 is not a CA certificate."; exit 1; }
log "ISRG Root X1 SHA256=$(cert_fingerprint "$ROOT_PEM")"
#ensure_ca_trusted "$HOST" "$ROOT_PEM" "$ROOT_FRIENDLY_NAME" "Let's Encrypt ISRG Root X1"
ensure_ca_trusted "$HOST" "$ROOT_PEM" "$ROOT_FRIENDLY_NAME" "Lets Encrypt ISRG Root X1"

mapfile -t CHAIN_CERTS < <(extract_pem_certs "$CHAIN_FILE")
intermediate_count=0
for cert in "${CHAIN_CERTS[@]}"; do
  openssl x509 -in "$cert" -noout >/dev/null
  if cert_is_ca "$cert"; then
    fp="$(cert_fingerprint "$cert")"
    root_fp="$(cert_fingerprint "$ROOT_PEM")"
    [[ "$fp" == "$root_fp" ]] && continue
    cn="$(cert_subject_cn "$cert")"
    [[ -n "$cn" ]] || cn="Let's Encrypt Intermediate"
    safe_cn="$(tr -cd '[:alnum:]. _-' <<<"$cn" | sed 's/[[:space:]]\+/ /g' | cut -c1-80)"
    #ensure_ca_trusted "$HOST" "$cert" "Lets Encrypt ${safe_cn} Intermediate Certificate" "Let's Encrypt intermediate CA ${cn}"
    ensure_ca_trusted "$HOST" "$cert" "Lets Encrypt ${safe_cn} Intermediate Certificate" "Lets Encrypt intermediate CA ${cn}"
    ((intermediate_count+=1))
  fi
done
log "Trusted CA validation complete; intermediate certificates processed=${intermediate_count}."
if [[ "$DRY_RUN" == true ]]; then log "Dry-run complete: no POST/PUT operations were sent."; fi
