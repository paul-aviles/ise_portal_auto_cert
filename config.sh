#!/usr/bin/env bash
# Cisco ISE 3.5 Let's Encrypt automation configuration.
# Keep credentials in NETRC_FILE, not here!

# Cisco ISE Let's Encrypt ACME script
# Author:  Paul Aviles
# Created: 10-21-2026
# Version: 0.1.0
# License: MIT

# Requested supported roles (SAML and NativeIPSec are intentionally excluded).
# Let's Encrypt issues certificates for TLS server authentication; you should not
# expect its standard certificates to include the client-authentication EKU, 
# therefore EAP, PXGRID and IMS are false!

CERT_DOMAIN="cisconian.net"
CERT_HOST="ise"
BASE_DIR="/home/sysadmin/ise_portal_auto_cert"
NETRC_FILE="/home/sysadmin/.secrets/.netrc"

# Each entry is: "node-fqdn|certbot-live-directory"
# For a distributed deployment, add one entry per node and give each node
# a certificate lineage whose SAN covers that node's FQDN.
# If you have a single not, just one entry is required.
ISE_NODES=(
  "ise.cisconian.net|/home/sysadmin/certbotconf/config/live/ise.cisconian.net"
)

# Trusted certificates are deployment-wide. Run trust-store operations
# against the primary PAN (or the standalone node).
ISE_TRUSTSTORE_HOST="ise.cisconian.net"

# Automatically maintained CA bundle for the ISE HTTPS API.
# On first connection, the script copies the OS CA roots into this file and
# adds the currently presented ISE certificate only if it is self-signed and
# its hostname/signature/validity checks pass. This allows the initial
# self-signed -> Let's Encrypt transition without curl -k.
ISE_CA_PEM="${BASE_DIR}/ise-api-ca.pem"
AUTO_CAPTURE_ISE_CERT=true
ISE_SYSTEM_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
ISE_API_PIN_DIR="${BASE_DIR}/ise-api-pins"

PORTAL_GROUP_TAG="Default Portal Certificate Group"
FRIENDLY_NAME_PREFIX="Let's Encrypt"

# Password used only to encrypt the temporary PKCS#8 key payload for ISE.
# Prefer setting ISE_PRIVATE_KEY_PASS in the environment instead.
PRIVATE_KEY_PASS="testing123"

CURL_RETRY_COUNT=2
CURL_CONNECT_TIMEOUT=15
CURL_MAX_TIME=120

# Requested supported roles (SAML, NativeIPSec and IMS intentionally excluded).
# Let's Encrypt issues certificates for TLS server authentication; you should not
# expect its standard certificates to include the client-authentication EKU, 
# therefore EAP, PXGRID and IMS are false!
ENABLE_ADMIN_ROLE=true
ENABLE_EAP_ROLE=false
ENABLE_RADIUS_ROLE=true
ENABLE_TACACS_ROLE=true
ENABLE_PXGRID_ROLE=false
ENABLE_IMS_ROLE=false
ENABLE_PORTAL_ROLE=true

# Safety gates. Admin activation restarts ISE application services.
# Set ALLOW_ADMIN_ROLE_ACTIVATION=true only when the restart or reboot is approved.
ALLOW_ADMIN_ROLE_ACTIVATION=true

# ISE replacement/role assignment controls. These are intentionally
# explicit because assigning EAP/DTLS/TACACS replaces the current assignment.
ALLOW_REPLACEMENT_OF_CERTIFICATES=true
ALLOW_REPLACEMENT_OF_PORTAL_GROUP_TAG=true
ALLOW_ROLE_TRANSFER_FOR_SAME_SUBJECT=true
ALLOW_PORTAL_TAG_TRANSFER_FOR_SAME_SUBJECT=true

# Trusted CA usage flags. The dependencies are enforced by ISE:
# ClientAuth requires IseAuth; CertificateBasedAdminAuth requires both.
TRUST_FOR_ISE_AUTH=true
TRUST_FOR_CLIENT_AUTH=true
TRUST_FOR_CERTIFICATE_BASED_ADMIN_AUTH=true
TRUST_FOR_CISCO_SERVICES_AUTH=false

