# ise_portal_auto_cert
# Cisco ISE 3.5 Let's Encrypt Certificate Automation

Automated Let's Encrypt certificate management and deployment for Cisco Identity Services Engine (ISE) 3.5, with certificate validation, trust-chain verification, fingerprint checks, and API-driven certificate imports.

> **Important — experimental / lab use only**
>
> This repository describes an independent, sample implementation. It is **not an approved, validated, or officially supported Cisco process** and is **not endorsed, sponsored, or supported by Cisco**. Use it for learning, evaluation, and lab environments only. Do not assume it is suitable for production.
>
> The software is provided **"AS IS"**, without warranty of any kind. The author is not responsible or liable for any damage, outage, data loss, security issue, misconfiguration, or other consequence arising from the use of this script. You are responsible for reviewing the code, testing it, validating compatibility, and determining whether its use is appropriate for your environment.

## Prerequisites

- A lab Cisco ISE 3.5 deployment with API access enabled and an administrator account.
- A DNS domain managed by Cloudflare.
- Ubuntu with `snapd`.
- A Cloudflare API token with the permissions required to update DNS records for the relevant zone.
- A certificate hostname that resolves to the intended ISE node.

Commands below use `sysadmin` as the example Linux account. Adjust paths and values for your environment.

## 1. Install Certbot and the Cloudflare DNS plugin

```bash
sudo apt update
sudo apt install -y snapd

sudo snap install core
sudo snap refresh core

sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/local/bin/certbot

sudo snap install certbot-dns-cloudflare
sudo snap set certbot trust-plugin-with-root=ok
sudo snap connect certbot:plugin certbot-dns-cloudflare
```

Create the working directories:

```bash
mkdir -p ~/certbotconf/config
mkdir -p ~/certbotconf/work
mkdir -p ~/certbotconf/logs
mkdir -p ~/.secrets
```

## 2. Configure Cloudflare credentials

Create the credentials file:

```bash
nano ~/.secrets/.cloudflare.ini
```

Add your own Cloudflare API token:

```ini
dns_cloudflare_api_token = YOUR_CLOUDFLARE_API_TOKEN
```

Protect the credentials file:

```bash
chmod 600 ~/.secrets/.cloudflare.ini
```

**Never commit this file or publish your API token.** Use a token with the minimum permissions required for the DNS challenge.

## 3. Request the Let's Encrypt certificate

The following example requests a certificate for `ise.cisconian.net`. Replace the email address and hostname with values for your lab.

```bash
certbot certonly \
  --config-dir ~/certbotconf/config \
  --work-dir ~/certbotconf/work \
  --logs-dir ~/certbotconf/logs \
  --email email@domain.com \
  --agree-tos \
  --no-eff-email \
  --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/.cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 \
  -d ise.cisconian.net
```

After successful issuance, the certificate lineage should be available under:

```text
~/certbotconf/config/live/ise.cisconian.net/
```

Confirm the actual lineage path and certificate files on your system before proceeding.

## 4. Clone the repository

```bash
cd ~
git clone https://github.com/paul-aviles/ise_portal_auto_cert.git
cd ~/ise_portal_auto_cert
```

Review the scripts before running them.

## 5. Configure the automation

Edit `config.sh` and update the values for your environment. For this example:

```bash
CERT_DOMAIN="cisconian.net"
CERT_HOST="ise"
BASE_DIR="/home/sysadmin/ise_portal_auto_cert"
NETRC_FILE="/home/sysadmin/.secrets/.netrc"
```

Check the remaining settings in `config.sh`, including the ISE node, certificate roles, and certificate lineage path. Make sure they match your lab and the certificate you issued.

## 6. Configure Cisco ISE API credentials

Create the `.netrc` file:

```bash
nano ~/.secrets/.netrc
```

Example format:

```text
machine ise.cisconian.net
login admin
password YOUR_ISE_ADMIN_PASSWORD
```

Protect the file:

```bash
chmod 600 ~/.secrets/.netrc
```

Use a dedicated lab administrator account where possible. Never commit `.netrc` or include real credentials in screenshots, logs, or support requests.

## 7. Run the script

From the repository directory, execute the main script:

```bash
cd ~/ise_portal_auto_cert
./ise_le_auto_cert.sh
```

If the script in your checked-out repository has a different filename, use that exact filename. Review its options and configuration before execution. Run a dry-run first if the script supports it.

**Caution:** Certificate imports and ISE application of system certificates can affect services and may trigger an ISE restart. Test in a non-production environment and plan for service interruption.

## Example output

The following is an illustrative example of a successful run. Identifiers and fingerprints are example output and may differ in your environment.

```text
sysadmin@cerbot:~/ise_portal_auto_cert$ ./ise_le_auto_cert.sh
[INFO]  Cisco ISE 3.5 Let's Encrypt import starting.
[INFO]  Validating node ise.cisconian.net (lineage /home/sysadmin/certbotconf/config/live/ise.cisconian.net).
[INFO]  OpenSSL chain verification passed against the system CA trust store.
[INFO]  Leaf subject: subject=CN=ise.cisconian.net
[INFO]  Leaf issuer:  issuer=C=US, O=Let's Encrypt, CN=YE2
[INFO]  Leaf SHA256:  BFA53AAB7CF660311A5CCE2C8F0B1ABCE38040F6C9697449793D729A085DDCC9
[INFO]  Certificate/key match and hostname validation passed.
[INFO]  Automatically pinned self-signed ISE HTTPS certificate for ise.cisconian.net; SHA256=BCCEA4C100620FE4B44DC7C45F515A80424B05F543D4E689D3CDC2FD6E48182B.
[INFO]  Certificate fingerprint is not installed on ise.cisconian.net.
[INFO]  Checking Let's Encrypt root and intermediate CA trust.
[INFO]  Downloading ISRG Root X1 from https://letsencrypt.org/certs/isrgrootx1.pem
[INFO]  ISRG Root X1 SHA256=96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6
[INFO]  Trusted CA check: Lets Encrypt ISRG Root X1 Trusted Root Certificate; SHA256=96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6
[INFO]  Imported trusted CA 'Lets Encrypt ISRG Root X1 Trusted Root Certificate' (HTTP success).
[INFO]  Trusted CA check: Lets Encrypt YE2 Intermediate Certificate; SHA256=97658DE8C68DFA98ACE1E5028A63D54A1AAE911B3E21471076C6850CD08CBAB4
[INFO]  CA already exists in ISE (ID d61a68dc-429b-4d24-946d-776839bae4de); checking trust flags.
[INFO]  CA trust settings already match.
[INFO]  Trusted CA check: Lets Encrypt Root YE Intermediate Certificate; SHA256=0FC0901CCA2BAE9E9FDBB02D50D02F1094F7B36672086991B9E897626DC485F0
[INFO]  Imported trusted CA 'Lets Encrypt Root YE Intermediate Certificate' (HTTP success).
[INFO]  Trusted CA check: Lets Encrypt ISRG Root X2 Intermediate Certificate; SHA256=EE5F7ABD6981BB0255632CD8F49283451B4B18844D12040B44EE00F07B8FE2C6
[INFO]  Imported trusted CA 'Lets Encrypt ISRG Root X2 Intermediate Certificate' (HTTP success).
[INFO]  Trusted CA validation complete; intermediate certificates processed=3.
[INFO]  System certificate import accepted on ise.cisconian.net; ID=fa918167-b006-400d-930f-1e73d044d829; message=System certificate was added successfully.The system will now restart
[INFO]  Post-import verification passed for ise.cisconian.net.
[INFO]  Completed processing 1 ISE node(s).
```

## License

This project is licensed under the [MIT License](LICENSE).

Cisco and Cisco Identity Services Engine are trademarks of Cisco Systems, Inc. This independent project is not affiliated with or endorsed by Cisco.
