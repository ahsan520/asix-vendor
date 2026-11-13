# ASIX vendor server

A small web application for the vendor only: **create clients, generate licenses, get a second person's approval, e-mail them to the client, and get renewal reminders**, with a tamper-evident audit log. The license **signing key is held by OpenBao** (open source, MPL-2.0; HashiCorp Vault answers the same API) and **never leaves it**: this server asks OpenBao to sign and gets a signature back. Keep this folder in a **private** repository and never ship it to a customer. It is separate from the ASIX product.

```
 staff browser --HTTPS--> reverse proxy --> vendor server (this app, SQLite) --> OpenBao (transit, Ed25519 key, not exportable)
                                                  |                                  signs; the key stays inside
                                                  +--> your SMTP server (license e-mail, reminders)
```

## What it gives you
- **Clients and installations:** a client has contacts (who gets licenses, who gets renewal reminders) and one or more installations (the installation id from their License page).
- **Generate:** pick the installation, a template (Residential 1 year, Enterprise 1 year, Trial 30 days with no grace, or a custom list of features), the term, tenants, retention and grace; press Generate. Every license is checked against the signing key's public key before it is kept.
- **Approval (second person):** with the default policy, an **enterprise license, a term over 400 days, or an any-installation license waits for someone else to approve**; the person who asked can never approve their own. The policy is `approval` in the configuration: `none`, `enterprise` (default) or `all`.
- **E-mail:** send the license as an attachment with install instructions (templates you can edit), resend, and see what was sent. Plain text only.
- **Renewals:** the Renewals page lists what expires soon; one click renews with the same features and limits. Optional reminder e-mails to each client's renewal contacts at 60, 30 and 7 days (switch on in Settings).
- **Audit log:** every sign-in, change, request, approval, signing and e-mail, each row chained to the one before it. It never holds a password, an authenticator secret or the license text.
- **People:** roles `viewer` (look), `issuer` (clients, requests, send, renew), `approver` (approve or reject, read the audit log) and `admin` (everything, users, settings). Everyone signs in with a password (12+ characters) **and an authenticator-app code**; five wrong tries lock an account for 15 minutes.
- **The ledger CLI (`license-vendor.js`)** still exists for offline or emergency use with a key file; see `README.md`. It keeps its own separate ledger.

## Setup, once

### 1. OpenBao (the key)
Install OpenBao on a small machine of its own (or at least under its own user), reachable only from the vendor server. See `deploy/openbao/openbao.hcl.example`.
```
bao operator init -key-shares=5 -key-threshold=3      # prints 5 unseal keys and a root token: store each key with a DIFFERENT person or place
bao operator unseal                                   # three times, with three different keys; again after every restart
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=<root token> ./deploy/openbao/setup.sh --token-file /etc/asix-vendor/bao.token
```
`setup.sh` enables the transit engine, creates the Ed25519 key **not exportable and with no plain-text backup**, loads a policy that lets the server **only sign and read the public key** (it cannot export, rotate, delete or configure the key), and writes the server's token (mode 600). Then put the root token away: do not use it day to day.

### 2. The vendor server
```
npm install --omit=dev
cp config.example.json /etc/asix-vendor/config.json     # edit: signer, smtp, baseUrl, approval
echo 'your smtp password' > /etc/asix-vendor/smtp.pass && chmod 600 /etc/asix-vendor/smtp.pass
ASIX_VENDOR_CONFIG=/etc/asix-vendor/config.json node server/index.js create-user --username ash --name "Ash" --role admin   # asks for a password; prints the authenticator secret ONCE
node server/index.js signer-info                         # prints the line to paste into the ASIX product
```
Add the printed secret to an authenticator app. Run the server as a service (`deploy/systemd/asix-vendor.service`) and put a TLS reverse proxy (nginx, Caddy) in front; the server listens on 127.0.0.1 and **`cookieSecure` must be `true`** behind TLS. Do not expose it to the internet: put it on a VPN or an allow-listed address.

### 3. Teach the ASIX product the key
Paste the line `signer-info` printed into `KEYS` in the product's `src/licensing/vendor-keys.js` (the `kid` must match `signer.kid`), ship a build, and deploy it. From then on the product accepts licenses this server signs.

## Day to day
1. Client sends their **installation id** (Settings, License in ASIX). Clients, add the client and the installation.
2. On the client page, **Generate license**. If it needs approval, a second person opens **Approvals** and approves.
3. Open the license, **Send by e-mail**. The client stores and activates it on their License page.
4. At renewal time: **Renewals**, open the license, **Renew this license**.

## Looking after the key (read this)
- **The key lives only in OpenBao.** If OpenBao's data and the unseal keys are both lost, the key is gone and you can no longer issue licenses that the deployed products accept. Back up: `bao operator raft snapshot save` regularly (the snapshot is encrypted; keep it away from the unseal keys), and keep the unseal key shares with different people.
- **Recovery plan if the key is lost:** create a new key with a new `kid`, add its public key to `vendor-keys.js` and ship a build, and **keep the old public key in `vendor-keys.js` until the last license signed with it has expired**, so existing customers keep working.
- **Rotation:** `bao write -f transit/keys/asix-license/rotate`. The server signs with the newest version and checks each license against it. Old licenses still verify (the product holds one public key per `kid`; rotate by adding a new `kid` in the product, not by changing the key under the same `kid`, unless every old license has expired).
- **The server's token** is periodic and renews itself while the server runs (at start and every 12 hours). If the server is off for over 32 days, run `setup.sh --token-file` again.
- **A sealed OpenBao** stops issuing (the page says so). Everything else keeps working.

## Security notes
- Passwords are scrypt-hashed; sessions are HttpOnly, SameSite=Strict cookies with a CSRF token on every change; the page sets no HTML from server data and the content policy forbids inline script.
- Every license is verified against the signer's public key before it is stored or sent; a failed or mismatching signature issues nothing.
- The license text is kept in the database (so you can resend) and is only shown through the download or e-mail, never in lists, the audit log or the CSV export. **Back up and protect the data directory** (`vendor.db`): it lists your customers.
- Not built: single sign-on, the AWS KMS adapter (the interface is in `server/signer.js`), per-client portals, payment or ERP hooks.

## What has and has not been tested
Tested (80 tests): the whole server against a real OpenBao 2.4.0 (signing, the shipped policy refusing everything but sign and read, key rotation, the setup script), real SMTP conversations (attachment, headers, refusals), the ASIX product's own license check accepting what this server signs (valid, grace, expired, wrong installation), sign-in, lockout, one-time codes, roles, approval rules, reminders, the audit chain, and nineteen deliberate breaks that each fail a test.
**Not tested:** the pages in a real browser (they are checked by reading the code, not by clicking), a production OpenBao (raft storage, unseal, TLS), a real mail provider, a TLS reverse proxy, more than one staff member at once, and any load.

## Tests
```
npm test                                   # most tests, no OpenBao needed
# with a dev OpenBao (bao server -dev -dev-root-token-id=devroot) and the ASIX product:
ASIX_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 ASIX_TEST_OPENBAO_TOKEN=devroot ASIX_TEST_BAO_BIN=$(which bao) ASIX_PRODUCT_REPO=/path/to/ash-app-builder npm test
```
