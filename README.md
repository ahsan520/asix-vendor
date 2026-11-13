# ASIX vendor tool and license ledger

> **There are now two tools.** This file describes the **command-line tool** (a key file, a ledger file) for offline or emergency use. For everyday work, use the **vendor server** with a web interface, client records, approvals, e-mail and the signing key held in OpenBao: see **README-SERVER.md**. The two use different keys unless you put the same public key in the product; the server's key can never be exported, so the command-line tool needs its own key (add it to the product's `KEYS` under its own `kid`).

For the vendor only. It signs the licenses you send to customers and keeps a record of every license you have ever issued. **Keep this folder in a PRIVATE repository. Never ship it, or its ledger, to a customer.** It is separate from the ASIX product repository on purpose.

## What lives where
| Thing | Where | Rule |
| --- | --- | --- |
| Private signing key `license-private.pem` | **offline**, outside this folder (password manager + encrypted backup) | Never on a server, never in Git. The tool refuses to sign with a key that sits inside this folder. If you lose it you cannot issue licenses any more. |
| Public key | pasted into the ASIX product (`src/licensing/vendor-keys.js`) | Not secret. |
| `ledger.jsonl` | this folder, committed to the private repo | One line per license issued. Append-only and hash-chained: an edited, removed or reordered line is detected. Holds no key and no license text. |
| `issued/` | this folder, committed to the private repo | One file per license (the text you send). A license is a signed public document, not a secret, but keep it private anyway. |

## One-time setup
```
npm install
node license-vendor.js keygen ~/asix-keys asix-2026-1       # keys go OUTSIDE this folder
```
Paste the line it prints into `KEYS` in the product's `src/licensing/vendor-keys.js`, commit that in the product repo, and ship a build. Then check the feature names agree with the product:
```
node license-vendor.js check-features --product /path/to/ash-app-builder
```
Run that after every ASIX release and before issuing a license for a new feature.

## Issue a license (the customer sends you their installation id from Settings, License)
```
# residential, one year
node license-vendor.js sign --key ~/asix-keys/license-private.pem --kid asix-2026-1 \
    --customer "Smith Home" --iid <installation-id> --days 365 --bundle @residential --tenants 1 --retention 365 --note "invoice 1042"

# enterprise, one year
node license-vendor.js sign --key ... --kid ... --customer "Acme Corp" --iid <id> --days 365 --bundle @enterprise --tenants 25 --retention unlimited --note "contract 77"

# a trial: 30 days, no grace period
node license-vendor.js sign --key ... --kid ... --customer "Acme Corp (trial)" --iid <id> --days 30 --bundle @enterprise --grace 0 --note "trial"

# only some features
node license-vendor.js sign --key ... --kid ... --customer "Home plus" --iid <id> --days 365 --features search,detections,alerts,cases
```
It prints the path of the license file in `issued/`. **Send that file** to the customer; they open Settings, License, choose the file (or paste it), press Store license, then Activate. Then commit `ledger.jsonl` and `issued/` to the private repo.

Residential or enterprise is worked out from the features. `--grace` is the days after expiry when everything still works (default 30, 0 to 90). `--iid '*'` makes a license that works on any installation: use it only on purpose.

## Renew
```
node license-vendor.js renew --customer "Acme Corp" --key ... --kid ...
```
Signs the same license again from today for the same term, with the same features, limits and grace; add `--days`, `--bundle`, `--tenants` and so on to change something. If the customer has several installations, say which with `--iid`. The old record stays in the history; the new one replaces it in `list`.

## Keep track
```
node license-vendor.js list                 # each customer's current license, soonest expiry first
node license-vendor.js list --all           # every license ever issued
node license-vendor.js expiring --days 60   # who needs a renewal (also lists the already expired)
node license-vendor.js show acme            # one customer's whole history
node license-vendor.js export --out ledger.csv   # for a spreadsheet; no license text (the CSV is git-ignored)
node license-vendor.js verify-ledger        # detects an edited, removed or reordered line, and a changed or missing license file
```
Habit: run `expiring --days 60` at the start of each month, and `verify-ledger` before you commit.

## Check or inspect a license
```
node license-vendor.js inspect issued/acme-corp-L-20261108-ab12cd.jwt      # what it says (not verified)
node license-vendor.js verify  issued/....jwt --pub ~/asix-keys/license-public.pem   # signature and dates
```

## What the ledger can and cannot tell you
- It tells you what you **issued**: to whom, for which installation, which features, until when, and who issued it.
- It does **not** know what is installed or activated at the customer: that would need the product to report back to you, which ASIX does not do (many customers run on closed networks).
- A signed license **cannot be recalled**, only left to expire. That is why terms are 90 to 365 days. To stop a customer, do not renew.
- If a customer loses the file, send them the one in `issued/` again.

## Back up
The ledger and `issued/` are the only record of what you sold. They are in Git, so a second copy of the private repository (another account or an encrypted drive) is your backup. The private key has its own, separate backup.

## Tests
```
npm test                                              # the tool by itself
ASIX_PRODUCT_REPO=/path/to/ash-app-builder npm test   # also checks the licenses made here are accepted by the product's own license check
```
