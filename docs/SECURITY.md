# Security

## ⚠️ Active incident: leaked credentials in a public repository

**Status: REMEDIATION REQUIRED — action is on the project owner.**

While auditing `github.com/HAAFIZTEAM-AI/haafiz-ai`, two sensitive files were
found **committed to a public GitHub repository**:

| File | Contents | Impact |
|---|---|---|
| `backend/.env` | `JWT_SECRET=haafiz_super_secret_jwt_key_change_me_123456789` | **Critical** — anyone can forge a valid JWT for any user |
| `backend/haafiz.db` | SQLite DB: 1 user (`fazeel@gmail.com`) with a bcrypt password hash, 23 history rows, 2 reports | **High** — offline password cracking + personal data exposure |

Both were tracked despite `.gitignore` listing `.env` and `*.db`.

> **Why .gitignore did not help:** `.gitignore` only prevents *untracked* files
> from being added. A file that is already in the index is committed on every
> change regardless of any ignore pattern. The only fix is
> `git rm --cached <file>`.

### What must be done

**1. Rotate the JWT secret immediately.**

The leaked secret signs every session token. Until it is rotated, anyone who
reads the public repo can mint a valid token for any `userId` and take over any
account.

```bash
openssl rand -hex 64     # use the output as the new JWT_SECRET
```

Rotating invalidates all existing tokens. Users will need to log in again — that
is the correct and intended outcome.

**2. Ask affected users to change their password.**

bcrypt with cost 10 is not trivially reversible, but a user who reused that
password elsewhere (very common) is exposed. Send a forced-reset.

**3. Purge both files from git history.**

Deleting them in a new commit does **not** remove them — they remain in history
and are still readable. Use `git filter-repo`:

```bash
pip install git-filter-repo

git filter-repo --invert-paths \
  --path backend/.env \
  --path frontend/.env \
  --path backend/haafiz.db

# then force-push and tell every collaborator to re-clone
git push --force --all
git push --force --tags
```

**4. Treat the exposed data as compromised permanently.**

Force-pushing does not undo clones, forks, mirrors, GitHub's cached views, or
archive services. Assume the secret and the email address are public forever.
That is why rotation — not deletion — is the actual fix.

**5. Add a secret scanner.**

```yaml
# .github/workflows/secrets.yml — see the CI workflow in this repo
```

---

## Findings fixed in this repository

### 1. SSRF in the website analyzer (Critical)

`ai-service/analyzers/website_analyzer.py` fetched **any** user-supplied URL with
a headless browser and no destination filtering. HAAFIZ is intended to be
deployed on cloud infrastructure, which makes this directly exploitable:

```http
POST /analyze/website
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

POST /analyze/website
{"url": "http://127.0.0.1:3001/api/auth/me"}

POST /analyze/website
{"url": "http://192.168.1.1/admin"}
```

The first returns cloud IAM credentials. The others turn HAAFIZ into an
authenticated proxy into internal networks.

**Fix:** `ai-service/haafiz/core/ssrf.py` — resolves the hostname *before* any
connection and rejects anything that is not publicly routable: loopback,
link-local (incl. `169.254.169.254`), RFC1918, CGNAT (`100.64.0.0/10`, heavily
used by Pakistani ISPs), multicast, reserved, unspecified, IPv4-mapped IPv6,
non-HTTP schemes (`file://`, `gopher://`), and non-web ports.

It also rejects parser-confusion payloads (`https://trusted.com@127.0.0.1/`,
backslash-in-authority, control-character injection) and validates **every**
address returned by DNS, since a dual-stack attacker controls which record the
client picks.

Covered by 30 tests in `ai-service/tests/test_ssrf.py`.

### 2. Unsigned public webhook (Critical)

The WhatsApp channel endpoint must be publicly reachable for Meta to POST to it.
Without signature verification, anyone who finds the URL can forge messages that
HAAFIZ analyzes and that appear to come from real users — enabling fake Family
Shield alerts, analyzer resource exhaustion, poisoning of the crowdsourced
threat registry, and quota exhaustion leading to the number being banned.

**Fix:** `channels/whatsapp/signature.py` verifies `X-Hub-Signature-256` over the
**raw request bytes** using `hmac.compare_digest`. Two details are easy to get
wrong and are handled explicitly:

- Verification must run on raw bytes. Parsing then re-serializing JSON changes
  key order and whitespace, and every valid signature then fails.
- Comparison must be constant-time. A byte-by-byte `==` leaks the digest through
  timing and allows incremental forgery.

Fails **closed**: an unconfigured `WHATSAPP_APP_SECRET` rejects everything rather
than accepting everything.

### 3. Missing JWT secret validation (High)

`backend/routes/auth.js` reads `process.env.JWT_SECRET` with no check. If unset,
`jwt.sign(payload, undefined)` produces tokens signed with the literal string
`"undefined"` — trivially forgeable.

**Fix:** fail at startup with a clear error. A service that cannot authenticate
users must not boot.

### 4. CORS misconfiguration (Medium)

`ai-service/app.py` sets `allow_origins=["*"]` **together with**
`allow_credentials=True`. Per the CORS spec that combination is invalid —
browsers reject wildcard origins on credentialed requests — so it either fails
silently or, in permissive clients, allows any origin to make credentialed calls.

**Fix:** explicit origin allowlist from `AI_CORS_ORIGINS`, credentials only with
named origins.

### 5. Webhook replay / amplification (Medium)

Meta retries webhooks that are not acknowledged quickly. Without idempotency, a
single forwarded voice note can be transcribed by Whisper three times — the most
expensive operation in the system — and the user receives three identical
verdicts.

**Fix:** `channels/whatsapp/dedupe.py` — thread-safe, TTL-bounded (10 min),
LRU-capped (50k entries) dedup on Meta's `wamid`. Bounded because an unbounded
dict on a public endpoint is a memory-exhaustion DoS. Verified under 8-way
concurrency that exactly one worker processes a given message.

### 6. Unbounded media upload (Medium)

WhatsApp allows media up to 100 MB. Feeding that to Whisper or OCR is a
denial-of-service vector.

**Fix:** 5 MB cap at a single choke point (`encode_media_base64`), rather than
duplicated checks at each call site.

### 7. Silent error swallowing (Medium)

Bare `except:` in `voice_analyzer.py` and `website_analyzer.py`, and
`except Exception: pass` in `phone_analyzer.py`, discarded every failure
including configuration errors. A broken deployment reported "no scam detected"
instead of failing.

**Fix:** specific exception types, structured logging, and — on the user-facing
channel — a fallback reply that tells the user the check failed and points them
to PTA 9000 / NCCIA 1930. **Silence is the worst outcome**: a user who forwards
a message and gets nothing concludes the service is broken and never returns.

### 8. Fake metrics presented as analysis (Medium — trust)

`analyzers/voice_analyzer.py` returned hardcoded `"authority": 50, "panic": 30`.
These are fabricated constants displayed to users as measurements.

Trust is the product. One discovered fake metric discredits every real one.
Either compute them (speech rate, pitch variance, pause and interruption
patterns) or remove them.

### 9. Cross-service database coupling (Low)

`analyzers/phone_analyzer.py` opened the backend's SQLite file directly across a
service boundary, using positional column indexing (`row[3]`, `row[4]`) that
breaks silently on any schema change.

**Fix:** phone reputation must be reached over the backend's HTTP API, with named
fields. This also makes the services independently deployable.

### 10. Unauthenticated quick-scan endpoint (Low)

`POST /api/scan/quick-scan` requires no authentication and has a keyword list
short enough to memorize and evade.

---

## Reporting a vulnerability

Please do **not** open a public issue.

Email the maintainers with:

- what you found and how to reproduce it
- whether you accessed any real user data (and if so, stop there — do not
  enumerate further)

We aim to acknowledge within 48 hours.

Researchers who report in good faith will be credited in the release notes if they
wish. HAAFIZ is a public-good project protecting people who are already the most
likely to be defrauded; responsible disclosure is how it stays trustworthy.

---

## Threat model

| Asset | Threat | Mitigation |
|---|---|---|
| User identity | JWT forgery | Secret rotation, startup validation, short expiry |
| Cloud credentials | SSRF → metadata endpoint | Destination filtering before every connect |
| Internal network | SSRF → private ranges | RFC1918/CGNAT/loopback/link-local rejection |
| Webhook integrity | Forged messages | HMAC-SHA256 over raw bytes, constant-time compare |
| Availability | Retry amplification, huge media | Idempotency, media size cap, bounded dedupe memory |
| Trust | Fake metrics, silent failure | Remove fabricated values, always reply to the user |
| Family Shield | Alert injection | Signed webhook, internal API token between services |
| User data | Committed database | `.env`/`*.db` untracked, secret scanning in CI |

---

## Security review checklist for contributors

Before opening a PR that touches networking, auth, or user data:

- [ ] Does any code path fetch a user-supplied URL? → route it through `assert_public_url`
- [ ] Is any new endpoint public? → does it verify its caller?
- [ ] Does anything read `process.env` / `os.getenv` for a secret? → is a missing value a hard failure?
- [ ] Can a failure be silent? → does the user still get told something happened?
- [ ] Is any number shown to the user actually computed?
- [ ] Is any new dict, list, or cache unbounded on a public input?
- [ ] Do new tests cover the *attack* case, not only the happy path?
