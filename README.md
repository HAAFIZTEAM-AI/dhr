# HAAFIZ (حافظ)

**Pakistan ke liye AI scam detection — Urdu, Roman Urdu, Sindhi, Punjabi, Pashto aur Balochi mein.**

Aap koi bhi shakkī message, SMS, link, tasveer ya voice note forward karein. HAAFIZ seconds mein batata hai ke wo scam hai ya nahi — aur **abhi kya karna hai**.

> **Koi app install nahi. Koi account nahi. Koi typing nahi. Bas forward karein.**

---

## Kyun (Why)

Pakistan mein **227,757 logon** ne teen saal mein cyber fraud ki shikayat ki aur **PKR 8.32 arab** khoaye. 2025 mein NCCIA ko **150,542** shikayatein milien — in mein se **81,996** maali dhoka dahi ke maamlaat thay.

Magar in mein se sirf **1,955** cases darj huay aur **32** sazaein huin.

> **Natija:** jo paisay chalay gaye, wo wapas nahi aate. Is liye HAAFIZ *recovery* nahi, **interception** par kaam karta hai — paisay nikalne se *pehle*.

NCCIA khud kehta hai ke hazaron log rozana Rs 2,000–20,000 gawatay hain magar **report nahi karte** kyunki process bohat lamba hai. Agar *shikayat* mein itni rukawat hai to *janch* mein kyun nahi?

**HAAFIZ ka poora design ek hi test par parkha jata hai: kya shikaar ko 10 second se kam waqt lagta hai?**

---

## Design ka usool

Aaj Pakistan mein **81%** log mobile broadband ki coverage mein hain, **68%** ke paas smartphone hai — magar sirf **29%** internet istemal karte hain. Ye **52% ka gap** poore ilaqe mein sab se barha hai, aur wajah hai: *qemat, khwandagi, aur bharosa.*

Sath hi, WhatsApp mulk ka **doosra barha** information source hai (19.9%).

> Matlab: logon ne digital raabta nahi reject kiya. Logon ne **websites, apps, forms aur typing** reject ki hai — aur **chat** qubool ki hai.

Is liye HAAFIZ ek *destination* nahi, ek **contact** hai.

---

## Channels

| # | Channel | Kaun pohanchta hai | Status |
|---|---|---|---|
| 1 | **WhatsApp bot** | ~70M social users — forward karo, jawab pao | 🚧 `channels/whatsapp/` |
| 2 | **Family Shield** | Buzurg, jo apne bachon ke zariye mehfooz hote hain | 🚧 backend mein maujood, extend ho raha hai |
| 3 | **IVR voice helpline** | Feature phones, kam-khwandah, نابینا log | 📋 planned |
| 4 | **SMS short code** | Bina internet wale ilaqay | 📋 planned |
| 5 | **Android app** | On-device, zero-touch protection | 📋 planned |
| 6 | **Web dashboard** | Power users, khandaan, researchers | ✅ maujood |

Poora plan: **[`docs/BLUEPRINT.md`](docs/BLUEPRINT.md)**

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │   USER  (forward karta hai, login nahi) │
                    └───────────────────┬─────────────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬──────────────┐
        │               │               │               │              │
   WhatsApp          Web app           IVR            SMS         Android
   channel/whatsapp  frontend/       (planned)      (planned)    (planned)
        │               │
        └───────┬───────┘
                │
        ┌───────▼────────┐     ┌──────────────────┐
        │  backend/      │────▶│  ai-service/     │
        │  Express+SQLite│     │  FastAPI         │
        │  auth, family, │     │                  │
        │  gamification, │     │  analyzers/      │
        │  history,      │     │   text  website  │
        │  threats       │     │   voice phone    │
        └────────────────┘     │   image          │
                               │                  │
                               │  scoring/engine  │◀── noisy-OR ensemble
                               │  verdict/render  │◀── 7 zubaanein, bolne
                               │  digital_arrest  │       ke liye likha
                               └──────────────────┘
```

### Analyzers

| Analyzer | Kya karta hai |
|---|---|
| `text` | 6 zubaanon ke keyword sets + CNIC/phone patterns + shakkī TLDs |
| `website` | SSRF guard, DNS, WHOIS domain age, SSL, **brand impersonation (74 institutions)**, Playwright crawl |
| `voice` | Whisper transcription → text analysis + tone |
| `phone` | Reputation registry + pattern analysis |
| `image` | OCR (pytesseract) → text analysis |
| **`digital_arrest`** | **نیا** — fake FIA/NCCIA arrest coercion signature |

### Detection: blocklist se aage

VirusTotal par ek shakkī URL daaliye aur wo `0/94 clean` kehta hai. Ye bug nahi,
us ka design hai — VirusTotal detector nahi, **aggregator** hai. Wo 70+ engines
se poochta hai, aur wo engines khud blocklists check karte hain. `0/94` ka matlab
"safe" nahi, **"abhi tak kisi ne report nahi ki"** hota hai. Nayi phishing site
kisi list par hoti hi nahi.

HAAFIZ do layers chalata hai:

```
Layer 1 — REACTIVE   jo duniya jaan chuki hai
  Safe Browsing · PhishTank · OpenPhish · URLhaus · apni registry
  (koi ek source ka timeout verdict ko dilute nahi karta)

Layer 2 — PROACTIVE  jo abhi kisi ne nahi dekha     ← asli farq yahan hai
  brand impersonation · Certificate Transparency · URL heuristics
```

Layer 2 **offline, instant aur zero-quota** hai. Ye paanch techniques chalata hai:

| Technique | Misal | Kaise |
|---|---|---|
| separator substitution | `hbl-com.pk` | normalized form verified registry se collide karta hai |
| homoglyph / IDN | `xn--80ak6aa92e.com` | punycode decode → Cyrillic `аррӏе` → `apple` |
| keyword stuffing | `secure-hbl-login.com` | brand + {login, verify, secure, kyc, otp…} |
| subdomain abuse | `hbl-login.attacker.com` | brand kisi gair-malikaana domain ke neeche |
| TLD variation | `hbl.co` | brand ka bilkul sahi naam, ghalat TLD par |

Natija: **`secure-hbl-login.com` → 90% malicious**, bina kisi blocklist ke,
bina kisi API key ke, milliseconds mein. Aur `hblstocks.com` (asli subsidiary)
clean rehta hai — false positive trust ko miss se zyada todta hai.

Dekhein: [`docs/DETECTION.md`](docs/DETECTION.md) ·
[`ai-service/haafiz/intel/domain_similarity.py`](ai-service/haafiz/intel/domain_similarity.py)

### Scoring: noisy-OR, na ke average

Purana code modules ka **arithmetic mean** leta tha. Ye ghalat hai:

```
Text analyzer 95% yaqeen se kehta hai "ye OTP phishing hai"
Baaki 4 modules ke paas dekhne ko kuch tha hi nahi (0)

PURANA:  (95 + 0 + 0 + 0 + 0) / 5 = 19%  →  "SAFE"  ❌  user paisay kho deta
NAYA:    noisy-OR                      = 95%  →  "CRITICAL"  ✅
```

Khamosh module *safety ka saboot* nahi — wo *saboot ki ghair-maujoodgi* hai.

$$P(\text{scam}) = 1 - \prod_i (1 - w_i \cdot p_i)$$

Dekhein: [`ai-service/haafiz/scoring/engine.py`](ai-service/haafiz/scoring/engine.py)

---

## Quick start

```bash
git clone https://github.com/HAAFIZTEAM-AI/dhr.git haafiz
cd haafiz
cp .env.example .env          # phir JWT_SECRET waghera bharein

docker compose up             # teeno services ek saath
```

Ya manually:

```bash
# 1. AI service (port 5001)
cd ai-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5001
#  ^ `app:app`, NAKE `app.main:app` aur naake koi `app/` directory.
#    ai-service/app.py FastAPI entrypoint hai. Usi folder mein `app/` naam ka
#    package banane se wo shadow ho jata hai -- Python package ko module par
#    tarjeeh deta hai -- aur server import hi nahi hota. Naya code
#    ai-service/haafiz/ mein jata hai.

# 2. Backend (port 3001)
cd backend && npm ci && npm run dev

# 3. Frontend (port 5173)
cd frontend && npm ci && npm run dev

# 4. WhatsApp channel (optional — primary delivery route)
cd channels/whatsapp && uvicorn app:create_app --factory --port 5002
```

**Zaroori:** `JWT_SECRET` generate karein: `openssl rand -hex 64`

---

## Tests

```bash
pip install pytest httpx
pytest
```

**331 tests** — scoring engine, SSRF guard, digital-arrest detector, verdict renderer (7 zubaanein), WhatsApp signature verification, dedupe, inbound parsing, language detection.

---

## Repository layout

```
ai-service/         FastAPI — analyzers, scoring engine, verdict renderer
  app.py              entrypoint  (uvicorn app:app — `app/` dir MAT banaiye)
  haafiz/core/        SSRF guard
  haafiz/intel/       brand impersonation + federated threat intelligence
  haafiz/scoring/     noisy-OR ensemble
  haafiz/verdict/     plain-language rendering, 7 languages
  haafiz/analyzers/   digital_arrest
  analyzers/          text, website, voice, phone, image
  data/               verified_domains.txt — 74 Pakistani institutions
  tests/
backend/            Express + SQLite — auth, family, gamification, history
frontend/           React + Vite + Tailwind — PWA, i18n, Leaflet heatmap
channels/
  whatsapp/         Cloud API webhook — the zero-friction front door
docs/
  DETECTION.md      ← VirusTotal kyun ghalat kehta hai, aur HAAFIZ ka jawab
  PLATFORMS.md      ← laptop / Android / iOS / feature phone: kya mumkin hai
  BLUEPRINT.md      ← poori strategy: research, channels, 90-din ka plan
  SECURITY.md       ← leaked-secret incident aur remediation
  MIGRATION.md      ← 30,151 vendored files kaise hataye gaye
```

---

## Security

⚠️ **Agar aap is repo ka koi purana version chala rahe hain:** us mein `backend/.env` (asli `JWT_SECRET` ke saath) aur `backend/haafiz.db` (ek user ka email aur password hash) ek **public** GitHub repo mein commit thay.

- `JWT_SECRET` foran rotate karein — purane secret se koi bhi **kisi bhi user ka token forge** kar sakta hai
- Tamam users ko password reset karne ka kahein
- `.env` aur `*.db` ko git history se purge karein

Tafseel: **[`docs/SECURITY.md`](docs/SECURITY.md)**

Naye vulnerabilities report karne ke liye bhi wahi file dekhein.

---

## Roadmap

- [x] Repo cleanup — 30,241 files → 88 (1 GB → 550 KB)
- [x] Noisy-OR scoring engine (dilution bug fix)
- [x] SSRF guard on the website analyzer
- [x] Digital-arrest detector
- [x] Plain-language verdict renderer — 7 zubaanein + spoken output
- [x] WhatsApp channel foundation (signature, dedupe, inbound, language)
- [x] Verified institutional registry — 74 banks/telcos/regulators/marketplaces
- [x] Brand-impersonation detector — zero-hour, offline, 5 techniques
- [x] Federated threat intelligence — parallel sources, fail-open combination
- [x] Cross-platform research — [`docs/PLATFORMS.md`](docs/PLATFORMS.md)
- [ ] Vendor adapters: Safe Browsing, PhishTank, OpenPhish, URLhaus feeds
- [ ] Certificate Transparency monitor (phishing ko *ban'te hue* pakarna)
- [ ] Browser extension (Manifest V3) — click se pehle interception
- [ ] Android app — `CallScreeningService` + Share target
- [ ] iOS app — Call Directory + Share Extension + Safari Web Extension
- [ ] WhatsApp channel: live Cloud API integration + closed beta
- [ ] Trained ML model (Zenodo Roman Urdu SMS dataset, DOI `10.5281/zenodo.21810885`)
- [ ] Family Shield: multi-group, severity, acknowledgement
- [ ] Evidence-bundle generator (NCCIA / PTA 9000)
- [ ] IVR voice helpline
- [ ] Cyber Mohalla ambassador programme

---

## License

MIT — see [LICENSE](LICENSE).

Is project ka maqsad ek public good hai. Permissive license is liye chuna gaya ke banks, telcos, universities aur government ise bina rukawat istemal kar saken.

---

## Research aur sources

Poora data with citations:

| Document | Kya cover karta hai |
|---|---|
| [`docs/DETECTION.md`](docs/DETECTION.md#sources) | blocklist limitations, VirusTotal/Safe Browsing/PhishTank/URLhaus, Certificate Transparency, ML literature |
| [`docs/PLATFORMS.md`](docs/PLATFORMS.md#sources) | Apple CallKit/Safari extensions, Android CallScreeningService/NotificationListener/Play policy, MV3 |
| [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md#sources) | Pakistan cybercrime data, PTA/NCCIA channels, GSMA connectivity, IVR studies, competitive gap |

NCCIA / Ministry of Interior parliamentary data · GSMA *Unlocking Pakistan's Digital Potential* · PTA · Kaspersky · Internet Society · LUMS (Mehfil, Polly IVR studies) · Zenodo Roman Urdu phishing corpus · *Nature Scientific Reports* · PMC · MDPI · Apple Developer · Android Developers · Google Play policy

---

<div align="center">

**HAAFIZ** — *paisay nikalne se pehle.*

</div>
