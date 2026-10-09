# Detection: why VirusTotal says "safe" on a phishing site

## Your observation is correct, and it is not a bug — it is the design

Aap ne VirusTotal par ek shakkī URL check ki aur us ne "theek" kaha. Ye VirusTotal
ki galti nahi hai. **Ye us tool ka bunyadi design hai** — aur isi mein HAAFIZ ki
sab se bari jeet chupi hai.

### VirusTotal ek detector nahi, ek *aggregator* hai

VirusTotal khud koi threat database nahi rakhta. Wo aap ka URL **70+ third-party
engines** ko bhejta hai aur har engine ka alag alag natija dikha deta hai —
`3/94 malicious`. Wo ye **decide hi nahi karta** ke site safe hai ya nahi; faisla
aap par chor deta hai.

Aur wo 70+ engines khud kya karte hain? **Zyadatar sirf blocklists check karte
hain.** Yaani VirusTotal dar-asal *"kya 94 logon ne is URL ko pehle dekha aur
report kiya?"* ka jawab deta hai.

> **`0/94` ka matlab "safe" nahi hota.**
> Iska matlab hota hai: **"abhi tak kisi ne report nahi ki."**

Nayi phishing site — jo aaj subah bani ho — kisi bhi blocklist par nahi hoti.
Is liye wo **0/94 clean** dikhti hai. Aur user samajh leta hai ke sab theek hai.

Ye *false negative* hai, aur phishing mein ye sab se khatarnak ghalti hai, kyunki
user ko ghalat tasalli mil jati hai.

### Ye problem sirf VirusTotal ki nahi — har list-based tool ki hai

| Tool | Model | Zero-hour phishing par |
|---|---|---|
| **VirusTotal** | 70+ engines ka aggregate | ❌ Naya domain kisi list par nahi |
| **Google Safe Browsing** | Apni blocklist, 5B devices | ❌ **15–30 minute ka delay** |
| **PhishTank** (Cisco Talos) | Community submissions + votes | ❌ Validation ka intezaar |
| **URLhaus** (abuse.ch) | Community, real-time | ❌ **Sirf malware, phishing nahi** |
| **OpenPhish** | Credential-phishing feed | ⚠️ Feed tak jo pohancha |
| **ScamAdviser** | 40+ sources ka trust score | ⚠️ Valid SSL + clean hosting = acha score |
| **urlscan.io** | Sandbox mein page load karta hai | ✅ Naya infrastructure pakarta hai |

Academic literature isi ko bar-bar confirm karti hai:

> *"Anti-phishing solutions like blacklist or whitelist, heuristic, and visual
> similarity based methods **cannot detect zero-hour phishing attacks or
> brand-new websites**."*
> — Modeling Hybrid Feature-Based Phishing Websites Detection (PMC, 2022)

> *"Blacklist/whitelist techniques are the traditional way to alleviate such
> threats. However, these methods **fail to detect non-blacklisted phishing
> websites (i.e., 0-day attacks)**."*
> — Nature Scientific Reports (2022)

> *"Visual similarity techniques cannot identify the fresh phishing websites and
> generate a **high false-negative rate**."*

Aur phishing sites **zinda hi kitni der rehti hain?** Research ke mutabiq
"phishing websites only take a few hours" — compromised servers par host sites
ek din se zyada purani hoti hain, magar aam phishing pages **chand ghante** mein
ban kar, loot kar, aur band ho jate hain.

> **Natija:** blocklist ka update cycle (15 min se kai ghante) phishing site ki
> **poori zindagi** se lamba ho sakta hai. Tool hamesha *peeche* rahega.

### Doosri wajah: rate limits aur qeemat

VirusTotal ka free API production ke liye usable hi nahi hai:

| | Free | Paid |
|---|---|---|
| Requests | **4/minute, 500/day** | 1,000+/min |
| Qeemat | Free | **$75,000/saal** (Standard), **$1.1M/saal** (Enterprise+) |

Ek national service jo rozana laakhon checks kare, wo 4 requests/minute par nahi
chal sakti. Aur $75,000/saal ek free public-good project ke liye mumkin nahi.

**Is liye HAAFIZ ka VirusTotal par inhasar karna architecturally ghalat hoga** —
na accuracy ki wajah se, na scale ki wajah se.

---

## HAAFIZ ka jawab: do layers

Blocklists zaroori hain — magar **kafi nahi**. Is liye HAAFIZ do alag layers
chalata hai:

```
Layer 1 — REACTIVE  (jo duniya jaan chuki hai)
  Google Safe Browsing · PhishTank · OpenPhish · URLhaus · apni crowdsourced registry
        ↓
  Koi bhi ek hit → foran verdict. Tez, muft, authoritative.

Layer 2 — PROACTIVE  (jo abhi kisi ne nahi dekha)     ← yahan asli farq hai
  Certificate Transparency logs · URL/HTML heuristics · ML model
  visual/brand similarity · domain age · infrastructure fingerprinting
        ↓
  Wo phishing site pakarta hai jo 20 minute pehle bani hai.
```

### Layer 1: Federated intelligence — ek source nahi, chaar

Research ka natija saaf hai:

> **"Combining 4 databases reduces false negatives by 15–30% compared to a
> single source."**

Aur ek misaal jo bilkul aap ka tajurba hai:

| Source | 10-minute purani phishing URL par |
|---|---|
| Google Safe Browsing | "not yet listed" |
| URLhaus | "no malware distributed" (ye phishing hai, malware nahi) |
| PhishTank | "reported but not yet validated" |
| VirusTotal | "4/70 engines flag it" |

> **Ek source se: 4 mein se 3 dafa threat miss ho jata.**
> **Chaaron se: VirusTotal ke 4 engines + PhishTank ka pending report mil kar
> "suspicious" alert bana dete hain.**

Is liye HAAFIZ chaaron ko **parallel** query karta hai aur natije ko apne
noisy-OR scoring engine (`ai-service/haafiz/scoring/engine.py`) se combine karta hai — bilkul
wahi principle jo modules par lagaya gaya: **ek strong signal doosron ki khamoshi
se dhulna nahi chahiye.**

Cost profile — tamam free tiers, aur ye production mein chale sakte hain:

| Source | Free tier | Quota | Note |
|---|---|---|---|
| Google Safe Browsing | ✅ non-commercial free | reasonable | Binary verdict. Commercial ke liye Web Risk API |
| PhishTank | ✅ free API key | **10,000 queries/day** | Cisco Talos chalata hai |
| OpenPhish | ✅ free feed | unlimited (bulk) | Community feed, low false positives |
| URLhaus | ✅ free, **no auth, no quota** | unlimited | Sirf malware — phishing ke liye nahi |
| Apni registry | ✅ | unlimited | **Ye asli moat hai** |

URLhaus aur OpenPhish ko **bulk feed** ki tarah local cache mein rakha ja sakta
hai — har check par API call ki zaroorat nahi. Is se latency aur quota dono ka
masla hal ho jata hai.

### Layer 2: Certificate Transparency — phishing ko *ban'te hue* pakarna

**Ye research ki sab se qeemti discovery hai.**

Har publicly-trusted TLS certificate ek **append-only public CT log** mein darj
hona zaroori hai — **seconds se minutes** ke andar. Modern browsers CT-logged
certificates hi trust karte hain.

Ab sochiye: phishing site ko **HTTPS chahiye**, warna browser "Not Secure" dikha
kar user ko darwa dega. Aur phishers **Let's Encrypt** istemal karte hain kyunki
wo free aur automated hai — aur Let's Encrypt har certificate multiple CT logs
mein submit karta hai.

> **Matlab: attacker jab `hbl-secure-login.com` ka certificate mangta hai, wo
> entry CT log mein aa jati hai — aksar phishing page live hone se kai ghante
> PEHLE.**

Ye detection ko **reactive se proactive** bana deta hai. Aap ka blocklist us URL
ko kabhi nahi janta, kyunki us par **abhi tak koi hamla hua hi nahi**.

**Asli natija:**
> *"A major bank implemented CT monitoring and detected **127 phishing domains
> in the first month**, taking down **89% of them before they received their
> first victim**."*

**Free tools jo ye karte hain:**
- **CertStream** — sab CT logs ka real-time WebSocket feed, free, open-source
- **crt.sh** — manual queries: `https://crt.sh/?q=%25hbl%25`
- **DNSTwist** — domain permutations generate karta hai
- **phishing_catcher** — CertStream domains ko keyword/entropy par score karta hai
- **ctCertWatch** (Go) — ~30–50 MB memory, webhook alerts

**HAAFIZ ke liye iska matlab:** Pakistani brands ki ek list — HBL, UBL, Meezan,
JazzCash, Easypaisa, NADRA, FIA, SBP, Jazz, Telenor, Zong, Ufone, Daraz, OLX,
Naya Pakistan Certificate — par CT log monitor karo. Jab bhi in se milta julta
naya domain certificate le, **pehle hi user ko bacha lo.**

#### CT detection ke paanch tareeqay

| Technique | Misal | Kaise pakdein |
|---|---|---|
| **Typosquatting** | `hbl.com.pk` → `hbl-com.pk`, `hblc0m.pk` | Levenshtein distance 1–2 |
| **Homoglyph / IDN** | Cyrillic `а` se `аpple.com` → `xn--80ak6aa92e.com` | Punycode decode + Unicode normalize |
| **Keyword stuffing** | `secure-hbl-login.com`, `verify-jazzcash.com` | Brand + {login, verify, secure, account, reset, update, confirm} |
| **Subdomain abuse** | `hbl-login.attacker.com` | Brand ko *kahin bhi* match karein, sirf registrable part mein nahi |
| **TLD variation** | `hbl.co`, `hbl.com.pk.evil.tld` | Brand ko tamam TLDs par |

#### CT ki limitations (imaan dari se)

- **Firehose hai** — rozana **tens of millions** certificates. Brand filtering ke
  baghair signal bekaar hai.
- **Noise** — resellers, partners, researchers, fan sites bhi brand name use karte
  hain. Is liye *ek* match par alert nahi; **multiple signals stack** karein
  (domain similarity + cert validity + issuing CA + registration age + hosting +
  login form presence).
- **Wildcard certs** — `*.hbl-portal.com` ka ek hi CT entry hota hai; per-subdomain
  phishing pages naye entries nahi banate.
- **Bina HTTPS phishing** CT mein nahi aati (magar ab ye nadir hai).
- **crt.sh manual queries production ke liye nahi** — wo investigation tool hai,
  alerting system nahi. Continuous polling chahiye.

**High-risk pattern jo sab se kaam ka hai:**
> Typosquatted domain + DV certificate + validity < 30 days + unusual CA
> + newly registered + hosts a login form
> = **near-certain phishing**

---

## Layer 2 ka doosra hissa: page ko *padhna*, sirf list se milana nahi

Blocklist ye poochta hai *"kya koi is URL ko janta hai?"*
HAAFIZ ye poochta hai *"ye URL aur ye page khud kya keh rahe hain?"*

Research mein ye features bar-bar sab se effective nikle:

### URL lexical features (client-side, koi third party nahi)
- Domain length, entropy, character distribution
- Hyphens, digits, `@` symbol, IP address in the host
- Subdomain depth
- Suspicious TLDs (`.top`, `.xyz`, `.click`, `.loan`, `.win`, `.tk`, `.ml`, `.ga`)
- Brand-name position: `hbl.attacker.com` vs `attacker.com/hbl`
- URL shorteners aur `data:` URLs (research note: models yahan fail hote hain —
  is liye inhein pehle resolve karna zaroori hai)

### Domain / infrastructure
- **Domain age** (WHOIS/RDAP) — phishers fresh domains banate hain
- Registrar reputation; privacy-protected registration
- Certificate: issuer, validity length, DV vs EV, single-domain vs wildcard
- Hosting ASN — disposable/bulletproof hosting
- Nameserver patterns

### Page content
- **Login/credential form** ki maujoodgi — sab se strong single signal
- OTP / CNIC / password / card-number input fields
- Brand logos aur trademarks ka istemal
- Character-level TF-IDF on HTML "noisy parts" + plaintext (Nature 2022 —
  XGBoost, **2–3 second execution**, real-time capable)
- Hyperlink analysis: kitne links bahar jaate hain, kahan
- Obfuscated JavaScript (`eval(`, `document.write`)
- Right-click disabled, popups for passwords

### Performance jo literature report karti hai

| Approach | Accuracy | Third-party par inhasar | Zero-hour |
|---|---|---|---|
| URL+hyperlink hybrid features (ML) | **99.17%** | ❌ none | ✅ |
| URL+HTML XGBoost (Nature 2022) | high, **2–3s** | ❌ none | ✅ |
| TF-IDF + Random Forest | 97.5% | ❌ | ✅ |
| DistilBERT + SVM | 98.07% | ❌ | ✅ |
| CNN-BiGRU hybrid | 99.82% | ❌ | ✅ |
| Random Forest on 50k URLs | 92.3% (AUC 0.95) | ❌ | ✅ |

> **Ahem:** jitne behtar models hain, wo **third-party services par inhasar nahi
> karte**. WHOIS aur search-engine lookups latency barhate hain. Is liye HAAFIZ ka
> ML model **URL lexical features** par chalna chahiye (instant, offline-capable),
> aur WHOIS/SSL/crawl ko **optional enrichment** ki tarah async mein chalana
> chahiye.

### Explainability — aur ye HAAFIZ ke liye zaroori hai

2025 ki research **SHAP** (Shapley Additive Explanations) ko phishing detection
mein la rahi hai, aur review papers **Explainable AI (XAI)** ko "industrial
security deployments ke liye emerging necessity" kehte hain.

HAAFIZ ke liye ye sirf academic nahi:

1. **User ko samjhana** — "0/94" kuch nahi batata. *"Ye domain 3 din purana hai,
   naam HBL se milta julta hai, aur page par OTP field hai"* — ye batata hai.
2. **Court mein sabit karna** — 0.04% conviction rate ka ek sabab evidence quality
   hai. Logged feature trace ek calibrated score se kahin behtar saboot hai.
3. **Ghalti sudharna** — jab user "Galat" dabaye, humein pata hona chahiye ke
   *kaunsa feature* ghalat tha.

`ai-service/haafiz/scoring/engine.py` already har module ka contribution return karta hai
(`contributing_modules`) — yehi explainability ki buniyaad hai.

---

## Threat intelligence ka architecture

```
                    ┌──────────────────────────────┐
                    │   INBOUND: URL / SMS / image │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │ 0. URL EXPANSION             │  ← shorteners, redirects,
                    │    (pehle, warna models fail)│    data: URLs resolve
                    └───────────────┬──────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │ LAYER 1: REACTIVE       │ LAYER 2: PROACTIVE      │
          │ (parallel, cached)      │ (client-side, instant)  │
          ├─────────────────────────┼─────────────────────────┤
          │ Google Safe Browsing    │ URL lexical ML model    │
          │ PhishTank               │ Brand similarity        │
          │ OpenPhish (local feed)  │  (Levenshtein/homoglyph)│
          │ URLhaus (local feed)    │ Domain age + cert       │
          │ Apni crowdsourced       │ CT log pre-computed     │
          │   registry              │   suspicious-domain set │
          └─────────────────────────┼─────────────────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │ 3. DEEP INSPECTION           │  ← sirf agar abhi tak
                    │    (async, expensive)        │    faisla na ho saka:
                    │    Playwright render, OCR,   │    WHOIS, SSL, crawl
                    │    form detection            │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │ 4. NOISY-OR ENSEMBLE         │
                    │    + hard overrides          │
                    │    + trust discount          │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │ 5. VERDICT + EXPLANATION     │
                    │    (7 languages, spoken form)│
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │ 6. FEEDBACK → REGISTRY       │  ← har "Galat" tap
                    │    + model retraining        │    ek free label hai
                    └──────────────────────────────┘
```

**Step 0 sab se aham hai aur sab se zyada nazar-andaz hota hai.** Research note
karti hai ke models "may fail to detect the phishing URLs which use shortening
URLs and data URL services." Ek `bit.ly` link ya `data:text/html` URL bina
resolve kiye kisi bhi analyzer ka kaam nahi — domain hi nahi dikhta.

**Step 3 ko conditional rakhna zaroori hai.** Playwright render + WHOIS + SSL
several seconds lete hain. Agar Layer 1 ya 2 ne pehle hi confident verdict de
diya (jaise Google Safe Browsing ka confirmed hit, ya apni registry ka known
scam number), to deep inspection **skip** karein. Ye wahi principle hai jo
existing `website_analyzer.py` mein `url_risk < 80` ke saath pehle se maujood
hai — bas usay formalize karna hai.

**Step 6 asli moat hai.** Google ke paas 5 billion devices hain. HAAFIZ ke paas
wo nahi — magar HAAFIZ ke paas kuch aisa hai jo unke paas nahi:
**Urdu, Roman Urdu, Sindhi, Pashto, Punjabi aur Balochi mein scam messages ka
corpus, aur Pakistani phone numbers ki reputation.** CT logs aur Safe Browsing
duniya bhar ke liye hain; **JazzCash impersonation karne wala 0300 number
sirf HAAFIZ janta hoga.**

> Ye network effect hai: jitne log check karte hain, detection utni behtar;
> jitni detection behtar, utne zyada log. **Copy karna namumkin.**

---

## Jo ban chuka hai, aur jo baaki hai

### ✅ Built

**`ai-service/haafiz/intel/domain_similarity.py`** — Layer 2 ka core.
Paanchon techniques implement hain (separator substitution, homoglyph/IDN,
keyword stuffing, subdomain abuse, TLD variation) plus Damerau-Levenshtein
typosquatting, `@` userinfo decoys aur IP literals. Poora offline, deterministic,
microseconds mein. `validate_registry()` configuration errors ko *loud* banata
hai, warna wo silent false positives ki shakl mein aate hain.

**`ai-service/haafiz/intel/federation.py`** — Layer 1 ka core. Sources parallel
chalte hain, har ek apne **absolute deadline** ke saath, aur jo jawab na de wo
`applicable=False` ho kar combination se **nikal** jata hai — mean mein ghul kar
verdict ko dilute nahi karta. Ye wahi principle hai jo scoring engine modules par
lagata hai. Offline sources (registry + brand detector) ke saath federation
**bina kisi network ke** verdict de deti hai.

**`ai-service/data/verified_domains.txt`** — **74 institutions, 82 domains**:
banks, wallets, telcos, regulators, marketplaces, news organisations. Purani
`website_analyzer.py` mein sirf **9 domains hardcoded** thay aur ek entry
(`sc.com/pk`) malformed thi.

**Wiring** — `website_analyzer.py` ab SSRF guard ke saath shuru hota hai aur
hardcoded Levenshtein block ki jagah real detector istemal karta hai. Naye
endpoints: `POST /analyze/intel`, `POST /analyze/domain`, `GET /intel/registry`.
`backend/routes/scan.js` ka arithmetic mean noisy-OR se badla gaya.

Measured behaviour: **`secure-hbl-login.com` → 90% malicious** bina kisi
blocklist ke, aur `hblstocks.com` (asli HBL subsidiary) clean rehta hai.

### ⬜ Baaki

1. **Vendor adapters** — `federation.py` ka `CallableSource` interface taiyar
   hai; ab sirf teen adapters chahiye:
   - Google Safe Browsing v4 (free, non-commercial)
   - PhishTank API (10k queries/day free)
   - OpenPhish + URLhaus bulk feeds (`FeedSource` already implemented; loader
     function likhna hai)

2. **`ct_monitor.py`** — CertStream consumer. **Background ingestion honi
   chahiye, real-time check nahi** — CT logs rozana tens of millions
   certificates hain. Natija `suspicious_domains` table mein jaye, aur detector
   usay pre-computed signal ki tarah padhe.

3. **URL feature extractor + trained model** — lexical features (instant,
   offline), shortener/`data:` URL expansion (**Step 0, sab se zyada
   nazar-andaz**), phishy DOM signals. Zenodo Roman Urdu SMS dataset
   (DOI `10.5281/zenodo.21810885`, 1,000 labeled messages) + PhishTank/OpenPhish
   + CT-derived domains. **Template-aware evaluation** zaroori hai — Zenodo
   dataset khud warn karta hai ke "template leakage" se results jhoothay barh
   jate hain.

4. **Official helpline numbers** — registry mein domains hain; numbers bhi
   chahiye, taake "ye number HBL ka nahi hai, asli helpline 111-222-333 hai"
   kaha ja sake. Phone analyzer ke liye bhi zaroori hai.

5. **SHAP explainability** — feature-level trace, taake har verdict ka sabab
   court-grade evidence ban sake. `evidence[]` iski buniyaad already hai.

---

## Sources

**VirusTotal aur blocklist limitations**
- CaptainDNS — *Google Safe Browsing, URLhaus, PhishTank, VirusTotal: how threat
  intelligence databases work* — VirusTotal aggregates 70+ engines, provides no
  binary verdict, free API 4 req/min, premium high cost, frequent false positives;
  Safe Browsing 15–30 min delay; **"combining 4 databases reduces false negatives
  by 15–30%"**; URLhaus covers malware not phishing
- SafeBrowz — *Best scam and phishing detection APIs in 2026, compared* — VirusTotal
  "No (aggregator)" for zero-hour AI, does not name impersonated brand;
  urlscan.io sandbox scanning; IPQualityScore ML zero-day
- DomScan — *urlscan.io vs VirusTotal* — VT free 500 req/day & 4 req/min;
  paid $75,000/yr Standard, $1.1M/yr Enterprise+; urlscan.io $5,000/yr Automate
- Guard.io — *8 Best Website Safety Checker Tools 2026* — PhishTank depends on
  community submissions so new pages absent until reported; ScamAdviser's
  sophisticated phishing with valid SSL gets moderate/high trust scores;
  URLVoid 30+ blocklists
- isMalicious — *Best Threat Intelligence APIs 2026* — URLhaus free with no rate
  limits, STIX/TAXII export; VT ~500/day free
- BrightSEOTools — *5 Free AI Phishing Detection Tools* — PhishTank free API
  **10,000 queries daily**; urlscan.io free tier 50 scans/day; VT free 4 req/min
- Reddit r/cybersecurity — practitioner confirmation: VT free tier limits;
  "pull OpenPhish and PhishTank feeds locally and match against them, no API
  calls needed"

**Zero-hour detection literature**
- PMC (2022) — *Modeling Hybrid Feature-Based Phishing Websites Detection Using ML* —
  blacklist/whitelist/visual-similarity **cannot detect zero-hour attacks**;
  99.17% accuracy with zero third-party dependency
- Nature Scientific Reports (2022) — *An effective detection approach for phishing
  websites using URL and HTML features* — XGBoost, character-level TF-IDF on HTML,
  **2–3 s execution**, client-side only; phishing sites live only hours
- MDPI Future Internet — *Towards Lightweight URL-Based Phishing Detection* —
  denylists "demonstrated inability to protect users from the dynamic nature of
  phishing URLs"; avoids WHOIS latency
- ScienceDirect (2023) — *A systematic literature review on phishing website
  detection techniques* — heuristic approach detects zero-hour attacks;
  Random Forest 99.57%; ensemble models 98.72%
- ScienceDirect (2026) — *Phishing URL Detection in Real-Time* — 50,000 labeled
  URLs, Random Forest 92.3% accuracy, ROC-AUC 0.95
- ResearchGate (2025) — *Phishing Detection Techniques: A review* — anti-phishing
  tools "heavily reliant on pre-existing blacklists, which limits their ability to
  detect zero-day phishing attacks"; **Explainable AI (XAI) an emerging necessity**;
  feature selection critical to prevent overfitting
- Nature Scientific Reports (2025) — *Explainable phishing website detection* —
  SHAP for feature interpretation; 11,000+ URLs, 30 features
- IJCSNS (2025) — Arabic SMS phishing, BiGRU 98.71%; CNN-BiGRU hybrid 99.82%;
  GANs demonstrated to bypass blacklist-based detectors

**Certificate Transparency**
- InventiveHQ — *Detecting Phishing Domains with Certificate Transparency* —
  full monitor→match→alert pipeline; **five impersonation techniques**
  (typosquatting, homoglyph/IDN, keyword stuffing, subdomain abuse, TLD
  variation); **"a major bank detected 127 phishing domains in the first month,
  taking down 89% before they received their first victim"**; high-risk pattern
  = typosquat + DV cert + validity <30 days + unusual CA; noise from partners,
  resellers, researchers, fan sites
- PhishFence — *How to Detect Phishing Using CT Logs* — Let's Encrypt submits
  every certificate to multiple logs; detection "usually several hours before the
  phishing campaign launches"; CT logs are firehoses (tens of millions/day);
  crt.sh is investigation not alerting; **wildcard cert pitfall**; phishing
  without HTTPS is now rare
- Have I Been Squatted — *Phishing domain detection and triage* — a domain in both
  a CT match and an NRD feed within a short window is far more likely phishing;
  **stack signals** (newly registered + brand-confusable + TLS cert + login form)
- ExamCollection — *How to Monitor and Detect Phishing Sites via Certstream* —
  CertStream WebSocket API, `message_type: certificate_update`,
  `leaf_cert.all_domains`; ML features: domain length, character distribution,
  **entropy**, cert metadata, domain age, WHOIS attributes
- GitHub `NDO4ME/ctCertWatch` — Go implementation, all active CT logs, regex
  filtering, DNS + ASN enrichment, webhook alerts, ~30–50 MB memory
- GitHub `PAST2212/certthreat` — full-word match, typosquat, `rn=m` look-alikes,
  IDN/homoglyph detection, WHOIS creation date, false-positive thresholds
- GitHub `sglambert/ct-log-monitor` — open-source CT monitor in Go

**Datasets**
- Zenodo — *Roman Urdu Phishing SMS Dataset for Smishing Detection Research*,
  DOI `10.5281/zenodo.21810885` — 1,000 messages (595 legitimate, 405 phishing),
  template IDs, **template-aware evaluation protocol to prevent template leakage**
- PhishTank (Cisco Talos) — community-verified phishing, free API + daily dump
- OpenPhish — credential phishing intelligence, free feed
- URLhaus (abuse.ch / Bern University) — 2.5M+ malware URLs in 2024, free, no auth
- Kaggle SMS Smishing Collection; ISCX-URL-2016; UCI SMS Spam Collection
