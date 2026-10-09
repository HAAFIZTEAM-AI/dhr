# HAAFIZ — Pakistan's Largest Cyber Defence Programme
### A research-backed blueprint for reaching non-technical Pakistanis at national scale

> **Version** 1.0 · **Date** 2026-10-09 · **Status** Strategy for review
>
> This document answers one question: *how does HAAFIZ go from "a website where you
> paste a suspicious message" to the largest cyber-defence programme Pakistan has ever
> run — for people who will never read a security blog, install an app, or visit a
> dashboard?*

---

## Executive summary (Roman Urdu)

Aap ne bilkul sahi masla pakra hai. **Problem detection ka nahi, *distribution* aur
*friction* ka hai.**

Haqeeqat ye hai:

1. **Jo log sab se zyada lootay ja rahe hain, wo internet par sab se kam hain.**
   Pakistan mein 50+ umar ke sirf **9%** log internet use karte hain — aur scam ka
   sab se bara shikaar wahi log hain. Ek website bana kar hum un tak *kabhi* nahi
   pohanch sakte.

2. **"Paste karo" ek failure hai.** Copy → open browser → paste → wait → samajhna —
   ye 5 steps hain, aur har step par user kho jata hai. NCCIA ke mutabiq hazaron log
   rozana Rs 2,000–20,000 gawatay hain aur **report hi nahi karte** kyunki process
   bohat lamba hai. Agar *reporting* mein itni rukawat hai to *checking* mein kyun nahi?

3. **Raasta khaali hai.** Google Messages ka scam detection sirf US-English hai.
   Trend Micro aur Bitdefender paid English apps hain. India ka FamAI Hindi mein hai.
   WhatsApp ka apna "Scam Alert" (Aug 2026) generic hai, Urdu context nahi janta.
   Aur IFCN ke WhatsApp fact-checker directory mein **Pakistan ka naam hi nahi**.
   **Urdu / Roman Urdu / Sindhi / Pashto / Balochi scam detection par koi qabza nahi.**

4. **Is liye HAAFIZ ko website nahi, *ek number* hona chahiye.** Ek WhatsApp number
   jo sab ko yaad ho. Message aage forward karo — 3 second mein Urdu mein jawab.
   Bas. Koi app nahi, koi login nahi, koi typing nahi.

Is document mein: **4 delivery channels**, **national programme layer** (ambassadors,
Family Shield, government integration), **AI roadmap**, **trust architecture**, aur
**90-din ka execution plan**.

---

## Part 1 — The problem, in hard numbers

### 1.1 The scale of loss

| Metric | Value | Source |
|---|---|---|
| Victims reporting cyber fraud (3 years) | **227,757** | NCCIA records |
| Reported financial loss | **PKR 8.32 billion** | NCCIA records |
| Complaints 2024 / 2025 / 2026 | 83,080 / 76,646 / 68,031 | NCCIA |
| Cybercrime complaints 2025 | **150,542** | Ministry of Interior → National Assembly |
| — of which financial fraud | **81,996** | Ministry of Interior |
| — of which WhatsApp account hacking | **2,974** | Ministry of Interior |
| On-device attacks detected, Jan–Sep 2025 | **5.3 million** (~1M/month) | Kaspersky |
| Banking malware detections | 166,000 | Kaspersky |
| Password stealers stopped | 107,000 | Kaspersky |
| APT groups targeting Pakistan (govt, oil & gas) | **7** | Kaspersky |

### 1.2 The enforcement collapse — this is the real insight

The numbers below explain why **prevention is the only strategy that can possibly work**:

| Year | Complaints | Cases registered | Convictions |
|---|---|---|---|
| 2023 | 134,710 | 1,375 | **92** |
| 2024 | 161,828 | 1,667 | **60** |
| 2025 | 157,465 | 2,256 | **39** |

Across four years NCCIA logged **523,000 complaints** and secured roughly **199
convictions** — a conviction rate near **0.04%**. In 2025, of 150,542 complaints,
**1,955** became cases, **2,445** suspects were arrested, and courts delivered **32
convictions and 122 acquittals**.

> **Strategic consequence:** money that leaves a victim's account is almost never
> coming back. Recovery is not the product. **Interception is the product.** Every
> rupee of value HAAFIZ creates is a rupee that never left.

### 1.3 The invisible majority

NCCIA sources state that beyond the 227,757 who complained, **"thousands of others
are defrauded of amounts ranging from Rs 2,000 to Rs 20,000 every day but do not
report the incidents"** — because the amount feels too small to justify the process.

This is the single most important sentence in this document for product design:

> The people being hurt most often are being hurt in amounts small enough that they
> conclude the system isn't worth their time.

If the *official* government reporting channel loses them at Rs 5,000, a scam-checker
that requires opening a browser and pasting text will lose them at Rs 0. **HAAFIZ's
entire design must be judged by one test: does it cost the victim less than 10 seconds?**

### 1.4 Why the victims can't reach a website

| Reality | Number | Implication |
|---|---|---|
| Mobile broadband **coverage** | **81%** | Infrastructure is not the barrier |
| Smartphone ownership | **68%** | Devices are not the barrier |
| Actually **used** mobile internet | **29%** | ← **52% usage gap, highest in the region** |
| Stated barriers | affordability, **literacy**, **trust** | GSMA, *Unlocking Pakistan's Digital Potential* |
| Internet use, age 50+ | **9%** | The most-targeted cohort is the least online |
| Internet use, age 30–49 | 19% | |
| Internet use, youth | 25% | |
| Primary info source: Facebook | 24.8% | National Trust Survey (n>2,000) |
| Primary info source: **WhatsApp** | **19.9%** | ← This is where Pakistan already is |

**Read those two rows together.** 52% of Pakistanis live under mobile-broadband
coverage and *choose not to use it*, citing literacy and trust. Meanwhile WhatsApp is
the second-largest primary information source in the country.

> The population has not rejected digital communication. It has rejected **websites,
> apps, forms, and typing**. It has embraced **chat**.

That is the whole strategy in one sentence.

---

## Part 2 — Why the current product cannot scale

HAAFIZ v5.0 is technically respectable — five analyzers, six languages, family groups,
gamification, a threat feed, a heatmap. But it is architected as a **destination**:

```
CURRENT FLOW (user must do all of this):
  notice something suspicious
    → remember HAAFIZ exists
    → find a browser
    → navigate to the site
    → create an account
    → verify email
    → log in
    → copy the message
    → paste it into a box
    → wait
    → read a confidence percentage
    → interpret what "68%" means
    → decide what to do

STEPS: 13    ·    LITERACY REQUIRED: yes    ·    TIME: 2–5 minutes
               ABANDONMENT: near-total
```

Every one of those steps is a filter that removes the least technical users — which
is to say, it removes exactly the people the programme exists to protect. The flow is
**anti-targeted**.

Three specific design failures worth naming:

1. **"68% confidence" is not an answer.** A non-technical 62-year-old cannot act on a
   percentage. They need a *verdict* and an *instruction*.
2. **Login is a wall, not a door.** Requiring an account before the first scan means
   the user never experiences value before paying the cost. Value must come first.
3. **The web app assumes the user is alone.** In Pakistan, the person who gets scammed
   and the person who could stop it are usually **two different people** — a father in
   a village and a son in Karachi. (More on this in Part 4.2 — it is the most
   under-used asset already sitting in the codebase.)

---

## Part 3 — The competitive gap is wide open

| Product | Channel | Languages | Cost | Pakistan-ready? |
|---|---|---|---|---|
| **Google Messages Scam Detection** | On-device SMS/RCS | English | Free | ❌ US English beta only |
| **WhatsApp "Scam Alert"** (Aug 2026) | On-device ML | Generic | Free | ⚠️ No Urdu scam corpus, off by default |
| **Trend Micro ScamCheck** | Android app | English | Freemium | ❌ Paid for real protection |
| **Bitdefender Scam Protection** | Android app | English | Paid | ❌ |
| **FamAI** (India) | **WhatsApp forward** | Hindi, English | Free at launch | ❌ Hindi, India-focused |
| **Perplexity WhatsApp bot** | WhatsApp forward | 20 Indian langs incl. Urdu | Free | ⚠️ General fact-check, not scam-specific |
| **UncovAI** | WhatsApp bot | English | — | ❌ |
| **Sanchar Saathi** (Govt. of India) | Portal + national DB | Indian | Free | ❌ No Pakistani equivalent |
| **PTA short code 9000** | SMS forward | — | Free | ⚠️ **Collects reports, returns no verdict** |
| **PTA Digital Assistant** (WhatsApp 0315-0055055) | WhatsApp | Urdu/English | Free | ⚠️ **Menu-driven, not live analysis** |
| **IFCN WhatsApp fact-checkers** | WhatsApp | — | Free | ❌ **Pakistan is not in the directory at all** |

### The opening

- **Nobody owns Urdu-language scam detection.** Not Google, not Meta, not Trend Micro.
- **PTA's channels collect but never answer.** Forwarding to 9000 helps the *state*
  eventually; it does nothing for the *victim* in the next 60 seconds. That silence is
  the exact gap HAAFIZ can fill — and it makes PTA a natural **partner**, not a rival.
- **No national crowdsourced scam-number database exists in Pakistan.** India built one
  (Sanchar Saathi). Pakistan has 200M+ subscribers and no equivalent. Whoever builds
  the corpus owns the moat.

> **Positioning:** *PTA collects the report. HAAFIZ gives the answer — in 3 seconds,
> in your own language, for free.*

---

## Part 4 — The strategy: go where the user already is

Stop asking Pakistanis to come to HAAFIZ. Put HAAFIZ inside the four interfaces they
already use every day.

### 4.1 Channel 1 — WhatsApp Bot *(primary · launch first)*

**The interaction:**
```
User receives suspicious SMS / WhatsApp message / voice note / link / screenshot
  → taps "Forward"
  → selects the HAAFIZ contact
  → sends

HAAFIZ replies in 3 seconds, in Urdu:

  🚨 YE SCAM HAI (94%)

  Kyun:
  • Ye number HBL ka nahi hai — asli HBL sirf 1122 se call karta hai
  • Aap se OTP maanga ja raha hai. HBL kabhi OTP nahi maangta
  • Link "hbl-secure-update.top" par jaata hai — asli site hbl.com hai

  Abhi kya karein:
  1. ❌ OTP kabhi na bhejein
  2. 🚫 Number block karein
  3. 📞 Agar paisay chalay gaye: foran 1930... [bank helpline]
  4. 👨‍👩‍👧 Apne betay/beti ko bhejein → [1-tap family share]

  [🎧 Suniye]  [📋 FIA complaint tayyar karein]  [⚠️ Galat? Batayein]
```

**Why this wins:**

| Property | Why it matters in Pakistan |
|---|---|
| **One tap, zero typing** | Forwarding is muscle memory for 70M+ social users |
| **Already installed** | No download, no storage cost, no Play Store trust barrier |
| **No login** | Value before cost — the #1 conversion fix |
| **Works on the cheapest data plan** | WhatsApp is heavily optimised; a browser session is not |
| **Voice notes supported** | Voice is the dominant medium for low-literacy users |
| **Verdict + instruction, not a score** | Actionable by a 65-year-old without interpretation |
| **Shareable by design** | Every forwarded verdict is free distribution |

**Validated precedent:** FamAI (India) proved the exact model in Hindi. Perplexity's
WhatsApp bot deliberately targets senior citizens for "decoding the truth in messages
they receive," supporting Urdu among 20 languages. The IFCN fact-checker network runs
entirely on this pattern across India and Kenya — and has **no Pakistani member**.

**Implementation note:** WhatsApp Business Platform (Cloud API) supports inbound text,
image, audio, video, document, and location messages via webhooks. Templates must be
pre-approved for *outbound* business-initiated messages, but **user-initiated
conversations have a free 24-hour reply window** — which is exactly this flow.

### 4.2 Channel 2 — Family Shield *(the sleeper killer feature)*

This already exists in the codebase (`family_groups`, `family_members`,
`family_alerts`) and is currently the **most valuable under-used asset in the repo.**

**The insight:** in Pakistan, the person at risk and the person who can help are
usually different people. A father in interior Sindh receives the call; a son in
Karachi knows what to do. Protecting the elder *directly* is the hard problem —
protecting them *through their family* is tractable.

```
Ammi forwards a message to HAAFIZ
   ↓
HAAFIZ detects: SCAM, 94%, "SBP account freeze" pattern
   ↓
HAAFIZ replies to Ammi in simple Urdu  +  silently notifies the son:

   ⚠️ Family Alert
   Your mother received a scam message 2 minutes ago.
   Pattern: fake State Bank "account freeze"
   Verdict shown to her: DO NOT PAY, block number
   Her response: [she tapped "Theek hai, samajh gaya"]
   → Call her?  [📞]   [💬 Send her a voice note]
```

**Why this is strategically decisive:**

- **The son installs it, not the mother.** Technical users onboard their own families.
  This inverts the adoption problem: you don't have to convince 60-year-olds to adopt
  technology, you convince their 30-year-old children to protect them. That is a far
  easier sale and it is already how Pakistani families operate.
- **It creates a *reason to keep the service running*.** A one-off check is forgettable;
  an ongoing duty of care is not.
- **It generates the viral loop.** Every family group pulls in 4–6 members.
- **Trend Micro charges for exactly this** ("Family Circle", up to 5 members, premium
  plan only). HAAFIZ should give it away free — that is the wedge.

**Required build:** the current schema allows one group per user and the alert message
is a plain string. Needs: multiple groups, alert severity, acknowledgement state
("did she see it?"), and a voice-note reply path for low-literacy recipients.

### 4.3 Channel 3 — IVR Voice Helpline *(for the 52% who will never use the internet)*

**The research is unambiguous.** Field studies in Pakistan repeatedly show text
interfaces fail for the target population:

- *"Textual interfaces are unusable by first-time low-literacy users, and error prone
  for literate but novice users"* — comparative study across India, 70+ subjects.
- A 2026 quasi-experimental study deploying voice AI across three rural Pakistani
  districts concluded that policy should treat **"voice-first AI interfaces as a main
  access pathway in rural, low-literacy settings rather than a secondary accessibility
  mechanism."**
- **Mehfil** (LUMS), Pakistan's first IVR citizen-journalism platform: **789 calls from
  535 users across 48 cities and all provinces in just 41 days**, 2.4% of callers blind.
- **Polly** (the Pakistani IVR that went viral): seeded with just **32 low-skilled
  office workers**, it reached **2,032 users and 10,629 interactions in 3 weeks**.
- An IVR study with 31 Punjabi farmers (ages 20–70): **only 14 could read Urdu**, yet
  "simple menu-based navigation was relatively easily understood and used."

**The interaction:**
```
Call HAAFIZ (toll-free / missed-call-back)
  → "Assalam-o-alaikum. Jo message ya call aayi hai, us ke baare mein
     apni zubaan mein batayein."
  → User describes it in Urdu / Punjabi / Sindhi / Pashto
  → Whisper transcribes → analyzer runs
  → HAAFIZ SPEAKS the verdict back:
     "Ye fraud hai. Koi bhi bank kabhi OTP nahi maangta.
      Phone kaat dein aur number block kar dein."
  → Optional: "Apne ghar ke kisi naujawan ko ye warning SMS karein? 1 dabayein."
```

**Also support:** a *missed-call* trigger (user gives one missed call → HAAFIZ calls
back free). Cost to user: zero. This matters enormously for prepaid users watching
balance.

**Distribution bonus:** Polly's virality came from *entertainment* — people forwarded it
because it was fun. A "Scam IQ" voice quiz on the same IVR would be both training and
viral distribution. The repo already has a gamification module (points, badges,
levels, streaks); repurpose it for this instead of for website logins.

### 4.4 Channel 4 — SMS Short Code *(feature phones, no internet at all)*

```
Forward the scam SMS to  HAAFIZ short code
  → receive an SMS verdict back in 10 seconds, in Roman Urdu
```

Reaches the ~2.5% of subscribers on basic telephony only, and rural users with no data
balance. Mirrors PTA's 9000 — **but unlike 9000, it answers.**

### 4.5 Channel 5 — Android on-device app *(later, and be honest about the friction)*

A notification-listener app gives true zero-touch protection: warnings appear *before*
the user taps. Google Messages does this on-device with Gemini Nano; WhatsApp's Scam
Alert does it with a local model.

**But note the distribution constraint:** Google Play Protect explicitly flags
sideloaded apps requesting `RECEIVE_SMS`, `READ_SMS`, `NOTIFICATION_LISTENER`, and
`ACCESSIBILITY` as high-risk, warning *"This app can request access to sensitive data.
This can increase the risk of identity theft or financial fraud."*

**Consequences:**
- **Play Store distribution with correct declaration is viable** — Bitdefender and Trend
  Micro both ship exactly this. Sideloading an APK will trigger scary warnings and
  destroy trust with precisely the users we're targeting.
- **On-device inference is strongly preferred.** A local model means the app can promise
  "aap ka message kahin nahi jata" — which directly attacks the *trust* barrier GSMA
  identified as one of the three reasons 52% of Pakistanis don't use mobile internet.
- **Sequence this last.** Channels 1–4 need no app install and reach further, faster.

### 4.6 Channel ranking

| # | Channel | Reach | Time-to-launch | Literacy needed | Priority |
|---|---|---|---|---|---|
| 1 | WhatsApp bot | ~70M social users | **Weeks** | None | 🥇 **Build first** |
| 2 | Family Shield | Multiplies #1 | Weeks | None | 🥇 **Build with #1** |
| 3 | IVR helpline | Feature phones + elders + blind | 1–2 months | **None** | 🥈 |
| 4 | SMS short code | No-internet users | 2–3 months (telco deal) | Minimal | 🥉 |
| 5 | Android app | Smartphone users | 3–6 months | Some | Later |
| 6 | Web dashboard | Power users, researchers, partners | ✅ exists | High | Maintain |

---

## Part 5 — From product to *programme*: the national layer

An app helps individuals. A **programme** changes a country. Five layers turn HAAFIZ
from tool into national infrastructure.

### 5.1 Crowdsourced Threat Intelligence — the moat

Every single check produces a data point. Aggregate them and you build something no
competitor can copy:

```
Each scan contributes (privacy-preserving):
  • sender phone number (hashed)     → phone_reputation table (already in schema)
  • domain / URL                     → blacklist table (already in schema)
  • message template fingerprint     → NEW: detect campaign waves
  • city / province (approximate)    → location_reports (already in schema)
  • verdict + user feedback          → training labels (the real gold)
```

The existing schema **already has `phone_reputation`, `blacklist`, and
`location_reports` tables — they are empty.** This is the highest-leverage unlock in
the whole codebase: turning a static keyword list into a **living national scam
registry**.

**Network effect:** the more people check, the better the detection, the more people
check. This is the only defensible position available.

**Publish an open dataset.** Pakistan has no public scam corpus. Releasing an anonymised
one (there is a 1,000-message Roman Urdu phishing SMS dataset on Zenodo, DOI
`10.5281/zenodo.21810885` — a starting seed, not a substitute) would attract academic
partners, journalists, and international funding, and establishes HAAFIZ as *the*
authority. Credibility is a distribution channel.

### 5.2 Evidence packaging — attack the 0.04% conviction rate

With ~199 convictions from 523,000 complaints, the bottleneck is **evidence quality**,
not law. Researchers note courts require exact loss quantification, timestamps, and
preserved originals — and that NCCIA is understaffed (~27% personnel gap reported).

HAAFIZ can auto-generate a **submission-ready evidence bundle** at the moment of
detection, while the victim still has everything:

```
HAAFIZ Evidence Pack (auto-generated PDF + JSON):
  ✓ Original message, unaltered (hash-verified SHA-256)
  ✓ Sender number + carrier prefix + first-seen timestamp
  ✓ Screenshot / OCR of the original
  ✓ Voice note + transcript (if applicable)
  ✓ Domain WHOIS record, registration date, SSL status, resolved IPs
  ✓ Detection verdict + confidence + matched indicators
  ✓ Chain-of-custody log (RFC 3161 timestamp)
  ✓ Pre-filled NCCIA complaint draft (PECA 2016 sections cited)
  ✓ Pre-filled PTA 9000 forwarding text
```

> This converts HAAFIZ from "a tool that tells you it's a scam" into
> **"a tool that helps put scammers in prison."** No competitor offers it. It is also
> the single most compelling thing to bring to a meeting with NCCIA or PTA.

### 5.3 Cyber Mohalla — the human layer

Technology will never reach everyone. But **one trusted person per neighbourhood can.**

Adapt the existing gamification system (points, badges, levels, login streaks) from a
consumer retention gimmick into a **volunteer ambassador programme**:

```
Ambassador tiers:
  Mohalla Guard   → 25 verified help sessions     → badge + certificate
  Cyber Sipahi    → 100 sessions, 10 families      → recognised on the map
  District Lead   → trains 10 new ambassadors      → access to campaign toolkit

Toolkit per ambassador:
  • WhatsApp group template + ready-made Urdu awareness posters
  • A "Scam of the Week" broadcast they can forward as-is
  • Offline: printable one-page Urdu guide (no internet needed)
  • A personal referral link → their contribution is counted and visible
```

**Why this works here specifically:** Polly's Pakistani virality study showed that
seeding just **32 low-skilled office workers** produced 2,032 users in 3 weeks — a 63×
multiplication from human seeds. Pakistan's social fabric is *mohalla*-based; trust
flows through people, not brands. And the heatmap page already in the frontend can
literally visualise ambassador coverage as a national map.

### 5.4 Institutional integration

| Partner | What HAAFIZ offers | What HAAFIZ gets |
|---|---|---|
| **PTA** | An *answering* layer on top of short code 9000; a working Urdu WhatsApp assistant | Legitimacy, a national short code, telco reach |
| **NCCIA** | Structured evidence bundles; real-time campaign early-warning | Official referral status, case data |
| **State Bank of Pakistan** | Detection of bank-impersonation patterns; a public "banks never ask for OTP" reference API | Trust anchor for the highest-value scam category |
| **Jazz / Telenor / Zong / Ufone** | An embeddable detection API; carrier-prefix reputation data | SMS short code, pre-install, zero-rated data |
| **Banks (HBL, Meezan, UBL…)** | Their *official* domains and helplines in the verified registry | Accurate impersonation detection — currently hardcoded to 9 domains |
| **Universities (LUMS, NUST, FAST)** | The open dataset | Model research, student volunteers, published papers |
| **NGOs (Digital Rights Foundation)** | Elder & women-focused safety tooling | Ground network, especially for the 1.8M women victimised 2020–2025 |

> **Note on GSMA:** the GSMA already runs an **APAC Cross-Sector Anti-Scam Taskforce**
> and explicitly recommended at the 2025 Digital Nation Summit in Islamabad that
> Pakistan expand anti-fraud initiatives and run **dedicated digital-literacy programmes
> for women and rural communities.** That is a published, funded, institutionally
> endorsed invitation. HAAFIZ is written to answer it.

### 5.5 Zero-rating

For the 52% who don't use mobile internet, **cost is a stated barrier**. Getting telcos
to zero-rate HAAFIZ traffic (WhatsApp bot + IVR) removes affordability from the
equation entirely. This is a negotiation, not an engineering problem — but it should be
on the roadmap from day one because it changes who can participate.

---

## Part 6 — AI roadmap

### 6.1 Where detection stands today

The current system is **keyword matching**. There is no trained model in the repo;
`train_model.py` requires a dataset that doesn't exist, and `models/scam_detector.pkl`
is never shipped. Code comments concede this — the confidence cap was manually raised
from 30 to 90 so the keyword heuristic could ever cross the scam threshold at all.

That is an honest patch, but keyword lists have a hard ceiling: they cannot generalise,
they break on paraphrase, and they produce false positives on legitimate messages that
merely *mention* banks.

### 6.2 The ladder

| Stage | Approach | Effort | Expected gain |
|---|---|---|---|
| **1. Now** | Curated keyword sets (6 languages) + rules | ✅ done | Baseline |
| **2. Weeks** | Train TF-IDF + Logistic Regression on the Zenodo Roman Urdu SMS set (1,000 msgs) + seeded synthetic corpus | Low | Real probabilities, calibrated |
| **3. Months** | Multilingual transformer (`XLM-RoBERTa` / `mBERT`) fine-tuned on the accumulated corpus | Medium | Handles paraphrase & code-mixing |
| **4. Ongoing** | **Human feedback loop** — every "⚠️ Galat? Batayein" tap is a free label | Low | Compounding accuracy; this is the actual moat |
| **5. Later** | Small on-device model (TFLite) for the Android app | Medium | Zero-touch + privacy |

### 6.3 Fix the scoring logic

`backend/routes/scan.js` currently computes an **unweighted arithmetic mean** across
module confidences. That is wrong: one decisive signal gets diluted by four modules
that found nothing.

```js
// CURRENT — a certain scam averaged with four silent modules looks "safe"
const avgConfidence = scores.reduce((a,b) => a+b, 0) / scores.length;
// text=95, phone=0, website=0, image=0, voice=0  →  avg = 19  →  "SAFE"  ❌
```

Replace with a **noisy-OR ensemble with evidence weighting and hard overrides**:

```
P(scam) = 1 − Π(1 − wᵢ·pᵢ)          # any strong signal dominates
  + hard override: verified-impersonation hit  → immediate critical
  + hard override: OTP/CNIC exfiltration ask   → immediate critical
  − trust discount:  domain on verified registry → strong suppression
```

See `ai-service/app/scoring/engine.py` for the implementation.

### 6.4 Kill the fake numbers

`analyzers/voice_analyzer.py` returns hardcoded `"authority": 50, "panic": 30`. These
are **fabricated constants presented as measurements** — displayed to users as if they
were analysis. Either compute them (speech rate, pitch variance, pause patterns,
interruption density) or remove them. Trust is the product; a fake metric discovered
once destroys it.

### 6.5 The LLM layer — but only for *explanation*, never for *detection*

Use an LLM for what it is genuinely best at here: turning a technical verdict into
**plain Urdu a 65-year-old can act on**, and answering free-form follow-up questions
("lekin ye to meri beti ka number hai?").

Keep detection on the deterministic ML/rules path: auditable, fast, offline-capable,
cheap, and — critically — **defensible in court**. An LLM hallucinating "this is safe"
is a liability; a calibrated classifier with a logged feature trace is evidence.

### 6.6 Add the "digital arrest" playbook

The fastest-growing scam in the region is **digital arrest**: fraudsters impersonate
law enforcement, accuse the victim of a serious crime, keep them on a video call for
*hours* to prevent them consulting family, and extort transfers. Quick Heal reports
2026 variants now use spoofed caller IDs, fake uniforms, forged FIRs, and
remote-access apps (AnyDesk/TeamViewer) to reach banking apps and OTPs.

In Pakistan this presents as fake **FIA / NCCIA / NADRA / SBP / PTA** officials. The
existing `authority` keyword category already lists these institutions — but there is
no dedicated detector. Build one:

```
DIGITAL ARREST SIGNATURE (any 2 → critical, speak the warning aloud):
  • claims of arrest / FIR / court / "digital arrest"
  • demands secrecy: "kisi ko mat batana", "family ko mat batana"
  • demands staying on the call / video
  • asks to install AnyDesk / TeamViewer / screen-share
  • claims CNIC / Aadhaar-like linkage to a crime
  • demands transfer to "settle" or "verify"

→ RESPONSE: audio warning + "Phone kaat dein. Koi bhi idara video call par
            arrest nahi karta. Apne ghar mein kisi ko abhi batayein."
→ AUTO-NOTIFY the Family Shield group immediately.
```

The secrecy demand is the tell. Any message or call instructing the victim **not to
consult their family** is definitionally hostile — and Family Shield (4.2) is the
structural answer to it.

---

## Part 7 — Trust and privacy architecture

GSMA names **trust** as one of three reasons 52% of Pakistanis don't use mobile
internet. A security product that asks for total message access faces the hardest
version of this problem. Design for it explicitly:

| Principle | Implementation |
|---|---|
| **No account needed to be safe** | WhatsApp/SMS/IVR work anonymously. Accounts are optional, for history only. |
| **Minimal retention** | Verdicts returned; message bodies discarded after analysis unless the user opts in to contribute to the corpus. |
| **On-device where possible** | Android app runs inference locally — "aap ka message kahin nahi jata" |
| **Hash, don't store** | Sender numbers stored hashed for reputation scoring |
| **Never sell data** | Stated plainly, in Urdu, on first interaction |
| **Publish the method** | Open dataset + documented scoring = auditable, not a black box |
| **Visible correction path** | "Galat? Batayein" on every verdict — and visibly act on it |

> **Trust is not a compliance checkbox here. It is the primary adoption barrier
> identified by GSMA. Treating privacy as a feature is a growth strategy.**

⚠️ **Immediate remediation required.** The current public repository contains
`backend/.env` with a real `JWT_SECRET` and `backend/haafiz.db` with a user's email and
password hash, both committed to a public GitHub repo. A programme whose pitch is
*"we protect your data"* cannot have leaked its own. These must be rotated, purged from
history, and the incident documented. See `docs/SECURITY.md`.

---

## Part 8 — 90-day execution plan

### Days 1–14 — Stop the bleeding, fix the foundation
- [ ] Rotate `JWT_SECRET`; purge `.env`, `*.db`, `venv/`, `node_modules/` from git history
- [ ] Remove 30,151 vendored files from the repo (✅ **done** — see `docs/MIGRATION.md`)
- [ ] Add SSRF guard to the website analyzer (currently fetches any URL, including internal IPs)
- [ ] Fix FastAPI async blocking (Whisper transcription currently freezes the whole server)
- [ ] `.env.example`, `LICENSE`, real `README.md`, Docker Compose, CI
- [ ] Write the first 200 automated tests around the analyzers

### Days 15–45 — Ship Channel 1 (WhatsApp)
- [ ] WhatsApp Business Cloud API integration (inbound text/image/audio/document)
- [ ] Urdu verdict renderer — **verdict + reason + action**, never a bare percentage
- [ ] Voice-note pipeline (Whisper → analyze → *spoken* Urdu reply)
- [ ] Train stage-2 model on the Zenodo Roman Urdu dataset + seeded corpus
- [ ] Replace mean-averaging with the noisy-OR scoring engine
- [ ] Human feedback capture ("Galat? Batayein") → labelled training data
- [ ] **Closed beta: 50 families.** Instrument everything. Iterate weekly.

### Days 46–75 — Family Shield + evidence
- [ ] Multi-group family model, alert severity, acknowledgement state
- [ ] Silent family notification on any critical verdict
- [ ] Digital-arrest signature detector
- [ ] Evidence-bundle generator (PDF + JSON, hash-verified, chain-of-custody)
- [ ] Pre-filled NCCIA complaint + PTA 9000 forwarding text
- [ ] Verified institutional registry (banks, telcos, government — replacing the 9 hardcoded domains)

### Days 76–90 — Programme launch
- [ ] Publish the open dataset + methodology
- [ ] Recruit the first 25 Cyber Mohalla ambassadors (one district)
- [ ] Approach PTA (answering layer on 9000) and NCCIA (evidence bundles) with real beta data
- [ ] Begin IVR prototype with a local Asterisk/Twilio provider
- [ ] Submit to the IFCN WhatsApp fact-checker directory (Pakistan is absent)
- [ ] Open-source release with a clear "how to run your own national node" guide

### Metrics that matter

| Metric | Target (90 days) | Why |
|---|---|---|
| **Median time-to-verdict** | < 10 seconds | The entire thesis rests on this |
| **Verdict completion rate** | > 80% of inbound | Measures whether the flow actually works |
| **Family Shield groups created** | 500 | Proxy for elder protection reach |
| **Ambassadors active** | 25 | Human-layer seed |
| **Feedback labels collected** | 5,000 | Fuels the model moat |
| **Distinct scam numbers in registry** | 10,000 | The national asset |
| **Evidence bundles generated** | 250 | Justice-layer adoption |
| **Rupees intercepted (self-reported)** | Publish it | The headline number for PTA, press, donors |

---

## Part 9 — What to build first, if only one thing

> **A WhatsApp number.**
>
> Not a website. Not an app. Not a login. One number that every Pakistani can save
> once, forward anything to, and get a verdict in Urdu in three seconds — which also
> quietly warns their family.
>
> That single change converts HAAFIZ from a destination nobody visits into a reflex
> everybody has. Everything else in this document is amplification of it.

---

## Sources

**Pakistan cybercrime data**
- Express Tribune — *Pakistanis lose Rs8.32b to cyber fraud* (227,757 victims; NCCIA records)
- PhotoNews Pakistan / Digital Pakistan — same NCCIA dataset (83,080 / 76,646 / 68,031)
- Ministry of Interior, National Assembly reply Jan 2026 — 150,542 complaints 2025; 81,996 financial fraud; 2,974 WhatsApp hacking; 26,036 inquiries; 1,955 cases; 2,445 arrests; 32 convictions; 122 acquittals
- NCCIA four-year totals — 523,000 complaints, 414,852 verifications, 80,090 inquiries, 5,755 cases, 7,600 arrests; convictions 92 (2023), 60 (2024), 39 (2025); ~199 total
- Journalismpakistan — 77,023 complaints in first five months of 2026; 457 cases; 520 arrests; 8 convictions
- LegalSparrow — FIA→NCCIA transition (est. 3 May 2024 under PECA 2016 §51; operational April 2025); Multan Rs 20bn fake trading scheme, June 2025
- PhoneWorld — Cybercrime Report 2025, 1,285 registered cases; harassment 545 FIRs
- Virginia Tech Tech for Humanity Lab — 1.8M women victimised 2020–2025; ~0.02% conviction rate
- ResearchGate — FIA Cyber Crime Wing analysis; ~27% personnel gap; 639,000 complaints 2020–2024; 222 convictions (~0.05%)
- Kaspersky via BrightDefense — 5.3M on-device attacks Jan–Sep 2025; 354k exploitation attempts; 166k banking malware; 126k spyware; 113k backdoors; 107k password stealers; 7 APT groups

**Reporting channels**
- PTA — short code **9000**; WhatsApp Digital Assistant **0315-0055055**; toll-free **0800-55055**; complaint.pta.gov.pk
- C-Suite Exchange — *How to Report Fraudulent Calls and Messages in Pakistan via PTA and FIA*
- PhoneWorld — *PTA Warns Citizens Against Digital Fraud as Scammers Exploit OTPs, CNIC Data*

**Connectivity & digital divide**
- GSMA, *Unlocking Pakistan's Digital Potential: Reform, Trust and Opportunity* (Digital Nation Summit, Islamabad 2025) — 81% coverage, 68% smartphone, 29% usage, **52% usage gap**; barriers: affordability, literacy, trust; 33% mobile taxation; APAC Cross-Sector Anti-Scam Taskforce; recommendation for digital-literacy programmes for women and rural communities
- PTA — 200M telecom subscribers, 150M broadband, 2M+ FTTH (June 2025); Jazz 37.15%, Zong 26.36%, Telenor 21.83%, Ufone 13.67%
- HIES 2024-25 — household internet 70%, individual usage 57%, household smartphone 96%
- Pakistan Development Review (2024) — internet use by age: 25% youth, 19% (30–49), **9% (50+)**; 67.1% use internet for chat/social
- TechJuice, *Pakistan's Freedom Report 2026* — Facebook 24.8%, **WhatsApp 19.9%**, websites 18%, X 15% as primary info source; ~70M active social media users; n>2,000 National Trust Survey
- Internet Society Pulse — 57% internet penetration; resilience score 42%

**IVR & low-literacy HCI**
- Raza et al. (ICTD 2017) — *Designing an IVR System for Farmers in Pakistan*; 31 farmers, only 14 read Urdu; menu navigation easily understood
- Raza et al. (MobileHCI 2018) — *The Case for IVR-Based Citizen Journalism in Pakistan* (**Mehfil**); 789 calls, 535 users, 48 cities, all provinces, 41 days, 2.4% blind
- *Polly* — seeded by 32 low-skilled office workers → 2,032 users, 10,629 interactions in 3 weeks
- AM Research Journal (2026) — rural Pakistani e-governance field study; recommends voice-first AI as a **main** access pathway, not secondary
- Comparative usability study (India, 70+ subjects) — textual interfaces "unusable by first-time low-literacy users"
- GASA — *What Uganda's IVR Trial Shows About Practice-Based Scam Prevention*

**Competitors & prior art**
- Google Security Blog (Mar 2025) — *New AI-Powered Scam Detection Features*; on-device, Gemini Nano, US English beta
- WhatsApp/Meta — **Scam Alert**, launched 14 Aug 2026; on-device ML; optional, off by default; Ed25519-signed models
- Trend Micro **ScamCheck** — 2M users; Scam Radar, AI Video Scan, SMS filter, call block, paid Family Circle (5 members)
- Bitdefender **Scam Protection** — paid; requires Accessibility + Notification + SMS permissions
- **FamAI** (India) — WhatsApp forward-to-check, Hindi/English, free at launch; limitation: requires user action
- Perplexity WhatsApp bot — 20 Indian languages incl. Urdu; explicitly targets senior citizens
- UncovAI — WhatsApp bot; voice-note deepfake detection, homograph audit
- Sanchar Saathi (Govt. of India) — national flagged-number database
- WhatsApp/IFCN fact-checker directory — India, Kenya, others; **no Pakistani organisation listed**

**Datasets & models**
- Zenodo — *Roman Urdu Phishing SMS Dataset for Smishing Detection Research*, DOI `10.5281/zenodo.21810885`; 1,000 messages (595 legitimate, 405 phishing); template-aware evaluation protocol
- GitHub `Sawera-Ali/roman-urdu-scam-detector` — Flask + scikit-learn Roman Urdu SMS classifier
- Literature: TF-IDF+Random Forest 97.5%; DistilBERT+SVM 98.07%; BiGRU (Arabic) 98.71%; CNN-GRU hybrid 99.82%; ensemble/stacking approaches outperform single classifiers

**Digital arrest scam pattern**
- Quick Heal advisory (2026) — spoofed caller IDs, fake uniforms, forged FIRs, remote-access apps
- Economic Times / RBL Bank / SBI — mechanism, psychology, and counter-measures
- Livemint — HDFC "kill screenshots" defence; AI transaction-anomaly flagging

**Android platform constraints**
- Google Play Protect developer guidance — sideloaded apps requesting `RECEIVE_SMS`, `READ_SMS`, `NOTIFICATION_LISTENER`, `ACCESSIBILITY` are treated as high-risk; Play Store distribution with correct declaration is the viable path
