# Platforms: har user ke liye — laptop, Android, iOS, feature phone

## Bunyadi baat: ek brain, kai patle client

Har platform ka apna permission model hai, aur wo **ek doosre se bilkul
mukhtalif** hain. Jo Android par mumkin hai wo iOS par **namumkin** hai — aur
ye koi kami nahi, ye platform ki hakeeqat hai.

Is liye HAAFIZ ka design ye hai:

```
        ┌─────────────────────────────────────────────────┐
        │              ai-service  (THE BRAIN)            │
        │   detection, scoring, verdict, 7 languages      │
        └────────────────────┬────────────────────────────┘
                             │  ek hi HTTP API
     ┌──────────┬────────────┼────────────┬──────────┬──────────┐
     │          │            │            │          │          │
 WhatsApp   Android      iOS app     Browser     SMS/IVR     Web/PWA
 (bot)      (app)        (app)      extension   (short code)
```

**Har platform sirf ek patla client hai** — wo input bhejta hai aur verdict
dikhata hai. Detection logic kahin duplicate nahi hoti.

Natija: **naya platform add karna sasta hai.** Aaj `channels/whatsapp/` hai;
kal `channels/browser-extension/`, `mobile/android/`, `mobile/ios/` usi API par
ban jayenge.

---

## Platform capability matrix — jo sach hai

Ye table guesswork nahi hai; har row Apple/Google ki official documentation se
hai. **Jo cheez namumkin hai wo saaf likhi hai**, taake koi waqt zaya na ho.

| Capability | 🖥️ Browser ext. | 🤖 Android | 🍎 iOS | 💬 WhatsApp |
|---|---|---|---|---|
| **Block a phishing click *before* it happens** | ✅ **full** | ⚠️ partial | ⚠️ partial | ❌ |
| **Screen/label incoming calls** | — | ✅ `CallScreeningService` | ✅ Call Directory | ❌ |
| **Silently reject spam calls** | — | ✅ (API 29+) | ⚠️ listed numbers only | ❌ |
| **Read SMS for scam detection** | — | ⚠️ restricted | ❌ **namumkin** | ⚠️ forwarded by user |
| **Read notifications (incl. OTPs)** | — | ⚠️ restricted | ❌ **namumkin** | ❌ |
| **Overlay the screen at any moment** | — | ⚠️ Accessibility | ❌ **namumkin** | ❌ |
| **Work with zero install** | ❌ | ❌ | ❌ | ✅ **only one** | ✅ (browser) |
| **Works on feature phones** | ❌ | ❌ | ❌ | ⚠️ smart only | ✅ SMS/IVR |
| **Play/App Store approval risk** | low | **high** | medium | none |
| **Reaches Pakistani users today** | ~1% | **majority** | small | **near-universal** |

> **Sab se ahem line pehli hai.** Desktop browser extension akeli jagah hai jahan
> aap link *click hone se pehle* rok sakte hain. Aur VirusTotal wala poora masla
> — "shakkī URL clean dikhta hai" — bilkul wahin hota hai.

---

## 🍎 iOS: jo mumkin hai aur jo bilkul nahi

iOS par HAAFIZ Android jitna nahi kar sakta. Ye sach hai aur isay design mein
shamil karna hoga, naake chupana.

### ✅ CallKit Call Directory Extension

Ye iOS par caller-ID aur call blocking ka **sirf** tareeqa hai. App ek data file
supply karti hai:

```swift
CXCallDirectoryExtensionContext
  .addBlockingEntry(phoneNumber:)       // number ko block kare
  .addIdentificationEntry(phoneNumber:, label:)   // "HAAFIZ: Fraud" label
```

User ko incoming call screen par `Fraud — HAAFIZ` nazar aata hai.

**Proof ke ye kaam karta hai:** Truecaller ne iOS par ye istemal kiya to
> *"spam detection rates have increased 50 percent-plus, with the company's
> service now detecting around **90 percent of spam calls**"* (TechCrunch)

Ek national HAAFIZ list isi tarah kaam kar sakti hai.

#### ⚠️ CallKit ki chhah pabandiyan — inhein jaanna zaroori hai

| Pabandi | Matlab | HAAFIZ ka hal |
|---|---|---|
| **Numbers ascending order mein hon** | Warna extension crash/load fail | Sort karke bhejein |
| **Ye live interceptor NAHI** | Extension call ke waqt **run nahi hota**; app incoming number **dekh hi nahi sakti** | Pre-computed list hi kaam karti hai |
| **Contacts override karte hain** | Agar number contacts mein hai, identification **nahi** dikhegi (blocking ke ilawa) | Acceptable — scammer contacts mein nahi hota |
| **"No Caller ID" block nahi ho sakta** | Hidden numbers se bachao namumkin | User ko alag se warn karein |
| **Allowlist (invert) nahi ban sakti** | "sab block siwaye inke" possible nahi | Explicit spam list only |
| **User ko manually ON karna hoga** | Settings → Phone → Call Blocking & Identification | **Onboarding mein step-by-step Urdu guide — ye critical hai** |

Plus: **memory limits** — barhi lists ke liye autorelease pools; aur
**incremental updates** supported hain (`context.isIncremental`), taake har
dafa poori list reload na karni pare. Data **App Group** se share hota hai
(UserDefaults/Core Data/file).

> **Design natija:** iOS par HAAFIZ ka model hai *"ek national spam-number list
> jo roz update ho."* Live interception nahi — **aur ye theek hai**, kyunki
> scam call ka sab se bara nuqsan to *number ka pehchana na jana* hai.

### ✅ Safari Web Extension (iOS 15+)

**Ye iOS par sab se powerful cheez hai jo aksar log bhool jate hain.**

Safari iOS par Web Extensions support karta hai — yaani aap Safari mein
`webNavigation.onBeforeNavigate` laga kar phishing link ko **click hone se
pehle** rok sakte hain, aur page par warning banner dikha sakte hain.

Ye desktop extension ka **wahi code** hai (Xcode mein wrap hota hai). Ek baar
likhein, dono jagah chale.

### ✅ Share Extension / Action Extension

User ne SMS ya WhatsApp mein link dekha → Share → HAAFIZ → verdict.
Ye **iOS par zero-effort detection ka sab se behtareen rasta** hai, kyunki
background reading namumkin hai magar **ek tap** kaam karti hai.

### ✅ Shortcuts + Siri

`Check this with HAAFIZ` shortcut; iOS Shortcuts app se automation.

### ❌ Jo iOS par namumkin hai — waqt zaya na karein

- **Background SMS reading** — koi API nahi. Period.
- **Notification listening** — koi API nahi. Period.
- **Accessibility overlay / screen reading** — koi API nahi. Period.
- **Default dialer banna** (Android jaisa) — CallKit sirf VoIP calls ke liye
  default ho sakta hai, carrier calls ke liye nahi.

> **Is liye iOS ki strategy alag hai:** *interception ki jagah friction kam
> karo.* Ek tap = verdict. Safari extension = automatic. Call Directory =
> national spam list. WhatsApp = zero install.

---

## 🤖 Android: zyada taqat, magar Play Store ka imtehan

Android par HAAFIZ bohat kuch kar sakta hai — magar har powerful permission
Google ki review se guzarti hai.

### ✅ `CallScreeningService` (API 29+) — behtareen, aur *saaf*

```java
public void onScreenCall(Call.Details callDetails) {
    // sirf un numbers ke liye jo CONTACTS MEIN NAHI hain
    Uri handle = callDetails.getHandle();
    if (callDetails.getCallDirection() == DIRECTION_INCOMING) {
        respondToCall(callDetails, new CallResponse.Builder()
            .setDisallowCall(true)        // phone ring hi na kare
            .setRejectCall(true)          // silently reject
            .setSkipCallLog(false)        // log mein rahe (evidence!)
            .setSkipNotification(true)
            .build());
    }
}
```

**Do bari khushiyan:**
1. **`READ_CALL_LOG` permission ki zaroorat NAHI** — ye ek restricted permission
   hai aur is se bachna bara fayda hai.
2. `callDetails.getCallerNumberVerificationStatus()` — carrier-level verification.
   `VERIFICATION_STATUS_FAILED` ka matlab **number spoof hai**.

Requirements: `BIND_SCREENING_SERVICE` permission + app ko default
caller-ID/spam app banana hoga (Android 10+ par `RoleManager.ROLE_CALL_SCREENING`
se request hoti hai — ek clean system dialog, koi scary warning nahi).

> **Note:** Ye API **sirf un numbers ko screen karta hai jo contacts mein nahi
> hain.** Scam calls contacts se nahi aatien, is liye ye exactly sahi behaviour
> hai — aur privacy ke liye bhi acha.

### ⚠️ `NotificationListenerService` — powerful, magar restricted

Ye **device ki har notification** padh sakta hai — SMS previews, banking alerts,
**OTPs**. HAAFIZ ke liye ye qeemti hai: "aap ko HBL ka OTP aaya hai magar aap ne
transaction nahi ki" = foran alert.

**Magar:**
- **Google Play restricted permission hai.** Declaration form, review, aur
  "genuine core functionality" ka saboot chahiye.
- **Privacy ka bohat bara masla** — ye OTPs padhta hai. `docs/SECURITY.md` mein
  jo promise hai ke "content kabhi server par nahi jata" — usay yahan
  **on-device matching** se nibhana hoga, warna poora trust model toot jayega.
- Android 16.1 ne `RECEIVE_SENSITIVE_NOTIFICATIONS` add kiya — alag permission.
- **Low-RAM devices** (Android Q se pehle) par notifications deliver nahi hotien —
  aur Pakistan mein low-end Android phones ki tadaad bohat zyada hai.
- **Work profile** mein restrictions.
- Google khud kehta hai: *"you can use this API only if it enables a core app
  functionality for the end user. Do not use it to collect private user data."*

> **Faisla:** Phase 2. Pehle `CallScreeningService` (clean, no review risk).
> Jab Play par establish ho jayein, tab notification listener — **sirf
> on-device pattern matching ke saath, content kabhi upload na ho.**

### ⚠️ Accessibility API — sab se powerful, sab se khatarnak

Ye screen padh kar **overlay** dikha sakta hai — yaani user jab bhi scam app
khole, HAAFIZ beech mein aa jaye. Technically ideal.

**Magar haqeeqat:**
- **Android 13 sideloaded apps ko accessibility permission dene se rokta hai**
  (`ACCESS_RESTRICTED_SETTINGS`) — user ko manually Settings se "Allow restricted
  settings" karna padta hai.
- **Play Store** declaration form + approval + prominent disclosure + user ka
  affirmative action.
- **Play Protect** un apps ko *high risk* kehta hai jo sideloaded hon aur
  `ACCESSIBILITY`, `RECEIVE_SMS`, `NOTIFICATION_LISTENER` mangein — *"can increase
  the risk of identity theft or financial fraud."*
- Bitdefender jaisa bara vendor bhi apni docs mein ye teenon `restrictedPermissions`
  mein shumar karta hai.
- Android 14+ par foreground service types ki alag requirements.

> **Faisla: Accessibility par product ki buniyaad NA rakhein.** Ye approval
> gamble hai. `CallScreeningService` + browser-level protection se 90% value
> milti hai bina kisi risk ke.

### ✅ SMS — sahi tareeqa

- `RECEIVE_SMS` / `READ_SMS` = restricted, Play Protect warning, sideload block.
- **Sahi rasta: SMS Retriever API aur User Consent API** — ye app ko sirf *apne
  liye bheje gaye* OTPs padhne dete hain, bina `READ_SMS` permission ke.
- Scam SMS detection ke liye: **Share target** banao. User SMS mein long-press →
  Share → HAAFIZ. Ek tap, koi permission nahi, koi Play risk nahi.

### ⚠️ Sideload vs Play Store — ye faisla bara hai

| | Play Store | Sideloaded APK |
|---|---|---|
| Restricted permissions | Declaration + review ke saath **allowed** | **Play Protect high-risk warning** |
| Accessibility (Android 13+) | Allowed with approval | **Blocked** |
| Auto-update | ✅ | ❌ |
| User trust | ✅ | ❌ *"ye app risky hai"* |
| Reach | Sab | Sirf tech-savvy |

> **Faisla: Play Store, har haal mein.** HAAFIZ ke target users — wo log jo
> digital fraud ka shikar hote hain — agar install ke waqt hi Google unhein
> *"identity theft ka khatra"* dikhaye, to poora product ulta pad jayega.
> Trust hi product hai.

---

## 🖥️ Desktop / Laptop: wo jagah jahan asli interception mumkin hai

### Browser Extension (Manifest V3) — **sab se powerful platform**

Chrome, Edge, Firefox, Brave, aur Safari (iOS 15+ wrap) — **sab par ek hi
codebase** (Xamarin ke mutabiq "Chromium-based platforms share a common code
base" aur Manifest V3 is the standard).

Ye kya kar sakta hai jo koi mobile platform nahi kar sakta:

| Capability | Kaise |
|---|---|
| **Click rok dein** | `webNavigation.onBeforeNavigate` / `declarativeNetRequest` |
| **Page par warning banner** | `content_scripts` — phishing page load hote hi red overlay |
| **Credential form detect karein** | DOM par `input[type=password]` + brand logo matching |
| **Typosquatted domain pehle hi pakdein** | address bar input par Levenshtein check |
| **Right-click "Check with HAAFIZ"** | context menu |
| **Download scan** | `downloads.onCreated` |
| **Offline** | Local suspicious-domain set (CT-derived) bundled |

**MV3 ki pabandiyan:** `background` pages ki jagah **service workers** (jo idle
par so jate hain), aur `webRequestBlocking` ab sirf `declarativeNetRequest` se.
Yaani heavy ML model extension mein nahi chalega — **wo `ai-service` par chalta
hai.** Extension patli rehni chahiye.

> **Ye wahi product hai jo VirusTotal ko harata hai.** VT ek website hai jahan aap
> URL *paste karte hain* — aur aap ne khud kaha tha ke copy-paste ka time kisi ke
> paas nahi. Extension **aap ke click par khud** chal jata hai. Zero friction.

### PWA (already exists)

Repo mein pehle se `manifest.webmanifest` hai — *"HAAFIZ - Pakistan Cybersecurity
Shield"*, theme `#020617`, 9 pages, service worker. Isay polish karein:
- **Offline verdicts** for known-bad domains (service worker cache)
- **Install prompt** Urdu mein
- Ye un logon ke liye hai jo extension install nahi karna chahte

---

## 💬 WhatsApp: zero-install, aur near-universal

Ye already built hai (`channels/whatsapp/`) aur `docs/BLUEPRINT.md` mein isay
**#1 channel** thehraya gaya. Wajah:

- **Koi install nahi** — jo number aap save karte hain, wahi app hai
- **Har platform par same** — Android, iOS, feature phone (WhatsApp Java), desktop
- Pakistan mein **19.9% logon ka #2 primary information source**
- Ek number yaad rakhna ek app install karne se kahin asaan hai

> **Cross-platform question ka sab se chota jawab:** WhatsApp. Baaki sab uske
> *upar* value add karte hain.

---

## Recommended build order

Har step pichle step ki infrastructure reuse karta hai:

| # | Platform | Kyun is tarteeb mein | Effort |
|---|---|---|---|
| **1** | **WhatsApp bot** ✅ *already built* | Zero install, sab platforms, sab se bari reach | Done |
| **2** | **Web/PWA polish** | Already exists; offline verdicts add karein | Chota |
| **3** | **Browser extension (MV3)** | **Asli interception** — VirusTotal ko yahan harana hai. Ek codebase Chrome+Firefox+Safari | Medium |
| **4** | **Android app** | `CallScreeningService` + Share target. Majority platform | Medium |
| **5** | **iOS app** | Share Extension + Call Directory + Safari extension (code from #3) | Medium |
| **6** | **SMS short code + IVR** | Feature phones, 50+ users (9% internet use) | Bada — telco partnership |

**Note karein:** #3 aur #5 share karte hain — Safari Web Extension desktop
extension ka Xcode wrap hai. Ek baar likhna, teen platform (Chrome, Firefox,
Safari-iOS) milte hain.

---

## Ek platform-agnostic principle

Har platform ke liye wahi test jo `docs/BLUEPRINT.md` mein hai:

> **Kya ye victim ka waqt 10 second se kam leta hai?**

- **Browser extension:** 0 second — click se pehle
- **Android CallScreening:** 0 second — phone hi nahi bajta
- **iOS Call Directory:** 0 second — screen par "Fraud" likha hai
- **WhatsApp:** ~5 second — message forward karo, jawab aa gaya
- **Share extension:** ~3 second — Share → HAAFIZ
- **Website paste:** 30+ second — ❌ **yehi problem hai jo khatam karni hai**

Agar kisi platform par jawab 10 second se zyada leta hai, to us platform par
**interception automatic honi chahiye**, warna user wo kaam karega hi nahi.

---

## Sources

**iOS**
- Apple Developer — *Call Directory Extension* — "Call Directory extensions can
  provide caller-ID lookup data and a list of phone numbers to be blocked";
  data shared via **App Group**; extension **does not run at call time**, app
  cannot see the incoming number
- Apple — *CXCallDirectoryExtensionContext* — `addBlockingEntry`,
  `addIdentificationEntry`, `isIncremental`, `invalidate`; entries must be
  **numerically ascending**; memory limits → use autorelease pools
- Apple — *CXCallDirectoryManager* — `reloadExtension(withIdentifier:)`
- Apple — *Supporting Incremental Updates in a Call Directory Extension*
- Apple — *Configuring a Call Directory Extension* — user must enable under
  **Settings → Phone → Call Blocking & Identification**; **user contacts override**
  the extension (except for blocking); **cannot block "No Caller ID"**;
  cannot invert to an allowlist
- TechCrunch — *Truecaller adds call-blocking capabilities for iPhone users* —
  **spam detection rates increased 50%+, now detecting around 90% of spam calls**
- Stack Overflow — *Blocking spam calls on iPhone using CallKit?* — confirmation
  that only CallKit + a user-managed blocklist is possible; third-party
  interception not available
- Xamarin / Microsoft Learn — *Publishing cross-platform browser extensions* —
  **Safari Web Extension (iOS 15+)**; Chromium platforms share a code base;
  Manifest V3 standard; MV3 uses **service workers** and
  `declarativeNetRequest` instead of blocking `webRequest`

**Android**
- Android Developers — *Screen incoming calls with CallScreeningService* —
  `onScreenCall(Call.Details)`, only for numbers **not in contacts**,
  `getCallerNumberVerificationStatus()` (`VERIFICATION_STATUS_FAILED` = likely
  spoof/spam), **no `READ_CALL_LOG` needed**, `BIND_SCREENING_SERVICE`,
  `CallResponse.Builder` with `setDisallowCall/setRejectCall/setSkipCallLog/
  setSkipNotification`
- Android Developers — *Provide caller ID & spam protection* (RoleManager)
- Android Developers — *Notification listener service* — **restricted Google Play
  permission**; "only if it enables a core app functionality"; **do not use it to
  collect private user data**; low-RAM devices ≤ Android Q don't deliver
  notifications; work-profile restrictions
- Android Developers — *RECEIVE_SENSITIVE_NOTIFICATIONS* (added in API 36.1 /
  Android 16.1)
- Android Developers — *Foreground service types are required* (Android 14+)
- Google Play — *Accessibility API Policy* — declaration form, approval required,
  must be core functionality, prominent in-app disclosure, affirmative user action
- Google Play — *App Bundle Requirements* — new personal developer accounts need
  **12 closed testers for 14 continuous days** before production
- Google Support — *Manage Google Play Protect settings* — **Android 13+ blocks
  accessibility permission for sideloaded apps** (`ACCESS_RESTRICTED_SETTINGS`);
  sideloaded apps requesting `RECEIVE_SMS`, `READ_SMS`, `NOTIFICATION_LISTENER`,
  `ACCESSIBILITY_SERVICE` are flagged **high risk**: *"can increase the risk of
  identity theft or financial fraud"*
- Bitdefender — *Google Play Protection blocked my Bitdefender product* —
  `restrictedPermissions` list confirms ACCESSIBILITY_SERVICE,
  BIND_NOTIFICATION_LISTENER_SERVICE, RECEIVE_SMS; notes Bitdefender and Trend
  Micro both ship these on Play
- XDA Developers — *Android 11 makes it harder for sideloaded apps to gain
  dangerous permissions*; *Android 13 sideloaded app restricted settings*
- Stack Overflow — *CallScreeningService not triggered on incoming calls* —
  `RoleManager.createRequestIntent(ROLE_CALL_SCREENING)` is how you become default
