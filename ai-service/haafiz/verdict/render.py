"""Plain-language verdict rendering for non-technical users.

THE PROBLEM THIS SOLVES
-----------------------
A "68% confidence" score is not an answer. The audience for HAAFIZ is a
62-year-old in interior Sindh who has never read a security advisory and may not
read Urdu fluently. They need three things, in this order:

    1. VERDICT      -- is this safe or not, in one unmistakable word
    2. REASON       -- why, stated concretely ("this is not HBL's number")
    3. ACTION       -- what to do right now, numbered, imperative

Research backing: field studies in Pakistan found textual interfaces "unusable by
first-time low-literacy users" and that voice-first interaction should be a MAIN
access pathway, not an accessibility afterthought. Every verdict here therefore
ships with a ``speech`` field -- a short spoken-language string that the IVR
helpline and WhatsApp voice replies read aloud verbatim. It is written to be
*heard*, not read: short clauses, no numerals, no English jargon.

Design rules applied throughout:
  * Never show a bare percentage to an end user. It is available in ``confidence``
    for the API and for family/guardian dashboards, but the primary UI string is
    the verdict word.
  * Actions are imperative and physical ("block karein"), never abstract
    ("remain vigilant").
  * Every critical verdict offers to notify the family. The secrecy demand is the
    scammer's main weapon; reaching a family member is the structural counter.
  * Roman Urdu is the default, not Urdu script, because it is what people type and
    read on phones. Urdu script and English are provided for every verdict.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal

__all__ = ["Lang", "SUPPORTED_LANGS", "VerdictMessage", "render_verdict"]

Lang = Literal["roman", "urdu", "en", "sd", "pa", "ps", "bal"]

SUPPORTED_LANGS: tuple[Lang, ...] = ("roman", "urdu", "en", "sd", "pa", "ps", "bal")


# Verdict words. These are the single most important strings in the product --
# they must be unmistakable at a glance and when spoken aloud.
_VERDICT_WORD: dict[str, dict[Lang, str]] = {
    "critical": {
        "roman": "KHATRA! YE SCAM HAI",
        "urdu": "خطرہ! یہ دھوکہ دہی ہے",
        "en": "DANGER — THIS IS A SCAM",
        "sd": "خطرو! هي فراڊ آهي",
        "pa": "خطرہ! ایہہ فراڈ اے",
        "ps": "خطر! دا درغلۍ ده",
        "bal": "خطر! اے فریب این",
    },
    "scam": {
        "roman": "YE SCAM HAI",
        "urdu": "یہ دھوکہ دہی ہے",
        "en": "THIS IS A SCAM",
        "sd": "هي فراڊ آهي",
        "pa": "ایہہ فراڈ اے",
        "ps": "دا درغلۍ ده",
        "bal": "اے فریب این",
    },
    "suspicious": {
        "roman": "SHAK HAI — PAHLE TASDEEQ KAREIN",
        "urdu": "شبہ ہے — پہلے تصدیق کریں",
        "en": "SUSPICIOUS — VERIFY FIRST",
        "sd": "شڪ آهي — پهرين تصديق ڪريو",
        "pa": "شک اے — پہلاں تصدیق کرو",
        "ps": "شک دی — لومړی تصدیق وکړئ",
        "bal": "گمان اے — پہداں تصدیق بکنیت",
    },
    "safe": {
        "roman": "THEEK HAI",
        "urdu": "ٹھیک ہے",
        "en": "LOOKS SAFE",
        "sd": "ٺيڪ آهي",
        "pa": "ٹھیک اے",
        "ps": "سم دی",
        "bal": "درست اے",
    },
    "unknown": {
        "roman": "JANCH NA HO SAKI",
        "urdu": "جانچ نہ ہو سکی",
        "en": "COULD NOT CHECK",
        "sd": "جانچ نه ٿي سگهي",
        "pa": "جانچ نہ ہو سکی",
        "ps": "معاینه ونه شوه",
        "bal": "جانچ نه بوت",
    },
}

# Spoken form of the verdict. Written for ears: no numerals, no abbreviations.
_SPEECH_VERDICT: dict[str, dict[Lang, str]] = {
    "critical": {
        "roman": "Rukiye. Ye message bilkul fraud hai. Is ka jawab mat dein.",
        "urdu": "رکیے۔ یہ پیغام بالکل فراڈ ہے۔ اس کا جواب مت دیں۔",
        "en": "Stop. This message is definitely a fraud. Do not reply to it.",
        "sd": "بيھو. هي پيغام بلڪل فراڊ آهي. ان جو جواب نه ڏيو.",
        "pa": "رکو۔ ایہہ پیغام بالکل فراڈ اے۔ اس دا جواب نہ دیو۔",
        "ps": "ودرېږئ. دا پيغام په بشپړه توګه درغلۍ ده. ځواب ورته مه ورکوئ.",
        "bal": "بئستیت۔ اے پیغام پوری فریب این۔ جاںئہ مشو دیت۔",
    },
    "scam": {
        "roman": "Ye message fraud lagta hai. Is par amal na karein.",
        "urdu": "یہ پیغام فراڈ لگتا ہے۔ اس پر عمل نہ کریں۔",
        "en": "This message looks like a fraud. Do not act on it.",
        "sd": "هي پيغام فراڊ لڳي ٿو. ان تي عمل نه ڪريو.",
        "pa": "ایہہ پیغام فراڈ لگدا اے۔ اس تے عمل نہ کرو۔",
        "ps": "دا پيغام درغلۍ ښکاري. پرې عمل مه کوئ.",
        "bal": "اے پیغام فریب لگت۔ ائیشی عمل مشو کنت۔",
    },
    "suspicious": {
        "roman": "Is message mein kuch shubeh hai. Kisi bhi link par click karne se pahle tasdeeq karein.",
        "urdu": "اس پیغام میں کچھ شبہ ہے۔ کسی بھی لنک پر کلک کرنے سے پہلے تصدیق کریں۔",
        "en": "There is something doubtful in this message. Verify before clicking any link.",
        "sd": "هن پيغام ۾ ڪجهه شڪ آهي. ڪنهن به لنڪ تي ڪلڪ ڪرڻ کان اڳ تصديق ڪريو.",
        "pa": "اس پیغام چ کجھ شک اے۔ کسی وی لنک تے کلک کرن توں پہلاں تصدیق کرو۔",
        "ps": "په دې پيغام کې شک دی. د کوم لينک له پرانيستلو مخکې تصدیق وکړئ.",
        "bal": "اے پیغامئِ تا گمان اے۔ ہریک لنکئِ کلیلک کتن ءِ پہداں تصدیق بکنیت۔",
    },
    "safe": {
        "roman": "Is message mein koi bari khatarnak baat nazar nahi aayi.",
        "urdu": "اس پیغام میں کوئی بڑی خطرناک بات نظر نہیں آئی۔",
        "en": "Nothing seriously dangerous was found in this message.",
        "sd": "هن پيغام ۾ ڪا به وڏي خطرنڪ ڳالهه نظر نه آئي.",
        "pa": "اس پیغام چ کوئی وڈی خطرناک گل نظر نہ آئی۔",
        "ps": "په دې پيغام کې کوم لوی خطرناک شی ونه موندل شو.",
        "bal": "اے پیغامئِ تا هیچ گرین خطرناک گپ دیست نه بوت۔",
    },
    "unknown": {
        "roman": "Maaf kijiye, is message ki janch nahi ho saki. Kisi aur tareeqe se tasdeeq karein.",
        "urdu": "معاف کیجیے، اس پیغام کی جانچ نہ ہو سکی۔ کسی اور طریقے سے تصدیق کریں۔",
        "en": "Sorry, this message could not be checked. Please verify another way.",
        "sd": "معاف ڪجو, هن پيغام جي جانچ نه ٿي سگهي. ڪنهن ٻئي طريقي سان تصديق ڪريو.",
        "pa": "معاف کرنا، اس پیغام دی جانچ نہ ہو سکی۔ کسی ہور طریقے نال تصدیق کرو۔",
        "ps": "بښنه غواړو، د دې پيغام معاینه ونه شوه. د بلې لارې تصدیق وکړئ.",
        "bal": "بخشگ بکنیت، اے پیغامئِ جانچ نه بوت۔ دیگه راه ءِ تصدیق بکنیت۔",
    },
}


#: Explanations of WHY. These answer "kis bunyad par kaha ye scam hai?" and are
#: deliberately distinct from the action strings below -- a message that repeats
#: the same sentence as both a reason and an instruction reads as broken.
_REASONS: dict[str, dict[Lang, str]] = {
    "otp_exfiltration": {
        "roman": "Is mein aap se OTP ya code maanga gaya hai — koi bhi bank ya idara kabhi nahi maangta.",
        "urdu": "اس میں آپ سے او ٹی پی یا کوڈ مانگا گیا ہے — کوئی بھی بینک یا ادارہ کبھی نہیں مانگتا۔",
        "en": "It asks you for an OTP or code — no bank or institution ever asks for one.",
        "sd": "ان ۾ توهان کان او ٽي پي يا ڪوڊ گهريو ويو آهي — ڪو به بينڪ يا ادارو ڪڏهن نه گهرندو آهي.",
        "pa": "اس چ تواڈے توں او ٹی پی یا کوڈ منگیا گیا اے — کوئی وی بینک یا ادارا کدی نہیں منگدا۔",
        "ps": "ستاسو څخه OTP يا کوډ غوښتل شوی — هېڅ بينک يا اداره يې هېڅکله نه غواړي.",
        "bal": "شما ئِ او ٹی پی یا کوڈ پرسته — هچ بینک یا اداره ہرگز نه پرسیت۔",
    },
    "cnic_request": {
        "roman": "Is mein aap ka CNIC number ya tasveer maangi gayi hai.",
        "urdu": "اس میں آپ کا شناختی کارڈ نمبر یا تصویر مانگی گئی ہے۔",
        "en": "It asks for your CNIC number or photo.",
        "sd": "ان ۾ توهان جو شناختي ڪارڊ نمبر يا تصوير گهري وئي آهي.",
        "pa": "اس چ تواڈا شناختی کارڈ نمبر یا تصویر منگی گئی اے۔",
        "ps": "ستاسو د CNIC شمېره يا انځور غوښتل شوی دی.",
        "bal": "شما ئی شناختی کارڈ نمبر یا عکس پرسته۔",
    },
    "digital_arrest": {
        "roman": "Ye dhamki de raha hai ke aap ki giraftari ya case banne wala hai — asli idaray aisa kabhi phone par nahi karte.",
        "urdu": "یہ دھمکی دے رہا ہے کہ آپ کی گرفتاری یا کیس بننے والا ہے — اصلی ادارے ایسا کبھی فون پر نہیں کرتے۔",
        "en": "It threatens you with arrest or a case being filed — real institutions never do this over the phone.",
        "sd": "هي ڌمڪي ڏئي رهيو آهي ته توهان جي گرفتاري يا ڪيس ٺهڻ وارو آهي — اصل ادارا ائين ڪڏهن فون تي نه ڪندا آهن.",
        "pa": "ایہہ دھمکی دے ریہا اے کہ تواڈی گرفتاری یا کیس بنن آلا اے — اصلی ادارے ایویں کدی فون تے نہیں کردے۔",
        "ps": "تاسو ته د نيونې يا دوسيه د ګواښ خبره کوي — رښتينې ادارې دا هېڅکله د تيليفون له لارې نه کوي.",
        "bal": "اے شمارا گرفتاری یا کیسئِ ڈر دات — رستیں ادارے ائشی ہرگز ٹیلی فون ءِ نہ کنت۔",
    },
    "isolation_demand": {
        "roman": "Is mein kaha gaya hai ke aap kisi ko na batayein — ye hi sab se bari nishani hai.",
        "urdu": "اس میں کہا گیا ہے کہ آپ کسی کو نہ بتائیں — یہی سب سے بڑی نشانی ہے۔",
        "en": "It tells you not to inform anyone — that alone is the biggest warning sign.",
        "sd": "ان ۾ چيو ويو آهي ته ڪنهن کي نه ٻڌايو — اها ئي سڀ کان وڏي نشاني آهي.",
        "pa": "اس چ کیہا گیا اے کہ کسی نوں نہ دسو — ایہی سب توں وڈی نشانی اے۔",
        "ps": "تاسو ته ويل شوي چې چا ته مه وايئ — دا پخپله تر ټولو لویه خبرداره نښه ده.",
        "bal": "اے آتگه که کسئِ مشو آتیت — اےئے گرینیں نشان این۔",
    },
    "remote_access_request": {
        "roman": "Is mein koi remote-access app install karne ko kaha gaya hai — us se wo aap ki screen dekh kar har OTP padh lete hain.",
        "urdu": "اس میں کوئی ریموٹ ایکسیس ایپ انسٹال کرنے کو کہا گیا ہے — اس سے وہ آپ کی سکرین دیکھ کر ہر او ٹی پی پڑھ لیتے ہیں۔",
        "en": "It asks you to install a remote-access app — that lets them watch your screen and read every OTP.",
        "sd": "ان ۾ ڪا ريموٽ ايڪسيس ايپ انسٽال ڪرڻ لاءِ چيو ويو آهي — ان سان اهي توهان جي اسڪرين ڏسي هر او ٽي پي پڙهي وٺندا آهن.",
        "pa": "اس چ کوئی ریموٹ ایکسیس ایپ انسٹال کرن نوں کیہا گیا اے — اس نال اوہ تواڈی سکرین ویکھ کے ہر او ٹی پی پڑھ لیندے نے۔",
        "ps": "تاسو ته د ريموټ اپ اپليکيشن د نصبولو ويل شوي — دا دوی ته اجازه ورکوي ستاسو پرده وګوري او هر OTP ولولي.",
        "bal": "ریموٹ ایکسیس ایپ نصب کتنئِ آتگه — آیشان شما ئی اسکرین دیستگانت و ہر او ٹی پی واندگانت۔",
    },
    "suspicious_link": {
        "roman": "Is mein jo link hai wo ek shakkī website par jaata hai.",
        "urdu": "اس میں جو لنک ہے وہ ایک مشکوک ویب سائٹ پر جاتا ہے۔",
        "en": "The link in this message goes to a suspicious website.",
        "sd": "ان ۾ جيڪو لنڪ آهي اهو هڪ شڪي ويب سائيٽ تي وڃي ٿو.",
        "pa": "اس چ جو لنک اے اوہ اک شک ویب سائٹ تے جاندا اے۔",
        "ps": "په دې پيغام کې لينک يوه شکمنه ويبپاڼې ته ځي.",
        "bal": "اے پیغامئِ لنک یک گمانین ویب سائیٹ ءِ روت۔",
    },
    "typosquatting": {
        "roman": "Ye website ka naam asli idaray se milta julta hai, magar ye wo nahi — chor aisa hi karte hain.",
        "urdu": "یہ ویب سائٹ کا نام اصلی ادارے سے ملتے جلتے ہے، مگر یہ وہ نہیں — چور ایسا ہی کرتے ہیں۔",
        "en": "This website's name closely mimics a real institution's, but it is not theirs — this is a standard fraud tactic.",
        "sd": "هن ويب سائيٽ جو نالو اصل اداري سان مشابهه آهي، پر اهو نه آهي — چور ائين ئي ڪندا آهن.",
        "pa": "اس ویب سائٹ دا ناں اصلی ادارے نال رلدا ملدا اے، پر ایہہ اوہ نہیں — چور ایویں ای کردے نے۔",
        "ps": "د دې ويبپاڼې نوم يوې رښتينې ادارې ته ورته دی، خو دا هغه نه ده — دا د درغليو معموده تګلاره ده.",
        "bal": "اے ویب سائیٹئِ نام رستین ادارے ئی مشابہ این، ولی او نہ این — درین ائشیءِ کنت۔",
    },
    "verified_impersonation": {
        "roman": "Ye number us idaray ka nahi hai jis ka naam likha hai — asli number hamari registry mein maujood hai.",
        "urdu": "یہ نمبر اس ادارے کا نہیں ہے جس کا نام لکھا ہے — اصلی نمبر ہماری رجسٹری میں موجود ہے۔",
        "en": "This number does not belong to the institution named — we know the real one.",
        "sd": "هي نمبر انهي ادارو جو ناهي جنهن جو نالو لکيل آهي — اصل نمبر اسان جي رجسٽري ۾ موجود آهي.",
        "pa": "ایہہ نمبر اس ادارے دا نہیں جسدا ناں لکھیا اے — اصلی نمبر ساڈی رجسٹری چ موجود اے۔",
        "ps": "دا شمېره د نومول شوې ادارې نه ده — موږ اصلي شمېره پېژنو.",
        "bal": "اے نمبر آ نبشتگیں ادارے نہ این — رستیں نمبر مائی رجسٹری ءِ هست۔",
    },
    "domain_age": {
        "roman": "Ye website haal hi mein banai gayi hai — asli idaray ki site saalon purani hoti hai.",
        "urdu": "یہ ویب سائٹ حال ہی میں بنائی گئی ہے — اصلی ادارے کی سائٹ سالوں پرانی ہوتی ہے۔",
        "en": "This website was created very recently — real institutions have sites that are years old.",
        "sd": "هي ويب سائيٽ تازي ٺاهي وئي آهي — اصل اداري جي سائيٽ سالون پراڻي هوندي آهي.",
        "pa": "ایہہ ویب سائٹ ہنیری بنائی گئی اے — اصلی ادارے دی سائٹ سالاں پرانی ہوندی اے۔",
        "ps": "دا ويبپاڼه ډېره نوي جوړه شوې — رښتينې ادارې کلونه زوړې ويبپاڼې لري.",
        "bal": "اے ویب سائیٹ ہنوں سازگه بوته — رستین ادارے ئی سائیٹ سالان کوهن بیت۔",
    },
    "ssl": {
        "roman": "Is site par security certificate nahi hai — jo site khud ko mehfooz nahi rakhti, wo aap ko kya rakhegi.",
        "urdu": "اس سائٹ پر سیکیورٹی سرٹیفکیٹ نہیں ہے — جو سائٹ خود کو محفوظ نہیں رکھتی، وہ آپ کو کیا رکھے گی۔",
        "en": "This site has no security certificate — a site that does not secure itself cannot secure you.",
        "sd": "هن سائيٽ تي سيڪيورٽي سرٽيفڪيٽ ناهي — جيڪا سائيٽ پاڻ کي محفوظ نه ٿي رکي، اها توهان کي ڇا رکندو.",
        "pa": "اس سائٹ تے سیکورٹی سرٹیفکیٹ نہیں — جیہڑی سائٹ آپ نوں محفوظ نہیں رکھدی اوہ تواڈا کی رکھے گی۔",
        "ps": "دا ويبپاڼه د امنيت سند نه لري — هغه ويبپاڼه چې ځان نه ساتي، تاسو نه شي ساتلی.",
        "bal": "اے سائیٹئِ تا امنیتئِ سند نیست — جس سائیٹ وتں نه بچنت، شما ئِ چیاں بچنت۔",
    },
    "dns": {
        "roman": "Ye website mojood hi nahi hai — ye address kahin nahi jaata.",
        "urdu": "یہ ویب سائٹ موجود ہی نہیں ہے — یہ پتہ کہیں نہیں جاتا۔",
        "en": "This website does not exist at all — this address goes nowhere.",
        "sd": "هي ويب سائيٽ وجود ئي ناهي — هي پتو ڪٿي به نه ٿو وڃي.",
        "pa": "ایہہ ویب سائٹ ہے ای نہیں — ایہہ پتہ کتے وی نہیں جاندا۔",
        "ps": "دا ويبپاڼه په بشپړه توګه شتون نه لري — دا پته هېڅرته نه ځي.",
        "bal": "اے ویب سائیٹ هستی نہ این — اے پتہ ہرچ جا نہ روت۔",
    },
    "investment": {
        "roman": "Is mein paisay double ya ziyada munafay ka wada hai — aisa koi halal zariya nahi hota.",
        "urdu": "اس میں پیسے ڈبل یا زیادہ منافع کا وعدہ ہے — ایسا کوئی جائز ذریعہ نہیں ہوتا۔",
        "en": "It promises doubled money or outsized returns — no legitimate source does this.",
        "sd": "ان ۾ پئسا ڊبل يا وڌيڪ منافع جو واعدو آهي — اهڙو ڪو به جائز ذريعو نه هوندو آهي.",
        "pa": "اس چ پیسے ڈبل یا ودھ منافع دا وعدہ اے — ایہا کوئی جائز ذریعہ نہیں ہوندا۔",
        "ps": "د پيسو د دوه چنده يا ډېر ګټې ژمنه کوي — هېڅ قانوني سرچينه دا نه کوي.",
        "bal": "پولیں دوبر یا زیاں سودئِ وعدہ این — ائشین ہچ جائز راهہ نبیت۔",
    },
    "reward": {
        "roman": "Is mein inaam ya lottery jeetne ka dawa hai — aap ne kahin hissa hi nahi liya tha.",
        "urdu": "اس میں انعام یا لاٹری جیتنے کا دعویٰ ہے — آپ نے کہیں حصہ ہی نہیں لیا تھا۔",
        "en": "It claims you won a prize or lottery — you never entered any competition.",
        "sd": "ان ۾ انعام يا لاٽري کٽڻ جو دعويٰ آهي — توهان ڪٿي به حصو ئي نه ورتو هو.",
        "pa": "اس چ انعام یا لاٹری جتن دا دعوہ اے — تسیں کتے حصہ ای نہیں لیا سی۔",
        "ps": "وايي چې تاسو جايزه يا لاتاري ګټلې — تاسو هېڅ سيالۍ کې ګډون نه و کړی.",
        "bal": "انعام یا لاٹری بردئِ دعوہ این — شما ہرگے حصہ نه گرتە بوت۔",
    },
    "payment_demand": {
        "roman": "Is mein paisay bhejne ko kaha gaya hai taake 'masla hal' ho jaye — ye hi fraud ka maqsad hai.",
        "urdu": "اس میں پیسے بھیجنے کو کہا گیا ہے تاکہ 'مسئلہ حل' ہو جائے — یہی فراڈ کا مقصد ہے۔",
        "en": "It asks you to send money so the 'problem' is resolved — that is the entire purpose of the fraud.",
        "sd": "ان ۾ پئسا موڪلڻ لاءِ چيو ويو آهي ته جيئن 'مسئلو حل' ٿي وڃي — اهو ئي فراڊ جو مقصد آهي.",
        "pa": "اس چ پیسے بھیجن نوں کیہا گیا اے تاکہ 'مسئلہ حل' ہو جاوے — ایہی فراڈ دا مقصد اے۔",
        "ps": "پيسې غواړي چې ستونزه حل شي — دا د درغليو بشپړ موخه ده.",
        "bal": "پولیں ٹاکتنئِ آتگه تا 'مشکل' حل بوت — اےئے فریبئِ سراپا مقصد این۔",
    },
    "legal_threat": {
        "roman": "Is mein case, warrant ya giraftari ka zikr hai taake aap dar jayein.",
        "urdu": "اس میں کیس، وارنٹ یا گرفتاری کا ذکر ہے تاکہ آپ ڈر جائیں۔",
        "en": "It mentions a case, warrant, or arrest to frighten you.",
        "sd": "ان ۾ ڪيس، وارنٽ يا گرفتاري جو ذڪر آهي ته جيئن توهان ڊپو وڃو.",
        "pa": "اس چ کیس، وارنٹ یا گرفتاری دا ذکر اے تاکہ تسیں ڈر جاؤ۔",
        "ps": "د دوسيه، وارنټ يا نيونې يادونه کوي ترڅو تاسو وډار شي.",
        "bal": "کیس، وارنٹ یا گرفتاریءِ زکر این تا شما ئِ بترسیت۔",
    },
    "urgency": {
        "roman": "Is mein jaldi karne ka dabao dala gaya hai — sochne ka waqt na mile.",
        "urdu": "اس میں جلدی کرنے کا دباؤ ڈالا گیا ہے — سوچنے کا وقت نہ ملے۔",
        "en": "It pressures you to hurry, so you have no time to think.",
        "sd": "ان ۾ جلدي ڪرڻ جو دٻاءُ وڌو ويو آهي — سوچڻ جو وقت نه ملي.",
        "pa": "اس چ جلدی کرن دا دباؤ پایا گیا اے — سوچن دا ویلہ نہ ملے۔",
        "ps": "تاسو ته د بيړې فشار راوړل شوی — چې د فکر کولو وخت ونه لرئ.",
        "bal": "زوتک کتنئِ زور داته — پند کتنئِ وخت مشو ملت۔",
    },
}

#: Action steps keyed by the finding that triggered them. Ordered by how urgent
#: the action is -- the most time-critical step must always be first, because
#: users frequently only read step one.
_ACTIONS: dict[str, dict[Lang, str]] = {
    "otp_exfiltration": {
        "roman": "OTP ya code kabhi kisi ko mat dein — bank ya FIA kabhi nahi maangta.",
        "urdu": "او ٹی پی یا کوڈ کبھی کسی کو نہ دیں — بینک یا ایف آئی اے کبھی نہیں مانگتا۔",
        "en": "Never give an OTP or code to anyone — no bank or the FIA ever asks for one.",
        "sd": "او ٽي پي يا ڪوڊ ڪنهن کي به نه ڏيو — بينڪ يا ايف آءِ اي ڪڏهن نه پڇندو آهي.",
        "pa": "او ٹی پی یا کوڈ کسے نوں نہ دیو — بینک یا ایف آئی اے کدے نہیں منگدا۔",
        "ps": "هیڅکله OTP يا کوډ چا ته مه ورکوئ — بينک يا FIA يې هېڅکله نه غواړي.",
        "bal": "او ٹی پی یا کوڈ ہرگز کسئِ مشو دیت — بینک یا FIA ہرگز نہ پرسیت۔",
    },
    "digital_arrest": {
        "roman": "Phone foran kaat dein. Koi bhi idara video call par arrest nahi karta.",
        "urdu": "فون فوراً کاٹ دیں۔ کوئی بھی ادارہ ویڈیو کال پر گرفتار نہیں کرتا۔",
        "en": "Hang up immediately. No agency ever arrests anyone over a video call.",
        "sd": "فون فوراً ڪاٽيو. ڪو به ادارو وڊيو ڪال تي گرفتار نه ڪندو آهي.",
        "pa": "فون فوراً کٹ کرو۔ کوئی وی ادارا ویڈیو کال تے گرفتار نہیں کردا۔",
        "ps": "سمدستي تيليفون پرېږدئ. هېڅ اداره د ويډيو کال له لارې چا نه نيسي.",
        "bal": "ٹیلی فون زوتکیں بند کنت۔ ہرگے ادارے ویڈیو کال ءِ گرفتار نه کنت۔",
    },
    "remote_access_request": {
        "roman": "AnyDesk ya TeamViewer harگز install na karein — is se aap ka poora phone un ke hath mein chala jata hai.",
        "urdu": "AnyDesk یا TeamViewer ہرگز انسٹال نہ کریں — اس سے آپ کا پورا فون ان کے ہاتھ میں چلا جاتا ہے۔",
        "en": "Never install AnyDesk or TeamViewer — it hands them your entire phone.",
        "sd": "AnyDesk يا TeamViewer ڪڏهن به انسٽال نه ڪريو — ان سان توهان جو سڄو فون انهن جي هٿ ۾ هليو ويندو.",
        "pa": "AnyDesk یا TeamViewer کدی وی انسٹال نہ کرو — اس نال تواڈا پورا فون اوہناں دے ہتھ چلا جاندا۔",
        "ps": "AnyDesk يا TeamViewer هېڅکله مه نصبوئ — دا ستاسو ټول تيليفون دوی ته ورکوي.",
        "bal": "AnyDesk یا TeamViewer ہرگز نصب مشو کنت — ائیشیاں شما ئی سراپا ٹیلی فون آئیشانی دست ءِ چلنت۔",
    },
    "isolation_demand": {
        "roman": "Jo kahe 'kisi ko mat batana' — wahi asli chor hota hai. Apne ghar mein kisi ko abhi batayein.",
        "urdu": "جو کہے 'کسی کو مت بتانا' — وہی اصلی چور ہوتا ہے۔ اپنے گھر میں کسی کو ابھی بتائیں۔",
        "en": "Whoever says 'don't tell anyone' is the actual thief. Tell someone in your family right now.",
        "sd": "جيڪو چوي 'ڪنهن کي نه ٻڌائيندو' — اهو ئي اصل چور هوندو آهي. پنهنجي گهر ۾ ڪنهن کي هاڻي ٻڌايو.",
        "pa": "جیہدا آکھے 'کسی نوں نہ دسو' — اوہی اصلی چور ہوندا اے۔ اپنے گھر چ کسی نوں ہنے دسو۔",
        "ps": "هر څوک چې وايي 'چا ته مه وايه' — هغه رښتيا غل دی. همدا اوس خپل کورنۍ کې چا ته ووايئ.",
        "bal": "ہر کسے آت 'کسئِ مشو آتگانت' — اوئے رستین درینت۔ ہنوں اپنے لوکئِ کسئِ آت بکنیت۔",
    },
    "cnic_request": {
        "roman": "CNIC number ya tasveer kabhi mat bhejein.",
        "urdu": "شناختی کارڈ نمبر یا تصویر کبھی نہ بھیجیں۔",
        "en": "Never send your CNIC number or photo.",
        "sd": "شناختي ڪارڊ نمبر يا تصوير ڪڏهن به نه موڪليو.",
        "pa": "شناختی کارڈ نمبر یا تصویر کدی نہ بھیجو۔",
        "ps": "خپل CNIC شمېره يا انځور هېڅکله مه ليږئ.",
        "bal": "شناختی کارڈ نمبر یا عکس ہرگز مشو ٹاکت۔",
    },
    "suspicious_link": {
        "roman": "Link par click na karein. Bank ki asli website khud type karein.",
        "urdu": "لنک پر کلک نہ کریں۔ بینک کی اصلی ویب سائٹ خود ٹائپ کریں۔",
        "en": "Do not click the link. Type your bank's real website yourself.",
        "sd": "لنڪ تي ڪلڪ نه ڪريو. بينڪ جي اصل ويب سائيٽ پاڻ ٽائيپ ڪريو.",
        "pa": "لنک تے کلک نہ کرو۔ بینک دی اصلی ویب سائٹ خود ٹائپ کرو۔",
        "ps": "په لينک کلیک مه کوئ. د بينک اصلي ويبپاڼه پخپله وليکئ.",
        "bal": "لنکئِ کلیلک مشو کنت۔ بینکئِ رستیں ویب سائیٹ وت ٹایپ کنت۔",
    },
    "typosquatting": {
        "roman": "Ye website asli bank ki nahi — naam milta julta hai magar farqi hai.",
        "urdu": "یہ ویب سائٹ اصلی بینک کی نہیں — نام ملتے جلتے مگر مختلف ہے۔",
        "en": "This website is not the real bank's — the name is similar but different.",
        "sd": "هي ويب سائيٽ اصل بينڪ جي ناهي — نالو مشابهه پر مختلف آهي.",
        "pa": "ایہہ ویب سائٹ اصلی بینک دی نہیں — ناں رلدا ملدا پر وکھرا اے۔",
        "ps": "دا ويبپاڼه د اصلي بينک نه ده — نوم ورته دی خو توپير لري.",
        "bal": "اے ویب سائیٹ رستین بینکئِ نه این — نام مشابہ این ولی فرقی اے۔",
    },
    "verified_impersonation": {
        "roman": "Ye number us idaray ka nahi hai jis ka naam likha hai.",
        "urdu": "یہ نمبر اس ادارے کا نہیں ہے جس کا نام لکھا ہے۔",
        "en": "This number does not belong to the institution it claims to be.",
        "sd": "هي نمبر انهي ادارو جو ناهي جنهن جو نالو لکيل آهي.",
        "pa": "ایہہ نمبر اس ادارے دا نہیں جسدا ناں لکھیا اے۔",
        "ps": "دا شمېره د هغې ادارې نه ده چې نوم يې اخيستل شوی.",
        "bal": "اے نمبر آ ادارے نہ این جسئِ نام نبشتە بوته۔",
    },
    "domain_age": {
        "roman": "Ye website haal hi mein bani hai — asal idaray ki site purani hoti hai.",
        "urdu": "یہ ویب سائٹ حال ہی میں بنی ہے — اصلی ادارے کی سائٹ پرانی ہوتی ہے۔",
        "en": "This website was created very recently — real institutions have old sites.",
        "sd": "هي ويب سائيٽ تازي ٺهي آهي — اصل اداري جي سائيٽ پراڻي هوندي آهي.",
        "pa": "ایہہ ویب سائٹ ہنیری بنی اے — اصلی ادارے دی سائٹ پرانی ہوندی اے۔",
        "ps": "دا ويبپاڼه ډېره نوي جوړه شوې — اصلي ادارې زاړه ويبپاڼې لري.",
        "bal": "اے ویب سائیٹ ہنوں سازگه بوته — رستین ادارے ئی سائیٹ کوهن بیت۔",
    },
    "ssl": {
        "roman": "Is site par security certificate nahi hai — ye bharose ke laiq nahi.",
        "urdu": "اس سائٹ پر سیکیورٹی سرٹیفکیٹ نہیں ہے — یہ بھروسے کے لائق نہیں۔",
        "en": "This site has no security certificate — it cannot be trusted.",
        "sd": "هن سائيٽ تي سيڪيورٽي سرٽيفڪيٽ ناهي — هي ڀروسي جي لائق ناهي.",
        "pa": "اس سائٹ تے سیکورٹی سرٹیفکیٹ نہیں — ایہہ بھروسے دے لائق نہیں۔",
        "ps": "دا ويبپاڼه د امنيت سند نه لري — باوري نه شي کېدای.",
        "bal": "اے سائیٹئِ تا امنیتئِ سند نیست — باورئِ نه این۔",
    },
    "dns": {
        "roman": "Ye website mojood hi nahi hai — address ghalat hai.",
        "urdu": "یہ ویب سائٹ موجود ہی نہیں ہے — پتہ غلط ہے۔",
        "en": "This website does not even exist — the address is wrong.",
        "sd": "هي ويب سائيٽ وجود ئي ناهي — پتو غلط آهي.",
        "pa": "ایہہ ویب سائٹ ہے ای نہیں — پتہ غلط اے۔",
        "ps": "دا ويبپاڼه شتون هم نه لري — پته يې غلط دی.",
        "bal": "اے ویب سائیٹ هست نه این — پتە غلط این۔",
    },
    "investment": {
        "roman": "Paisay double karne wala koi scheme nahi hoti. Ye sab dhoka hai.",
        "urdu": "پیسے ڈبل کرنے والا کوئی اسکیم نہیں ہوتی۔ یہ سب دھوکہ ہے۔",
        "en": "There is no scheme that doubles your money. This is all fraud.",
        "sd": "پئسا ڊبل ڪرڻ واري ڪا اسڪيم نه هوندي آهي. هي سڀ ڌوکا آهي.",
        "pa": "پیسے ڈبل کرن آلی کوئی سکیم نہیں ہوندی۔ ایہہ سب دھوکا اے۔",
        "ps": "د پيسو د دوه چنده کولو هېڅ پلان شتون نه لري. دا ټول درغلۍ ده.",
        "bal": "پولیں دوبر کتنئِ هیچ اسکیم نبیت۔ اے سراپا فریب این۔",
    },
    "reward": {
        "roman": "Aap ne koi inaam nahi jeeta. Jo bina mehnat ke paisay de, wo chor hota hai.",
        "urdu": "آپ نے کوئی انعام نہیں جیتا۔ جو بغیر محنت کے پیسے دے، وہ چور ہوتا ہے۔",
        "en": "You have not won any prize. Anyone offering free money is a thief.",
        "sd": "توهان ڪو انعام نه کٽيو آهي. جيڪو بغير محنت جي پئسا ڏي اهو چور هوندو آهي.",
        "pa": "تسیں کوئی انعام نہیں جتے۔ جیہڑا بغیر محنت دے پیسے دیوے اوہ چور ہوندا اے۔",
        "ps": "تاسو هېڅ جايزه نه ده ګټلې. هر څوک چې وړيا پيسې وړانديز کوي غل دی.",
        "bal": "شما هچ انعام نه برده‌ئت۔ ہرکسے مفت پولیں دات، درینت۔",
    },
}

#: Actions that apply to every scam verdict regardless of specific findings.
_UNIVERSAL_ACTIONS: dict[Lang, list[str]] = {
    "roman": [
        "Sender ka number block karein.",
        "Agar paisay chalay gaye hain to foran apne bank ko call karein.",
        "Shikayat ke liye PTA ko 9000 par SMS bhejein ya NCCIA 1930 par call karein.",
    ],
    "urdu": [
        "بھیجنے والے کا نمبر بلاک کریں۔",
        "اگر پیسے چلے گئے ہیں تو فوراً اپنے بینک کو کال کریں۔",
        "شکایت کے لیے پی ٹی اے کو 9000 پر ایس ایم ایس بھیجیں یا این سی سی آئی اے 1930 پر کال کریں۔",
    ],
    "en": [
        "Block the sender's number.",
        "If money was transferred, call your bank immediately.",
        "To report: SMS the PTA on 9000, or call NCCIA on 1930.",
    ],
    "sd": [
        "موڪليندڙ جو نمبر بلاڪ ڪريو.",
        "جيڪڏهن پئسا ويا آهن ته فوراً پنهنجي بينڪ کي ڪال ڪريو.",
        "شڪايت لاءِ پي ٽي اي کي 9000 تي ايس ايم ايس موڪليو يا اين سي سي آءِ اي 1930 تي ڪال ڪريو.",
    ],
    "pa": [
        "بھیجن والے دا نمبر بلاک کرو۔",
        "جے پیسے چلے گئے نے تاں فوراً اپنے بینک نوں کال کرو۔",
        "شکایت لئی پی ٹی اے نوں 9000 تے SMS بھیجو یا NCCIA 1930 تے کال کرو۔",
    ],
    "ps": [
        "د ليږونکي شمېره بنده کړئ.",
        "که پيسې ليږدول شوي وي سمدستي خپل بينک ته زنګ ووهئ.",
        "د شکايت لپاره: PTA ته په 9000 پيغام واستوئ، يا NCCIA ته په 1930 زنګ ووهئ.",
    ],
    "bal": [
        "ٹاکتوکیں نمبر بند کنت۔",
        "پولیں ٹاکه بوته انت تہا وتے بینکئِ زوتکیں کال کنت۔",
        "شکایت ءِ PTA 9000 ءِ SMS ٹاکت یا NCCIA 1930 ءِ کال کنت۔",
    ],
}

#: Section headers for the rendered message. These must be localized too -- an
#: Urdu-script message with Roman Urdu headers reads as half-translated.
_HEADERS: dict[str, dict[Lang, str]] = {
    "why": {
        "roman": "Kyun:",
        "urdu": "وجہ:",
        "en": "Why:",
        "sd": "ڇو:",
        "pa": "کیوں:",
        "ps": "ولې:",
        "bal": "چرا:",
    },
    "actions": {
        "roman": "Abhi kya karein:",
        "urdu": "ابھی کیا کریں:",
        "en": "What to do right now:",
        "sd": "هاڻي ڇا ڪريو:",
        "pa": "ہنے کی کرو:",
        "ps": "همدا اوس څه وکړئ:",
        "bal": "ہنوں چیاں بکنیت:",
    },
    "family_notified": {
        "roman": "Aap ke family group ko bhi inform kar diya gaya hai.",
        "urdu": "آپ کے فیملی گروپ کو بھی مطلع کر دیا گیا ہے۔",
        "en": "Your family group has also been informed.",
        "sd": "توهان جي فيملي گروپ کي به آگاهه ڪيو ويو آهي.",
        "pa": "تواڈے فیملی گروپ نوں وی دس دتا گیا اے۔",
        "ps": "ستاسو د کورنۍ ډله هم خبره شوه.",
        "bal": "شما ئی خاندانئِ ٹولار ہم باخبر بوت۔",
    },
}

_FAMILY_NUDGE: dict[Lang, str] = {
    "roman": "Ye paighaam apne ghar ke kisi naujawan ko bhejein — akele faisla na karein.",
    "urdu": "یہ پیغام اپنے گھر کے کسی نوجوان کو بھیجیں — اکیلے فیصلہ نہ کریں۔",
    "en": "Send this to a younger member of your family — do not decide alone.",
    "sd": "هي پيغام پنهنجي گهر جي ڪنهن نوجوان کي موڪليو — اڪيلي فيصلو نه ڪريو.",
    "pa": "ایہہ پیغام اپنے گھر دے کسی نوجوان نوں بھیجو — اکلے فیصلہ نہ کرو۔",
    "ps": "دا پيغام خپلې کورنۍ يو ځوان غړي ته وليږئ — په يوازې توګه پريکړه مه کوئ.",
    "bal": "اے پیغام وتے لوکئِ جوانیں کسئِ ٹاکت — وتینیءِ فيصله مشو کنت۔",
}


class VerdictMessage:
    """A fully localized, ready-to-send verdict.

    Attributes:
        verdict_word: the big, unmistakable headline ("YE SCAM HAI").
        speech: text written to be *heard* — used by the IVR helpline and
            WhatsApp voice replies. No numerals, no abbreviations.
        reasons: concrete explanations, one per finding.
        actions: numbered imperative steps, most time-critical first.
        family_nudge: prompt to involve a family member, present on every
            non-safe verdict because isolation is the scammer's main weapon.
        show_confidence: whether the UI should render the numeric score. True
            only for ``guardian`` audiences (the family member watching over an
            elder) and never in the plain-language consumer view.
    """

    def __init__(
        self,
        *,
        label: str,
        lang: Lang,
        confidence: int,
        verdict_word: str,
        speech: str,
        reasons: list[str],
        actions: list[str],
        family_nudge: str | None,
        show_confidence: bool = False,
        notify_family: bool = False,
        escalate: bool = False,
    ) -> None:
        self.label = label
        self.lang = lang
        self.confidence = confidence
        self.verdict_word = verdict_word
        self.speech = speech
        self.reasons = reasons
        self.actions = actions
        self.family_nudge = family_nudge
        self.show_confidence = show_confidence
        self.notify_family = notify_family
        self.escalate = escalate

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "language": self.lang,
            "confidence": self.confidence,
            "show_confidence": self.show_confidence,
            "verdict_word": self.verdict_word,
            "speech": self.speech,
            "reasons": self.reasons,
            "actions": self.actions,
            "family_nudge": self.family_nudge,
            "notify_family": self.notify_family,
            "escalate": self.escalate,
        }

    def as_whatsapp_text(self) -> str:
        """Render as a plain-text WhatsApp message.

        WhatsApp renders no HTML and strips most formatting, so this uses emoji
        anchors and short lines. Emoji are not decoration here: for a
        low-literacy reader the colour-coded symbol carries the verdict on its
        own, before any text is read.
        """
        icon = {"critical": "🚨", "scam": "🚨", "suspicious": "⚠️", "safe": "✅", "unknown": "❓"}.get(
            self.label, "❓"
        )
        lines = [f"{icon} *{self.verdict_word}*"]
        if self.reasons:
            lines.append("")
            lines.append(f"*{_HEADERS['why'][self.lang]}*")
            lines.extend(f"• {r}" for r in self.reasons)
        if self.actions:
            lines.append("")
            lines.append(f"*{_HEADERS['actions'][self.lang]}*")
            lines.extend(f"{i}. {a}" for i, a in enumerate(self.actions, 1))
        if self.family_nudge:
            lines.append("")
            lines.append(f"👨‍👩‍👧 {self.family_nudge}")
        if self.notify_family:
            lines.append("")
            lines.append(f"🔔 {_HEADERS['family_notified'][self.lang]}")
        return "\n".join(lines)


def _resolve_lang(lang: str | None) -> Lang:
    if not lang:
        return "roman"
    low = lang.strip().lower()
    # Map the codes the rest of the codebase uses onto our render set.
    aliases = {
        "roman_urdu": "roman",
        "roman-urdu": "roman",
        "ru": "roman",
        "ur": "urdu",
        "ur-pk": "urdu",
        "en": "en",
        "eng": "en",
        "sd": "sd",
        "pa": "pa",
        "ps": "ps",
        "pus": "ps",
        "bal": "bal",
        "brh": "bal",
    }
    resolved = aliases.get(low, low)
    return resolved if resolved in SUPPORTED_LANGS else "roman"


def render_verdict(
    *,
    label: str,
    risk_factors: Iterable[str] = (),
    critical_indicators: Iterable[str] = (),
    confidence: int = 0,
    lang: str | None = "roman",
    audience: Literal["consumer", "guardian"] = "consumer",
    is_critical: bool = False,
) -> VerdictMessage:
    """Turn a machine verdict into something a person can act on.

    Args:
        label: one of critical / scam / suspicious / safe / unknown.
        risk_factors: analyzer finding keys, e.g. ``["otp_exfiltration", "ssl"]``.
        critical_indicators: dispositive overrides from the scoring engine.
        confidence: 0-100 numeric score. Only surfaced when ``audience`` is
            ``guardian``.
        lang: target language code. Unknown codes fall back to Roman Urdu, which
            is the widest-reaching written form in Pakistan.
        audience: ``consumer`` is the person who may be getting scammed — they get
            plain language and no numbers. ``guardian`` is the family member
            watching over them — they get the numeric score and module detail,
            because they are the one who needs to judge severity.
        is_critical: force critical handling (family notification, escalation).

    Returns:
        A :class:`VerdictMessage` ready to render on any channel.
    """
    resolved = _resolve_lang(lang)
    factors = list(dict.fromkeys([*critical_indicators, *risk_factors]))

    label_key = label if label in _VERDICT_WORD else "unknown"

    # Reasons EXPLAIN ("kis bunyad par kaha ye scam hai?"); actions INSTRUCT
    # ("abhi kya karein?"). They are deliberately separate string tables -- a
    # message that repeats the same sentence as both a reason and an instruction
    # reads as broken to a low-literacy user.
    #
    # Both lists follow the same priority order, because the most dangerous
    # finding is both the most important explanation and the most urgent action,
    # and users frequently only read the first item of each.
    priority = [
        "digital_arrest",
        "remote_access_request",
        "otp_exfiltration",
        "isolation_demand",
        "cnic_request",
        "typosquatting",
        "verified_impersonation",
        "suspicious_link",
        "payment_demand",
        "legal_threat",
    ]
    ordered_factors = [f for f in priority if f in factors] + [f for f in factors if f not in priority]

    reasons = [_REASONS[f][resolved] for f in ordered_factors if f in _REASONS]
    if not reasons:
        # No recognizable finding -- fall back to the overall verdict sentence,
        # which is still written to be spoken and understood.
        reasons = [_SPEECH_VERDICT[label_key][resolved]]

    ordered: list[str] = []
    for key in ordered_factors:
        if key in _ACTIONS:
            candidate = _ACTIONS[key][resolved]
            if candidate not in ordered:
                ordered.append(candidate)

    if label_key in ("critical", "scam"):
        for step in _UNIVERSAL_ACTIONS[resolved]:
            if step not in ordered:
                ordered.append(step)

    # A list longer than five steps is a list nobody finishes.
    ordered = ordered[:5]
    reasons = reasons[:5]

    escalate = bool(is_critical or label_key == "critical")
    notify_family = escalate or "isolation_demand" in factors or "digital_arrest" in factors

    family_nudge = None
    if label_key != "safe":
        family_nudge = _FAMILY_NUDGE[resolved]

    return VerdictMessage(
        label=label_key,
        lang=resolved,
        confidence=confidence,
        verdict_word=_VERDICT_WORD[label_key][resolved],
        speech=_SPEECH_VERDICT[label_key][resolved],
        reasons=reasons[:5],
        actions=ordered,
        family_nudge=family_nudge,
        # Consumers never see a bare percentage -- it is not actionable for them.
        # Guardians do, because they are triaging on someone else's behalf.
        show_confidence=(audience == "guardian"),
        notify_family=notify_family,
        escalate=escalate,
    )
