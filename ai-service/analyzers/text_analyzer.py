import os
import json
import re
import joblib
from pathlib import Path

# Load model if exists, else fallback to heuristic
MODEL_PATH = os.getenv("MODEL_PATH", "./models/scam_detector.pkl")
KEYWORDS_PATH = os.getenv("KEYWORDS_PATH", "./data/scam_keywords.json")

# Load keywords
keywords = {}
if Path(KEYWORDS_PATH).exists():
    with open(KEYWORDS_PATH, 'r', encoding='utf-8') as f:
        keywords = json.load(f)

def load_model():
    if Path(MODEL_PATH).exists():
        return joblib.load(MODEL_PATH)
    return None

model = load_model()

def detect_language(text):
    # Simple script detection
    if re.search(r'[\u0600-\u06FF]', text):
        # Arabic script: could be Urdu, Sindhi, Balochi, Punjabi (Shahmukhi)
        return 'ur'
    if re.search(r'[\u0A00-\u0A7F]', text):
        return 'pa'  # Gurmukhi
    # Latin script: could be English or Roman Urdu. Previously both were
    # lumped together as 'roman', which meant plain English text (e.g. OCR'd
    # from an English scam SMS/image) was always checked against the
    # roman_urdu keyword set instead of the english one. Use a lightweight
    # marker-word heuristic to tell them apart.
    roman_urdu_markers = [
        ' hai', ' hain', ' ho', ' ka ', ' ki ', ' ke ', ' aap', ' ap ',
        ' kya', ' nahi', ' nahin', ' mein', ' se ', ' bhi ', ' keren',
        ' karein', ' bhejo', ' bhejein', ' foran', ' abhi ', ' turant',
    ]
    lowered = f' {text.lower()} '
    if any(marker in lowered for marker in roman_urdu_markers):
        return 'roman'
    return 'en'

# Maps the short language codes used by detect_language()/the frontend
# (en, ur, roman, sd, pa, bal) to the keyword-set keys used in
# scam_keywords.json (english, urdu, roman_urdu, sindhi, punjabi, balochi).
# Without this mapping, `lang in keywords` never matched and every
# language silently fell back to the roman_urdu keyword set.
LANGUAGE_KEYWORD_MAP = {
    'en': 'english',
    'ur': 'urdu',
    'roman': 'roman_urdu',
    'sd': 'sindhi',
    'pa': 'punjabi',
    'bal': 'balochi',
}

def analyze_text(text, language='auto'):
    lang = language if language != 'auto' else detect_language(text)
    
    # If model available, get base confidence
    base_confidence = 0
    if model:
        proba = model.predict_proba([text])[0][1]
        base_confidence = int(proba * 100)
    
    # Keyword matching boost
    boost = 0
    risk_factors = []
    matched_keywords = []
    
    # Choose keyword set based on language
    kw_key = LANGUAGE_KEYWORD_MAP.get(lang)
    if kw_key and kw_key in keywords:
        kw_set = keywords[kw_key]
    else:
        # fallback to roman urdu
        kw_set = keywords.get('roman_urdu', {})
    
    for category, words in kw_set.items():
        for word in words:
            if word.lower() in text.lower():
                boost += 25
                matched_keywords.append(word)
                if category not in risk_factors:
                    risk_factors.append(category)
                break  # one match per category for risk factor
    
    # Cap raised from 30 -> 90: with no trained ML model present (the common
    # case, since models/scam_detector.pkl isn't shipped by default),
    # base_confidence is 0 and keyword matches were the ONLY signal. A cap of
    # 30 meant confidence could never reach the is_scam threshold (60) no
    # matter how many scam indicators were found - every scan was silently
    # always "safe". Raising both the per-category boost and this cap lets
    # the keyword heuristic function as a real standalone detector.
    boost = min(boost, 90)
    confidence = min(base_confidence + boost, 100)
    
    # Pakistani-specific checks (applied regardless of language)
    cnic_pattern = r'\d{5}-\d{7}-\d{1}'
    phone_pattern = r'03\d{2}-\d{7}'
    if re.search(cnic_pattern, text):
        risk_factors.append('cnic_request')
        confidence += 15
        matched_keywords.append('CNIC')
    if re.search(phone_pattern, text):
        risk_factors.append('phone_request')
        confidence += 15
        matched_keywords.append('Phone number')

    # Suspicious link check: a URL's own riskiness (cheap/unusual TLDs that
    # are heavily abused for phishing, since they're nearly free and
    # anonymous to register) is a strong signal on its own, independent of
    # wording - important for image/text scans of SMS phishing messages
    # that just say "pay via <link>" without any classic CNIC/OTP wording.
    suspicious_tlds = {'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click',
                        'work', 'live', 'info', 'loan', 'win', 'bid',
                        'review', 'stream', 'date', 'racing', 'accountant'}
    for url_match in re.findall(r'https?://[^\s]+', text):
        domain_match = re.search(r'https?://(?:www\.)?([^/\s]+)', url_match)
        if domain_match:
            host = domain_match.group(1).lower()
            tld = host.split('.')[-1]
            if tld in suspicious_tlds:
                risk_factors.append('suspicious_link')
                confidence += 40
                matched_keywords.append(url_match)

    is_scam = confidence >= 60
    explanation = "This message contains scam indicators." if is_scam else "No significant scam indicators found."
    if risk_factors:
        explanation = f"This message contains {len(risk_factors)} scam indicators: {', '.join(risk_factors)}."
    
    return {
        "is_scam": is_scam,
        "confidence": min(confidence, 100),
        "risk_factors": list(set(risk_factors)),
        "explanation": explanation,
        "matched_keywords": matched_keywords,
        "language_detected": lang
    }