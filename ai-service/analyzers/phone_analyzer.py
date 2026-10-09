import re
import sqlite3
import os

DB_PATH = os.getenv('DB_PATH', '../backend/haafiz.db')

def normalize_phone(phone):
    # Remove spaces, dashes, parentheses
    phone = re.sub(r'[\s\-\(\)]', '', phone)
    if phone.startswith('+92'):
        phone = '0' + phone[3:]
    elif phone.startswith('92'):
        phone = '0' + phone[2:]
    return phone

def analyze_phone(phone_number):
    normalized = normalize_phone(phone_number)
    # Connect to backend SQLite DB (assumes shared volume or path)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM phone_reputation WHERE phone_number = ?', (normalized,))
        row = cursor.fetchone()
        conn.close()
        if row:
            risk_score = row[3]  # risk_score column
            report_count = row[2]
            scam_types = row[4].split(',') if row[4] else []
            return {
                "phone_number": normalized,
                "reputation_score": risk_score,
                "report_count": report_count,
                "scam_types": scam_types,
                "last_reported": row[5],
                "risk_level": 'critical' if risk_score >= 80 else 'high' if risk_score >= 60 else 'medium' if risk_score >= 30 else 'low'
            }
    except Exception as e:
        pass
    
    # Pattern analysis
    risk_score = 10
    if re.fullmatch(r'0\d{10}', normalized):
        # Check sequential/repeated patterns
        if normalized[1:] in ['0000000000', '1111111111', '2222222222', '3333333333', '4444444444', '5555555555', '6666666666', '7777777777', '8888888888', '9999999999']:
            risk_score += 20
        elif len(set(normalized[3:])) <= 3:
            risk_score += 10
    else:
        risk_score = 30  # invalid format
    
    return {
        "phone_number": normalized,
        "reputation_score": risk_score,
        "report_count": 0,
        "scam_types": [],
        "last_reported": None,
        "risk_level": 'low' if risk_score < 30 else 'medium'
    }