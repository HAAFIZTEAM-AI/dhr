import asyncio
import base64
import ssl
import socket
import whois
import tldextract
from urllib.parse import urlparse
import dns.resolver
from datetime import datetime, timedelta
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import re

async def analyze_website(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"
    
    findings = []
    url_risk = 0

    # 1. DNS resolution - check this FIRST. A domain that doesn't resolve at
    # all doesn't exist / isn't routable, which is a strong standalone
    # red flag on its own (real businesses don't have broken DNS). Treat
    # it decisively rather than as one of several weak, easily-diluted
    # signals, and skip the WHOIS/SSL/crawl steps below since they would
    # just fail or time out against a domain that isn't there.
    dns_resolves = True
    try:
        dns.resolver.resolve(domain, 'A')
    except Exception:
        dns_resolves = False
        url_risk += 60
        findings.append({"type": "dns", "detail": "Domain does not resolve - it does not appear to exist", "severity": "high"})

    # 2. Domain age via WHOIS
    domain_age_days = None
    if dns_resolves:
        try:
            w = whois.whois(registered_domain)
            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                domain_age_days = (datetime.now() - creation_date).days
                if domain_age_days < 30:
                    url_risk += 30
                    findings.append({"type": "domain_age", "detail": f"Domain registered {domain_age_days} days ago", "severity": "high"})
                elif domain_age_days < 90:
                    url_risk += 15
                    findings.append({"type": "domain_age", "detail": f"Domain registered {domain_age_days} days ago", "severity": "medium"})
        except Exception as e:
            url_risk += 10
            findings.append({"type": "whois", "detail": "WHOIS lookup failed", "severity": "low"})
    else:
        findings.append({"type": "whois", "detail": "WHOIS lookup skipped - domain does not resolve", "severity": "low"})

    # 3. SSL check
    ssl_valid = False
    if dns_resolves:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_valid = True
                    # Check self-signed (basic)
                    if not cert.get('issuer'):
                        ssl_valid = False
        except:
            pass
        if not ssl_valid:
            url_risk += 20
            findings.append({"type": "ssl", "detail": "Invalid or missing SSL certificate", "severity": "medium"})
    else:
        findings.append({"type": "ssl", "detail": "SSL check skipped - domain does not resolve", "severity": "low"})
    
    # 4. Typosquatting check against known Pakistani domains
    known_domains = ['hbl.com', 'ubl.com.pk', 'meezanbank.com', 'jazzcash.com.pk', 'easypaisa.com.pk',
                     'alliedbank.com.pk', 'alfalah.com', 'nbp.com.pk', 'statebank.com.pk']
    for known in known_domains:
        # Simple Levenshtein distance
        if levenshtein(registered_domain, known) <= 2 and registered_domain != known:
            url_risk += 30
            findings.append({"type": "typosquatting", "detail": f"Domain resembles {known}", "severity": "critical"})
            break
    
    # 5. Crawl if not already obvious scam and the domain actually resolves
    screenshot_base64 = None
    content_risk = 0
    if dns_resolves and url_risk < 80:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
                page = await browser.new_page()
                response = await page.goto(url, timeout=10000)
                final_url = page.url
                # Check redirects
                if final_url != url:
                    findings.append({"type": "redirect", "detail": f"Redirected to {final_url}", "severity": "medium"})
                    url_risk += 10
                # Screenshot
                screenshot = await page.screenshot(full_page=True)
                screenshot_base64 = base64.b64encode(screenshot).decode('utf-8')
                # Get HTML content
                content = await page.content()
                soup = BeautifulSoup(content, 'html.parser')
                # Check for login forms
                forms = soup.find_all('form')
                if forms:
                    for form in forms:
                        inputs = form.find_all('input')
                        for inp in inputs:
                            if inp.get('type') in ['password', 'text'] and 'otp' in (inp.get('name') or '').lower():
                                content_risk += 30
                                findings.append({"type": "form", "detail": "OTP input detected", "severity": "critical"})
                                break
                # Check for bank keywords
                text_content = soup.get_text().lower()
                bank_keywords = ['hbl', 'ubl', 'meezan', 'jazzcash', 'easypaisa', 'alfalah', 'bank al habib', 'login', 'account']
                for kw in bank_keywords:
                    if kw in text_content:
                        content_risk += 10
                        break
                # Check for obfuscated JS
                scripts = soup.find_all('script')
                for script in scripts:
                    if 'eval(' in script.text or 'document.write' in script.text:
                        content_risk += 20
                        findings.append({"type": "obfuscated_js", "detail": "Suspicious JavaScript detected", "severity": "high"})
                        break
                await browser.close()
        except Exception as e:
            findings.append({"type": "crawl_error", "detail": f"Could not crawl website: {str(e)[:100]}", "severity": "low"})
    
    # Combine risks. When the crawl step was skipped - either because
    # url_risk was already high, or because the domain doesn't even
    # resolve - content_risk stays 0 and the weighted formula would
    # otherwise under-report confidence (e.g. url_risk=80 -> ~32, or a
    # non-existent domain's url_risk=60 -> ~24). In those cases, trust the
    # url-based signal directly instead of diluting it with a content
    # score that was never actually measured.
    if url_risk >= 80 or not dns_resolves:
        confidence = min(100, url_risk)
    else:
        confidence = min(100, int(url_risk * 0.4 + content_risk * 0.6))
    is_scam = confidence >= 60
    
    return {
        "is_scam": is_scam,
        "confidence": confidence,
        "screenshot_base64": screenshot_base64,
        "findings": findings,
        "domain_age_days": domain_age_days,
        "ssl_valid": ssl_valid,
        "url_risk": url_risk,
        "content_risk": content_risk
    }

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]