import asyncio
import base64
import os
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

from haafiz.core.ssrf import SSRFError, assert_public_url
from haafiz.intel.domain_similarity import (
    BrandImpersonationDetector,
    load_brands_from_file,
)

# The verified institutional registry: every Pakistani bank, telco, wallet,
# regulator and marketplace whose official domains we have confirmed. This
# replaces a hardcoded nine-domain subset, which could not tell a genuine HBL
# subsidiary from an impersonator. Overridable for tests and for deployments
# that ship a curated private list. See docs/DETECTION.md.
_REGISTRY_PATH = os.environ.get(
    "HAAFIZ_VERIFIED_DOMAINS",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "data", "verified_domains.txt"),
)

_detector = None


def get_detector():
    """Lazily build and cache the brand detector.

    Loading at import time would make the whole AI service fail to boot when
    the data file is missing, and the website analyzer is only one of several
    endpoints. A missing registry degrades to "no brand signal" instead.
    """
    global _detector
    if _detector is None:
        brands = load_brands_from_file(_REGISTRY_PATH)
        for problem in BrandImpersonationDetector(brands).validate_registry():
            print(f"[website_analyzer] registry problem: {problem}")
        _detector = BrandImpersonationDetector(brands)
    return _detector

async def analyze_website(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"
    
    findings = []
    url_risk = 0

    # 0. SSRF guard -- BEFORE any network access.
    #
    # Everything below resolves and connects to a hostname supplied by an
    # unauthenticated caller. Without this guard the analyzer is an open proxy
    # into the host network: submit http://169.254.169.254/ and the cloud
    # metadata service answers; submit http://localhost:6379/ and it reaches
    # whatever is listening on the loopback. assert_public_url resolves the
    # name itself and rejects private, loopback, link-local and reserved
    # ranges, so DNS rebinding onto an internal address is caught too.
    try:
        assert_public_url(url)
    except SSRFError as exc:
        findings.append({
            "type": "ssrf",
            "detail": f"URL internal/private network ki taraf ishara karta hai: {exc}",
            "severity": "critical",
        })
        return {
            "risk_score": 100,
            "is_safe": False,
            "verdict": "BLOCKED",
            "findings": findings,
            "url": url,
            "domain": domain,
        }

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
        except (ssl.SSLError, ssl.CertificateError, socket.timeout,
                socket.gaierror, OSError) as exc:
            # A bare `except:` here swallowed KeyboardInterrupt and SystemExit
            # as well as the real error, and discarded the reason entirely, so
            # a certificate problem and a dead network looked identical.
            ssl_error = f"{type(exc).__name__}: {exc}"
        if not ssl_valid:
            url_risk += 20
            detail = "Invalid or missing SSL certificate"
            if locals().get("ssl_error"):
                detail = f"{detail} ({ssl_error})"
            findings.append({"type": "ssl", "detail": detail, "severity": "medium"})
    else:
        findings.append({"type": "ssl", "detail": "SSL check skipped - domain does not resolve", "severity": "low"})
    
    # 4. Brand impersonation -- see haafiz/intel/domain_similarity.py
    #
    # The previous check was `levenshtein(registered_domain, known) <= 2` over
    # nine hardcoded domains. A fixed edit-distance budget is wrong for short
    # brands: with distance <= 2 the three-letter "UBL" matched a large slice
    # of the alphabet, while "nbp.com.pk" is four edits from "hbl.com.pk" so it
    # matched nothing at all. The detector scales its tolerance to the brand's
    # length and checks five impersonation techniques rather than substitution
    # alone, against a 74-institution registry instead of nine hardcoded names.
    assessment = get_detector().assess(domain)
    if assessment.suspicious:
        url_risk += int(round(assessment.risk * 40))
        brand = assessment.impersonated_brand or "aik verified institution"
        reason = assessment.evidence[0] if assessment.evidence else "domain verified brand se milta julta hai"
        findings.append({
            "type": "brand_impersonation",
            "detail": f"{brand} ki naqal: {reason}",
            "severity": "critical",
            "techniques": assessment.techniques,
            "risk": assessment.risk,
        })
    
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

# NOTE: the local ``levenshtein`` helper that used to live here is gone. It was
# dead once brand matching moved to haafiz.intel.domain_similarity, which uses
# Damerau-Levenshtein (transpositions count as one edit, not two) and scales its
# tolerance to the brand's length. Keeping a second, weaker copy around invited
# someone to use the wrong one.