"""URL Explanation & Prediction Formatting Module.

Extracts human-explainable lexical and structural indicators matching
the LureLock research design, and formats predictions consistently across the
Interactive CLI, Web UI, and Chrome Extension.
All keyword lists, shorteners, and trusted domains are loaded from external datasets.
"""

import re
import sys
from urllib.parse import urlparse
from .feature_extractor import (
    load_keywords,
    load_shorteners,
    normalize_url,
    calculate_shannon_entropy
)
from .domain_utils import is_trusted_domain, get_apex_domain

# Verdict definitions mapped to risk thresholds
VERDICTS = {
    'safe': ('Likely Legitimate', 'The model identified no typical phishing signatures in this link structure.'),
    'warn': ('Suspicious URL Structure', 'Contains irregular structural patterns frequently observed in phishing attacks.'),
    'bad': ('High Risk Phishing Detected', 'High probability of malicious impersonation, spoofing, or deceptive redirection.')
}


def describe_url(url: str) -> list[dict]:
    """Generates the static lexical and structural breakdown displayed
    in the LureLock Web UI and Chrome Extension popup.
    
    Extracts 11 explainable security indicators:
      1. URL character length
      2. Domain character length
      3. Subdomain nesting count
      4. Path directory depth
      5. Special character frequency
      6. Digit character count
      7. Host type (Domain name vs bare IP address)
      8. Suspicious keywords (from external dataset)
      9. Character entropy (randomness score)
     10. Protocol scheme (HTTPS vs HTTP)
     11. URL shortener service detection (from external dataset)
    """
    clean_url = normalize_url(url)
    try:
        parsed = urlparse(clean_url)
        host = (parsed.hostname or parsed.netloc.split(':')[0] or "").lower()
        path = parsed.path or "/"
        scheme = parsed.scheme.lower()
    except Exception:
        host, path, scheme = "", "/", "https"

    kws_dataset = load_keywords()
    shorts_dataset = load_shorteners()
    trusted = is_trusted_domain(clean_url)
    apex = get_apex_domain(clean_url)

    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    labels = host.split(".") if host else []
    subs = 0 if is_ip else max(0, len(labels) - 2)
    depth = len([p for p in path.split("/") if p])
    digits = sum(c.isdigit() for c in clean_url)
    special = sum(not c.isalnum() for c in clean_url)

    # Search for keywords from external dataset in domain and path
    low_full = clean_url.lower()
    matched_kws = [k for k in kws_dataset if k in low_full]
    ent = calculate_shannon_entropy(host)
    is_short = host in shorts_dataset

    def f(label, value, note, flag=False):
        if trusted:
            flag = False
            note = f"Verified domain ({apex})."
        return {"label": label, "value": str(value), "note": note, "flag": bool(flag)}

    return [
        f("URL length", f"{len(clean_url)} chars", "Long URLs can bury the real destination." if len(clean_url) > 75 else "Within typical length.", len(clean_url) > 75),
        f("Domain length", f"{len(host)} chars", "Unusually long hostnames are common in generated phishing domains." if len(host) > 30 else "Normal domain length.", len(host) > 30),
        f("Subdomains", subs, "Multiple subdomains can imitate a trusted brand." if subs >= 2 else "Standard subdomain structure.", subs >= 2),
        f("Path depth", depth, "Deep directory paths can hide a malicious page." if depth >= 4 else "Shallow path.", depth >= 4),
        f("Special characters", special, f"{clean_url.count('-')} hyphen(s), {clean_url.count('@')} '@', {clean_url.count('%')} '%', {clean_url.count('?')} '?'.", clean_url.count("@") > 0 or clean_url.count("-") > 2),
        f("Digits", digits, "Heavy digit usage is typical of auto-generated hosts." if digits > 6 else "Few digits.", digits > 6),
        f("Host type", "IP address" if is_ip else "Domain name", "A bare IP bypasses standard domain accountability." if is_ip else "Uses a registered domain name.", is_ip),
        f("Suspicious keywords", ", ".join(matched_kws[:4]) if matched_kws else "None", "Found credential or action keywords from reference dataset." if matched_kws else "No credential or action wording found.", bool(matched_kws)),
        f("Character entropy", f"{ent:.2f} bits", "High randomness suggests machine-generated domain." if ent > 3.8 else "Domain reads as natural language.", ent > 3.8),
        f("Protocol", scheme.upper() or "—", "Unencrypted connection." if scheme == "http" else "Encrypted (HTTPS).", scheme == "http"),
        f("Shortener", "Yes" if is_short else "No", "Masks true destination until clicked." if is_short else "Destination is directly visible.", is_short),
    ]


def get_prediction_details(url: str, probability: float, is_trusted: bool = False) -> dict:
    """Constructs the standardized prediction response used by the CLI,
    local API server, Web UI, and Chrome Extension.
    """
    clean_url = normalize_url(url)
    trusted = is_trusted or is_trusted_domain(clean_url)

    if trusted:
        risk = 0
        prob = 0.0
        level = 'safe'
        title = VERDICTS['safe'][0]
        apex = get_apex_domain(clean_url)
        summary = f"Verified domain ({apex}) from trusted reference dataset. Safe to browse."
    else:
        prob = float(min(1.0, max(0.0, probability)))
        risk = round(prob * 100)
        level = 'bad' if risk >= 60 else 'warn' if risk >= 30 else 'safe'
        title, summary = VERDICTS[level]

    return {
        'url': url,
        'probability': prob,
        'risk': risk,
        'level': level,
        'title': title,
        'summary': summary,
        'label': 'phishing' if (risk >= 50 and not trusted) else 'legitimate',
        'features': describe_url(clean_url)
    }


def print_result_display(details: dict):
    """Renders a readable, stylized ASCII risk meter and breakdown table in the terminal."""
    level = details['level']
    risk = details['risk']
    try:
        level_tags = {'safe': '[✓ SAFE]', 'warn': '[! WARNING]', 'bad': '[✗ PHISHING DETECTED]'}
        meter_filled_char, meter_empty_char = '█', '░'
        flag_mark, safe_mark = "⚠️ ", "✓ "
        tag = level_tags.get(level, '[RESULT]')
        bar_len = 20
        filled = int(round(bar_len * (risk / 100.0)))
        meter = meter_filled_char * filled + meter_empty_char * (bar_len - filled)
        f" {tag} {meter}".encode(sys.stdout.encoding or 'utf-8')
    except (UnicodeEncodeError, LookupError):
        level_tags = {'safe': '[+ SAFE]', 'warn': '[! WARNING]', 'bad': '[- PHISHING DETECTED]'}
        meter_filled_char, meter_empty_char = '#', '-'
        flag_mark, safe_mark = "! ", "+ "
        tag = level_tags.get(level, '[RESULT]')
        bar_len = 20
        filled = int(round(bar_len * (risk / 100.0)))
        meter = meter_filled_char * filled + meter_empty_char * (bar_len - filled)

    print("\n" + "=" * 65)
    print(f" {tag}  {details['title'].upper()}  (Risk Score: {risk}%)")
    print(f" Risk Meter : [{meter}] {risk}%")
    print(f" Verdict    : {details['summary']}")
    print("-" * 65)
    print(" Lexical & Structural Indicators:")
    for item in details['features']:
        mark = flag_mark if item['flag'] else safe_mark
        print(f"   {mark} {item['label']:<20}: {item['value']}  ({item['note']})")
    print("=" * 65 + "\n")


def validate_url(user_input: str) -> tuple[bool, str]:
    """Validates user input string for basic URL structure."""
    s = user_input.strip()
    if not s:
        return False, "Input cannot be empty."
    if len(s) > 2048:
        return False, "URL length exceeds 2048 character limit."
    if " " in s:
        return False, "URLs cannot contain whitespace."
    if not ('.' in s or '://' in s):
        return False, "Input must contain a valid domain (e.g. example.com) or protocol."
    return True, ""
