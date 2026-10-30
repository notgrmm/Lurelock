"""URL Explanation & Prediction Formatting Module.

Extracts the 11 lexical and structural indicators matching the LureLock study,
and formats predictions consistently for the Interactive CLI, Web UI,
and Chrome Extension.
"""

import re
import sys
from urllib.parse import urlparse
from .feature_extractor import calculate_shannon_entropy, KEYWORDS, SHORTENERS

# Verdict definitions mapped to risk thresholds
VERDICTS = {
    'safe': ('No warning signs', 'The model rates this URL as likely legitimate. No detector can guarantee a site is safe.'),
    'warn': ('Some warning signs', 'The model sees some phishing-like patterns in this URL. These are signals, not proof.'),
    'bad': ('Likely phishing', 'The model rates this URL as likely phishing. Avoid entering credentials and confirm the intended domain.')
}


def describe_url(url: str) -> list[dict]:
    """Generates the static lexical and structural breakdown displayed
    in the LureLock Web UI and Chrome Extension popup.
    
    Extracts 11 explainability signals:
      1. URL character length
      2. Domain character length
      3. Subdomains nesting count
      4. Path directory depth
      5. Special character frequency (-, @, %, ?, =)
      6. Digit character count
      7. Host type (bare IP address vs registered domain name)
      8. Suspicious brand or security keywords
      9. Character entropy (randomness score)
     10. Protocol scheme (HTTPS vs HTTP)
     11. URL shortener service detection
    
    Args:
        url: Target URL string to inspect.
        
    Returns:
        List of feature description dictionaries:
        [{'label': str, 'value': str, 'note': str, 'flag': bool}, ...]
    """
    formatted = url if url.startswith(('http://', 'https://')) else f'http://{url}'
    parsed = urlparse(formatted)
    host = (parsed.hostname or parsed.netloc.split(':')[0] or "").lower()
    path = parsed.path or "/"
    low = url.lower()
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    labels = host.split(".") if host else []
    subs = 0 if is_ip else max(0, len(labels) - 2)
    depth = len([p for p in path.split("/") if p])
    digits = sum(c.isdigit() for c in url)
    special = sum(not c.isalnum() for c in url)
    kws = [k for k in KEYWORDS if k in low]
    ent = calculate_shannon_entropy(host)
    scheme = parsed.scheme.lower()
    is_short = host in SHORTENERS

    def f(label, value, note, flag=False):
        return {"label": label, "value": str(value), "note": note, "flag": bool(flag)}

    return [
        f("URL length", f"{len(url)} chars", "Long URLs can bury the real destination." if len(url) > 75 else "Within a typical length.", len(url) > 75),
        f("Domain length", f"{len(host)} chars", "Unusually long hostnames are common in generated phishing domains." if len(host) > 30 else "Normal hostname length.", len(host) > 30),
        f("Subdomains", subs, "Many nested subdomains can imitate a trusted brand." if subs >= 3 else "No excessive subdomain nesting.", subs >= 3),
        f("Path depth", depth, "Deep paths can hide a malicious page behind a benign host." if depth >= 5 else "Shallow path.", depth >= 5),
        f("Special characters", special, f"{url.count('-')} hyphen(s), {url.count('@')} “@”, {url.count('%')} “%”, {url.count('?')} “?”, {url.count('=')} “=”.", url.count("@") > 0 or url.count("%") > 2 or url.count("-") > 3),
        f("Digits", digits, "Heavy digit use is typical of auto-generated hosts." if digits > 6 else "Few digits.", digits > 6),
        f("Host type", "IP address" if is_ip else "Domain name", "A bare IP replaces a readable, accountable domain." if is_ip else "Uses a registered-style domain name.", is_ip),
        f("Suspicious keywords", ", ".join(kws[:4]) if kws else "None", "Sign-in, urgency or brand words often appear in impersonation links." if kws else "No sign-in or urgency wording found.", bool(kws)),
        f("Character entropy", f"{ent:.2f} bits", "High randomness suggests a machine-generated host." if ent > 3.8 else "Host reads as natural text.", ent > 3.8),
        f("Protocol", scheme.upper() or "—", "Unencrypted connection." if scheme == "http" else "Encrypted (HTTPS), which does not by itself prove a site is safe.", scheme == "http"),
        f("Shortener", "Yes" if is_short else "No", "The final destination is hidden; structure cannot be judged before redirect." if is_short else "Destination is visible in the URL.", is_short),
    ]


def get_prediction_details(url: str, probability: float, is_trusted: bool = False) -> dict:
    """Constructs the comprehensive prediction response dictionary used
    by both the local API server and the interactive terminal CLI.
    """
    risk = 0 if is_trusted else round(probability * 100)
    level = 'bad' if risk >= 60 else 'warn' if risk >= 30 else 'safe'
    title, summary = VERDICTS[level]
    if is_trusted:
        summary = "This domain is on the trusted VIP safe list. ML scanning was bypassed."

    return {
        'url': url,
        'probability': 0.0 if is_trusted else float(probability),
        'risk': risk,
        'level': level,
        'title': title,
        'summary': summary,
        'label': 'phishing' if (risk >= 50 and not is_trusted) else 'legitimate',
        'features': describe_url(url)
    }


def print_result_display(details: dict):
    """Renders a readable, stylized ASCII risk meter and breakdown table
    in the terminal CLI.
    """
    level = details['level']
    try:
        level_tags = {'safe': '[✓ SAFE]', 'warn': '[! WARNING]', 'bad': '[✗ PHISHING DETECTED]'}
        meter_filled_char, meter_empty_char = '█', '░'
        flag_mark, safe_mark = "⚠️ ", "✓ "
        tag = level_tags.get(level, '[RESULT]')
        bar_len = 20
        filled = int(round(bar_len * (details['risk'] / 100.0)))
        meter = meter_filled_char * filled + meter_empty_char * (bar_len - filled)
        
        # Test encoding
        f" {tag} {meter}".encode(sys.stdout.encoding or 'utf-8')
    except (UnicodeEncodeError, LookupError):
        level_tags = {'safe': '[+ SAFE]', 'warn': '[! WARNING]', 'bad': '[- PHISHING DETECTED]'}
        meter_filled_char, meter_empty_char = '#', '-'
        flag_mark, safe_mark = "! ", "+ "
        tag = level_tags.get(level, '[RESULT]')
        bar_len = 20
        filled = int(round(bar_len * (details['risk'] / 100.0)))
        meter = meter_filled_char * filled + meter_empty_char * (bar_len - filled)

    risk = details['risk']
    print("\n" + "=" * 65)
    print(f" {tag}  {details['title'].upper()}  (Risk Score: {risk}%)")
    print(f" Risk Meter : [{meter}] {risk}%")
    print(f" Verdict    : {details['summary']}")
    print("-" * 65)
    print(" Lexical & Structural Features (Website & Extension breakdown):")
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
        return False, "Input must contain a valid domain dot (e.g. example.com) or protocol."
    return True, ""

