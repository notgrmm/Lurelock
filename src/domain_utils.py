"""Domain and TLD Processing Utilities.

Provides domain parsing, multi-part ccTLD resolution, cloud provider infrastructure filtering,
and benign domain sanitization against known phishing datasets.
"""

import re
from urllib.parse import urlparse
import pandas as pd

# Multi-part ccTLDs and dynamic/free DNS suffixes
KNOWN_MULTI_SUFFIXES = {
    # Common multi-part country codes
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
    'com.ph', 'org.ph', 'edu.ph', 'gov.ph', 'net.ph',
    'com.mx', 'org.mx', 'edu.mx', 'gob.mx',
    'co.kr', 'ne.kr', 're.kr', 'or.kr', 'go.kr',
    'com.tr', 'org.tr', 'edu.tr', 'gov.tr',
    'co.za', 'org.za', 'net.za', 'gov.za',
    'com.ar', 'org.ar', 'gov.ar',
    'com.co', 'org.co', 'edu.co', 'gov.co',
    'com.ng', 'org.ng', 'edu.ng', 'gov.ng',
    'com.hk', 'org.hk', 'edu.hk', 'gov.hk',
    'com.tw', 'org.tw', 'edu.tw', 'gov.tw',
    'com.my', 'org.my', 'edu.my', 'gov.my',
    'com.vn', 'org.vn', 'edu.vn', 'gov.vn',
    'com.pk', 'org.pk', 'edu.pk', 'gov.pk',
    'com.in', 'net.in', 'org.in', 'edu.in', 'gov.in',
    'co.in', 'gen.in', 'firm.in', 'ind.in',
    'co.id', 'web.id', 'or.id', 'go.id', 'ac.id',
    'com.ru', 'net.ru', 'org.ru', 'pp.ru',
    # Free cloud & dynamic DNS hosts with private suffixes
    'pages.dev', 'github.io', 'gitlab.io', 'netlify.app',
    'azurewebsites.net', 'firebaseapp.com', 'web.app',
    's3.amazonaws.com', 'herokuapp.com', 'duckdns.org',
    'no-ip.com', 'hopto.org', 'wordpress.com', 'blogspot.com',
    'weebly.com', 'wixsite.com'
}

# Cloud and shared infrastructure that must not be blindly treated as benign apex domains
CLOUD_AND_FREE_INFRA = {
    'firebaseapp.com', 'web.app', 'github.io', 'pages.dev', 'gitlab.io',
    'netlify.app', 'herokuapp.com', 'azurewebsites.net', 's3.amazonaws.com',
    'blob.core.windows.net', 'storage.googleapis.com', 'drive.google.com',
    'docs.google.com', 'sites.google.com', 'formsite.com', 'typeform.com',
    'jotform.com', '000webhostapp.com', 'wixsite.com', 'weebly.com',
    'blogspot.com', 'wordpress.com', 'duckdns.org', 'no-ip.com', 'ngrok.io',
    'ngrok-free.app', 'glitch.me', 'replit.app', 'surge.sh', 'render.com',
    'vercel.app'
}

# High-trust VIP apex domains bypassed by security filters to prevent false positives
TRUSTED_APEX_DOMAINS = {
    'google.com', 'microsoft.com', 'microsoftonline.com', 'github.com',
    'paypal.com', 'apple.com', 'amazon.com', 'wikipedia.org', 'facebook.com',
    'netflix.com', 'twitter.com', 'linkedin.com', 'live.com', 'office.com'
}


class ExtractResult:
    """Standardized domain extraction result object containing subdomain,
    registered domain name, and public suffix (similar to tldextract.ExtractResult).
    """

    def __init__(self, subdomain: str, domain: str, suffix: str):
        self.subdomain = subdomain
        self.domain = domain
        self.suffix = suffix

    def __repr__(self):
        return f"ExtractResult(subdomain='{self.subdomain}', domain='{self.domain}', suffix='{self.suffix}')"


def fallback_extract(url_or_domain: str) -> ExtractResult:
    """Robust pure-Python public suffix and domain parser.
    
    Used when tldextract is not installed or when offline. Accurately segments
    multi-part ccTLDs like '.co.uk' and cloud suffixes like '.pages.dev'.
    
    Args:
        url_or_domain: Raw link or domain string.
        
    Returns:
        ExtractResult with subdomain, domain, and suffix.
    """
    s = str(url_or_domain).strip().lower()
    formatted = s if '://' in s else f'http://{s}'
    try:
        parsed = urlparse(formatted)
        host = (parsed.hostname or parsed.netloc.split(':')[0] or s.split('/')[0]).split(':')[0]
    except Exception:
        host = s.split('/')[0].split(':')[0]
    host = host.strip('.')

    if not host:
        return ExtractResult('', '', '')

    # Bare IP address host
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        return ExtractResult('', host, '')

    parts = host.split('.')
    if len(parts) <= 1:
        return ExtractResult('', host, '')

    matched_suffix = None
    for length in (3, 2):
        if len(parts) > length:
            candidate = '.'.join(parts[-length:])
            if candidate in KNOWN_MULTI_SUFFIXES:
                matched_suffix = candidate
                break

    if matched_suffix:
        suffix = matched_suffix
        domain_parts = parts[:-len(suffix.split('.'))]
        if domain_parts:
            domain = domain_parts[-1]
            subdomain = '.'.join(domain_parts[:-1])
        else:
            domain, subdomain = '', ''
    else:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = '.'.join(parts[:-2])

    return ExtractResult(subdomain, domain, suffix)


def tld_extractor(url_or_domain: str) -> ExtractResult:
    """Extracts domain components using tldextract if available, falling back
    to fallback_extract without throwing errors.
    """
    try:
        import tldextract
        res = tldextract.extract(str(url_or_domain))
        return ExtractResult(res.subdomain, res.domain, res.suffix)
    except Exception:
        return fallback_extract(url_or_domain)


def get_apex_domain(url: str) -> str:
    """Returns the registered apex domain (e.g., 'example.com' or 'example.co.uk')
    from an arbitrary URL string.
    """
    res = tld_extractor(url)
    if res.domain and res.suffix:
        return f"{res.domain}.{res.suffix}".lower()
    return (res.domain or res.suffix or url).lower()


def sanitize_benign_domains(apex_df: pd.DataFrame, phishing_urls: set) -> pd.DataFrame:
    """Filters apex domains to purge:
      1. Shared cloud / PaaS infrastructure (e.g. firebaseapp.com, pages.dev).
      2. Compromised or known phishing apex domains.
    
    Args:
        apex_df: DataFrame containing benign candidate URLs.
        phishing_urls: Set of known phishing URLs to cross-check.
        
    Returns:
        Cleaned, deduplicated DataFrame of benign URLs (label 0).
    """
    print(f"[INFO] Sanitizing benign domains from apex_set (Initial count: {len(apex_df):,})...")
    dropped_infra = 0
    dropped_compromised = 0
    sanitized_urls = []

    # Build set of registered apex domains seen in phishing records
    phishing_apexes = set()
    for p_url in phishing_urls:
        try:
            ext = tld_extractor(str(p_url))
            if ext.domain and ext.suffix:
                phishing_apexes.add(f"{ext.domain}.{ext.suffix}".lower())
            elif ext.domain:
                phishing_apexes.add(ext.domain.lower())
        except Exception:
            pass

    for url in apex_df['url']:
        try:
            ext = tld_extractor(str(url))
            if not ext.domain and not ext.suffix:
                continue

            registered_domain = f"{ext.domain}.{ext.suffix}".lower() if (ext.domain and ext.suffix) else (ext.domain or ext.suffix).lower()

            # 1. Purge shared cloud & dynamic DNS infrastructure
            if ext.suffix.lower() in CLOUD_AND_FREE_INFRA or registered_domain in CLOUD_AND_FREE_INFRA:
                dropped_infra += 1
                continue

            # 2. Threat intelligence subtraction (drop benign domains that exist in phish sets)
            if registered_domain in phishing_apexes:
                dropped_compromised += 1
                continue

            sanitized_urls.append(url)
        except Exception:
            continue

    print(f"[INFO] Sanitization complete. Dropped {dropped_infra} shared infrastructure and {dropped_compromised} compromised domains.")
    return pd.DataFrame({'url': sanitized_urls, 'label': 0})

