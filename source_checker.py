"""
source_checker.py  -  "Where did this email come from, and can we trust it?"
-----------------------------------------------------------------------------
Three checks, one function each:
    check_sender()       who sent it, from which domain / IP, is it a fake?
    check_links()        do the links go where they pretend to?
    check_attachments()  are any attached files dangerous?

check_source() runs all three and counts the warnings.
(The lists below are small on purpose - add your own words to them!)
"""

import ipaddress
import re
from urllib.parse import urlparse

# Companies scammers love to imitate, with their REAL domains
REAL_DOMAINS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonses.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "googleusercontent.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com"],
    "whatsapp": ["whatsapp.com"],
    "paytm": ["paytm.com"],
    "flipkart": ["flipkart.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
    "icici": ["icicibank.com"],
}

FREE_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com",
                  "protonmail.com", "proton.me", "aol.com", "icloud.com"}

# Website endings that are very common in scam emails
SUSPICIOUS_ENDINGS = {"xyz", "top", "click", "work", "loan", "gq", "tk", "ml", "cf", "ga",
                      "icu", "buzz", "rest", "monster", "zip"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}

# Country hint from the domain ending (shows registration, NOT real location)
COUNTRY_ENDINGS = {
    "in": "India", "uk": "United Kingdom", "us": "United States", "ng": "Nigeria",
    "ru": "Russia", "cn": "China", "pk": "Pakistan", "bd": "Bangladesh", "za": "South Africa",
    "de": "Germany", "fr": "France", "au": "Australia", "ca": "Canada", "br": "Brazil",
    "ke": "Kenya", "gh": "Ghana", "ph": "Philippines", "id": "Indonesia", "ae": "UAE",
}

# Files that can run a program or a macro on your computer
DANGEROUS_FILES = {"exe", "scr", "bat", "cmd", "com", "js", "vbs", "jar", "msi", "apk",
                   "ps1", "lnk", "iso", "docm", "xlsm", "pptm", "html", "htm"}
ARCHIVE_FILES = {"zip", "rar", "7z"}

# Nicer spelling of company names for the warnings
BRAND_LABELS = {"paypal": "PayPal", "whatsapp": "WhatsApp", "sbi": "SBI", "hdfc": "HDFC", "icici": "ICICI"}

# Tricks to turn 'paypa1' into 'paypal' before comparing
LOOKALIKE_LETTERS = str.maketrans("0135", "oles")


# ----------------------------------------------------------------------
# Brand-imitation helpers
# ----------------------------------------------------------------------
def is_real_domain(domain, brand):
    """True if the domain really belongs to that company (or is its sub-domain)."""
    return any(domain == real or domain.endswith("." + real) for real in REAL_DOMAINS[brand])


def imitated_brand(domain):
    """If a domain pretends to be a famous company, return that company's name."""
    cleaned = domain.lower().translate(LOOKALIKE_LETTERS).replace("rn", "m").replace("vv", "w")
    parts = re.split(r"[.\-]", cleaned)
    for brand in REAL_DOMAINS:
        if is_real_domain(domain, brand):
            continue                    # it IS the real company, so no problem
        # short names like 'sbi' must match a whole word; longer ones can appear anywhere
        if brand in parts or (len(brand) >= 4 and brand in cleaned):
            return brand
    return None


# ----------------------------------------------------------------------
# CHECK 1: the sender  (this is the "where is the mail from?" feature)
# ----------------------------------------------------------------------
def check_sender(parsed):
    domain = parsed["sender_domain"]
    info = {
        "found": bool(domain), "name": parsed["sender_name"], "address": parsed["sender_address"],
        "domain": domain, "domain_type": "", "country_hint": "",
        "origin_ip": parsed["origin_ip"], "auth": parsed["auth"], "notes": [], "warnings": [],
    }
    if not domain:
        return info

    ending = domain.rsplit(".", 1)[-1]

    # What kind of address is it?
    if domain in FREE_PROVIDERS:
        info["domain_type"] = "Free email service"
        info["notes"].append("Banks and big companies rarely write from free email services.")
    else:
        info["domain_type"] = "Organisation / custom domain"

    if ending in COUNTRY_ENDINGS:
        info["country_hint"] = (f".{ending} = {COUNTRY_ENDINGS[ending]}. This only shows how the "
                                "domain was registered, not where the sender really is.")

    # Warnings (each one is a real red flag)
    brand = imitated_brand(domain)
    if brand:
        info["warnings"].append(f"The domain '{domain}' looks like it is imitating {BRAND_LABELS.get(brand, brand.title())}.")

    for brand in REAL_DOMAINS:
        if re.search(r"\b" + brand + r"\b", parsed["sender_name"].lower()) and not is_real_domain(domain, brand):
            info["warnings"].append(f"The sender name mentions {BRAND_LABELS.get(brand, brand.title())}, but the address is from "
                                    f"'{domain}', which is not {BRAND_LABELS.get(brand, brand.title())}'s real domain.")

    if ending in SUSPICIOUS_ENDINGS:
        info["warnings"].append(f"The domain ending '.{ending}' is very common in scam emails.")

    if parsed["reply_to_domain"] and parsed["reply_to_domain"] != domain:
        info["warnings"].append(f"Replies would go to a DIFFERENT domain ('{parsed['reply_to_domain']}') "
                                "than the one that sent the email.")

    # SPF / DKIM / DMARC are the mail servers' own "is this sender genuine?" tests
    for test, result in parsed["auth"].items():
        if result in ("fail", "softfail"):
            info["warnings"].append(f"The {test.upper()} security check FAILED, so the sender may be forged.")
        elif result == "pass":
            info["notes"].append(f"The {test.upper()} security check passed.")

    return info


# ----------------------------------------------------------------------
# CHECK 2: the links
# ----------------------------------------------------------------------
def find_links(parsed):
    """Collect (web address, visible text) pairs from the email."""
    links = []

    # Clickable links in an HTML email: <a href="REAL ADDRESS">TEXT YOU SEE</a>
    pattern = r"""(?is)<a\s[^>]*?href=["']([^"']+)["'][^>]*>(.*?)</a>"""
    for href, shown in re.findall(pattern, parsed["html"]):
        links.append((href.strip(), re.sub(r"<[^>]+>", "", shown).strip()))

    # Plain web addresses written in the text
    for url in re.findall(r"""(?i)\b(?:https?://|www\.)[^\s<>"')\]]+""", parsed["body"]):
        links.append((url.rstrip(".,;:!?"), ""))

    # Tidy up: add http:// if missing, drop duplicates, keep only web links
    clean, seen = [], set()
    for url, shown in links:
        if url.lower().startswith("www."):
            url = "http://" + url
        if url.lower().startswith(("http://", "https://")) and url not in seen:
            seen.add(url)
            clean.append((url, shown))
    return clean[:20]       # look at the first 20 only


def bare(host):
    return host[4:] if host.startswith("www.") else host


def check_one_link(url, shown_text):
    parts = urlparse(url)
    host = parts.hostname or ""
    ending = host.rsplit(".", 1)[-1]
    flags = []

    try:
        ipaddress.ip_address(host)
        flags.append("Uses a number (IP address) instead of a website name.")
    except ValueError:
        pass    # it is a normal name, which is fine

    if "@" in parts.netloc:
        flags.append("Contains '@', which can hide the real destination.")
    if host in SHORTENERS:
        flags.append("Shortened link: you cannot see where it really leads.")
    if ending in SUSPICIOUS_ENDINGS:
        flags.append(f"Unusual ending '.{ending}'.")
    brand = imitated_brand(host)
    if brand:
        flags.append(f"The website name imitates {BRAND_LABELS.get(brand, brand.title())}.")

    # Does the visible text look like a web address that differs from the real one?
    shown = shown_text.strip()
    if re.match(r"(?i)^(https?://)?[\w-]+(\.[\w-]+)+(/\S*)?$", shown):
        shown_host = urlparse(shown if "://" in shown else "http://" + shown).hostname or ""
        if bare(shown_host) != bare(host) and not host.endswith("." + bare(shown_host)):
            flags.append(f"The link text shows '{shown_host}' but it really goes to '{host}'.")

    return {"url": url, "host": host, "flags": flags}


def check_links(parsed):
    results = []
    for url, shown in find_links(parsed):
        try:
            results.append(check_one_link(url, shown))
        except ValueError:      # a badly written web address - just skip it
            continue
    return results


# ----------------------------------------------------------------------
# CHECK 3: the attachments (only available for .eml files)
# ----------------------------------------------------------------------
def check_attachments(file_names):
    results = []
    for name in file_names:
        pieces = name.lower().split(".")
        extension = pieces[-1] if len(pieces) > 1 else ""
        flags = []

        if extension in DANGEROUS_FILES:
            flags.append(f"'.{extension}' files can run programs or macros on your computer.")
        elif extension in ARCHIVE_FILES:
            flags.append(f"'.{extension}' archives can hide harmful files inside.")

        if len(pieces) >= 3 and extension in DANGEROUS_FILES:
            flags.append("Double extension: it is pretending to be a harmless document.")

        results.append({"name": name, "flags": flags})
    return results


# ----------------------------------------------------------------------
# Run all three checks
# ----------------------------------------------------------------------
def check_source(parsed):
    sender = check_sender(parsed)
    links = check_links(parsed)
    attachments = check_attachments(parsed["attachments"])

    # Total number of problems found (used by Analysis in detector.py)
    warning_count = (len(sender["warnings"])
                     + sum(1 for link in links if link["flags"])
                     + sum(1 for item in attachments if item["flags"]))

    return {"sender": sender, "links": links, "attachments": attachments, "warning_count": warning_count}
