"""
email_parser.py  -  reads an email and pulls out its useful parts
-----------------------------------------------------------------
The email can arrive in two ways:
    1. pasted into the text box        -> parse_email_text()
    2. uploaded as a file (.eml/.txt/.pdf) -> read_uploaded_file()

Both give back the SAME kind of dictionary (called "parsed" in the other files):
    subject, sender_name, sender_address, sender_domain, reply_to_domain,
    origin_ip, auth, body, html, attachments, has_headers, model_text

An email has two halves:
    HEADERS = the "envelope" (From:, Subject:, Received: ...)  <- tells us the SOURCE
    BODY    = the message the person actually reads
"""

import email
import html
import io
import ipaddress
import re
from email import policy
from email.utils import parseaddr

MAX_FILE_BYTES = 2 * 1024 * 1024   # uploads bigger than 2 MB are refused (PR-04)

# Addresses that only exist inside a private network, so they say nothing about the sender
PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# ----------------------------------------------------------------------
# Small helper functions
# ----------------------------------------------------------------------
def empty_email(body_text=""):
    """A blank 'parsed' dictionary. Used when no headers are available."""
    return {
        "has_headers": False, "subject": "", "sender_name": "", "sender_address": "",
        "sender_domain": "", "reply_to_domain": "", "origin_ip": "", "auth": {},
        "body": body_text, "html": "", "attachments": [], "model_text": "",
    }


def get_domain(address):
    """'help@paypal.com' -> 'paypal.com'"""
    return address.split("@")[-1].strip().lower() if "@" in address else ""


def strip_html(html_text):
    """Remove HTML tags so only readable text is left."""
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html_text)   # drop scripts/styles
    text = re.sub(r"<[^>]+>", " ", text)                              # drop all tags
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def is_public_ip(ip):
    """True if the IP address belongs to the open internet (not a private network)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local:
        return False
    return not any(address in network for network in PRIVATE_NETWORKS)


def find_origin_ip(msg):
    """Every mail server adds a 'Received:' line. The BOTTOM one is the first
    server that handled the email, so its IP is our best clue to the origin."""
    for header in reversed(msg.get_all("Received", [])):
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(header)):
            if is_public_ip(ip):
                return ip
    return ""


def safe_content(part):
    """Read the text of one part of the email; return '' if it is broken."""
    if part is None:
        return ""
    try:
        return part.get_content()
    except Exception:       # a damaged email must never crash the app (SSR-01)
        return ""


def add_model_text(parsed):
    """The text given to the 3 algorithms = subject + body."""
    parsed["model_text"] = (parsed["subject"] + "\n" + parsed["body"]).strip()
    return parsed


# ----------------------------------------------------------------------
# Turn a real email object into our simple dictionary
# ----------------------------------------------------------------------
def message_to_dict(msg):
    parsed = empty_email()
    parsed["has_headers"] = True
    parsed["subject"] = str(msg.get("Subject", ""))

    name, address = parseaddr(str(msg.get("From", "")))
    parsed["sender_name"] = name
    parsed["sender_address"] = address
    parsed["sender_domain"] = get_domain(address)
    parsed["reply_to_domain"] = get_domain(parseaddr(str(msg.get("Reply-To", "")))[1])
    parsed["origin_ip"] = find_origin_ip(msg)

    # Authentication-Results looks like:  spf=pass ...; dkim=fail ...; dmarc=pass
    auth_text = str(msg.get("Authentication-Results", ""))
    parsed["auth"] = {k.lower(): v.lower() for k, v in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", auth_text, re.I)}

    # Body: prefer plain text, otherwise strip the HTML version
    plain = safe_content(msg.get_body(preferencelist=("plain",)))
    html_text = safe_content(msg.get_body(preferencelist=("html",)))
    parsed["body"] = plain if plain.strip() else strip_html(html_text)
    parsed["html"] = html_text

    parsed["attachments"] = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    return add_model_text(parsed)


# ----------------------------------------------------------------------
# Way 1: pasted text
# ----------------------------------------------------------------------
def parse_email_text(text):
    """If the pasted text starts with headers (From: ...), read them.
    Otherwise treat the whole text as the email body."""
    text = (text or "").strip()
    first_lines = text.splitlines()[:30]
    has_headers = any(re.match(r"(?i)from:\s*\S", line) for line in first_lines)

    if has_headers:
        return message_to_dict(email.message_from_string(text, policy=policy.default))
    return add_model_text(empty_email(text))


# ----------------------------------------------------------------------
# Way 2: uploaded file
# ----------------------------------------------------------------------
def read_uploaded_file(file_name, file_bytes):
    """Returns (parsed_email, error_message). Exactly one of them is None."""
    if len(file_bytes) > MAX_FILE_BYTES:
        return None, "That file is too big. Please upload a file smaller than 2 MB."

    extension = file_name.lower().rsplit(".", 1)[-1]

    if extension == "eml":      # a saved email: has full headers + attachments
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
        return message_to_dict(msg), None

    if extension == "txt":
        return parse_email_text(file_bytes.decode("utf-8", errors="replace")), None

    if extension == "pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            return None, "PDF support needs one extra library. Run:  pip install pypdf"
        try:
            reader = PdfReader(io.BytesIO(file_bytes))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            return None, "Sorry, this PDF could not be read."
        if not text.strip():
            return None, "No readable text was found in this PDF (it may be a scanned image)."
        return parse_email_text(text), None

    return None, "This file type is not supported. Please upload a .eml, .txt or .pdf file."
