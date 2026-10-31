"""TrustLens detector: rule-based, explainable, fully offline.

It only reads message TEXT. It never opens links, sends replies,
or takes any action on the user's behalf.
"""
import json
import re
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

DATASET_PATH = Path(__file__).with_name("dataset.json")

# Illustrative allowlist for the demo. Verify real domains before real-world use.
BRANDS = {
    "HDFC Bank": {"aliases": ["hdfc", "hdfc bank"], "domains": ["hdfcbank.com"], "sms_ids": ["HDFC"]},
    "SBI": {"aliases": ["sbi", "state bank of india", "yono"],
            "domains": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], "sms_ids": ["SBI"]},
    "ICICI Bank": {"aliases": ["icici", "icici bank"], "domains": ["icicibank.com"], "sms_ids": ["ICICI"]},
    "Amazon": {"aliases": ["amazon"], "domains": ["amazon.in", "amazon.com"], "sms_ids": ["AMZN", "AMAZON"]},
    "Flipkart": {"aliases": ["flipkart"], "domains": ["flipkart.com"], "sms_ids": ["FLIPKT", "FLPKRT"]},
    "Paytm": {"aliases": ["paytm", "पेटीएम"], "domains": ["paytm.com"], "sms_ids": ["PAYTM"]},
    "India Post": {"aliases": ["india post", "indiapost"], "domains": ["indiapost.gov.in"],
                   "sms_ids": ["INDPST", "INDPOST"]},
    "Income Tax Dept": {"aliases": ["income tax", "incometax"], "domains": ["incometax.gov.in"],
                        "sms_ids": ["INCTAX", "ITDEPT"]},
}

FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "proton.me"}
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "rb.gy", "is.gd"}
BAD_TLDS = {"xyz", "top", "click", "icu", "buzz", "live", "rest", "cfd", "sbs", "support"}

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|t\.co|goo\.gl|rb\.gy|is\.gd)/[^\s<>\"']+",
    re.I,
)

# ---- Language patterns: English + Hinglish + Hindi/Kannada script ----
URGENCY_LATIN = (
    r"\b(?:urgent(?:ly)?|immediately|right away|act now|last warning|final notice"
    r"|within \d+ ?(?:hours?|hrs?|minutes?|mins?)|expires? (?:today|tonight)"
    r"|turant|abhi|jaldi|\d+ ghante(?: me| mein)?|block ho jayega|band ho jayega"
    r"|account (?:will be |is |has been )?(?:blocked|suspended|closed|disconnected)"
    r"|(?:blocked|suspended|disconnected) (?:tonight|today))\b"
)
URGENCY_SCRIPT = "|".join(["तुरंत", "ब्लॉक", "ತಕ್ಷಣ", "ಬ್ಲಾಕ್"])
URGENCY_RE = re.compile(URGENCY_LATIN + "|" + URGENCY_SCRIPT, re.I)

CRED_TERMS = re.compile(
    r"\b(?:otp|password|passcode|pin|cvv|aadhaar|aadhar|pan|kyc|card number|net ?banking|upi pin)\b"
    r"|ओटीपी|ಒಟಿಪಿ|पासवर्ड",
    re.I,
)
REQ_VERBS_BASE = (
    r"\b(?:share|send|submit|provide|give|reply|verify|confirm|update|click"
    r"|karein|kariye|kijiye|bhejo|bhejein|bheje|bhejiye|batao|batayein|bataiye|dijiye|dalein|daalein)\b"
    r"|भेजें|बताएं|कीजिए|ಕಳುಹಿಸಿ|ಕ್ಲಿಕ್"
)
WARN_RE = re.compile(
    r"do not share|don'?t share|never share|never ask|will never ask|not share|share na|"
    r"kisi ko na|कभी नहीं|ಹಂಚಿಕೊಳ್ಳಬೇಡಿ|do not disclose",
    re.I,
)
MONEY_RE = re.compile(
    r"\b(?:processing|registration|customs|clearance|redelivery|delivery|release) (?:fee|charges?)\b"
    r"|\bgift ?cards?\b"
    r"|\bsend (?:me )?(?:money|rs\.? ?\d[\d,]*|₹ ?\d[\d,]*)"
    r"|\btransfer (?:rs\.? ?\d[\d,]*|₹ ?\d[\d,]*|the amount|money)"
    r"|\bpay (?:rs\.? ?\d[\d,]*|₹ ?\d[\d,]*)"
    r"|\b(?:paisa|paise) bhej\w*",
    re.I,
)
LURE_RE = re.compile(
    r"\b(?:you(?:'ve| have)? won|congratulations|lucky draw|lottery|jeet liya|inaam|cashback of|claim your (?:prize|reward|gift)|claim (?:now|prize))\b", re.I
)
GENERIC_GREETING_RE = re.compile(
    r"\bdear (?:customer|user|valued customer|account holder|sir/madam|taxpayer|beneficiary)\b"
    r"|प्रिय ग्राहक|ಪ್ರಿಯ ಗ್ರಾಹಕ",
    re.I,
)
EXEC_TITLE_RE = re.compile(r"\b(?:ceo|md|director|manager|hr|finance|accounts|boss)\b", re.I)

WEIGHTS = {
    "Suspicious link": 3,
    "Sender / domain inconsistency": 3,
    "Asks for credentials or money": 3,
    "Suspicious urgency": 2,
    "Too-good-to-be-true lure": 2,
    "Unrecognised link": 1,
    "Missing provenance": 1,
}

VERIFY_HINTS = {
    "Suspicious link": "Don't open it. Type the official website yourself or use the official app.",
    "Sender / domain inconsistency": "Compare the sender with the brand's real domain / SMS header on the official website.",
    "Asks for credentials or money": "Real banks and agencies never ask for OTP, PIN, passwords, or fees through a message.",
    "Suspicious urgency": "Scammers rush you so you skip verification. Pause and verify first.",
    "Too-good-to-be-true lure": "Genuine prizes don't ask you to click links or share OTPs.",
    "Unrecognised link": "This link is not a known official site. Do not open it; go to the real site yourself.",
    "Missing provenance": "Check who really sent this through a number or app you already trust.",
}


def find_urls(text):
    return [m.group(0).rstrip(".,;:!?)»") for m in URL_RE.finditer(text)]


def _host(url):
    u = url if "://" in url else "http://" + url
    p = urlparse(u)
    return (p.hostname or "").lower(), "@" in p.netloc


def _is_official(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def find_brands(*parts):
    hay = " ".join(parts).lower()
    found = []
    for name, b in BRANDS.items():
        for a in b["aliases"]:
            if re.search(r"(?<!\w)" + re.escape(a.lower()) + r"(?!\w)", hay):
                found.append(name)
                break
    return found


def _link_issues(url, brands):
    host, has_at = _host(url)
    issues = []
    if host in SHORTENERS:
        issues.append("shortened link hides the real destination")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        issues.append("uses a raw IP address instead of a domain")
    if "xn--" in host:
        issues.append("punycode (look-alike characters) in domain")
    if has_at:
        issues.append("contains '@' to disguise the real host")
    if host.rsplit(".", 1)[-1] in BAD_TLDS:
        issues.append(f"uses a high-abuse domain ending (.{host.rsplit('.', 1)[-1]})")
    if host.count("-") >= 2:
        issues.append("domain has several hyphens (common in fake sites)")
    leet = host.translate(str.maketrans("035", "oes"))
    for name, b in BRANDS.items():
        if _is_official(host, b["domains"]):
            continue
        if any(a.replace(" ", "") in leet for a in b["aliases"] if a.isascii()):
            issues.append(f"imitates {name} but is not its real domain")
            break
    if issues and url.lower().startswith("http://"):
        issues.append("not even HTTPS")
    return issues


def _credential_requests(text, has_url):
    verbs = REQ_VERBS_BASE + (r"|\benter\b" if has_url else "")
    req_re = re.compile(verbs, re.I)
    evidence, whys = [], []
    for sent in re.split(r"(?<=[.!?।])\s+|\n+", text):
        terms = [m.group(0) for m in CRED_TERMS.finditer(sent)]
        if not terms or WARN_RE.search(sent):
            continue
        verb = req_re.search(sent)
        if verb:
            evidence += terms
            whys.append(f"asks you to \"{verb.group(0)}\" {', '.join(terms)}")
    return evidence, whys


def analyze(text, sender="", channel="sms"):
    """Return risk tier, signals with quoted evidence, and safe next steps."""
    text, sender = text or "", (sender or "").strip()
    if "@" in sender:
        display, addr = parseaddr(sender)
        sender_domain = addr.split("@")[-1].lower()
    else:
        display, sender_domain = sender, ""
    urls = find_urls(text)
    brands = find_brands(text, sender)
    signals = []

    # 1. Suspicious links (text analysis only; never fetched)
    link_evidence, link_why = [], []
    for u in urls:
        issues = _link_issues(u, brands)
        if issues:
            link_evidence.append(u)
            link_why.append(f"{u}: {'; '.join(issues)}")
    if link_evidence:
        signals.append({"name": "Suspicious link", "evidence": link_evidence, "why": " | ".join(link_why)})

    # 1b. Links that are not a known official site (weak signal on its own)
    flagged = set(link_evidence)
    unknown = [u for u in urls if u not in flagged and not any(
        _is_official(_host(u)[0], b["domains"]) for b in BRANDS.values())]
    if unknown:
        signals.append({"name": "Unrecognised link", "evidence": unknown,
                        "why": "link goes to a site that is not a known official domain: " + ", ".join(unknown)})

    # 2. Credential / money requests
    cred_ev, cred_why = _credential_requests(text, bool(urls))
    money_ev = [m.group(0) for m in MONEY_RE.finditer(text)]
    if cred_ev or money_ev:
        why = "; ".join(cred_why + ([f"mentions a payment demand: {', '.join(money_ev)}"] if money_ev else []))
        signals.append({"name": "Asks for credentials or money", "evidence": cred_ev + money_ev, "why": why})
    risky_ask = bool(urls or cred_ev or money_ev)

    # 3. Sender / domain inconsistency
    if brands:
        sms_header = re.fullmatch(r"[A-Za-z]{2}-([A-Za-z0-9]{3,8})", sender)
        is_phone = bool(re.fullmatch(r"\+?[\d\s-]{8,15}", sender))
        sender_ok, sender_problem = None, None
        if sender_domain:
            sender_ok = any(_is_official(sender_domain, BRANDS[b]["domains"]) for b in brands)
            if not sender_ok:
                sender_problem = f"sender domain '{sender_domain}' is not an official {' / '.join(brands)} domain"
        elif sms_header:
            suffix = sms_header.group(1).upper()
            sender_ok = any(i in suffix for b in brands for i in BRANDS[b]["sms_ids"])
            if not sender_ok:
                sender_problem = f"SMS sender ID '{sender}' does not match {' / '.join(brands)}"
        elif is_phone:
            sender_ok = False
            sender_problem = f"claims to be {' / '.join(brands)} but came from a personal phone number"
        brand_in_display = bool(find_brands(display))
        ev, why = [], []
        if sender_ok is False and (risky_ask or brand_in_display):
            ev.append(sender)
            why.append(sender_problem)
        for u in urls:
            host, _ = _host(u)
            if not any(_is_official(host, BRANDS[b]["domains"]) for b in brands):
                ev.append(u)
                why.append(f"link goes to '{host}', not an official {' / '.join(brands)} site")
        if ev:
            signals.append({"name": "Sender / domain inconsistency", "evidence": ev, "why": " | ".join(why)})

    # 4. Urgency
    urg = [m.group(0) for m in URGENCY_RE.finditer(text)]
    if urg:
        signals.append({"name": "Suspicious urgency", "evidence": urg,
                        "why": "pressure language pushes you to act before verifying"})

    # 5. Lure
    lure = [m.group(0) for m in LURE_RE.finditer(text)]
    if lure:
        signals.append({"name": "Too-good-to-be-true lure", "evidence": lure,
                        "why": "unexpected prize/reward language"})

    # 6. Missing provenance
    prov_ev, prov_why = [], []
    g = GENERIC_GREETING_RE.search(text)
    if g:
        prov_ev.append(g.group(0))
        prov_why.append("generic greeting instead of your real name")
    if sender_domain in FREEMAIL and EXEC_TITLE_RE.search(display):
        prov_ev.append(display)
        prov_why.append("authority/job title shown on a free email address")
    if not sender:
        prov_why.append("no sender information provided, so origin can't be verified")
    if prov_why:
        signals.append({"name": "Missing provenance", "evidence": prov_ev, "why": "; ".join(prov_why)})

    score = sum(WEIGHTS[s["name"]] for s in signals)
    tier = "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"
    return {"tier": tier, "score": score, "signals": signals, "urls": urls,
            "brands": brands, "advice": _advice(tier, signals, brands)}


def _advice(tier, signals, brands):
    names = {s["name"] for s in signals}
    if tier == "LOW":
        return ["No strong warning signs found, but this is not a guarantee.",
                "If it asks you to act on money or accounts, confirm via the official app or website first."]
    steps = ["Do not click links, call numbers in the message, or reply."]
    if brands:
        steps.append(f"Contact {' / '.join(brands)} through a channel you already trust: the official app, "
                     "the number printed on your card or statement, or by typing the official website yourself.")
    else:
        steps.append("Verify with the sender using a number or app you already have, not details from this message.")
    if "Asks for credentials or money" in names:
        steps.append("Never share OTP, PIN, CVV or passwords through a message or link.")
    if tier == "HIGH":
        steps.append("If you already clicked or paid: call 1930 immediately and report at cybercrime.gov.in.")
    return steps


def reconsider(result, verified_via_trusted_channel):
    """Handle the user's 'this looks legit' challenge without blindly overriding."""
    order = ["LOW", "MEDIUM", "HIGH"]
    tier = result["tier"]
    names = {s["name"] for s in result["signals"]}
    if not verified_via_trusted_channel:
        return tier, ("We can't confirm legitimacy from the text alone. Please verify through the official "
                      "app or the number on your card, then come back and tick the box below.")
    new = order[max(0, order.index(tier) - 1)]
    if "Asks for credentials or money" in names:
        new = max(new, "MEDIUM", key=order.index)
        return new, ("Since you verified the sender, we lowered the tier one step. But even genuine senders "
                     "should never collect OTPs, passwords or fees through a message link, so stay cautious.")
    return new, "Since you verified the sender through a trusted channel, we lowered the tier one step."


if __name__ == "__main__":
    data = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    correct = 0
    for d in data:
        r = analyze(d["text"], d.get("sender", ""), d["channel"])
        pred = "phishing" if r["tier"] != "LOW" else "benign"
        ok = pred == d["label"]
        correct += ok
        print(f"{'OK ' if ok else 'BAD'} #{d['id']:<2} {d['label']:<8} -> {r['tier']:<6} score={r['score']}")
    print(f"\nAccuracy: {correct}/{len(data)}")
