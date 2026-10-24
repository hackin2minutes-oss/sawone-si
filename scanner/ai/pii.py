"""Personal and sensitive data in training sets and RAG corpora.

Finding personal data in a file that trains or grounds a model matters for PDPL (Saudi Personal Data
Protection Law), the OWASP LLM "sensitive information disclosure" risk, and data-poisoning review. This is a
detector of patterns, not a classifier: it reports counts and a few redacted samples per type so a human can
judge, and it never writes the raw values into the report.

Saudi-specific detectors (national ID / Iqama with its checksum-free 1/2 prefix rule, IBAN with mod-97, local
mobile numbers) sit next to the generic ones (email, credit card via Luhn, IPv4, generic long secrets).
"""
import re
from pathlib import Path

SAMPLE_BYTES = 3_000_000

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SA_MOBILE = re.compile(r"(?<!\d)(?:\+?966|00966|0)5\d{8}(?!\d)")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SA_ID = re.compile(r"(?<!\d)[12]\d{9}(?!\d)")
IBAN = re.compile(r"\bSA\d{22}\b")      # Saudi IBAN: SA + 2 check + 20 BBAN digits = 24 chars
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
SECRET = re.compile(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|"
                    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b")


def _luhn(num):
    digits = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            d = d - 9 if d > 9 else d
        total += d
    return total % 10 == 0


def _iban_ok(iban):
    s = iban[4:] + iban[:4]
    n = "".join(str(int(c, 36)) for c in s)
    try:
        return int(n) % 97 == 1
    except ValueError:
        return False


def _redact(value, kind):
    v = value.strip()
    if kind in ("email",):
        name, _, dom = v.partition("@")
        return (name[:2] + "***@" + dom) if dom else "***"
    if len(v) <= 4:
        return "***"
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


DETECTORS = [
    ("sa-national-id", "Saudi national ID / Iqama", SA_ID, "CRITICAL", None),
    ("iban", "IBAN (bank account)", IBAN, "CRITICAL", _iban_ok),
    ("credit-card", "payment card number", CARD, "CRITICAL", _luhn),
    ("secret", "API key or token", SECRET, "CRITICAL", None),
    ("jwt", "JWT", JWT, "HIGH", None),
    ("email", "email address", EMAIL, "MEDIUM", None),
    ("sa-mobile", "Saudi mobile number", SA_MOBILE, "MEDIUM", None),
    ("ipv4", "IP address", IPV4, "LOW", None),
]


def scan_text(text, source):
    """One finding per data type present, with a count and up to three redacted samples."""
    out = []
    for key, label, rx, sev, validate in DETECTORS:
        seen, samples = set(), []
        for m in rx.finditer(text):
            val = m.group(0)
            if validate and not validate(val):
                continue
            if key == "ipv4" and val.startswith(("0.", "127.", "255.255.255")):
                continue
            norm = re.sub(r"\s", "", val)
            if norm in seen:
                continue
            seen.add(norm)
            if len(samples) < 3:
                samples.append(_redact(val, key))
        if seen:
            out.append({"id": f"data-pii-{key}", "severity": sev, "kind": label, "count": len(seen),
                        "samples": samples, "file": source})
    return out


def scan_files(ws, entries, max_files=200):
    """entries: detect() dataset/corpus items ({path, ...}); ws: workspace root. Returns findings with file+line
    omitted (the file is the unit) and a per-file sample."""
    ws = Path(ws)
    out = []
    for e in entries[:max_files]:
        p = ws / e["path"]
        try:
            text = p.read_text(errors="replace")[:SAMPLE_BYTES]
        except OSError:
            continue
        for f in scan_text(text, e["path"]):
            f["title"] = (f"{f['count']} {f['kind']}(s) in training/RAG data" if f["count"] != 1
                          else f"a {f['kind']} in training/RAG data") + f" — e.g. {', '.join(f['samples'])}"
            out.append(f)
    return out
