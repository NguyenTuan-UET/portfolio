"""
Shared guardrail layers for Email Guard — adapted from the Day 11 lab
(K4-L3A-Day11-Guardrails-HITL-Responsible-AI).

  Rate Limiter → Input Guardrail → (doc_guard: scanner / output / actions) → Audit / Monitoring

Every layer is plain Python (no framework) so the server has zero dependencies.
Decisions are explicit strings ("ALLOW" / "BLOCK"), never ambiguous booleans.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import unicodedata
from collections import Counter, defaultdict, deque
from pathlib import Path

MAX_INPUT_CHARS = 1500


# ============================================================
# Layer 2a — Prompt-injection detection
# ============================================================

# Zero-width / bidi / soft-hyphen characters attackers use to split keywords
_INVISIBLE_CHARS = (
    "\u00ad\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c"
    "\u202d\u202e\u2060\u2061\u2062\u2063\u2064\ufeff"
)

INJECTION_PATTERNS = [
    # Instruction override (EN)
    r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+)*"
    r"(previous|prior|above|earlier|preceding|system|safety|security)?\s*"
    r"(instructions?|rules?|prompts?|directives?|guidelines?|polic(y|ies))",
    # Persona switch / jailbreak roles
    r"\byou\s+are\s+now\b",
    r"\bpretend\s+(you\s+are|to\s+be)\b",
    r"\bact\s+as\s+(a\s+|an\s+)?(unrestricted|unfiltered|jailbroken|evil|uncensored)",
    # "DAN" only in jailbreak context: after accent stripping "hướng dẫn" / "dân" also read "dan"
    r"\b(you\s+are|act\s+as|be|become|ban\s+la|dong\s+vai)\s+(a\s+|an\s+)?dan\b|\bdan\s+mode\b"
    r"|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b|\bjailbreak",
    # System prompt / hidden config extraction
    r"\bsystem\s+prompt\b",
    r"\b(reveal|show|print|repeat|dump|output|leak)\s+(me\s+)?(your|the)\s+"
    r"(hidden\s+|internal\s+|initial\s+|original\s+)?(instructions?|prompt|config(uration)?|rules)",
    r"\btranslate\s+(your|the)\s+(instructions?|prompt|rules)",
    # Direct credential extraction
    r"\b(admin|root|system|internal|database|db)\s+(password|credentials?)",
    r"\bapi[\s_-]*keys?\b",
    r"\b(database|db)\s+(host|server|connection|string)",
    r"\bconnection\s+string\b",
    r"\bfill\s+in\s+(the\s+)?blanks?\b",
    # Vietnamese variants (matched after accent stripping)
    r"\bbo\s+qua\s+(moi\s+|tat\s+ca\s+|cac\s+)?(huong\s+dan|chi\s+dan|quy\s+tac|lenh)",
    r"\bquen\s+(moi\s+|tat\s+ca\s+|cac\s+)?(huong\s+dan|chi\s+dan|quy\s+tac|lenh)",
    r"\b(tiet\s+lo|cho\s+(toi\s+)?xem|in\s+ra)\s+.*(mat\s+khau|system\s+prompt|api|cau\s+hinh|prompt)",
    r"\bmat\s+khau\s+(admin|quan\s+tri|he\s+thong)",
    r"\bgia\s+vo\s+(ban\s+)?la\b",
]


def normalize_text(text: str) -> str:
    """Canonicalize before matching: NFKC, drop invisible chars, strip accents, collapse spaces.

    NFKC folds full-width letters (``ｉｇｎｏｒｅ``) into ASCII; removing zero-width
    chars defeats ``Ignore​ all``; accent stripping lets one set of
    Vietnamese patterns match both ``bỏ qua`` and ``bo qua``.
    """
    text = unicodedata.normalize("NFKC", text or "")
    text = "".join(ch for ch in text if ch not in _INVISIBLE_CHARS)
    text = text.replace("đ", "d").replace("Đ", "D")
    text = "".join(
        ch for ch in unicodedata.normalize("NFD", text) if unicodedata.category(ch) != "Mn"
    )
    return re.sub(r"\s+", " ", text).strip().lower()


def detect_injection(user_input: str) -> str:
    normalized = normalize_text(user_input)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return "BLOCK"
    return "ALLOW"


# ============================================================
# Layer 2b — Harmful-request filter
#
# Asking "is this email phishing / a scam?" is exactly what the tool is for,
# so only requests to *produce* harm are blocked, not mentions of it.
# ============================================================

HARMFUL_REQUESTS = [
    r"\b(write|create|make|build|generate|draft|craft)\b.{0,40}\b(malware|ransomware|keylogger|virus"
    r"|phishing\s+(email|page|site|kit)|scam\s+(email|message))",
    r"\b(viet|tao|soan|lam)\b.{0,40}\b(ma\s+doc|virus|email\s+(lua\s+dao|gia\s+mao)|trang\s+gia\s+mao)",
    # Weapons / drugs only together with a make / buy verb: accent stripping turns "bơm" and
    # "bom hàng" (a refused COD order) into "bom", so the bare word would block normal shop emails
    r"\b(make|build|buy|get|sell|order)\b.{0,30}\b(bombs?|explosives?|weapons?|guns?|drugs?|meth|cocaine)\b",
    r"\b(che\s+tao|lam|mua|ban|tu\s+che|dat\s+hang)\b.{0,30}\b(bom\s+(xang|min|tu\s+che)|thuoc\s+no|vu\s+khi|sung|ma\s+tuy)\b",
]


def harmful_request(user_input: str) -> str:
    normalized = normalize_text(user_input)
    if any(re.search(p, normalized) for p in HARMFUL_REQUESTS):
        return "BLOCK"
    return "ALLOW"


# ============================================================
# Layer 2c — Restricted topics for the chatbot
#
# The assistant helps judge whether an email is a scam; it is not a lawyer and
# must not help anyone break the law. Asking "is this fake police / court email
# a scam?" stays allowed — only legal ADVICE and law-breaking requests are refused.
# ============================================================

LEGAL_ADVICE = [
    r"\b(legal\s+advice|(need|hire|find|ask)\s+a\s+(lawyer|attorney)|lawsuit|sue\s+(him|her|them|the|a)|file\s+a\s+(lawsuit|complaint)"
    r"|is\s+(it|this|that)\s+(legal|illegal|against\s+the\s+law)|what\s+does\s+the\s+law\s+say"
    r"|how\s+much\s+(is\s+the\s+)?fine|penalty\s+for)\b",
    r"\b(tu\s+van\s+(phap\s+(ly|luat)|luat)|(can|thue|tim|hoi)\s+luat\s+su|khoi\s+kien|kien\s+(ra\s+toa|ho|nguoi|cong\s+ty)"
    r"|tranh\s+chap|ly\s+hon|thua\s+ke|dieu\s+luat|bo\s+luat|nghi\s+dinh|thong\s+tu\s+\d"
    r"|(co\s+)?(vi\s+pham|trai|pham)\s+(phap\s+)?luat\s+(khong|ko|k)\b|co\s+hop\s+phap\s+(khong|ko)"
    r"|muc\s+phat|bi\s+phat\s+bao\s+nhieu|di\s+tu\s+bao\s+lau|an\s+tu|thu\s+tuc\s+phap\s+ly"
    r"|(rang\s+buoc|hieu\s+luc|gia\s+tri|trach\s+nhiem)\s+phap\s+ly|quyen\s+loi\s+hop\s+phap"
    r"|theo\s+(phap\s+)?luat|luat\s+hien\s+hanh|quy\s+dinh\s+(cua\s+)?(phap\s+luat|luat)"
    r"|(bi\s+)?phat\s+(the\s+nao|ra\s+sao|bao\s+nhieu|nhu\s+the\s+nao)"
    r"|(ve\s+mat|khia\s+canh|hau\s+qua|van\s+de)\s+phap\s+ly)",
    r"\blegally\s+binding\b|\blegal(ly)?\s+(liable|liability|rights?|obligations?)\b",
]

ILLEGAL_ACTIVITY = [
    r"\b(evade|avoid\s+paying)\s+tax(es)?\b|\blaunder(ing)?\s+money\b|\bmoney\s+laundering\b",
    r"\b(forge|fake|counterfeit)\s+(a\s+)?(id|passport|documents?|signature|invoice|certificate|license)\b",
    r"\b(get\s+around|bypass|evade|dodge)\s+the\s+(law|police|authorities)\b",
    r"\b(hack|break\s+into|take\s+over|access)\s+(someone|another|other\s+people|his|her|their)('s)?\s+(account|email|phone)",
    r"\btron\s+thue\b|\bnon\s+thue\b|\brua\s+tien\b|\blach\s+luat\b|\bqua\s+mat\s+(cong\s+an|co\s+quan)",
    r"\blam\s+gia\s+(giay\s+to|cccd|can\s+cuoc|ho\s+chieu|chu\s+ky|hoa\s+don|bang|con\s+dau)",
    r"\b(hack|chiem|lay\s+cap|danh\s+cap|vao\s+trom)\s+(tai\s+khoan|facebook|email|zalo|mat\s+khau)(\s+\w+){0,2}\s+cua\s+(nguoi|ban|vo|chong|ai)",
    r"\blua\s+(dao\s+)?(tien\s+)?(nguoi\s+khac|ho|ban\s+be)\b|\bchiem\s+doat\b",
]


# Output side: the model sometimes says "I'm not a lawyer" and then explains the law anyway.
# Strong markers (a decree number, an article, a fine amount) are enough on their own; weak markers
# only count when two different ones appear, so a lone disclaimer in a scam answer is not blocked.
LEGAL_STRONG = [
    r"\b(nghi\s+dinh|bo\s+luat|thong\s+tu)\s+(so\s+)?\d",
    r"\b(dieu|khoan)\s+\d+\s+(bo\s+luat|luat|nghi\s+dinh)",
    r"\b(phat\s+tien|muc\s+phat)\s+(tu|den|la)?\s*\d",
    r"\btheo\s+(quy\s+dinh\s+)?(cua\s+)?(phap\s+luat|luat)\s+(viet\s+nam|hien\s+hanh)",
    r"\b(article|section)\s+\d+\s+of\s+the\b|\bpenal\s+code\b|\bunder\s+(the\s+)?law,?\s+you\b",
]
LEGAL_WEAK = {
    "disclaimer": r"\b(toi|minh)\s+khong\s+phai\s+(la\s+)?(mot\s+)?luat\s+su\b|\bi('m|\s+am)\s+not\s+a\s+lawyer\b",
    "fine": r"\b(phat\s+tien|xu\s+phat|bi\s+phat|muc\s+phat|fined?|penalt(y|ies))\b",
    "violation": r"\bvi\s+pham\s+(giao\s+thong|phap\s+luat|hanh\s+chinh|hop\s+dong|ban\s+quyen)\b",
    "liability": r"\b(truy\s+cuu|trach\s+nhiem\s+(hinh\s+su|dan\s+su|phap\s+ly)|khoi\s+to|hinh\s+su|liable|liability)\b",
    "court": r"\b(toa\s+an|khoi\s+kien|kien\s+tung|boi\s+thuong|court|lawsuit|sue)\b",
    "law_ref": r"\b(quy\s+dinh\s+(cua\s+)?(phap\s+luat|luat)|theo\s+luat|luat\s+(giao\s+thong|lao\s+dong|dan\s+su|hinh\s+su))\b",
}


def legal_content(model_output: str) -> str | None:
    """Return a short description of the legal evidence found in a reply, or None."""
    normalized = normalize_text(model_output)
    for pattern in LEGAL_STRONG:
        m = re.search(pattern, normalized)
        if m:
            return f"'{m.group(0)}'"
    weak = [f"{kind}:'{m.group(0)}'" for kind, p in LEGAL_WEAK.items() if (m := re.search(p, normalized))]
    return ", ".join(weak) if len(weak) >= 2 else None


def restricted_topic(user_input: str) -> str | None:
    """Return "illegal_activity" / "legal_advice" for refused topics, else None."""
    normalized = normalize_text(user_input)
    if any(re.search(p, normalized) for p in ILLEGAL_ACTIVITY):
        return "illegal_activity"
    if any(re.search(p, normalized) for p in LEGAL_ADVICE):
        return "legal_advice"
    return None


# ============================================================
# Layer 3 — Secret patterns (used by the output guardrail in doc_guard)
# ============================================================

# Emails / phones in the user's own document are fine to echo back; secrets are not
SECRET_PATTERNS = {
    "api_key": r"\bsk-[a-zA-Z0-9_-]{6,}",
    "password": r"\b(?:password|passwd|pwd|mật\s*khẩu)\s*(?:is|là|[:=])\s*[\"'`]?[^\s\"'`,;]+",
    "internal_host": r"\b[\w.-]+\.internal(?::\d+)?\b",
}


# ============================================================
# Layer 1 — Sliding-window rate limiter (per client)
# ============================================================

class RateLimiter:
    def __init__(self, max_requests: int = 8, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client_id: str) -> tuple[str, float]:
        """Return ("ALLOW", 0) or ("BLOCK", seconds_to_wait)."""
        now = time.time()
        with self._lock:
            window = self._windows[client_id]
            while window and window[0] <= now - self.window_seconds:
                window.popleft()
            if len(window) >= self.max_requests:
                return "BLOCK", self.window_seconds - (now - window[0])
            window.append(now)
            return "ALLOW", 0.0


# ============================================================
# Layer 4 — Audit log + monitoring (side observers, never block)
# ============================================================

def anonymize(client_id: str) -> str:
    """Audit rows carry a salted hash, never the raw client address."""
    return hashlib.sha256(f"devtamin-chat:{client_id}".encode()).hexdigest()[:12]


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, **row) -> None:
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **row}
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


class Monitor:
    def __init__(self):
        self.total = 0
        self.blocked = 0
        self.redacted = 0
        self.by_layer: Counter = Counter()
        self._lock = threading.Lock()

    def record(self, *, blocked: bool, redacted: bool, layer: str | None) -> None:
        with self._lock:
            self.total += 1
            self.blocked += blocked
            self.redacted += redacted
            if layer:
                self.by_layer[layer] += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total": self.total,
                "blocked": self.blocked,
                "redacted": self.redacted,
                "block_rate": round(self.blocked / self.total, 3) if self.total else 0,
                "by_layer": dict(self.by_layer),
            }
