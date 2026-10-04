from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import re
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "sangyan.db"
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="SANGYAN Suraksha",
    description="Investor resilience and financial scam-risk assistant",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: str
    language: str = "en"


class Finding(BaseModel):
    rule: str
    severity: str
    explanation: str
    evidence: str


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    summary: str
    findings: List[Finding]
    safe_actions: List[str]
    urls: List[str]


RED_FLAGS = [
    {
        "rule": "Guaranteed returns",
        "severity": "high",
        "patterns": [
            r"\bguaranteed\b",
            r"\bguarantee(?:d)?\s+(?:profit|return|income)\b",
            r"\b100%\s*(?:profit|return)\b",
            r"\bno\s+risk\b",
        ],
        "explanation": "Guaranteed or risk-free investment returns are a major warning sign.",
        "weight": 25,
    },
    {
        "rule": "Urgency / pressure",
        "severity": "medium",
        "patterns": [
            r"\bact now\b",
            r"\blimited time\b",
            r"\bjoin now\b",
            r"\btoday only\b",
            r"\blast chance\b",
            r"\bimmediately\b",
        ],
        "explanation": "Pressure to act immediately can be used to prevent careful verification.",
        "weight": 12,
    },
    {
        "rule": "Payment request",
        "severity": "high",
        "patterns": [
            r"\bpay\b",
            r"\bdeposit\b",
            r"\btransfer\b",
            r"\bsend\s+(?:money|funds)\b",
            r"₹\s?[\d,]+",
        ],
        "explanation": "A direct request for money deserves independent verification before payment.",
        "weight": 20,
    },
    {
        "rule": "OTP / credential request",
        "severity": "critical",
        "patterns": [
            r"\botp\b",
            r"\bpassword\b",
            r"\bpin\b",
            r"\bcvv\b",
            r"\bshare\s+(?:your\s+)?(?:otp|pin|password)\b",
        ],
        "explanation": "Legitimate support should not require sharing OTPs, PINs or passwords.",
        "weight": 35,
    },
    {
        "rule": "Messaging-app tip group",
        "severity": "medium",
        "patterns": [
            r"\btelegram\b",
            r"\bwhatsapp\b",
            r"\btip\s+group\b",
            r"\bpremium\s+group\b",
        ],
        "explanation": "Unverified investment tips distributed through messaging groups can be risky.",
        "weight": 15,
    },
    {
        "rule": "Guaranteed monthly profit",
        "severity": "critical",
        "patterns": [
            r"\b\d+(?:\.\d+)?%\s*(?:monthly|per\s+month)\b",
            r"\bmonthly\s+(?:profit|return)\b",
        ],
        "explanation": "Specific guaranteed recurring returns should be treated with extreme caution.",
        "weight": 30,
    },
    {
        "rule": "Remote-access request",
        "severity": "critical",
        "patterns": [
            r"\banydesk\b",
            r"\bteamviewer\b",
            r"\bremote\s+access\b",
            r"\bscreen\s+share\b",
        ],
        "explanation": "Remote access can expose sensitive information and should not be granted to unknown parties.",
        "weight": 35,
    },
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            language TEXT NOT NULL,
            text TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            summary TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


def extract_urls(text: str) -> List[str]:
    return re.findall(
        r"https?://[^\s<>\"]+",
        text
    )


def check_url(url: str) -> Optional[Finding]:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if not host:
            return None

        suspicious_words = [
            "login",
            "verify",
            "wallet",
            "bonus",
            "reward",
            "investment",
            "profit",
            "sebi",
            "support",
        ]

        matched = [
            word
            for word in suspicious_words
            if word in host
        ]

        if len(matched) >= 2:
            return Finding(
                rule="Suspicious URL",
                severity="medium",
                explanation=(
                    "The URL contains terms commonly seen in "
                    "financial impersonation or phishing pages. "
                    "Verify the domain independently before opening "
                    "or entering credentials."
                ),
                evidence=url,
            )

    except Exception:
        return None

    return None


def analyze_text(text: str, language: str):
    findings = []
    score = 0

    normalized = text.lower()

    for rule in RED_FLAGS:
        matched_evidence = []

        for pattern in rule["patterns"]:
            match = re.search(pattern, normalized)

            if match:
                matched_evidence.append(match.group(0))

        if matched_evidence:
            findings.append(
                Finding(
                    rule=rule["rule"],
                    severity=rule["severity"],
                    explanation=rule["explanation"],
                    evidence=", ".join(
                        dict.fromkeys(matched_evidence)
                    ),
                )
            )

            score += rule["weight"]

    urls = extract_urls(text)

    for url in urls:
        url_finding = check_url(url)

        if url_finding:
            findings.append(url_finding)
            score += 15

    score = min(score, 100)

    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if risk_level == "CRITICAL":
        summary = (
            "Multiple high-risk indicators were detected. "
            "Do not send money, OTPs, passwords or remote access "
            "until the source is independently verified."
        )
    elif risk_level == "HIGH":
        summary = (
            "Several warning signs were detected. "
            "Pause and independently verify the sender, claim and payment request."
        )
    elif risk_level == "MEDIUM":
        summary = (
            "Some warning signs were detected. "
            "Verify the information before taking financial action."
        )
    else:
        summary = (
            "No major red flags were detected by the current rules. "
            "This does not prove that the content is safe."
        )

    if language.lower().startswith("hi"):
        hindi_summaries = {
            "CRITICAL": (
                "कई गंभीर जोखिम संकेत मिले हैं। "
                "स्वतंत्र रूप से सत्यापन किए बिना पैसे, OTP, पासवर्ड "
                "या remote access साझा न करें।"
            ),
            "HIGH": (
                "कई warning signs मिले हैं। "
                "रुकें और sender, claim तथा payment request को independently verify करें।"
            ),
            "MEDIUM": (
                "कुछ warning signs मिले हैं। "
                "कोई financial action लेने से पहले जानकारी verify करें।"
            ),
            "LOW": (
                "मौजूदा rules से कोई बड़ा red flag नहीं मिला। "
                "फिर भी इसका मतलब यह नहीं है कि content निश्चित रूप से सुरक्षित है।"
            ),
        }

        summary = hindi_summaries[risk_level]

    safe_actions = [
        "Do not share OTP, PIN, CVV or passwords.",
        "Do not install remote-access applications at someone else's request.",
        "Verify the organisation and contact details using an independently found official source.",
        "Do not transfer money solely because a message creates urgency or promises returns.",
        "If money has already been sent, preserve screenshots, transaction details and communication records.",
    ]

    if language.lower().startswith("hi"):
        safe_actions = [
            "OTP, PIN, CVV या password साझा न करें।",
            "किसी अनजान व्यक्ति के कहने पर remote-access application install न करें।",
            "Organisation और contact details को independently मिले official source से verify करें।",
            "सिर्फ urgency या promised returns के कारण पैसे transfer न करें।",
            "अगर पैसे भेज चुके हैं, तो screenshots, transaction details और communication records सुरक्षित रखें।",
        ]

    return score, risk_level, summary, findings, safe_actions, urls


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "SANGYAN Suraksha"
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    text = payload.text.strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Text is required."
        )

    if len(text) > 10000:
        raise HTTPException(
            status_code=400,
            detail="Text is too long."
        )

    (
        risk_score,
        risk_level,
        summary,
        findings,
        safe_actions,
        urls,
    ) = analyze_text(
        text,
        payload.language
    )

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO analyses
        (created_at, language, text, risk_score, risk_level, summary)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            payload.language,
            text,
            risk_score,
            risk_level,
            summary,
        ),
    )

    conn.commit()
    conn.close()

    return AnalyzeResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        summary=summary,
        findings=findings,
        safe_actions=safe_actions,
        urls=urls,
    )


@app.get("/api/history")
def history(limit: int = 20):
    limit = max(1, min(limit, 100))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT
            id,
            created_at,
            language,
            text,
            risk_score,
            risk_level,
            summary
        FROM analyses
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


if FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(
            directory=FRONTEND_DIR,
            html=True
        ),
        name="frontend",
    )
