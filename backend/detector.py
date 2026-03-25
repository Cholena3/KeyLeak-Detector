"""
CredShield - Secret Detection Engine
Regex + Shannon Entropy based credential leak detector.
"""
import re
import math
import time
import uuid
from datetime import datetime, timezone


# ── Credential Pattern Registry ──────────────────────────────────────────────
CREDENTIAL_PATTERNS = {
    "AWS Access Key": {
        "regex": r"(?<![A-Za-z0-9/+])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])",
        "severity": "critical",
        "service": "Amazon Web Services",
        "description": "AWS IAM Access Key ID",
        "entropy_threshold": 3.0,
    },
    "AWS Secret Key": {
        "regex": r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        "severity": "critical",
        "service": "Amazon Web Services",
        "description": "AWS Secret Access Key (entropy-validated)",
        "entropy_threshold": 4.5,
        "requires_context": ["aws_secret", "secret_access_key", "AWS_SECRET"],
    },
    "OpenAI API Key": {
        "regex": r"(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
        "severity": "critical",
        "service": "OpenAI",
        "description": "OpenAI GPT API Key",
        "entropy_threshold": 4.0,
    },
    "OpenAI Project Key": {
        "regex": r"(sk-proj-[A-Za-z0-9_-]{40,200})",
        "severity": "critical",
        "service": "OpenAI",
        "description": "OpenAI Project API Key",
        "entropy_threshold": 4.0,
    },
    "GitHub PAT (Classic)": {
        "regex": r"(ghp_[A-Za-z0-9]{36})",
        "severity": "high",
        "service": "GitHub",
        "description": "GitHub Personal Access Token (Classic)",
        "entropy_threshold": 3.5,
    },
    "GitHub PAT (Fine-grained)": {
        "regex": r"(github_pat_[A-Za-z0-9_]{82})",
        "severity": "high",
        "service": "GitHub",
        "description": "GitHub Fine-grained Personal Access Token",
        "entropy_threshold": 3.5,
    },
    "GitHub OAuth Token": {
        "regex": r"(gho_[A-Za-z0-9]{36})",
        "severity": "high",
        "service": "GitHub",
        "description": "GitHub OAuth Access Token",
        "entropy_threshold": 3.5,
    },
    "Stripe Secret Key": {
        "regex": r"(sk_live_[A-Za-z0-9]{24,99})",
        "severity": "critical",
        "service": "Stripe",
        "description": "Stripe Live Secret API Key",
        "entropy_threshold": 4.0,
    },
    "Stripe Publishable Key": {
        "regex": r"(pk_live_[A-Za-z0-9]{24,99})",
        "severity": "medium",
        "service": "Stripe",
        "description": "Stripe Live Publishable Key",
        "entropy_threshold": 3.5,
    },
    "Google API Key": {
        "regex": r"(AIza[0-9A-Za-z\-_]{35})",
        "severity": "high",
        "service": "Google Cloud Platform",
        "description": "Google Cloud / Maps API Key",
        "entropy_threshold": 3.5,
    },
    "GCP Service Account": {
        "regex": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "service": "Google Cloud Platform",
        "description": "GCP Service Account JSON Key",
        "entropy_threshold": 0,
    },
    "Slack Bot Token": {
        "regex": r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24})",
        "severity": "high",
        "service": "Slack",
        "description": "Slack Bot User OAuth Token",
        "entropy_threshold": 3.5,
    },
    "Slack Webhook URL": {
        "regex": r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})",
        "severity": "medium",
        "service": "Slack",
        "description": "Slack Incoming Webhook URL",
        "entropy_threshold": 3.0,
    },
    "Twilio API Key": {
        "regex": r"(SK[0-9a-fA-F]{32})",
        "severity": "high",
        "service": "Twilio",
        "description": "Twilio API Key SID",
        "entropy_threshold": 3.5,
    },
    "SendGrid API Key": {
        "regex": r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})",
        "severity": "high",
        "service": "SendGrid",
        "description": "SendGrid Mail API Key",
        "entropy_threshold": 4.0,
    },
    "Mailgun API Key": {
        "regex": r"(key-[0-9a-zA-Z]{32})",
        "severity": "high",
        "service": "Mailgun",
        "description": "Mailgun API Key",
        "entropy_threshold": 3.5,
    },
    "Private SSH Key": {
        "regex": r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
        "severity": "critical",
        "service": "SSH",
        "description": "Private SSH/PEM Key",
        "entropy_threshold": 0,
    },
    "Heroku API Key": {
        "regex": r"(heroku[a-zA-Z0-9_]*[=:]\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        "severity": "high",
        "service": "Heroku",
        "description": "Heroku Platform API Key",
        "entropy_threshold": 3.0,
    },
    "Generic JWT": {
        "regex": r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        "severity": "medium",
        "service": "JWT",
        "description": "JSON Web Token",
        "entropy_threshold": 4.0,
    },
    "Azure Storage Key": {
        "regex": r"(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};)",
        "severity": "critical",
        "service": "Microsoft Azure",
        "description": "Azure Storage Account Connection String",
        "entropy_threshold": 4.0,
    },
    "Discord Bot Token": {
        "regex": r"([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27})",
        "severity": "high",
        "service": "Discord",
        "description": "Discord Bot Token",
        "entropy_threshold": 4.0,
    },
}

# ── False Positive Indicators ────────────────────────────────────────────────
FALSE_POSITIVE_INDICATORS = [
    "example", "sample", "test", "fake", "dummy", "placeholder",
    "your_api_key", "xxxx", "0000", "INSERT_KEY_HERE", "REPLACE_ME",
    "todo", "fixme", "changeme", "<your", "{your", "YOUR_",
    "aaaaaaa",
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string — higher = more random = more likely real."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_false_positive(secret: str, context: str) -> bool:
    """NLP-lite context filtering to reduce false positives."""
    combined = (secret + " " + context).lower()
    for indicator in FALSE_POSITIVE_INDICATORS:
        if indicator in combined:
            return True
    # Check for repeating characters (low entropy junk)
    if len(set(secret)) < len(secret) * 0.3:
        return True
    return False


def compute_risk_score(severity: str, entropy: float, source: str) -> int:
    """Compute 0-100 risk score based on severity, entropy, and source."""
    base = {"critical": 80, "high": 60, "medium": 40, "low": 20}.get(severity, 30)
    # Entropy bonus: higher entropy = more likely real
    entropy_bonus = min(int(entropy * 3), 15)
    # Source bonus
    source_bonus = {
        "github_repo": 10, "github_gist": 8, "pastebin": 12,
        "forum": 5, "log_file": 7, "manual_scan": 3,
    }.get(source, 0)
    return min(base + entropy_bonus + source_bonus, 100)


def scan_text(text: str, source: str = "manual_scan", source_url: str = "") -> list:
    """
    Core detection engine: scan text for credential leaks.
    Returns list of finding dicts.
    """
    findings = []
    for cred_type, config in CREDENTIAL_PATTERNS.items():
        pattern = re.compile(config["regex"])
        for match in pattern.finditer(text):
            secret = match.group(0)
            # Context: 80 chars around the match
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            context = text[start:end]

            # If pattern requires context keywords, check them
            if "requires_context" in config:
                if not any(kw.lower() in text.lower() for kw in config["requires_context"]):
                    continue

            # False positive check
            if is_false_positive(secret, context):
                continue

            # Entropy check
            entropy = shannon_entropy(secret)
            if entropy < config["entropy_threshold"]:
                continue

            risk_score = compute_risk_score(config["severity"], entropy, source)

            findings.append({
                "id": str(uuid.uuid4()),
                "credential_type": cred_type,
                "service": config["service"],
                "description": config["description"],
                "severity": config["severity"],
                "secret_masked": secret[:6] + "*" * (len(secret) - 10) + secret[-4:] if len(secret) > 14 else secret[:3] + "***",
                "entropy": round(entropy, 3),
                "risk_score": risk_score,
                "source": source,
                "source_url": source_url,
                "context_snippet": context[:60] + "..." if len(context) > 60 else context,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "status": "active",
            })
    return findings


def get_supported_key_types() -> list:
    """Return info about all supported credential types for the dashboard."""
    return [
        {
            "name": name,
            "service": cfg["service"],
            "severity": cfg["severity"],
            "description": cfg["description"],
            "pattern_hint": cfg["regex"][:50] + "..." if len(cfg["regex"]) > 50 else cfg["regex"],
        }
        for name, cfg in CREDENTIAL_PATTERNS.items()
    ]
