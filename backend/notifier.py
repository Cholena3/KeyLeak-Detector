"""
CredShield - Mock Notification Module
Simulates alerting affected developers/services when credentials are leaked.
"""
from datetime import datetime, timezone
import uuid

# In-memory notification log
notification_log = []


def send_alert(finding: dict) -> dict:
    """
    Mock notification: in production this would send email/Slack/PagerDuty alerts.
    Returns the notification record.
    """
    notification = {
        "id": str(uuid.uuid4()),
        "finding_id": finding["id"],
        "credential_type": finding["credential_type"],
        "service": finding["service"],
        "severity": finding["severity"],
        "risk_score": finding["risk_score"],
        "message": (
            f"🚨 ALERT: {finding['severity'].upper()} severity {finding['credential_type']} "
            f"detected from {finding['source']}. Risk score: {finding['risk_score']}/100. "
            f"Service: {finding['service']}. Immediate rotation recommended."
        ),
        "channels": get_channels_for_severity(finding["severity"]),
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "status": "sent",
    }
    notification_log.append(notification)
    return notification


def get_channels_for_severity(severity: str) -> list:
    """Determine notification channels based on severity."""
    channels = {
        "critical": ["email", "slack", "pagerduty", "sms"],
        "high": ["email", "slack", "pagerduty"],
        "medium": ["email", "slack"],
        "low": ["email"],
    }
    return channels.get(severity, ["email"])


def get_notifications(limit: int = 50) -> list:
    """Return recent notifications."""
    return sorted(notification_log, key=lambda n: n["sent_at"], reverse=True)[:limit]


def get_notification_stats() -> dict:
    """Return notification statistics."""
    total = len(notification_log)
    by_severity = {}
    for n in notification_log:
        sev = n["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"total_sent": total, "by_severity": by_severity}
