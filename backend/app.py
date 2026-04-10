"""
KeyLeak Detector - Flask API Server
Main API for the credential leak detection framework with SQLite persistence.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from detector import scan_text, get_supported_key_types, shannon_entropy
from evaluator import run_evaluation
from notifier import send_alert, get_notifications, get_notification_stats
from datetime import datetime, timezone
import uuid
import sqlite3
import json

app = Flask(__name__)
CORS(app)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keyleak.db')

# ── Database Setup ───────────────────────────────────────────────────────────

def get_db():
    """Get database connection for current request."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at end of request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database tables."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            credential_type TEXT,
            service TEXT,
            description TEXT,
            severity TEXT,
            secret_masked TEXT,
            entropy REAL,
            risk_score INTEGER,
            source TEXT,
            source_url TEXT,
            context_snippet TEXT,
            discovered_at TEXT,
            status TEXT DEFAULT 'active'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            finding_id TEXT,
            channel TEXT,
            message TEXT,
            sent_at TEXT,
            status TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def seed_demo_data():
    """Seed demo data if database is empty."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM findings')
    count = cursor.fetchone()[0]
    
    if count == 0:
        demo_findings = [
            {
                "id": str(uuid.uuid4()),
                "credential_type": "AWS Access Key",
                "service": "Amazon Web Services",
                "description": "AWS IAM Access Key ID",
                "severity": "critical",
                "secret_masked": "AKIAI7****PLE1",
                "entropy": 3.684,
                "risk_score": 92,
                "source": "github_repo",
                "source_url": "https://github.com/user/repo/blob/main/config.py",
                "context_snippet": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE1...",
                "discovered_at": "2026-03-25T08:12:00Z",
                "status": "active",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "OpenAI Project Key",
                "service": "OpenAI",
                "description": "OpenAI Project API Key",
                "severity": "critical",
                "secret_masked": "sk-pro****z9Kf",
                "entropy": 5.102,
                "risk_score": 95,
                "source": "pastebin",
                "source_url": "https://pastebin.com/abc123",
                "context_snippet": "OPENAI_API_KEY=sk-proj-abc123def456ghi789...",
                "discovered_at": "2026-03-25T09:30:00Z",
                "status": "active",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "GitHub PAT (Classic)",
                "service": "GitHub",
                "description": "GitHub Personal Access Token (Classic)",
                "severity": "high",
                "secret_masked": "ghp_AB****efgh",
                "entropy": 4.321,
                "risk_score": 78,
                "source": "github_gist",
                "source_url": "https://gist.github.com/user/abc123",
                "context_snippet": "GITHUB_TOKEN=ghp_ABCDEFghijklmnop12345...",
                "discovered_at": "2026-03-25T10:15:00Z",
                "status": "active",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "Stripe Secret Key",
                "service": "Stripe",
                "description": "Stripe Live Secret API Key",
                "severity": "critical",
                "secret_masked": "sk_liv****wxyz",
                "entropy": 4.876,
                "risk_score": 88,
                "source": "forum",
                "source_url": "https://stackoverflow.com/questions/12345",
                "context_snippet": "stripe.api_key = sk_live_abcdefghijklmn...",
                "discovered_at": "2026-03-25T07:45:00Z",
                "status": "notified",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "Google API Key",
                "service": "Google Cloud Platform",
                "description": "Google Cloud / Maps API Key",
                "severity": "high",
                "secret_masked": "AIzaS****2345",
                "entropy": 4.102,
                "risk_score": 72,
                "source": "github_repo",
                "source_url": "https://github.com/org/app/blob/dev/.env",
                "context_snippet": "GOOGLE_MAPS_KEY=AIzaSyA1bcDefGhIjKlMn...",
                "discovered_at": "2026-03-24T22:00:00Z",
                "status": "active",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "Private SSH Key",
                "service": "SSH",
                "description": "Private SSH/PEM Key",
                "severity": "critical",
                "secret_masked": "-----****-----",
                "entropy": 5.5,
                "risk_score": 97,
                "source": "pastebin",
                "source_url": "https://pastebin.com/xyz789",
                "context_snippet": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...",
                "discovered_at": "2026-03-25T11:00:00Z",
                "status": "active",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "Slack Bot Token",
                "service": "Slack",
                "description": "Slack Bot User OAuth Token",
                "severity": "high",
                "secret_masked": "xoxb-1****vWx",
                "entropy": 3.95,
                "risk_score": 68,
                "source": "log_file",
                "source_url": "https://logs.example.com/app.log",
                "context_snippet": "Bot token: xoxb-1234567890-123456789...",
                "discovered_at": "2026-03-24T18:30:00Z",
                "status": "resolved",
            },
            {
                "id": str(uuid.uuid4()),
                "credential_type": "SendGrid API Key",
                "service": "SendGrid",
                "description": "SendGrid Mail API Key",
                "severity": "high",
                "secret_masked": "SG.abc****opq",
                "entropy": 4.65,
                "risk_score": 75,
                "source": "github_repo",
                "source_url": "https://github.com/startup/mailer/blob/main/send.py",
                "context_snippet": "SENDGRID_API_KEY=SG.abcdefghijklmnopqr...",
                "discovered_at": "2026-03-25T06:20:00Z",
                "status": "active",
            },
        ]
        
        for f in demo_findings:
            cursor.execute('''
                INSERT INTO findings (id, credential_type, service, description, severity,
                    secret_masked, entropy, risk_score, source, source_url, context_snippet,
                    discovered_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (f['id'], f['credential_type'], f['service'], f['description'],
                  f['severity'], f['secret_masked'], f['entropy'], f['risk_score'],
                  f['source'], f['source_url'], f['context_snippet'],
                  f['discovered_at'], f['status']))
        
        conn.commit()
    conn.close()

# Initialize database on startup
init_db()
seed_demo_data()

# ── Database Helper Functions ────────────────────────────────────────────────

def db_get_all_findings():
    """Get all findings from database."""
    db = get_db()
    cursor = db.execute('SELECT * FROM findings ORDER BY discovered_at DESC')
    return [dict(row) for row in cursor.fetchall()]

def db_add_finding(finding):
    """Add a finding to database."""
    db = get_db()
    db.execute('''
        INSERT INTO findings (id, credential_type, service, description, severity,
            secret_masked, entropy, risk_score, source, source_url, context_snippet,
            discovered_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (finding['id'], finding['credential_type'], finding['service'],
          finding['description'], finding['severity'], finding['secret_masked'],
          finding['entropy'], finding['risk_score'], finding['source'],
          finding['source_url'], finding['context_snippet'],
          finding['discovered_at'], finding['status']))
    db.commit()

def db_update_finding_status(finding_id, status):
    """Update finding status in database."""
    db = get_db()
    db.execute('UPDATE findings SET status = ? WHERE id = ?', (status, finding_id))
    db.commit()
    cursor = db.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


# ── API Routes ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def root():
    return jsonify({"service": "KeyLeak Detector API", "version": "1.0.0", "status": "running", "docs": "/api/health"})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "KeyLeak Detector API", "version": "1.0.0"})


@app.route("/api/scan", methods=["POST"])
def scan():
    """Scan text for credential leaks."""
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Request body must include 'text' field"}), 400

    text = data["text"]
    source = data.get("source", "manual_scan")
    source_url = data.get("source_url", "")

    results = scan_text(text, source=source, source_url=source_url)

    # Store findings and send alerts
    notifications = []
    for finding in results:
        db_add_finding(finding)
        notif = send_alert(finding)
        notifications.append(notif)

    return jsonify({
        "scan_id": str(uuid.uuid4()),
        "findings_count": len(results),
        "findings": results,
        "notifications_sent": len(notifications),
        "notifications": notifications,
    })


@app.route("/api/scan/entropy", methods=["POST"])
def analyze_entropy():
    """Analyze Shannon entropy of a given string."""
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Request body must include 'text' field"}), 400
    text = data["text"]
    ent = shannon_entropy(text)
    return jsonify({
        "text_length": len(text),
        "entropy": round(ent, 4),
        "assessment": "high randomness (likely secret)" if ent > 4.0 else
                      "moderate randomness" if ent > 3.0 else "low randomness (likely not a secret)",
    })


@app.route("/api/findings", methods=["GET"])
def get_findings():
    """Get all findings with optional filters."""
    severity = request.args.get("severity")
    service = request.args.get("service")
    source = request.args.get("source")
    status = request.args.get("status")

    results = db_get_all_findings()
    
    if severity:
        results = [f for f in results if f["severity"] == severity]
    if service:
        results = [f for f in results if f["service"].lower() == service.lower()]
    if source:
        results = [f for f in results if f["source"] == source]
    if status:
        results = [f for f in results if f["status"] == status]

    return jsonify({"total": len(results), "findings": results})


@app.route("/api/findings/<finding_id>/status", methods=["PATCH"])
def update_finding_status(finding_id):
    """Update finding status (active/notified/resolved)."""
    data = request.get_json()
    new_status = data.get("status")
    if new_status not in ("active", "notified", "resolved"):
        return jsonify({"error": "Status must be active, notified, or resolved"}), 400
    
    updated = db_update_finding_status(finding_id, new_status)
    if updated:
        return jsonify(updated)
    return jsonify({"error": "Finding not found"}), 404


@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Dashboard summary statistics."""
    findings = db_get_all_findings()
    
    total = len(findings)
    by_severity = {}
    by_service = {}
    by_source = {}
    by_status = {}
    risk_scores = []

    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_service[f["service"]] = by_service.get(f["service"], 0) + 1
        by_source[f["source"]] = by_source.get(f["source"], 0) + 1
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        risk_scores.append(f["risk_score"])

    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    notif_stats = get_notification_stats()

    return jsonify({
        "total_findings": total,
        "by_severity": by_severity,
        "by_service": by_service,
        "by_source": by_source,
        "by_status": by_status,
        "average_risk_score": round(avg_risk, 1),
        "max_risk_score": max(risk_scores) if risk_scores else 0,
        "notifications": notif_stats,
    })


@app.route("/api/key-types", methods=["GET"])
def key_types():
    """List all supported credential types."""
    return jsonify({"key_types": get_supported_key_types()})


@app.route("/api/notifications", methods=["GET"])
def notifications():
    """Get notification history."""
    limit = request.args.get("limit", 50, type=int)
    return jsonify({"notifications": get_notifications(limit)})


@app.route("/api/evaluate", methods=["GET"])
def evaluate():
    """Run precision/recall evaluation."""
    report = run_evaluation()
    return jsonify(report)


@app.route("/api/findings/clear", methods=["DELETE"])
def clear_findings():
    """Clear all findings (admin endpoint)."""
    db = get_db()
    db.execute('DELETE FROM findings')
    db.commit()
    seed_demo_data()
    return jsonify({"message": "Findings cleared and demo data restored"})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=False, port=port, host="0.0.0.0")
