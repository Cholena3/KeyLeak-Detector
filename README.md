# 🛡️ CredShield — API Key & Secret Leak Detection Framework

Hackathon project: Automatically discovers exposed credentials, classifies type/severity, and alerts affected services.

## Quick Start

### Backend (Python/Flask)
```bash
cd backend
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5050
```

### Frontend (React)
```bash
cd frontend
npm install
npm start
# Runs on http://localhost:3000
```

## Features
- 21 credential pattern detectors (AWS, OpenAI, GitHub, Stripe, GCP, Slack, etc.)
- Shannon entropy analysis + NLP context filtering for false positive reduction
- Risk scoring (0-100) based on severity, entropy, and source
- Dark/Light mode dashboard with charts
- Pop-up alert notifications on detection
- Precision/Recall evaluation report (F1=1.0 on benchmark)
- Mock notification system (email, Slack, PagerDuty, SMS)

## API Endpoints
| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/scan` | POST | Scan text for secrets |
| `/api/findings` | GET | List all findings (filterable) |
| `/api/dashboard/stats` | GET | Dashboard statistics |
| `/api/key-types` | GET | Supported credential types |
| `/api/notifications` | GET | Notification history |
| `/api/evaluate` | GET | Run precision/recall evaluation |
