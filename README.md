# 🛡️ APK Shield — AI-Powered APK Malware Analysis Platform

A production-ready system for Android APK malware analysis, reverse engineering, risk scoring, fraud intelligence, and AI-powered reporting.

---

## 🏗️ Architecture

```
boiproject/
├── backend/                    # Python FastAPI
│   ├── main.py                 # FastAPI app entrypoint
│   ├── requirements.txt
│   ├── Dockerfile
│   └── app/
│       ├── database.py         # SQLAlchemy (SQLite/PostgreSQL)
│       ├── models.py           # DB models
│       ├── schemas.py          # Pydantic schemas
│       ├── analysis/
│       │   ├── apk_analyzer.py      # Static analysis (Androguard + ZIP parser)
│       │   ├── risk_scorer.py       # Weighted risk scoring engine
│       │   ├── fraud_mapper.py      # Fraud type mapping engine
│       │   ├── similarity_engine.py # Cosine similarity engine
│       │   └── ai_explainer.py      # OpenAI/Gemini explanation layer
│       └── routes/
│           ├── upload.py       # POST /api/upload/
│           ├── analyze.py      # POST/GET /api/analyze/
│           ├── score.py        # GET /api/score/
│           ├── explain.py      # GET/POST /api/explain/
│           ├── history.py      # GET /api/history/
│           └── report.py       # GET /api/report/
├── frontend/                   # React + Vite + Tailwind
│   ├── src/
│   │   ├── pages/
│   │   │   ├── UploadPage.jsx      # File upload with drag-and-drop
│   │   │   ├── DashboardPage.jsx   # Analytics dashboard
│   │   │   ├── ReportPage.jsx      # Full analysis report viewer
│   │   │   └── HistoryPage.jsx     # Historical analyses
│   │   ├── components/
│   │   │   └── Layout.jsx          # Sidebar navigation
│   │   └── api/client.js           # Axios API client
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml          # One-command deployment
└── .env                        # Environment configuration
```

---

## 🚀 Quick Start (ONE COMMAND)

```bash
# 1. Clone/navigate to project
cd boiproject

# 2. (Optional) Set AI API key for real AI explanations
echo "GEMINI_API_KEY=your_key_here" >> .env

# 3. Run everything
docker-compose up --build

# 4. Open browser
open http://localhost:3000
```

That's it! Upload any APK and get instant analysis.

---

## 🖥️ Local Development (No Docker)

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Backend API: http://localhost:8000  
API Docs: http://localhost:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:3000 (proxies API to port 8000)

---

## 🔑 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./apk_analysis.db` | Database connection string |
| `AI_PROVIDER` | `gemini` | `gemini` or `openai` |
| `GEMINI_API_KEY` | *(empty)* | Google Gemini API key |
| `OPENAI_API_KEY` | *(empty)* | OpenAI API key |
| `SECRET_KEY` | dev key | App secret key |

> **Note:** The system works WITHOUT any API keys using intelligent template-based AI explanations.

---

## 🔍 Core Features

### 1. APK Static Analysis
- Android Manifest permission extraction
- Dangerous permission identification
- API call pattern detection
- Embedded URL extraction
- Obfuscation detection (DexGuard/ProGuard indicators)
- Multi-DEX detection
- Service, receiver, activity enumeration

### 2. Risk Scoring Engine (0–100)
Weighted multi-factor scoring:
| Component | Weight | Factors |
|-----------|--------|---------|
| Permissions | 30% | Count, severity, dangerous permissions ratio |
| API Calls | 25% | Suspicious API patterns (SMS, admin, reflect) |
| URLs | 20% | Raw IPs, suspicious TLDs, C2 endpoints |
| Obfuscation | 15% | Code hiding indicators |
| Behavior | 10% | Persistence, accessibility abuse, admin |

**Risk Levels:**
- 🟢 **SAFE** (0–24): Allow
- 🟡 **SUSPICIOUS** (25–54): Flag for review
- 🔴 **BLOCK** (55–100): Block immediately

### 3. Fraud Mapping Engine
Maps technical behaviors to fraud types:
| Technical Behavior | Fraud Type |
|-------------------|------------|
| READ_SMS + SmsManager | OTP Theft |
| SYSTEM_ALERT_WINDOW + AccessibilityService | Phishing/Overlay |
| Location + Audio + Background service | Spyware |
| DevicePolicyManager + Encryption | Ransomware |
| DexClassLoader + REQUEST_INSTALL | Dropper |
| GET_ACCOUNTS + keylogger service | Credential Stealer |

### 4. Threat Similarity Engine
- Converts APK features to 46-dimensional numeric vector
- Cosine similarity comparison against all stored APKs
- Returns top-5 similar threats with similarity percentage

### 5. AI Explanation Layer
- Supports Google Gemini API and OpenAI GPT-3.5
- Generates human-readable threat summaries
- Provides specific security recommendations
- Falls back to intelligent template explanations (no API key needed)

---

## 📡 API Reference

```
POST /api/upload/                    Upload APK file
POST /api/analyze/{hash}?filename=   Run full analysis pipeline
GET  /api/analyze/{id}               Get analysis by ID
GET  /api/score/{id}                 Get detailed score breakdown
GET  /api/explain/{id}               Get AI explanation
POST /api/explain/{id}/regenerate    Regenerate AI explanation
GET  /api/history/                   List all analyses (paginated)
GET  /api/history/stats/dashboard    Dashboard statistics
GET  /api/report/{id}/json           Full JSON report
DELETE /api/history/{id}             Delete an analysis
```

---

## 🐳 Docker Deployment

### Build & Run
```bash
docker-compose up --build -d
docker-compose logs -f
```

### Stop
```bash
docker-compose down
```

### With PostgreSQL (production)
Edit `docker-compose.yml` to uncomment the PostgreSQL service, then:
```bash
DATABASE_URL=postgresql://apkuser:apkpassword@db:5432/apkdb docker-compose up --build
```

---

## ☁️ Cloud Deployment

### Railway
```bash
# Install Railway CLI
npm install -g @railway/cli
railway login
railway init
railway up
```

### Render
1. Fork this repo
2. Create new Web Service → connect repo → set root to `backend/`
3. Build: `pip install -r requirements.txt`
4. Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Deploy frontend as Static Site → root: `frontend/` → build: `npm run build` → publish: `dist/`

---

## 🔬 Analysis Pipeline Flow

```
APK File Upload
    ↓
SHA256 Hash Computation
    ↓
Static Analysis (Androguard / ZIP Parser / Simulation)
    ↓ Extract: permissions, APIs, URLs, obfuscation, services
Risk Scoring Engine
    ↓ Weighted score 0-100 → SAFE/SUSPICIOUS/BLOCK
Fraud Mapping Engine
    ↓ Map behaviors → OTP theft, phishing, spyware, ransomware...
Feature Vectorization
    ↓ 46-dim numeric vector
Similarity Engine
    ↓ Cosine similarity → top-5 similar APKs
AI Explanation Layer
    ↓ Gemini/OpenAI → human-readable analysis + recommendations
Database Storage (SQLite/PostgreSQL)
    ↓
JSON Report + Dashboard Display
```

---

## 🧪 Testing

Run the full pipeline test:
```bash
cd backend
source venv/bin/activate
python -c "
from app.analysis.apk_analyzer import analyze_apk_simulated
from app.analysis.risk_scorer import compute_risk_score
from app.analysis.fraud_mapper import map_fraud_types
import tempfile, os

with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
    f.write(b'PK' + b'\x00' * 500)
    tmp = f.name

apk = analyze_apk_simulated(tmp)
score = compute_risk_score(apk)
fraud = map_fraud_types(apk)
print(f'Score: {score[\"risk_score\"]} | Level: {score[\"risk_level\"]}')
print(f'Frauds: {fraud[\"fraud_types\"]}')
os.unlink(tmp)
"
```

---

## 📊 Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11, FastAPI, Uvicorn |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | SQLAlchemy |
| ML | scikit-learn, numpy, pandas |
| APK Analysis | Androguard (optional) + ZIP parser |
| AI Layer | Google Gemini / OpenAI GPT-3.5 |
| Frontend | React 18, Vite, Tailwind CSS |
| Charts | Recharts |
| Animations | Framer Motion |
| Deployment | Docker, Docker Compose, Nginx |

---

## 🛡️ Security Notes

- APK files are stored by hash (no filename conflicts)
- Maximum file size: 100 MB
- Files are processed server-side only
- No APK data is sent to external services (except AI explanation text)
- SQLite database is local; PostgreSQL for production

---

*Built with ❤️ for Android security research*
