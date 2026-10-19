# SecureLens — URL Analysis Using LLM

> **Graduation Project** · A full-stack URL threat-analysis platform that combines multi-source threat intelligence with AI-generated security reports.

SecureLens lets you paste any URL, runs it through **8+ security scanners** in parallel, calculates a weighted risk score, and hands the raw evidence to an LLM that writes both an executive summary and a deep technical assessment — all inside a polished web dashboard.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Windows](#windows)
  - [Linux / macOS](#linux--macos)
- [Configuration](#configuration)
  - [API Keys](#api-keys)
  - [AI Provider Setup](#ai-provider-setup)
  - [Performance Tuning](#performance-tuning)
- [Running the Application](#running-the-application)
- [Browser Extension](#browser-extension)
- [Project Structure](#project-structure)
- [Usage Guide](#usage-guide)
- [API Documentation](#api-documentation)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

| Category | Details |
|---|---|
| **Threat Intelligence** | VirusTotal, AbuseIPDB, Shodan, URLScan.io, SecurityTrails, NVD (CVE lookup), IPinfo GeoIP, ProjectDiscovery Chaos |
| **Deep Content Analysis** | Redirect chain tracing, DOM profiling, security-header audit, suspicious-pattern detection, page metadata extraction |
| **AI Reports** | Dual reports (executive + technical) via Ollama (local), Ollama Cloud, OpenAI GPT, or Google Gemini — now grounded with bundled threat-knowledge RAG and MITRE ATT&CK enrichment |
| **AI Chat** | Ask follow-up questions about any scan result using any configured AI provider |
| **CVE Intelligence** | Technology fingerprinting → NVD CVE mapping, EPSS scores, Shodan port enrichment, subdomain-wide scanning |
| **Risk Engine** | Weighted scoring from every source with a full breakdown visible in the report |
| **Dashboard** | Scan history, statistics (malicious / suspicious / caution / safe), recent activity |
| **User System** | Registration, login, JWT auth, admin panel, password policies, account lockout, CSRF protection |
| **Browser Extension** | Chrome Manifest V3 extension ("SecureLens Guardian") with popup scan, warning interstitials, and extension-to-backend pairing |
| **Scan Caching** | Domain-level deduplication — repeated scans of the same domain reuse the existing analysis within a configurable TTL |
| **Export** | Exportable HTML reports for offline archival |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      Browser / Extension                     │
└────────────────────────────┬─────────────────────────────────┘
                             │  HTTP / REST
┌────────────────────────────▼─────────────────────────────────┐
│                    FastAPI Application                        │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
│  │  Routes   │  │  Auth    │  │ Dashboard │  │ Extension  │  │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  └─────┬──────┘  │
│       └──────────────┴──────────────┴──────────────┘         │
│                          │                                    │
│  ┌───────────────────────▼───────────────────────────────┐   │
│  │              Scan Service (Orchestrator)               │   │
│  │  ┌─────────────────────────────────────────────────┐  │   │
│  │  │           Threat Intelligence Engine             │  │   │
│  │  │  VirusTotal · AbuseIPDB · Shodan · URLScan.io   │  │   │
│  │  │  SecurityTrails · NVD · IPinfo · Chaos · SSL    │  │   │
│  │  │  DeepContent · DNS · WHOIS · Tech Fingerprint   │  │   │
│  │  └─────────────────────────────────────────────────┘  │   │
│  │  ┌─────────────────────────────────────────────────┐  │   │
│  │  │    LLM Service (Ollama / OpenAI / Gemini)       │  │   │
│  │  └─────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────┘   │
│                          │                                    │
│  ┌───────────────────────▼───────────────────────────────┐   │
│  │                SQLite Database                         │   │
│  │  scans · users · rules · chat · extension_sessions    │   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12+, FastAPI, Uvicorn, Pydantic |
| Database | SQLite (zero-config, file-based) |
| Templating | Jinja2 + custom HTML/CSS/JS frontend |
| HTTP Client | httpx (async, HTTP/2) |
| AI Integration | Ollama, OpenAI API, Google Gemini API, local threat-knowledge RAG (FAISS + sentence-transformers with lexical fallback) |
| Security | bcrypt, python-jose (JWT), HMAC-based CSRF |
| Rate Limiting | aiolimiter (per-API), slowapi, in-memory IP trackers |
| DNS | dnspython |
| Parsing | BeautifulSoup4, lxml |
| Browser Extension | Chrome Manifest V3 (vanilla JS) |

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.12 or newer** | Tested on 3.12, 3.13 and 3.14. Any 3.12+ release works. |
| **pip** | Ships with Python. |
| **Git** | To clone the repository. |
| **Ollama** *(optional)* | Required only if you want **local** AI reports. Install from [ollama.com](https://ollama.com). If you skip Ollama, use OpenAI or Gemini instead. |

---

## Installation

### Windows

```powershell
# 1. Clone the repository
git clone https://github.com/<your-username>/securelens.git
cd securelens

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the virtual environment
venv\Scripts\activate

# 4. Verify Python version (should print 3.12+)
python --version

# 5. Install dependencies
pip install -r requirements.txt
```

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/securelens.git
cd securelens

# 2. Create a virtual environment
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Verify Python version (should print 3.12+)
python --version

# 5. Install dependencies
pip install -r requirements.txt
```

> **Note:** On some Linux distributions you may need `python3-venv` installed first:
> ```bash
> sudo apt install python3-venv   # Debian / Ubuntu
> ```

---

## Configuration

All configuration lives in **`config.ini`** at the project root. A template is included in the repository — open it and fill in your own values.

### API Keys

Obtain free API keys from each provider and paste them into the `[API_KEYS]` section:

| Key | Where to Get It | Required? |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Recommended |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Recommended |
| `IPINFO_TOKEN` | [ipinfo.io](https://ipinfo.io/account/token) | Optional |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com/api) | Optional |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/profile/) | Optional |
| `SECURITYTRAILS_API_KEY` | [securitytrails.com](https://securitytrails.com/app/account) | Optional |
| `CHAOS_API_KEY` | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/) | Optional |
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | Optional |

> Missing keys are **not fatal** — scanners that lack a key are simply skipped, and their section in the report shows "No API Key".

### AI Provider Setup

Configure one or more AI providers in `config.ini`. You only need **one** working provider for AI reports.

**Ollama (local, free)**
```ini
[OLLAMA]
MODEL_NAME = llama3.2
API_URL = http://localhost:11434/api/generate
```
Then start Ollama in a separate terminal:
```bash
ollama serve
ollama pull llama3.2
```

**OpenAI**
```ini
[OPENAI]
API_KEY = sk-...
MODEL_NAME = gpt-4o
```

**Google Gemini**
```ini
[GEMINI]
API_KEY = your-gemini-api-key
MODEL_NAME = gemini-2.5-flash
```

Set the default provider:
```ini
[AI_CHAT]
DEFAULT_PROVIDER = ollama        # ollama | ollama_cloud | openai | gemini
```

> You can switch providers at runtime from the Settings page inside the web UI.

### Performance Tuning

The `[PERFORMANCE]` and `[CACHE]` sections let you control concurrency, timeouts, and how aggressively the CVE engine enriches results:

```ini
[PERFORMANCE]
MAX_CONNECTIONS = 15
REQUEST_TIMEOUT = 20
NVD_RATE_LIMIT_DELAY = 0.4
MAX_CVE_ENRICHMENT = 500
MAX_SUBDOMAIN_CVE_SCAN = 200
MAX_SUBDOMAIN_RESOLVE = 500

[CACHE]
IP_CACHE_TTL = 300
ENABLE_SCAN_CACHE = true
SCAN_CACHE_TTL = 86400
```

---

## Running the Application

```bash
# Make sure the virtual environment is active, then:
python -m uvicorn main:app --reload
```

Or simply:
```bash
python main.py
```

The server starts at **http://127.0.0.1:8000**. Open it in your browser.

| URL | Description |
|---|---|
| `http://127.0.0.1:8000` | Home page — enter a URL to scan |
| `http://127.0.0.1:8000/login` | Login page |
| `http://127.0.0.1:8000/register` | Create an account (first user becomes admin) |
| `http://127.0.0.1:8000/dashboard` | Dashboard with scan history and stats |
| `http://127.0.0.1:8000/docs` | Interactive Swagger API docs |
| `http://127.0.0.1:8000/redoc` | ReDoc API reference |

---

## Browser Extension

The **SecureLens Guardian** Chrome extension lives in the `extension/` directory.

### Installation (Developer Mode)

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **"Load unpacked"** and select the `extension/` folder
4. The SecureLens icon appears in your toolbar

### Pairing with the Backend

1. Start the backend server (`python main.py`)
2. Log in to the web UI
3. Navigate to **Settings → Extension** and click **"Generate Pairing Code"**
4. Open the extension popup and enter the pairing code
5. The extension is now authenticated and can trigger scans directly from any tab

### Features

- **Quick Scan** — scan the current tab's domain with one click
- **Warning Interstitial** — blocks navigation to high-risk pages with a warning screen
- **Scan History** — view recent scans directly in the popup

---

## Project Structure

```
securelens/
├── main.py                        # Application entry point
├── config.ini                     # API keys and settings (DO NOT COMMIT real keys)
├── requirements.txt               # Pinned Python dependencies
├── README.md
│
├── app/
│   ├── core/
│   │   ├── application.py         # FastAPI factory (create_app)
│   │   ├── config.py              # Settings dataclass + config.ini reader
│   │   ├── database.py            # SQLite handler, migrations, repositories
│   │   ├── security.py            # Password hashing, JWT, CSRF, rate limiting
│   │   └── logger.py              # Structured event logging
│   │
│   ├── models/
│   │   └── schemas.py             # Pydantic request/response schemas
│   │
│   ├── routes/
│   │   ├── api.py                 # REST API endpoints (scan, status, chat)
│   │   ├── auth.py                # Login, register, logout, password change
│   │   ├── dashboard.py           # Dashboard page and stats
│   │   ├── scans.py               # Scan submission and result pages
│   │   ├── admin.py               # Admin user management
│   │   ├── settings.py            # User settings page
│   │   └── extension.py           # Extension pairing and scan API
│   │
│   ├── services/
│   │   ├── threat_intel.py        # Threat intelligence engine (all scanners)
│   │   ├── llm_service.py         # Multi-provider LLM integration
│   │   ├── scan_service.py        # Scan lifecycle orchestration
│   │   ├── report_service.py      # Report formatting helpers
│   │   ├── rag_service.py         # Local threat-knowledge RAG retrieval and MITRE enrichment
│   │   └── extension_service.py   # Extension session management
│   │
│   ├── data/
│   │   └── rag/                   # Bundled threat corpus, FAISS index, and RAG metadata
│   │
│   ├── repositories/             # Data access layer (scans, auth, chat, config)
│   │
│   └── utils/
│       ├── dependencies.py        # FastAPI dependency injection
│       ├── domain_utils.py        # Domain parsing and normalization
│       └── json_utils.py          # Safe JSON serialization
│
├── tools/
│   └── rebuild_rag_index.py       # Rebuild the local FAISS index after editing the threat corpus
│
├── templates/                     # Jinja2 HTML templates
│   ├── base.html                  # Shared layout (navbar, footer)
│   ├── index.html                 # Home / URL submission page
│   ├── login.html                 # Login page
│   ├── register.html              # Registration page
│   ├── dashboard.html             # User dashboard
│   ├── result.html                # Full scan report
│   ├── result_export.html         # Exportable report format
│   ├── loading.html               # Scan progress screen with animations
│   ├── settings.html              # User settings
│   ├── admin_users.html           # Admin panel
│   ├── change_password.html       # Password change form
│   └── extension_connect.html     # Extension pairing page
│
├── static/
│   ├── css/styles.css             # Global styles
│   └── js/                        # Client-side JavaScript
│       ├── home-page.js
│       ├── loading-page.js
│       ├── loading-games.js
│       ├── report-page.js
│       ├── report-filters.js
│       ├── dashboard-page.js
│       └── scripts.js
│
└── extension/                     # Chrome Extension (Manifest V3)
    ├── manifest.json
    ├── background.js              # Service worker
    ├── popup.html / popup.js / popup.css
    └── warning.html / warning.js / warning.css
```

---

## Usage Guide

### Scanning a URL

1. Open **http://127.0.0.1:8000**
2. Enter a URL (e.g., `https://example.com`) and click **Scan**
3. A real-time progress screen shows each analysis stage
4. The full report loads when all scanners and the AI summary complete

### Test URLs

Use these to verify the system works correctly:

| URL | Expected Result |
|---|---|
| `http://testsafebrowsing.appspot.com/s/malware.html` | Flagged as **Malicious** |
| `https://example.com` | Classified as **Safe** |

### Understanding the Report

- **Risk Score** — 0–100 composite score from all sources
- **Verdict** — SAFE / CAUTION / SUSPICIOUS / MALICIOUS
- **AI Report** — Executive summary + technical analysis
- **Scanner Breakdown** — Individual results from each intelligence source
- **Security Headers** — Which HTTP security headers are present/missing
- **CVE Intelligence** — Known vulnerabilities for detected technologies
- **AI Chat** — Ask follow-up questions about the scan

---

## API Documentation

The backend exposes a full REST API. Once the server is running, visit:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

Key endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Submit a URL for analysis |
| `GET` | `/api/scan/{id}/status` | Poll scan progress |
| `GET` | `/report/{id}` | View completed report |
| `POST` | `/api/chat` | Chat about a scan result |
| `POST` | `/login` | Authenticate and receive JWT |
| `POST` | `/register` | Create a new account |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError` | Make sure the virtual environment is **activated** before running |
| Ollama "not reachable" error | Start Ollama with `ollama serve` in a separate terminal, then pull a model: `ollama pull llama3.2` |
| "No API Key" in report sections | Add the corresponding key to `config.ini` — see [API Keys](#api-keys) |
| Port 8000 already in use | Stop the other process or run with `--port 8001` |
| Extension not connecting | Ensure the backend is running on `127.0.0.1:8000` and the extension is paired |
| Slow scans | Reduce `MAX_SUBDOMAIN_CVE_SCAN` and `MAX_CVE_ENRICHMENT` in `config.ini` |
| Database errors after update | Delete `url_analysis.db` to reset (warning: this clears all data) |
| Python version mismatch | The project requires Python 3.12+. Check with `python --version` |

---

## Security Notes

- **`config.ini` contains sensitive API keys** — add it to `.gitignore` before pushing to a public repository, or replace real keys with placeholders.
- The `SECRET_KEY` in `[SYSTEM]` is auto-generated on first run if not set. Keep it consistent across deployments to avoid invalidating existing JWT sessions.
- The first registered user is automatically promoted to **admin**.

---

## License

This project was developed as a graduation project. Refer to your institution's guidelines for usage and distribution terms.
