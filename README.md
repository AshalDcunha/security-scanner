# 🔍 Mini Security Scanner with AI Analysis

A security reconnaissance tool that crawls a target website, runs basic security checks, and uses an LLM to analyze and summarize findings.

---

## 📁 Project Structure

```
security-scanner/
├── crawler.py          # Part 1: Endpoint discovery (web crawling)
├── checker.py          # Part 2: Security checks on each endpoint
├── ai_analysis.py      # Part 3: AI-powered analysis via OpenRouter
├── main.py             # Orchestrator — runs all 3 parts together
├── .env                # Your API key (never commit this to Git!)
├── .env.example        # Template showing what .env should look like
├── README.md           # This file
│
├── endpoints.json      # [Generated] Crawler output
├── security_findings.json  # [Generated] Checker output
└── ai_report.md        # [Generated] AI analysis report
```

---

## ⚙️ Setup Instructions

### 1. Prerequisites

- **Python 3.8+** — Download from https://python.org
- **Docker Desktop** — Download from https://docker.com/products/docker-desktop/

### 2. Run the Target Application (OWASP Juice Shop)

Open a terminal and run:

```bash
docker run -p 3000:3000 bkimminich/juice-shop
```

Wait for the message: `Server listening on port 3000`  
Then verify it works by visiting: http://localhost:3000

> ⚠️ **Keep this terminal open** while running the scanner. The app stops when you close it.

### 3. Set Up Python Environment

Open a **new terminal** in the project folder:

```bash
# Create a virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Activate it (Mac/Linux)
source venv/bin/activate

# Install dependencies
pip install requests beautifulsoup4 python-dotenv
```

### 4. Configure Your API Key

1. Sign up at https://openrouter.ai (free)
2. Go to **API Keys** → Create a new key
3. Create a file called `.env` in the project folder:

```
OPENROUTER_API_KEY=sk-or-v1-your-actual-key-here
```

> ⚠️ Never share this file or commit it to GitHub.

---

## 🚀 How to Run

### Run the full scanner (all 3 parts):

```bash
python main.py
```

### Run with options:

```bash
# Scan a different URL
python main.py --url http://localhost:3000

# Crawl deeper (more pages found, but slower)
python main.py --depth 3

# Skip AI analysis (if no API key yet)
python main.py --skip-ai

# Re-run checks without re-crawling (faster)
python main.py --no-crawl

# Save outputs to a specific folder
python main.py --output-dir ./results
```

### Run each part individually (for testing/debugging):

```bash
# Part 1 only — crawl and find endpoints
python crawler.py

# Part 2 only — run security checks (needs endpoints.json)
python checker.py

# Part 3 only — get AI analysis (needs security_findings.json)
python ai_analysis.py
```

---

## 📊 Sample Output

### endpoints.json (Part 1 output)
```json
{
  "base_url": "http://localhost:3000",
  "endpoints_found": [
    "/",
    "/api/Challenges",
    "/api/Products",
    "/rest/admin/application-configuration",
    "/rest/user/login",
    "/rest/basket/1"
  ],
  "total_count": 6
}
```

### security_findings.json (Part 2 output)
```json
{
  "summary": {
    "endpoints_with_findings": 3,
    "total_findings": 8,
    "by_severity": { "critical": 0, "high": 2, "medium": 5, "low": 1 }
  },
  "results": [
    {
      "endpoint": "/rest/admin/application-configuration",
      "findings": [
        {
          "type": "sensitive_path",
          "severity": "high",
          "detail": "URL contains sensitive keyword: 'admin'"
        },
        {
          "type": "missing_header",
          "severity": "medium",
          "detail": "Missing Content-Security-Policy — no protection against XSS injection"
        }
      ]
    }
  ]
}
```

### ai_report.md (Part 3 output)
```
## 1. CRITICAL FINDINGS SUMMARY
The most serious issue found is the exposed admin configuration endpoint...

## 2. PRIORITIZED ENDPOINT LIST
1. /rest/admin/application-configuration — HIGH priority...

## 3. RECOMMENDED NEXT STEPS
- Restrict access to /rest/admin/* with authentication middleware...
```

---

## 🧠 Assumptions Made

1. **Juice Shop runs on `http://localhost:3000`** — This is the default Docker setup.

2. **Crawl depth defaults to 2** — Depth 3+ finds more endpoints but takes significantly longer since Juice Shop is a large app. Depth 2 finds the most important ones.

3. **Only same-domain URLs are followed** — External links (e.g., to GitHub or Twitter) are ignored, since we're only assessing the target application.

4. **JavaScript endpoint extraction uses regex** — Juice Shop is an Angular SPA, meaning endpoints are embedded in minified JavaScript. We use pattern matching rather than executing the JavaScript (which would require a full browser engine). This means some dynamically constructed URLs may be missed.

5. **Security checks are passive** — We don't attempt authentication bypass, SQL injection, or any active exploitation. This is a reconnaissance tool only.

6. **OPTIONS requests may not always reveal all methods** — Some servers don't implement OPTIONS correctly. The check is best-effort.

---

## 🔧 What I Would Improve With More Time

_(See writeup.md for the full version)_

- **Async crawling** with `asyncio` + `httpx` for 5–10x faster discovery
- **JavaScript execution** using Playwright/Puppeteer to handle dynamically rendered endpoints
- **Authentication testing** — retry endpoints with/without session cookies and compare responses
- **SARIF export** format for integration with GitHub Code Scanning
- **Rate limiting** to be more respectful of target servers
- **Deduplication** of functionally identical endpoints (e.g., `/api/Products/1` and `/api/Products/2`)

---

## 🛡️ Disclaimer

This tool is for **educational use only** against systems you have permission to test. Only run it against OWASP Juice Shop or other intentionally vulnerable applications you control.
