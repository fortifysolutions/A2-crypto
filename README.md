📌 A02 Cryptographic Failure Automated Tester

The script asks the user for the target domain or full URL and automatically performs a comprehensive set of security tests related to transport-layer security, cookies, headers, mixed-content, token leakages, and more.

**🚀 Features
  This tool automatically performs the following checks:

🔐 Transport Layer (TLS) Security Checks
    HTTP → HTTPS redirect enforcement
    HTTPS response analysis
    TLS certificate validation (expiry, CN/SAN, chain errors)
    HSTS (Strict-Transport-Security) detection

🍪 Cookie & Header Security Checks
    Secure flag
    HttpOnly flag
    SameSite flag
    Cache-Control for sensitive pages

🌐 Mixed Content Detection
    Detect insecure http:// assets loaded on an HTTPS page
    Prevent downgrade attacks

🔑 Token / Secret Leakage Detection
    Heuristically scans HTML for:
    JWT tokens
    API keys
    Session tokens
    Bearer tokens
    Hardcoded secrets

🧩 Generic & Universal
    Works for any web interface
    No app code access required
    No dependency on technology stack
-------------------------------------------------------------------------------------------------------------
📥 Installation
Ensure you have Python 3.7+ installed.
Install dependencies:
pip install requests beautifulsoup4

Clone the repository:
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>

▶️ Usage
Run the script:
python3 a02_crypto_test.py


When prompted:
Enter target domain or full URL: https://your-sok-or-webapp.com


The script will automatically perform all cryptographic security checks and display results in the terminal.

📊 Example Output
--------------------------------------------------------------
TEST 1: HTTP → HTTPS Redirect Check
--------------------------------------------------------------
[RESULT] HTTP status: 301
[PASS] Redirect found: https://your-domain.com/

--------------------------------------------------------------
TEST 2: HTTPS Header Inspection
--------------------------------------------------------------
Strict-Transport-Security: max-age=31536000; includeSubDomains
[PASS] HSTS Enabled
Set-Cookie: SESSION=xyz; Secure; HttpOnly; SameSite=Strict
...

--------------------------------------------------------------
TEST 3: Mixed Content Scan
--------------------------------------------------------------
[PASS] No mixed content found.

--------------------------------------------------------------
TEST 4: Token / Secret Leakage (Heuristic)
--------------------------------------------------------------
[PASS] No obvious tokens detected.

SUMMARY
✔ Redirection validated
✔ HSTS checked
✔ Cookies flags inspected
✔ Cache-control evaluated
✔ Mixed content scanned
✔ Token leak heuristics applied

📦 Project Structure
├── a02_crypto_test.py     # Main automation script
├── README.md              # Documentation (this file)
└── requirements.txt       # Dependency list (optional)

🧪 Supported Test Categories (Mapped to OWASP Top 10 – 2021 A02)
Category	Automated	Manual Required
TLS version checks	✔	Deep cipher checks (nmap)
Cert validation	✔	Full chain audit
HTTPS enforcement	✔	—
HSTS	✔	—
Cookie flags	✔	—
Mixed content	✔	Runtime monitoring (browser)
Token leakage	✔	Source code audit
Cache-control	✔	—
MITM resistance	—	Browser / proxy testing
TLS pinning	—	Mobile/embedded clients
----------------------------------------------------------------------------------------------------------------------------------
⚠️ Disclaimer
This tool is intended for authorized security testing ONLY.
Do NOT run against any target without explicit written permission.

By using this tool, you agree that:

You are responsible for your actions

You have proper authorization and approvals for the target

You comply with all legal & ethical requirements
