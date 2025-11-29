#!/usr/bin/env python3
"""
AUTOMATED OWASP A02 – CRYPTOGRAPHIC FAILURE TESTER
Generic script usable for SOK, CMS, OMS, or any web interface.
It AUTOMATICALLY asks the tester for the target domain/URL.
"""

import requests
import re
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
urllib3.disable_warnings()

# ------------------------- USER INPUT --------------------------
TARGET = input("Enter target domain or full URL (e.g., https://kiosk.example.com): ").strip()

if not TARGET.startswith("http://") and not TARGET.startswith("https://"):
    TARGET = "https://" + TARGET

print("\n[INFO] Testing target:", TARGET)
# ---------------------------------------------------------------

def print_header(title):
    print("\n" + "-"*70)
    print(title)
    print("-"*70)

# ---------------------------------------------------------------
# Test 1: HTTP → HTTPS Redirect
print_header("TEST 1: HTTP → HTTPS Redirect Check")
try:
    http_url = TARGET.replace("https://", "http://")
    r = requests.get(http_url, allow_redirects=False, verify=False, timeout=8)
    print("[RESULT] HTTP status:", r.status_code)

    if r.is_redirect:
        print("[PASS] Redirect found:", r.headers.get("Location"))
    else:
        print("[FAIL] NO redirect seen. HTTP content may be exposed!")
except Exception as e:
    print("[ERROR] Could not connect:", e)

# ---------------------------------------------------------------
# Test 2: Header inspection (HSTS, cookies, cache-control)
print_header("TEST 2: HTTPS Header Inspection")

try:
    r = requests.get(TARGET, verify=False, timeout=10)
    for k,v in r.headers.items():
        print(f"{k}: {v}")

    # HSTS Check
    if "strict-transport-security" in (k.lower() for k in r.headers.keys()):
        print("[PASS] HSTS Enabled")
    else:
        print("[FAIL] HSTS Missing")

    # Cache-Control
    cc = r.headers.get("Cache-Control", "")
    if "no-store" in cc.lower() or "no-cache" in cc.lower():
        print("[PASS] Cache-Control prevents caching:", cc)
    else:
        print("[WARN] Cache-Control may allow caching:", cc)

    # Cookies
    print("\nCookie Analysis:")
    sc = r.headers.get("Set-Cookie", "")
    if sc:
        print("[INFO] Raw Set-Cookie:", sc)
        print("  Secure flag:", "secure" in sc.lower())
        print("  HttpOnly flag:", "httponly" in sc.lower())
        print("  SameSite flag:", "samesite" in sc.lower())
    else:
        print("[WARN] No Set-Cookie observed in this request.")
except Exception as e:
    print("[ERROR]", e)

# ---------------------------------------------------------------
# Test 3: Mixed content scan (http:// assets)
print_header("TEST 3: Mixed Content Scan")

try:
    soup = BeautifulSoup(r.text, "html.parser")
    http_assets = []

    for tag in soup.find_all(src=True) + soup.find_all(href=True):
        url = tag.get("src") or tag.get("href")
        if url and url.startswith("http://"):
            http_assets.append(url)

    if http_assets:
        print(f"[FAIL] Found {len(http_assets)} Mixed-Content assets:")
        for i in http_assets[:20]:
            print(" -", i)
    else:
        print("[PASS] No mixed content found.")
except Exception as e:
    print("[ERROR]", e)

# ---------------------------------------------------------------
# Test 4: Token/key leakage in HTML
print_header("TEST 4: Token / Secret Leakage (Heuristic)")

html = r.text
patterns = r"(token|session|auth|jwt|bearer|api_key|apikey|secret)[\"'\s:=]+([A-Za-z0-9\-\._=]{10,})"
leaks = re.findall(patterns, html, re.IGNORECASE)

if leaks:
    print("[FAIL] Suspicious keys/tokens found:")
    for k,v in leaks:
        print(f" - {k}: {v}")
else:
    print("[PASS] No obvious tokens detected.")

# ---------------------------------------------------------------
# Final summary
print_header("SUMMARY")

print("""
✔ Redirection validated  
✔ HSTS checked  
✔ Cookies flags inspected  
✔ Cache-control evaluated  
✔ Mixed content scanned  
✔ Token leak heuristics applied  

You should now manually verify:
- TLS cipher strength (use: nmap --script ssl-enum-ciphers -p 443 host)
- PINNING / MITM behaviour (requires browser or puppeteer-based test)
- localStorage/sessionStorage runtime secrets (requires puppeteer test)

Script Completed.
""")
