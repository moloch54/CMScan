#!/usr/bin/env python3
"""
cmsscan.py — Unified CMS Security Scanner (WordPress, Drupal, Joomla, PrestaShop)
Augmented CyberSecurity
"""

import sys
import os
import re
import csv
import json
import time
import random
import shutil
import argparse
import datetime
import threading
import urllib.request
from http.cookiejar import CookieJar
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ── Couleurs ANSI ──────────────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

import signal

def auto_update():
    """Vérifie automatiquement les mises à jour via le fichier version.txt sur GitHub."""
    if not os.path.exists(".git"):
        return
    try:
        import urllib.request
        import subprocess
        url = "https://raw.githubusercontent.com/moloch54/CMScan/main/version.txt"
        with urllib.request.urlopen(url, timeout=3) as response:
            remote_version = response.read().decode('utf-8').strip()
        with open("version.txt", "r") as f:
            local_version = f.read().strip()
        if local_version != remote_version:
            print(f"\n[+] Nouvelle version disponible : {remote_version} (actuelle : {local_version})")
            print("[*] Téléchargement de la mise à jour...")
            subprocess.run(["git", "pull", "--quiet"], check=True)
            print("[+] Mise à jour terminée, redémarrage...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        pass

        
def signal_handler(sig, frame):
    print("\n\n  Interruption reçue, arrêt immédiat...")
    os._exit(0)
signal.signal(signal.SIGINT, signal_handler)

try:
    import git
    HAS_GIT = True
except ImportError:
    HAS_GIT = False

try:
    from packaging import version as pkg_version
    HAS_PKG_VERSION = True
except ImportError:
    HAS_PKG_VERSION = False

VERSION = "3.0"

# ── Couleurs ──────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    ORANGE = "\033[33m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"
    BOLD   = "\033[1m"
    RST    = "\033[0m"

def sev_color(sev: str) -> str:
    s = sev.upper()
    if s in ("CRITICAL", "C", "HIGH", "H"): return C.RED
    if s in ("MEDIUM", "M"):                return C.ORANGE
    if s in ("LOW", "L"):                   return C.YELLOW
    return C.WHITE

def sev_label(sev: str) -> str:
    MAP = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW",
           "n": "INFO", "critical": "CRITICAL", "high": "HIGH",
           "medium": "MEDIUM", "low": "LOW", "unknown": "UNKNOWN"}
    return MAP.get(sev.lower(), sev.upper())

VERBOSE = False
REQUEST_COUNT = 0
TARGET_BASE = None
CUSTOM_HOST = None

def vlog(msg: str, t0: float = None):
    if not VERBOSE: return
    if t0 is not None:
        elapsed = time.time() - t0
        print(f"  {C.DIM}[v] {elapsed:5.2f}s  {msg}{C.RST}", flush=True)
    else:
        print(f"  {C.DIM}[v] {msg}{C.RST}", flush=True)

BANNER = f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║   CMScan v{VERSION} — Unified CMS Security Scanner          ║
║   Augmented CyberSecurity                                ║
╚══════════════════════════════════════════════════════════╝{C.RST}"""

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
]

DB_DIR         = os.path.join(os.path.dirname(__file__), "vulnDatabase")
CORE_DIR       = os.path.join(DB_DIR, "coreVuln")
PLUGINS_DIR    = os.path.join(DB_DIR, "pluginsVuln")
THEMES_DIR     = os.path.join(DB_DIR, "themesVuln")
TEMPLATES_DIR  = os.path.join(DB_DIR, "templates")
SPIDERS_DIR    = os.path.join(DB_DIR, "spiders")
LAST_UPDATE    = os.path.join(DB_DIR, "lastUpdate.txt")
FOPHP_DIR      = os.path.join(DB_DIR, "friendsOfPhp")

for d in (CORE_DIR, PLUGINS_DIR, THEMES_DIR, TEMPLATES_DIR, SPIDERS_DIR, FOPHP_DIR):
    os.makedirs(d, exist_ok=True)

@dataclass
class Vuln:
    id: str
    name: str
    cve: str
    link: str
    severity: str
    privileges: str
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    poc: list = field(default_factory=list)
    published: str = ""
    package: str = ""

@dataclass
class ScanResult:
    target: str
    cms: str = "unknown"
    version: str = ""
    title: str = ""
    authors: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    paths: list = field(default_factory=list)
    headers: list = field(default_factory=list)
    request_count: int = 0

# ── HTTP helpers ─────────────────────────────────────────────────────────
def _should_count(url: str) -> bool:
    global TARGET_BASE
    if not TARGET_BASE:
        return False
    try:
        parsed = urlparse(url)
        base_parsed = urlparse(TARGET_BASE)
        if parsed.scheme != base_parsed.scheme:
            return False
        if parsed.netloc != base_parsed.netloc:
            return False
        if not parsed.path.startswith(base_parsed.path):
            return False
        return True
    except:
        return False

def get(url: str, **kw) -> Optional[requests.Response]:
    global REQUEST_COUNT
    ua_list = USER_AGENTS + [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ]
    headers = {}
    if CUSTOM_HOST:
        headers["Host"] = CUSTOM_HOST
    if "headers" in kw:
        kw["headers"].update(headers)
    else:
        kw["headers"] = headers

    try:
        from curl_cffi import requests as cffi_requests
        r = cffi_requests.get(url, impersonate="chrome124",
                              timeout=kw.get("timeout", 6),
                              verify=False, allow_redirects=kw.get("allow_redirects", True))
        if _should_count(url):
            REQUEST_COUNT += 1
        if r.status_code in (403, 429):
            pass
        else:
            return r
    except:
        pass

    for ua in ua_list:
        try:
            s = requests.Session()
            s.headers["User-Agent"] = ua
            if CUSTOM_HOST:
                s.headers["Host"] = CUSTOM_HOST
            allow_redir = kw.get("allow_redirects", True)
            r = s.get(url, timeout=kw.get("timeout", 6), verify=False,
                      allow_redirects=allow_redir)
            if _should_count(url):
                REQUEST_COUNT += 1
            if r.status_code in (403, 429):
                continue
            return r
        except Exception:
            continue

    try:
        r = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                         timeout=kw.get("timeout", 6), verify=False,
                         allow_redirects=kw.get("allow_redirects", True))
        if _should_count(url):
            REQUEST_COUNT += 1
        return r
    except:
        return None

def normalize_url(t: str) -> str:
    t = t.strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")

# ── Output helpers ──────────────────────────────────────────────────────
def sep(w=64):
    print(f"{C.DIM}{'─'*w}{C.RST}")

def section(title: str):
    print(f"{C.BLUE}{C.BOLD}[{title}]{C.RST}", flush=True)

def ok(msg):   print(f"  {C.GREEN}[+]{C.RST} {msg}")
def warn(msg): print(f"  {C.YELLOW}[-]{C.RST} {msg}")
def err(msg):  print(f"  {C.RED}[!]{C.RST} {msg}")
def info(msg): print(f"  {C.DIM}    {msg}{C.RST}")

def print_vuln(v: Vuln):
    col      = sev_color(v.severity)
    id_str   = v.cve if v.cve and v.cve != v.id else v.id
    priv     = "UNAUTHENTICATED" if v.privileges in ("n", "none", "") else "AUTHENTICATED"
    priv_col = C.RED if priv == "UNAUTHENTICATED" else C.ORANGE
    if v.fixed_version:
        extra = f"  {C.DIM}<= {v.fixed_version}{C.RST}"
    elif v.cvss_score:
        extra = f"  {C.DIM}CVSS:{v.cvss_score:.1f}{C.RST}"
    else:
        extra = ""
    print(f"        {col}{C.BOLD}[{v.severity}]{C.RST}  "
          f"{priv_col}[ {priv} ]{C.RST}  "
          f"{C.WHITE}{C.BOLD}{id_str}{C.RST}{extra}")
    if v.name:
        print(f"                  {C.DIM}{v.name}{C.RST}")
    if v.link:
        print(f"                  {C.DIM}{v.link}{C.RST}")
    for p in v.poc[:2]:
        print(f"                  {C.ORANGE}⚡ {p}{C.RST}")

# ── Version comparison ──────────────────────────────────────────────────
def parse_version(v: str):
    if not v:
        return None
    v = v.strip()
    if v.lower().startswith('v'):
        v = v[1:]
    if HAS_PKG_VERSION:
        try:
            return pkg_version.parse(v)
        except:
            pass
    if '-' in v:
        v = v.split('-')[0]
    if '+' in v:
        v = v.split('+')[0]
    parts = v.split('.')
    try:
        return tuple(int(p) for p in parts)
    except:
        return (0,)

def version_le(v1, v2):
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    if p1 is None or p2 is None:
        return False
    if HAS_PKG_VERSION:
        return p1 <= p2
    return p1 <= p2

def version_ge(v1, v2):
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    if p1 is None or p2 is None:
        return False
    if HAS_PKG_VERSION:
        return p1 >= p2
    return p1 >= p2

# ── Security headers & sensitive paths ──────────────────────────────────
EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS missing — MitM/downgrade risk",
    "content-security-policy":   "CSP missing — XSS risk",
    "x-frame-options":           "Clickjacking protection absent",
    "x-content-type-options":    "MIME sniffing not blocked",
    "referrer-policy":           "Referrer-Policy not set",
    "permissions-policy":        "Permissions-Policy not set",
}

def audit_headers(resp_headers: dict) -> list:
    lower = {k.lower(): v for k, v in resp_headers.items()}
    issues = []
    for h, msg in EXPECTED_HEADERS.items():
        if h not in lower:
            issues.append({"header": h, "issue": msg, "severity": "MEDIUM"})
    if "strict-transport-security" in lower:
        m = re.search(r"max-age=(\d+)", lower["strict-transport-security"])
        if m and int(m.group(1)) < 31536000:
            issues.append({"header": "strict-transport-security",
                           "issue": "HSTS max-age < 1 year", "severity": "LOW"})
    return issues

WP_SENSITIVE_PATHS = [
    ("/wp-config.php.bak",                  "wp-config backup exposed",                  "CRITICAL"),
    ("/wp-config.php~",                     "wp-config backup exposed",                  "CRITICAL"),
    ("/wp-config.php.old",                  "wp-config backup exposed",                  "CRITICAL"),
    ("/wp-config.php.save",                 "wp-config backup exposed",                  "CRITICAL"),
    ("/.git/config",                        "Git repo exposed",                          "CRITICAL"),
    ("/.env",                               ".env file exposed",                         "CRITICAL"),
    ("/wp-content/debug.log",               "debug.log exposed — may contain creds",     "CRITICAL"),
    ("/wp-content/uploads/error_log",       "PHP error_log exposed",                     "HIGH"),
    ("/xmlrpc.php",                         "xmlrpc.php accessible (brute/DoS/SSRF)",    "HIGH"),
    ("/wp-includes/",                       "wp-includes/ directory listing",            "HIGH"),
    ("/wp-content/",                        "wp-content/ directory listing",             "HIGH"),
    ("/wp-admin/install.php",               "install.php accessible — reinstall risk",   "HIGH"),
    ("/wp-admin/setup-config.php",          "setup-config.php accessible",               "HIGH"),
    ("/wp-content/uploads/.htaccess",       ".htaccess missing in uploads (PHP exec)",   "HIGH"),
    ("/wp-content/uploads/phpinfo.php",     "phpinfo.php in uploads",                    "CRITICAL"),
    ("/php.ini",                            "php.ini exposed",                           "HIGH"),
    ("/error_log",                          "error_log exposed in webroot",              "HIGH"),
    ("/wp-admin/",                          "wp-admin accessible",                       "MEDIUM"),
    ("/wp-json/wp/v2/users",                "User enumeration via REST API",             "MEDIUM"),
    ("/wp-login.php",                       "wp-login.php exposed (brute-force target)", "MEDIUM"),
    ("/wp-cron.php",                        "wp-cron.php publicly accessible",           "MEDIUM"),
    ("/wp-content/plugins/",               "plugins/ directory listing",                "MEDIUM"),
    ("/wp-content/themes/",                "themes/ directory listing",                 "MEDIUM"),
    ("/.htaccess",                          ".htaccess exposed",                         "MEDIUM"),
    ("/wp-admin/admin-ajax.php",            "admin-ajax.php exposed",                    "MEDIUM"),
    ("/readme.html",                        "Version disclosure via readme.html",        "LOW"),
    ("/license.txt",                        "license.txt exposed",                       "LOW"),
    ("/wp-mail.php",                        "wp-mail.php accessible",                    "LOW"),
    ("/wp-trackback.php",                   "wp-trackback.php accessible",               "LOW"),
]

DRUPAL_SENSITIVE_PATHS = [
    ("/CHANGELOG.txt",                   "Version disclosure",              "MEDIUM"),
    ("/core/CHANGELOG.txt",              "Version disclosure (core)",       "MEDIUM"),
    ("/.git/config",                     "Git repo exposed",                "HIGH"),
    ("/.env",                            ".env file exposed",               "HIGH"),
    ("/sites/default/settings.php",      "settings.php accessible",        "HIGH"),
    ("/update.php",                       "update.php accessible",          "HIGH"),
    ("/install.php",                      "install.php accessible",         "HIGH"),
    ("/xmlrpc.php",                       "xmlrpc.php exposed",             "MEDIUM"),
    ("/admin",                            "Admin path accessible",          "MEDIUM"),
    ("/user/register",                    "User registration open",         "LOW"),
    ("/sites/default/files/backup_migrate/", "Backup files exposed",       "HIGH"),
]

def _is_404(text: str) -> bool:
    patterns = ["404 Not Found", "Page not found", "The requested URL was not found",
                "Sorry, the page you are looking for", "Error 404"]
    return any(p in text for p in patterns)

_PATH_SIGNATURES = {
    "/CHANGELOG.txt":                    re.compile(r"Drupal \d+\.\d+\.\d+"),
    "/core/CHANGELOG.txt":               re.compile(r"Drupal \d+\.\d+\.\d+"),
    "/readme.html":                      "WordPress",
    "/license.txt":                      ["GNU", "WordPress", "MIT"],
    "/.git/config":                      "[core]",
    "/.env":                             ["APP_", "DB_", "SECRET", "PASSWORD"],
    "/wp-config.php.bak":                "DB_",
    "/wp-config.php~":                   "DB_",
    "/wp-config.php.old":                "DB_",
    "/wp-config.php.save":               "DB_",
    "/xmlrpc.php":                       "XML-RPC",
    "/wp-content/debug.log":             ["PHP", "Warning", "Error", "WordPress"],
    "/error_log":                        ["PHP", "Warning", "Error"],
    "/wp-content/uploads/error_log":     ["PHP", "Warning", "Error"],
    "/php.ini":                          ["php", "extension", "memory_limit"],
    "/wp-content/uploads/phpinfo.php":   "PHP Version",
    "/.htaccess":                        ["RewriteEngine", "Options", "Allow", "Deny"],
    "/wp-includes/":                     None,
    "/wp-content/":                      None,
    "/wp-content/plugins/":              None,
    "/wp-content/themes/":               None,
    "/wp-admin/":                        None,
    "/wp-admin/install.php":             None,
    "/wp-admin/setup-config.php":        None,
    "/wp-admin/admin-ajax.php":          None,
    "/wp-login.php":                     None,
    "/wp-cron.php":                      None,
    "/wp-mail.php":                      None,
    "/wp-trackback.php":                 None,
    "/wp-json/wp/v2/users":              None,
    "/user/register":                    None,
    "/update.php":                       None,
    "/install.php":                      None,
    "/wp-content/uploads/.htaccess":     None,
}



# ── check_paths (version qui utilise _cmseek_getsource) ─────────────────
def _cmseek_getsource(url, ua):
    try:
        ckreq = urllib.request.Request(
            url,
            data=None,
            headers={
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                'Accept-Language': 'en-US,en;q=0.8',
                'Connection': 'keep-alive'
            }
        )
        cj = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        with opener.open(ckreq, timeout=8) as response:
            source = response.read().decode('utf-8', errors='ignore')
            headers = str(response.info())
            final_url = response.geturl()
            return ('1', source, headers, final_url)
    except Exception as e:
        return ('0', str(e), '', '')

def check_paths(base: str, path_list: list) -> list:
    findings = []
    lock = threading.Lock()
    def check_one(entry):
        path, desc, sev = entry
        ua = random.choice(USER_AGENTS)
        src = _cmseek_getsource(base + path, ua)
        if src[0] != '1':
            return None
        content = src[1]
        if len(content.strip()) < 20:
            return None
        sig = _PATH_SIGNATURES.get(path)
        if sig is None:
            if _is_404(content):
                return None
        elif hasattr(sig, "search"):
            if not sig.search(content):
                return None
        elif isinstance(sig, list):
            if not any(kw in content for kw in sig):
                return None
        else:
            if sig not in content:
                return None
        with lock:
            findings.append({"path": path, "url": base + path,
                             "description": desc, "severity": sev,
                             "status": 200})
    threads = []
    for entry in path_list:
        t = threading.Thread(target=check_one, args=(entry,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=8)
    sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_ord.get(x["severity"], 4))
    return findings

# ── CMS Detection ──────────────────────────────────────────────────────
COMMON_SUBDIRS = ["/wordpress", "/wp", "/blog", "/cms", "/site"]

def _detect_wp_drupal(base: str) -> dict:
    def probe(url):
        r = get(url)
        if not r:
            return None
        return r
    r = probe(base)
    if not r:
        parsed = urlparse(base)
        if not parsed.netloc.startswith("www."):
            alt = parsed._replace(netloc="www." + parsed.netloc)
            alt_url = alt.geturl()
            r = probe(alt_url)
            if r:
                base = alt_url
        if not r:
            return {"cms": "unknown", "version": None, "html": "",
                    "resp_headers": {}, "status": 0, "actual_base": base}
    html = r.text
    headers = dict(r.headers)
    def detect_from_html(html, headers):
        wp_signals = [
            "/wp-content/" in html,
            "/wp-includes/" in html,
            "wp-json" in html,
            "wordpress" in headers.get("x-powered-by", "").lower(),
            bool(re.search(r'<meta name="generator" content="WordPress', html, re.I)),
        ]
        drupal_signals = [
            "drupal" in headers.get("x-generator", "").lower(),
            "x-drupal-cache" in headers,
            "x-drupal-dynamic-cache" in headers,
            bool(re.search(r'<meta name="Generator" content="Drupal', html, re.I)),
            "drupalSettings" in html,
            "Drupal.settings" in html,
            "/sites/default/" in html,
            "/core/themes/" in html,
        ]
        if any(wp_signals):
            return "wordpress"
        elif any(drupal_signals):
            return "drupal"
        return None
    cms = detect_from_html(html, headers)
    actual_base = base
    if not cms:
        for sub in COMMON_SUBDIRS:
            test_url = base + sub
            r2 = probe(test_url)
            if r2 and r2.status_code == 200:
                html2 = r2.text
                headers2 = dict(r2.headers)
                cms2 = detect_from_html(html2, headers2)
                if cms2:
                    cms = cms2
                    html = html2
                    headers = headers2
                    actual_base = test_url
                    break
    if not cms:
        r_wp = get(base + "/wp-login.php")
        if r_wp and r_wp.status_code == 200:
            cms = "wordpress"
        else:
            r_dr = get(base + "/user/login")
            if r_dr and r_dr.status_code == 200 and "drupal" in r_dr.text.lower():
                cms = "drupal"
    version = None
    if cms == "wordpress":
        version = _extract_wp_version(actual_base, html)
    elif cms == "drupal":
        version = _extract_drupal_version(actual_base, html)
    return {
        "cms": cms or "unknown",
        "version": version,
        "html": html,
        "resp_headers": headers,
        "status": r.status_code if r else 0,
        "actual_base": actual_base
    }

def _extract_wp_version(base, html):
    m = re.search(r'<meta name="generator" content="WordPress ([\d]+\.[\d\.]+)', html, re.I)
    if m:
        ver = m.group(1)
        if ver and "trunk" not in ver and "Download" not in ver:
            return ver
    r_admin = get(base + "/wp-admin/")
    if r_admin and r_admin.status_code == 200:
        admin_html = r_admin.text
        versions = re.findall(r'[?"\']ver=([\d]+\.[\d\.]+)', admin_html)
        if versions:
            from collections import Counter
            best = Counter(versions).most_common(1)[0][0]
            if best and "trunk" not in best and "Download" not in best:
                return best
    r_opml = get(base + "/wp-links-opml.php")
    if r_opml and r_opml.status_code == 200:
        m = re.search(r'generator="WordPress/(\d+\.\d+[\.\d]*)"', r_opml.text)
        if m:
            ver = m.group(1)
            if ver and "trunk" not in ver and "Download" not in ver:
                return ver
    r_feed = get(base + "/feed")
    if r_feed and r_feed.status_code == 200:
        m = re.search(r'<generator>https://wordpress.org/\?v=([\d\.]+)</generator>', r_feed.text)
        if m:
            ver = m.group(1)
            if ver and "trunk" not in ver and "Download" not in ver:
                return ver
    r_ver = get(base + "/wp-includes/version.php")
    if r_ver and r_ver.status_code == 200:
        m = re.search(r"\$wp_version\s*=\s*'([\d\.]+)'", r_ver.text)
        if m:
            ver = m.group(1)
            if ver and "trunk" not in ver and "Download" not in ver:
                return ver
    return None

def _extract_drupal_version(base, html):
    version_candidate = None
    for p in ("/core/CHANGELOG.txt", "/CHANGELOG.txt"):
        cr = get(base + p)
        if cr and cr.status_code == 200:
            m = re.search(r"Drupal (\d+\.\d+\.\d+)", cr.text)
            if m:
                version_candidate = m.group(1)
                break
    if not version_candidate:
        pj = get(base + "/core/package.json")
        if pj and pj.status_code == 200:
            try:
                pkg = json.loads(pj.text)
                v = pkg.get("version", "")
                if re.match(r"\d+\.\d+\.\d+", v):
                    version_candidate = v
            except:
                pass
    if not version_candidate:
        m = re.search(r'drupalSettings\.data[^}]*"version"\s*:\s*"(\d+\.\d+\.\d+)"', html)
        if m:
            version_candidate = m.group(1)
    if not version_candidate:
        versions = re.findall(r"/core/[^\x22\x27]+[?&]v=(\d+\.\d+\.\d+)", html)
        if versions:
            from collections import Counter
            version_candidate = Counter(versions).most_common(1)[0][0]
    if not version_candidate:
        m = re.search(r'<meta name="Generator" content="Drupal ([\d.]+)"', html, re.I)
        if m and "." in m.group(1):
            version_candidate = m.group(1)
    return version_candidate

def detect_joomla_version(base):
    ua = random.choice(USER_AGENTS)
    # 1. XML du manifeste (J! 3.x)
    src = _cmseek_getsource(base + '/administrator/manifests/files/joomla.xml', ua)
    if src[0] == '1':
        m = re.search(r'<version>([^<]+)</version>', src[1])
        if m:
            return m.group(1)
    # 2. Fichier version (J! 4.x)
    src = _cmseek_getsource(base + '/libraries/src/Version.php', ua)
    if src[0] == '1':
        m = re.search(r"const\s+RELEASE\s*=\s*'([^']+)'", src[1])
        if m:
            version = m.group(1)
            m = re.search(r"const\s+DEV_LEVEL\s*=\s*'([^']+)'", src[1])
            if m:
                return f"{version}.{m.group(1)}"
            return version
    # 3. Balise meta generator
    r = get(base)
    if r and r.status_code == 200:
        m = re.search(r'<meta name="generator" content="Joomla! - Open Source Content Management - Version ([^"]+)"', r.text, re.I)
        if m:
            return m.group(1)
    return None

def detect_prestashop_version(base):
    ua = random.choice(USER_AGENTS)
    # 1. Fichier defines.inc.php (le plus fiable)
    paths = [
        '/config/defines.inc.php',
        '/classes/Configuration.php',
        '/index.php'
    ]
    for p in paths:
        src = _cmseek_getsource(base + p, ua)
        if src[0] == '1':
            m = re.search(r"_PS_VERSION_\s*=\s*'([^']+)'", src[1])
            if m:
                return m.group(1)
    # 2. Balise meta generator
    r = get(base)
    if r and r.status_code == 200:
        m = re.search(r'<meta name="generator" content="PrestaShop ([^"]+)"', r.text, re.I)
        if m:
            return m.group(1)
        m = re.search(r'PrestaShop\s*([\d\.]+)', r.text)
        if m:
            return m.group(1)
    return None

def detect_cms(base):
    # 1. D'abord, essayer de lire le HTML de la racine
    r = get(base)
    html = r.text if r and r.status_code == 200 else ""

    # 2. Détection par balise meta generator (très fiable)
    if html:
        if re.search(r'<meta name="generator" content="WordPress', html, re.I):
            # WordPress détecté, on utilise la fonction existante
            info = _detect_wp_drupal(base)
            if info['cms'] == 'wordpress':
                return info
        if re.search(r'<meta name="Generator" content="Drupal', html, re.I):
            info = _detect_wp_drupal(base)
            if info['cms'] == 'drupal':
                return info
        if re.search(r'Joomla!', html, re.I) or 'joomla' in html.lower():
            version = detect_joomla_version(base)
            if version:
                return {"cms": "joomla", "version": version, "html": html, "resp_headers": r.headers if r else {}, "status": r.status_code if r else 200, "actual_base": base}
        if re.search(r'PrestaShop', html, re.I) or 'prestashop' in html.lower():
            version = detect_prestashop_version(base)
            if version:
                return {"cms": "prestashop", "version": version, "html": html, "resp_headers": r.headers if r else {}, "status": r.status_code if r else 200, "actual_base": base}

    # 3. Fallback sur la détection classique (WP/Drupal)
    info = _detect_wp_drupal(base)
    if info['cms'] != 'unknown':
        return info

    # 4. Dernier essai pour Joomla et PrestaShop (sans HTML)
    version = detect_joomla_version(base)
    if version:
        return {"cms": "joomla", "version": version, "html": "", "resp_headers": {}, "status": 200, "actual_base": base}
    version = detect_prestashop_version(base)
    if version:
        return {"cms": "prestashop", "version": version, "html": "", "resp_headers": {}, "status": 200, "actual_base": base}

    return {"cms": "unknown", "version": None, "html": "", "resp_headers": {}, "status": 0, "actual_base": base}

def extract_meta(base: str, html: str) -> dict:
    info = {"title": None, "description": None, "authors": [],
            "emails": [], "og": {}, "dns_prefetch": []}
    m = re.search(r"<title>([^<]+)</title>", html, re.I)
    if m: info["title"] = m.group(1).strip()
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if m: info["description"] = m.group(1).strip()[:200]
    for prop in ("og:site_name", "og:title", "article:author"):
        m = re.search(rf'property=["\']{{prop}}["\'][^>]+content=["\']([^"\']+)'.format(prop=prop), html, re.I)
        if m: info["og"][prop] = m.group(1).strip()
    info["emails"] = list(set(
        e for e in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html)
        if not e.lower().endswith((".png", ".jpg", ".css", ".js", ".svg"))
    ))[:10]
    info["dns_prefetch"] = re.findall(
        r'<link[^>]+rel=["\']dns-prefetch["\'][^>]+href=["\']([^"\']+)', html, re.I)[:5]
    return info


# ── WordPress helpers ──────────────────────────────────────────────────
def _wp_fetch_version_txt(url: str) -> str:
    try:
        r = get(url)
        if r and r.status_code == 200:
            m = re.search(r'Stable tag:\s*([\d][\d.]+)', r.text, re.I)
            if m and m.group(1).lower() != "trunk":
                return m.group(1)
            m = re.search(r'(?m)^Version:\s*([\d][\d.]+)', r.text)
            if m:
                return m.group(1)
    except:
        pass
    return ""

def _wp_fetch_all_versions(base: str, slugs: list, kind: str) -> dict:
    results = {}
    if not slugs:
        return results
    sub = "plugins" if kind == "plugin" else "themes"
    suffix = "readme.txt" if kind == "plugin" else "style.css"
    urls = {slug: f"{base}/wp-content/{sub}/{slug}/{suffix}" for slug in slugs}
    def fetch_one(slug, url):
        try:
            r = get(url, timeout=3)
            if r and r.status_code == 200:
                m = re.search(r'Stable tag:\s*([\d][\d.]+)', r.text, re.I)
                if m and m.group(1).lower() != "trunk":
                    return slug, m.group(1)
                m = re.search(r'(?m)^Version:\s*([\d][\d.]+)', r.text)
                if m:
                    return slug, m.group(1)
        except Exception:
            pass
        return slug, ""
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(fetch_one, slug, url): slug for slug, url in urls.items()}
        try:
            for future in as_completed(futures, timeout=15):
                try:
                    slug, ver = future.result(timeout=2)
                    if ver:
                        results[slug] = ver
                except Exception:
                    pass
        except TimeoutError:
            pass
    return results

def _wp_slugs_from_html(html: str, kind: str) -> list:
    pat = re.compile(rf'/wp-content/{kind}s/([a-z0-9][a-z0-9_\-]+)/', re.I)
    return sorted(set(pat.findall(html)))

def _wp_ver_from_html(html: str, slug: str, kind: str, core_ver: str) -> str:
    from collections import Counter
    pat = re.compile(
        rf'/wp-content/{kind}s/{re.escape(slug)}/[^"\'\s]*[?&]ver=([\d][\d.]+)', re.I)
    versions = [v for v in pat.findall(html)
                if v != core_ver and len(v) < 12 and "." in v]
    return Counter(versions).most_common(1)[0][0] if versions else ""

# ── FriendsOfPHP vuln check ────────────────────────────────────────────
def update_friendsofphp_db():
    print(f"\n{C.BLUE}[*] Updating FriendsOfPHP security-advisories...{C.RST}")
    if not HAS_GIT:
        warn("gitpython not installed — skipping FriendsOfPHP update")
        return
    repo_path = FOPHP_DIR
    if not os.path.exists(repo_path):
        try:
            git.Repo.clone_from("https://github.com/FriendsOfPHP/security-advisories", repo_path)
            ok("Cloned FriendsOfPHP repository")
        except Exception as e:
            warn(f"Clone failed: {e}")
    else:
        try:
            repo = git.Repo(repo_path)
            # Vérifier si un lock existe
            lock_path = os.path.join(repo_path, ".git", "index.lock")
            if os.path.exists(lock_path):
                os.remove(lock_path)
                info("Removed index.lock")
            repo.remotes.origin.pull()
            ok("Updated FriendsOfPHP repository")
        except Exception as e:
            warn(f"Pull failed: {e}, removing and recloning...")
            shutil.rmtree(repo_path)
            try:
                git.Repo.clone_from("https://github.com/FriendsOfPHP/security-advisories", repo_path)
                ok("Recloned FriendsOfPHP repository")
            except Exception as e2:
                warn(f"Reclone failed: {e2}")

def check_vulns_friendsofphp(cms_group: str, package: str, version: str) -> list:
    if not version or not HAS_GIT:
        return []
    repo_path = FOPHP_DIR
    file_path = os.path.join(repo_path, cms_group, package, f"{version}.json")
    if not os.path.exists(file_path):
        if cms_group == 'drupal' and package == 'drupal/drupal':
            alt = os.path.join(repo_path, 'drupal', 'core', f"{version}.json")
            if os.path.exists(alt):
                file_path = alt
        if not os.path.exists(file_path):
            return []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except:
        return []
    vulns = []
    for vuln in data.get('advisories', []):
        cve = vuln.get('cve', '')
        if not cve:
            cve = vuln.get('title', '')[:20]
        sev_raw = vuln.get('severity', 'medium').lower()
        sev = sev_label(sev_raw)
        cvss = vuln.get('cvss', None)
        if cvss:
            try:
                cvss = float(cvss)
            except:
                cvss = None
        fixed = ''
        branches = vuln.get('branches', {})
        if branches:
            for branch, info in branches.items():
                if 'versions' in info and info['versions']:
                    fixed = info['versions'][0]
                    break
        vulns.append(Vuln(
            id=cve,
            name=vuln.get('title', ''),
            cve=cve,
            link=vuln.get('link', ''),
            severity=sev,
            privileges='n',
            cvss_score=cvss,
            fixed_version=fixed,
            poc=[],
            published=vuln.get('published', '')[:10] if vuln.get('published') else '',
            package=package
        ))
    return vulns

# ── WordPress vuln parsing (avec fallback FriendsOfPHP) ──────────────
def _wp_vuln_from_file(path: str, item_version: str) -> list:
    results = []
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        vulns_raw = data.get('data', {}).get('vulnerability', [])
        for v in vulns_raw:
            try:
                sources = v.get("source", [])
                if not sources:
                    continue
                src0 = sources[0]
                cve = src0.get("id", "")
                link = src0.get("link", "")
                impact_raw = v.get("impact", {})
                if isinstance(impact_raw, list):
                    impact = impact_raw[0] if impact_raw else {}
                else:
                    impact = impact_raw or {}
                cvss = impact.get("cvss", {})
                if not cvss:
                    continue
                sev = cvss.get("severity", "")
                priv = cvss.get("pr", "")
                cvss_score_val = cvss.get("score", "")
                name = ""
                cwe_list = impact.get("cwe") or []
                if cwe_list and isinstance(cwe_list, list):
                    name = cwe_list[0].get("name", "")
                if not name and len(sources) > 1:
                    name = sources[1].get("name", "")
                if not name:
                    name = src0.get("description", "")[:120]
                operator = v.get("operator") or {}
                min_v = operator.get("min_version") or "0"
                max_v = operator.get("max_version") or ""
                if min_v in ("", "null", None): min_v = "0"
                if max_v in ("", "null", None): max_v = ""
                affected_ver = ""
                if not max_v:
                    for src in sources:
                        src_name = src.get("name", "") or src.get("description", "")
                        m = re.search(r"(?:<=?|through|up to)\s*([\d]+\.[\d]+\.?[\d]*)", src_name, re.I)
                        if m:
                            affected_ver = m.group(1)
                            break
                if item_version:
                    if max_v and max_v != "1000000":
                        if not version_le(item_version, max_v):
                            continue
                    elif affected_ver:
                        if not version_le(item_version, affected_ver):
                            continue
                    if min_v and min_v != "0":
                        if not version_ge(item_version, min_v):
                            continue
                else:
                    continue
                if sev not in ("c", "h"):
                    continue
                if priv not in ("n", "l"):
                    continue
                if "CVE" not in cve:
                    continue
                display_max = ""
                if max_v and max_v != "1000000":
                    display_max = max_v
                elif affected_ver:
                    display_max = affected_ver
                results.append(Vuln(
                    id=cve,
                    name=name.replace("&lt;", "<"),
                    cve=cve,
                    link=link,
                    severity=sev_label(sev),
                    privileges=priv,
                    cvss_score=float(cvss_score_val) if cvss_score_val else None,
                    fixed_version=display_max,
                    package=os.path.basename(path),
                ))
            except:
                continue
    except:
        pass
    # Fallback FriendsOfPHP si peu ou pas de résultats
    if len(results) < 2:
        package = 'wordpress/wordpress'
        if 'core' in path:
            package = 'wordpress/wordpress'
        elif 'plugin' in path:
            slug = os.path.basename(path)
            package = f'wordpress/plugins/{slug}'
        else:
            package = 'wordpress/themes/' + os.path.basename(path)
        fophp = check_vulns_friendsofphp('wordpress', package, item_version)
        results.extend(fophp)
    return results

# ── WordPress helpers (templates, spiders) ────────────────────────────
def _load_templates():
    templates = []
    if not os.path.isdir(TEMPLATES_DIR):
        return templates
    for fname in os.listdir(TEMPLATES_DIR):
        with open(os.path.join(TEMPLATES_DIR, fname)) as f:
            lines = f.readlines()
        if lines:
            templates.append(lines)
    return templates

def _load_spiders():
    spiders = []
    if not os.path.isdir(SPIDERS_DIR):
        return spiders
    for fname in os.listdir(SPIDERS_DIR):
        with open(os.path.join(SPIDERS_DIR, fname)) as f:
            lines = f.readlines()
        if lines:
            spiders.append(lines)
    return spiders

def _extract_with_template(html: str, regex: str, nb_group: str, template_name: str) -> list:
    result = []
    seen = set()
    regex = regex.rstrip("\n").rstrip("\\n")
    try:
        pat = re.compile(regex)
    except re.error:
        return result
    for line in html.splitlines():
        if len(line) > 2000:
            continue
        try:
            m = pat.search(line)
            if not m:
                continue
            groups = m.groups()
            name = template_name if template_name else (groups[0] if groups else m.group(0))
            version = groups[1] if len(groups) > 1 else ""
            name = name.strip()
            if name and name not in seen:
                seen.add(name)
                result.append((name, version.strip()))
        except Exception:
            continue
    return result

def _ensure_wp_vuln(slug: str, kind: str) -> str:
    dirmap = {"core": CORE_DIR, "plugin": PLUGINS_DIR, "theme": THEMES_DIR}
    path = os.path.join(dirmap[kind], slug)
    if not os.path.exists(path):
        try:
            r = get(f"https://www.wpvulnerability.net/{kind}/{slug}")
            if r and r.status_code == 200:
                with open(path, "wb") as f:
                    f.write(r.content)
        except:
            pass
    return path

def _fetch_wp_vulns_parallel(slugs: list, kind: str) -> dict:
    if not slugs:
        return {}
    dirmap = {"core": CORE_DIR, "plugin": PLUGINS_DIR, "theme": THEMES_DIR}
    cached = {}
    missing = []
    for slug in slugs:
        path = os.path.join(dirmap[kind], slug)
        if os.path.exists(path):
            cached[slug] = path
        else:
            missing.append(slug)
    if not missing:
        return cached
    def fetch_one(slug):
        path = os.path.join(dirmap[kind], slug)
        try:
            r = get(f"https://www.wpvulnerability.net/{kind}/{slug}", timeout=3)
            if r and r.status_code == 200:
                with open(path, "wb") as f:
                    f.write(r.content)
        except Exception:
            pass
        return slug, path
    result = dict(cached)
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(fetch_one, s): s for s in missing}
        try:
            for future in as_completed(futures, timeout=10):
                try:
                    slug, path = future.result(timeout=2)
                    result[slug] = path
                except Exception:
                    pass
        except TimeoutError:
            pass
    return result

# ── WordPress username harvest ─────────────────────────────────────────
def harvest_usernames_wp(base: str) -> set:
    usernames = set()
    ua = random.choice(USER_AGENTS)
    src = _cmseek_getsource(base + '/wp-json/wp/v2/users', ua)
    if src[0] == '1' and 'slug' in src[1]:
        try:
            data = json.loads(src[1])
            for user in data:
                slug = user.get('slug', '')
                if slug:
                    usernames.add(slug)
                    print(f"    {C.GREEN}[+]{C.RST} Found user from wp-json: {C.BOLD}{slug}{C.RST}")
        except:
            pass
    stripped = base.replace('http://', '').replace('https://', '').split('/')[0]
    jp_url = f'https://public-api.wordpress.com/rest/v1.1/sites/{stripped}/posts?number=100&pretty=true&fields=author'
    src = _cmseek_getsource(jp_url, ua)
    if src[0] == '1' and 'login' in src[1]:
        try:
            data = json.loads(src[1])
            for post in data.get('posts', []):
                login = post.get('author', {}).get('login', '')
                if login:
                    usernames.add(login)
                    print(f"    {C.GREEN}[+]{C.RST} Found user from Jetpack API: {C.BOLD}{login}{C.RST}")
        except:
            pass
    results = []
    lock = threading.Lock()
    def check_author(i):
        try:
            src = _cmseek_getsource(base + f'/?author={i}', ua)
            if src[0] == '1':
                final_url = src[3]
                if final_url and '/author/' in final_url:
                    m = re.search(r'/author/([^/]+)/?', final_url)
                    if m:
                        with lock:
                            results.append(m.group(1))
                        return
                if '/author/' in src[1]:
                    m = re.search(r'/author/([^/]+)/', src[1])
                    if m:
                        with lock:
                            results.append(m.group(1))
        except:
            pass
    threads = []
    for i in range(1, 31):
        t = threading.Thread(target=check_author, args=(i,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=5)
    for username in results:
        if username and username not in usernames:
            usernames.add(username)
            print(f"    {C.GREEN}[+]{C.RST} Found user from ?author: {C.BOLD}{username}{C.RST}")
    src = _cmseek_getsource(base + '/feed', ua)
    if src[0] == '1':
        feed_authors = re.findall(r'<dc:creator>\s*<!\[CDATA\[([\w\s\-]+)\]', src[1])
        for a in feed_authors:
            if a and a not in usernames:
                usernames.add(a)
                print(f"    {C.GREEN}[+]{C.RST} Found user from feed: {C.BOLD}{a}{C.RST}")
    return usernames

# ── WordPress scan ─────────────────────────────────────────────────────
def scan_wordpress(base: str, cms_info: dict) -> dict:
    html = cms_info["html"]
    core_version = cms_info.get("version") or ""
    result = {"vulns": [], "paths": [], "authors": [], "emails": []}
    section("WordPress Core")
    if core_version:
        ok(f"Version: {C.BOLD}{core_version}{C.RST}")
        path = _ensure_wp_vuln(core_version, "core")
        core_vulns = _wp_vuln_from_file(path, core_version)
        if core_vulns:
            for v in core_vulns:
                v.package = f"WP core {core_version}"
                result["vulns"].append(v)
                print_vuln(v)
    else:
        warn("Core version not detected")
    theme_slugs = _wp_slugs_from_html(html, "theme")
    theme_css_versions = _wp_fetch_all_versions(base, theme_slugs, "theme")
    theme_versions = {}
    for t in theme_slugs:
        theme_versions[t] = (theme_css_versions.get(t)
                             or _wp_ver_from_html(html, t, "theme", core_version))
    theme_vuln_paths = _fetch_wp_vulns_parallel([t for t, v in theme_versions.items() if v], "theme")
    section("Themes")
    if not theme_slugs:
        warn("No themes detected")
    for theme in theme_slugs:
        tv = theme_versions.get(theme, "")
        print(f"  {C.WHITE}{C.BOLD}{theme}{C.RST}  {C.DIM}{tv or '?'}{C.RST}", flush=True)
        if not tv:
            continue
        vulns = _wp_vuln_from_file(theme_vuln_paths.get(theme, ""), tv)
        vulns.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.severity, 4))
        for v in vulns:
            v.package = f"theme:{theme}"
            result["vulns"].append(v)
            print_vuln(v)
    plugin_slugs = _wp_slugs_from_html(html, "plugin")
    templates = _load_templates()
    template_slug_ver = {}
    for tpl in templates:
        regex = tpl[0].rstrip("\n")
        tname = tpl[2].rstrip("\n") if len(tpl) > 2 else None
        for name, ver in _extract_with_template(html, regex, "1", tname):
            if name and name not in plugin_slugs:
                plugin_slugs.append(name)
            if name and ver:
                template_slug_ver[name] = ver
    plugin_slugs = sorted(set(plugin_slugs))
    spiders = _load_spiders()
    spider_versions = {}
    spider_args = []
    for sp in spiders:
        if len(sp) < 3: continue
        spider_args.append((sp[0].rstrip("\n"), base + sp[1].rstrip("\n"), sp[2].rstrip("\n")))
    if spider_args:
        def run_spider_isolated(args):
            name, url, regex = args
            try:
                r = get(url)
                if r and r.status_code == 200:
                    m = re.search(regex, r.text)
                    if m:
                        return (name, m.group(1))
            except:
                pass
            return None
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(run_spider_isolated, a): a[0] for a in spider_args}
            for fut in as_completed(futs, timeout=10):
                try:
                    res = fut.result(timeout=1)
                    if res:
                        name, ver = res
                        spider_versions[name] = ver
                        if name not in plugin_slugs:
                            plugin_slugs.append(name)
                except:
                    pass
        plugin_slugs = sorted(set(plugin_slugs))
    html_versions = {slug: _wp_ver_from_html(html, slug, "plugin", core_version)
                     for slug in plugin_slugs}
    readme_versions = _wp_fetch_all_versions(base, plugin_slugs, "plugin")
    plugin_versions = {}
    for slug in plugin_slugs:
        plugin_versions[slug] = (readme_versions.get(slug)
                                 or spider_versions.get(slug)
                                 or template_slug_ver.get(slug)
                                 or html_versions.get(slug))
    slugs_with_ver = [s for s, v in plugin_versions.items() if v]
    vuln_paths = _fetch_wp_vulns_parallel(slugs_with_ver, "plugin")
    section("Plugins")
    if not plugin_slugs:
        warn("No plugins detected")
    for plugin in plugin_slugs:
        pv = plugin_versions.get(plugin, "")
        print(f"  {C.WHITE}{C.BOLD}{plugin}{C.RST}  {C.DIM}{pv or '?'}{C.RST}", flush=True)
        if not pv:
            continue
        vulns = _wp_vuln_from_file(vuln_paths.get(plugin, ""), pv)
        vulns.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.severity, 4))
        for v in vulns:
            v.package = f"plugin:{plugin}"
            result["vulns"].append(v)
            print_vuln(v)
    section("Authors")
    usernames = harvest_usernames_wp(base)
    if usernames:
        for idx, name in enumerate(sorted(usernames), 1):
            print(f"    {C.WHITE}{idx}:{C.RST} {name}")
            result["authors"].append(name)
    else:
        warn("No authors found")
    return result


# ── Drupal helpers ─────────────────────────────────────────────────────
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN  = "https://api.osv.dev/v1/vulns/{}"

def _osv_fetch_full(vuln_id: str) -> dict:
    try:
        r = get(OSV_VULN.format(vuln_id))
        if r and r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def _osv_query_packages(packages: list) -> dict:
    if not packages:
        return {}
    queries = [{"package": {"name": p, "ecosystem": "Packagist"}} for p in packages]
    try:
        r = get(OSV_BATCH, json={"queries": queries})
        if r and r.status_code != 200:
            return {}
        pkg_ids = {}
        for i, item in enumerate(r.json().get("results", [])):
            ids = [v.get("id") for v in item.get("vulns", []) if v.get("id")]
            if ids:
                pkg_ids[packages[i]] = ids
    except:
        return {}
    if not pkg_ids:
        return {}
    all_ids = list({vid for ids in pkg_ids.values() for vid in ids})
    id_to_full = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(_osv_fetch_full, vid): vid for vid in all_ids}
        for fut in as_completed(futs, timeout=20):
            vid = futs[fut]
            try:
                full = fut.result(timeout=2)
                if full:
                    id_to_full[vid] = full
            except:
                pass
    out = {}
    for pkg, ids in pkg_ids.items():
        full_vulns = [id_to_full[vid] for vid in ids if vid in id_to_full]
        if full_vulns:
            out[pkg] = full_vulns
    return out

def _parse_osv_vuln(v: dict, package: str) -> Vuln:
    cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
    cvss_score = None
    sev = "UNKNOWN"
    db = v.get("database_specific") or {}
    SEV_MAP = {
        "critical": "CRITICAL", "high": "HIGH",
        "moderate": "MEDIUM",   "medium": "MEDIUM",
        "low": "LOW",           "minor": "LOW",
    }
    for s in v.get("severity") or []:
        score_raw = s.get("score", "")
        try:
            cvss_score = float(score_raw)
            break
        except:
            pass
        m = re.search(r"(\d+\.\d+)$", score_raw)
        if m:
            cvss_score = float(m.group(1))
            break
    if cvss_score is None:
        for key in ("cvss", "cvss_score", "cvss_v3", "base_score"):
            try:
                cvss_score = float(db[key]); break
            except:
                pass
    if cvss_score is None:
        for aff in v.get("affected") or []:
            aff_db = aff.get("database_specific") or {}
            for key in ("cvss", "cvss_score", "base_score"):
                try:
                    cvss_score = float(aff_db[key]); break
                except:
                    pass
            if cvss_score is not None:
                break
    if cvss_score is not None:
        if cvss_score >= 9.0:   sev = "CRITICAL"
        elif cvss_score >= 7.0: sev = "HIGH"
        elif cvss_score >= 4.0: sev = "MEDIUM"
        else:                   sev = "LOW"
    if sev == "UNKNOWN":
        sev = SEV_MAP.get((db.get("severity") or "").lower(), "UNKNOWN")
    if sev == "UNKNOWN":
        for aff in v.get("affected") or []:
            raw = (aff.get("database_specific") or {}).get("severity", "")
            if raw:
                sev = SEV_MAP.get(raw.lower(), "UNKNOWN")
                break
    if sev == "UNKNOWN" and v.get("id","").startswith("DRUPAL-"):
        sev = "MEDIUM"
    refs = []
    poc = []
    for ref in v.get("references", []):
        url = ref.get("url", "")
        rtyp = ref.get("type", "")
        if not url:
            continue
        refs.append(url)
        if rtyp in ("EVIDENCE", "EXPLOIT") or any(x in url.lower() for x in
                ("exploit", "poc", "proof", "nuclei", "metasploit",
                 "packetstorm", "edb.id", "exploitdb")):
            poc.append(url)
    advisory = next((u for u in refs if "drupal.org/sa-" in u or
                     "github.com/advisories" in u), refs[0] if refs else "")
    fixed = None
    for aff in v.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev and ev["fixed"]:
                    fixed = ev["fixed"]
    summary = v.get("summary", "")
    if not summary:
        details = v.get("details", "")
        if details:
            summary = next((l.strip() for l in details.splitlines() if l.strip()), "")[:140]
    return Vuln(
        id=v.get("id", ""),
        name=summary[:140],
        cve=cves[0] if cves else v.get("id", ""),
        link=advisory,
        severity=sev,
        privileges="n",
        cvss_score=cvss_score,
        fixed_version=fixed,
        poc=poc,
        published=v.get("published", "")[:10] if v.get("published") else '',
        package=package,
    )

def _fetch_drupal_module_version(base: str, name: str, kind: str) -> str:
    paths = [
        f"/modules/contrib/{name}/{name}.info.yml",
        f"/themes/contrib/{name}/{name}.info.yml",
        f"/modules/contrib/{name}/{name}.info",
        f"/themes/contrib/{name}/{name}.info",
    ]
    for p in paths:
        try:
            r = get(base + p)
            if r and r.status_code == 200:
                m = re.search(r"version\s*[:=]\s*['\"\s]*([\d]+\.x-[\d]+\.[\d]+|[\d]+\.[\d]+\.[\d]+)", r.text)
                if m:
                    return m.group(1)
        except:
            pass
    return ""

def _extract_drupal_modules(base: str, html: str) -> dict:
    found = {}
    pages = ["/", "/user/login", "/node"]
    type_pat = re.compile(
        r'(modules/contrib|modules/custom|themes/contrib|themes/custom)/([a-z0-9_\-]+)/', re.I)
    for page in pages:
        r = get(base + page)
        src = r.text if r else html
        for m in type_pat.finditer(src):
            kind    = "module" if "module" in m.group(1) else "theme"
            contrib = "contrib" if "contrib" in m.group(1) else "custom"
            name    = m.group(2).lower()
            if name not in found:
                found[name] = {"type": kind, "contrib": contrib,
                               "version": "", "paths": set()}
            found[name]["paths"].add(m.group(0))
    def fetch_ver(item):
        name, info = item
        return (name, _fetch_drupal_module_version(base, name, info["type"]))
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(fetch_ver, item): item[0] for item in found.items()
                if item[1]["contrib"] == "contrib"}
        for fut in as_completed(futs, timeout=15):
            try:
                name, ver = fut.result(timeout=1)
                if ver:
                    found[name]["version"] = ver
            except:
                pass
    for v in found.values():
        v["paths"] = list(v["paths"])
    return found

def scan_drupal(base: str, cms_info: dict) -> dict:
    html = cms_info["html"]
    version = cms_info.get("version") or ""
    result = {"vulns": [], "paths": [], "authors": [], "emails": []}
    section("Drupal Core")
    if version:
        ok(f"Version: {C.BOLD}{version}{C.RST}")
    else:
        warn("Core version not detected — skipping vuln check")
    if version:
        ids_raw = []
        try:
            payload = {"version": version,
                       "package": {"name": "drupal/core", "ecosystem": "Packagist"}}
            r = get(OSV_QUERY, json=payload)
            if r and r.status_code == 200:
                ids_raw = r.json().get("vulns", [])
        except:
            pass
        if ids_raw:
            all_ids = [v.get("id") for v in ids_raw if v.get("id")]
            full_records = {}
            with ThreadPoolExecutor(max_workers=10) as ex:
                futs = {ex.submit(_osv_fetch_full, vid): vid for vid in all_ids}
                for fut in as_completed(futs, timeout=20):
                    vid = futs[fut]
                    try:
                        rec = fut.result(timeout=2)
                        if rec:
                            full_records[vid] = rec
                    except:
                        pass
            core_vulns_raw = [full_records[vid] for vid in all_ids if vid in full_records]
            _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            core_parsed = [_parse_osv_vuln(v, "drupal/core") for v in core_vulns_raw]
            _seen_cve = {}
            for vuln in core_parsed:
                key = vuln.cve or vuln.id
                if key not in _seen_cve or _sev_order.get(vuln.severity, 4) < _sev_order.get(_seen_cve[key].severity, 4):
                    _seen_cve[key] = vuln
            core_parsed = sorted(_seen_cve.values(), key=lambda x: _sev_order.get(x.severity, 4))
            for vuln in core_parsed:
                result["vulns"].append(vuln)
                print_vuln(vuln)
    modules = _extract_drupal_modules(base, html)
    contrib_mods    = sorted(n for n, i in modules.items()
                             if i["contrib"] == "contrib" and i["type"] == "module")
    contrib_themes  = sorted(n for n, i in modules.items()
                             if i["contrib"] == "contrib" and i["type"] == "theme")
    custom_items    = sorted(n for n, i in modules.items() if i["contrib"] == "custom")
    section("Themes")
    if contrib_themes:
        for name in contrib_themes:
            ver = modules[name]["version"]
            print(f"  {C.WHITE}{C.BOLD}{name}{C.RST}  {C.DIM}{ver or '?'}{C.RST}")
    else:
        warn("No contrib themes detected")
    section("Modules")
    if not contrib_mods and not custom_items:
        warn("No modules detected (assets may be aggregated)")
    if custom_items:
        info(f"Custom: {', '.join(custom_items)}")
    osv_results = _osv_query_packages([f"drupal/{m}" for m in contrib_mods]) if contrib_mods else {}
    for name in contrib_mods:
        ver = modules[name]["version"]
        pkg = f"drupal/{name}"
        vulns_raw = osv_results.get(pkg, []) if ver else []
        print(f"  {C.WHITE}{C.BOLD}{name}{C.RST}  {C.DIM}{ver or '?'}{C.RST}", flush=True)
        if not vulns_raw:
            continue
        _sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        parsed = [_parse_osv_vuln(v, pkg) for v in vulns_raw]
        _seen = {}
        for vuln in parsed:
            key = vuln.cve or vuln.id
            if key not in _seen or _sev_ord.get(vuln.severity, 4) < _sev_ord.get(_seen[key].severity, 4):
                _seen[key] = vuln
        parsed = sorted(_seen.values(), key=lambda x: _sev_ord.get(x.severity, 4))
        for vuln in parsed:
            result["vulns"].append(vuln)
            print_vuln(vuln)
    section("Authors")
    authors = {}
    r = get(base + "/jsonapi/user/user")
    if r and r.status_code == 200:
        try:
            data = r.json().get("data", [])
            for u in data[:20]:
                name = u.get("attributes", {}).get("name", "")
                if name:
                    authors[f"json_{name}"] = name
        except:
            pass
    for i in range(1, 11):
        r = get(base + f"/user/{i}")
        if r and r.status_code == 200:
            m = re.search(r'<h1[^>]*>([^<]+)</h1>', r.text, re.I)
            if m:
                name = m.group(1).strip()
                if name and name not in authors.values():
                    authors[f"user_{i}"] = name
    if authors:
        for uid, name in sorted(authors.items()):
            print(f"    {C.WHITE}{uid}:{C.RST} {name}")
            result["authors"].append(name)
    else:
        warn("No authors found")
    return result

# ── Joomla scanner ─────────────────────────────────────────────────────
def scan_joomla(base: str, cms_info: dict) -> dict:
    version = cms_info.get('version')
    result = {"vulns": [], "authors": []}
    section("Joomla Core")
    if version:
        ok(f"Version: {C.BOLD}{version}{C.RST}")
        core_vulns = check_vulns_friendsofphp('joomla', 'joomla/joomla', version)
        for v in core_vulns:
            result["vulns"].append(v)
            print_vuln(v)
    else:
        warn("Version not detected")
    return result

# ── PrestaShop scanner ──────────────────────────────────────────────────
def scan_prestashop(base: str, cms_info: dict) -> dict:
    version = cms_info.get('version')
    result = {"vulns": [], "authors": []}
    section("PrestaShop Core")
    if version:
        ok(f"Version: {C.BOLD}{version}{C.RST}")
        core_vulns = check_vulns_friendsofphp('prestashop', 'prestashop/prestashop', version)
        for v in core_vulns:
            result["vulns"].append(v)
            print_vuln(v)
    else:
        warn("Version not detected")
    return result


# ── Update WP DB ──────────────────────────────────────────────────────
def _update_one(kind: str, slug: str, session: requests.Session,
                total: int, counter: list):
    dirmap = {"core": CORE_DIR, "plugin": PLUGINS_DIR, "theme": THEMES_DIR}
    try:
        r = session.get(f"https://www.wpvulnerability.net/{kind}/{slug}",
                        timeout=3)
        if r.status_code == 200:
            with open(os.path.join(dirmap[kind], slug), "wb") as f:
                f.write(r.content)
    except:
        pass
    counter[0] += 1
    print(f"\r  {counter[0]}/{total}", end="", flush=True)

def update_wp_db():
    print(f"\n{C.BLUE}[*] Updating WP vuln database from wpvulnerability.net...{C.RST}")
    for kind, d in (("core", CORE_DIR), ("plugin", PLUGINS_DIR), ("theme", THEMES_DIR)):
        files = os.listdir(d)
        if not files:
            continue
        counter = [0]
        print(f"  Updating {kind} ({len(files)} entries)...")
        with ThreadPoolExecutor(max_workers=8) as ex:
            with requests.Session() as s:
                s.headers["User-Agent"] = random.choice(USER_AGENTS)
                if CUSTOM_HOST:
                    s.headers["Host"] = CUSTOM_HOST
                for f in files:
                    ex.submit(_update_one, kind, f, s, len(files), counter)
        print()
    with open(LAST_UPDATE, "w") as f:
        f.write(str(datetime.date.today()))
    ok("WP database update complete")

def _check_db_age():
    if not os.path.exists(LAST_UPDATE):
        return
    try:
        with open(LAST_UPDATE) as f:
            parts = f.read().strip().split("-")
        last = datetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
        if (datetime.date.today() - last).days > 7:
            print(f"{C.YELLOW}[!] vuln database is >7 days old — run with --update{C.RST}")
    except:
        pass

# ── Searchsploit ──────────────────────────────────────────────────────
def _searchsploit_available() -> bool:
    import shutil
    return shutil.which("searchsploit") is not None

def run_searchsploit(vulns: list, cms: str, version: str):
    import subprocess
    if not _searchsploit_available():
        return
    cves = sorted({v.cve for v in vulns if v.cve and v.cve.startswith("CVE-")})
    core_queries = []
    if version:
        if cms == "wordpress":
            core_queries.append(f"WordPress {version}")
        elif cms == "drupal":
            core_queries.append(f"Drupal {version}")
        elif cms == "joomla":
            core_queries.append(f"Joomla {version}")
        elif cms == "prestashop":
            core_queries.append(f"PrestaShop {version}")
    queries = core_queries + cves
    if not queries:
        return
    section("Searchsploit")
    def run_one(query):
        try:
            r = subprocess.run(
                ["searchsploit", "--colour", query],
                capture_output=True, text=True, timeout=10
            )
            lines = [l for l in r.stdout.splitlines()
                     if l.strip() and "No Results" not in l
                     and "------" not in l and "Exploit Title" not in l
                     and "Exploits:" not in l]
            return lines
        except:
            return []
    for q in queries:
        lines = run_one(q)
        if lines:
            label = f"{C.CYAN}[core]{C.RST} {q}" if q in core_queries else f"{C.WHITE}{C.BOLD}{q}{C.RST}"
            print(f"  {label}")
            for l in lines:
                print(f"    {C.ORANGE}{l}{C.RST}")

# ── CSV export ────────────────────────────────────────────────────────
def export_csv(res: ScanResult, outfile: str):
    rows = []
    for v in res.vulns:
        rows.append({
            "target": res.target, "cms": res.cms,
            "type": "vuln", "package": v.package,
            "id": v.id, "cve": v.cve,
            "severity": v.severity, "cvss": v.cvss_score or "",
            "privileges": v.privileges,
            "summary": v.name,
            "fixed": v.fixed_version or "",
            "link": v.link,
            "poc": "|".join(v.poc[:2]),
            "published": v.published,
        })
    for p in res.paths:
        rows.append({
            "target": res.target, "cms": res.cms,
            "type": "exposed_path", "package": "",
            "id": p["path"], "cve": "",
            "severity": p["severity"], "cvss": "",
            "privileges": "n",
            "summary": p["description"],
            "fixed": "", "link": p["url"], "poc": p["url"],
            "published": "",
        })
    for h in res.headers:
        rows.append({
            "target": res.target, "cms": res.cms,
            "type": "missing_header", "package": "",
            "id": h["header"], "cve": "",
            "severity": h["severity"], "cvss": "",
            "privileges": "n",
            "summary": h["issue"],
            "fixed": "", "link": "", "poc": "",
            "published": "",
        })
    if not rows:
        return
    write_hdr = not os.path.exists(outfile)
    try:
        with open(outfile, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            if write_hdr:
                w.writeheader()
            w.writerows(rows)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"  {C.YELLOW}[!] CSV write error: {e}{C.RST}")

# ── Main scan ─────────────────────────────────────────────────────────
def scan(target: str, csv_out: str) -> ScanResult:
    global TARGET_BASE, REQUEST_COUNT
    base = normalize_url(target)
    TARGET_BASE = base
    REQUEST_COUNT = 0
    res = ScanResult(target=base)

    print(f"\n{C.CYAN}{C.BOLD}{'═'*66}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}  TARGET: {base}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}{'═'*66}{C.RST}")

    _probe = None
    try:
        _probe = get(base)
    except:
        pass
    if _probe is None:
        err("Cannot reach target")
        return res
    if _probe.status_code >= 500:
        warn(f"HTTP {_probe.status_code} — scan may be incomplete")
    elif _probe.status_code == 403:
        warn("403 — trying with alternative user‑agents")

    section("CMS Detection")
    cms_info = detect_cms(base)
    res.cms = cms_info["cms"]
    actual_base = cms_info.get("actual_base", base)
    if actual_base != base:
        ok(f"Detected CMS in subdirectory: {actual_base}")
        base = actual_base
    cms_label = {"wordpress": f"{C.BLUE}WordPress{C.RST}",
                 "drupal":    f"{C.GREEN}Drupal{C.RST}",
                 "joomla":    f"{C.CYAN}Joomla{C.RST}",
                 "prestashop": f"{C.ORANGE}PrestaShop{C.RST}",
                 "unknown":   f"{C.YELLOW}Unknown{C.RST}"}.get(res.cms, f"{C.YELLOW}Unknown{C.RST}")
    print(f"  CMS     : {cms_label}")

    if cms_info["version"]:
        res.version = cms_info["version"]
        print(f"  Version : {C.BOLD}{res.version}{C.RST}")
    else:
        warn("Version not detected")

    section("Meta / Site Info")
    meta = extract_meta(base, cms_info.get("html", ""))
    res.authors = meta["authors"]
    res.emails  = meta["emails"]

    if meta["title"]:       print(f"  Title       : {meta['title']}")
    if meta["description"]: print(f"  Description : {meta['description']}")
    if meta["emails"]:      print(f"  {C.ORANGE}Emails : {', '.join(meta['emails'][:5])}{C.RST}")
    for k, v in meta["og"].items():
        print(f"  {k}: {v}")
    if meta["dns_prefetch"]:
        print(f"  DNS prefetch: {', '.join(meta['dns_prefetch'])}")

    section("Security Headers")
    res.headers = audit_headers(cms_info.get("resp_headers", {}))
    if not res.headers:
        ok("All key security headers present")
    for h in res.headers:
        col = sev_color(h["severity"])
        print(f"  {col}[{h['severity']}]{C.RST} {h['issue']}  {C.DIM}({h['header']}){C.RST}")
    lower_h = {k.lower(): v for k, v in cms_info.get("resp_headers", {}).items()}
    for k in ("x-generator", "x-drupal-cache", "x-frame-options",
              "x-content-type-options", "server", "x-powered-by"):
        if k in lower_h:
            print(f"  {C.DIM}{k}: {lower_h[k][:80]}{C.RST}")

    section("Exposed Paths")
    path_list = WP_SENSITIVE_PATHS if res.cms == "wordpress" else DRUPAL_SENSITIVE_PATHS
    res.paths = check_paths(base, path_list)
    if not res.paths:
        ok("No obviously exposed sensitive paths")
    for p in res.paths:
        col = sev_color(p["severity"])
        print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")

    if res.cms == "wordpress":
        eng = scan_wordpress(base, cms_info)
    elif res.cms == "drupal":
        eng = scan_drupal(base, cms_info)
    elif res.cms == "joomla":
        eng = scan_joomla(base, cms_info)
    elif res.cms == "prestashop":
        eng = scan_prestashop(base, cms_info)
    else:
        warn("CMS unknown — running generic header/path checks only")
        eng = {"vulns": [], "authors": [], "emails": []}

    res.vulns   += eng.get("vulns", [])
    res.authors += eng.get("authors", [])
    res.emails  += eng.get("emails", [])

    run_searchsploit(res.vulns, res.cms, res.version)

    print(f"\n{C.CYAN}{C.BOLD}{'─'*66}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}  SUMMARY — {base}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}{'─'*66}{C.RST}")

    crit = [v for v in res.vulns if v.severity in ("CRITICAL","HIGH")]
    med  = [v for v in res.vulns if v.severity == "MEDIUM"]
    low  = [v for v in res.vulns if v.severity == "LOW"]
    p_hi = [p for p in res.paths if p["severity"] in ("CRITICAL","HIGH")]

    print(f"  {C.RED}Critical/High vulns : {len(crit)}{C.RST}")
    print(f"  {C.ORANGE}Medium vulns        : {len(med)}{C.RST}")
    print(f"  {C.YELLOW}Low vulns           : {len(low)}{C.RST}")
    print(f"  {C.RED}Exposed paths (H/C) : {len(p_hi)}{C.RST}")
    print(f"  {C.ORANGE}Header issues       : {len(res.headers)}{C.RST}")
    if res.version:
        print(f"  {C.GREEN}{res.cms.capitalize()} version : {res.version}{C.RST}")
    print(f"  {C.DIM}Total HTTP requests to target: {REQUEST_COUNT}{C.RST}")

    export_csv(res, csv_out)
    print(f"\n  {C.DIM}→ Results appended to {csv_out}{C.RST}")

    res.request_count = REQUEST_COUNT
    return res

# ── Entry point ────────────────────────────────────────────────────────────
def main():
    auto_update()
    print(BANNER)
    parser = argparse.ArgumentParser(description="CMScan — Unified CMS Scanner")
    parser.add_argument("-L", metavar="TARGET|FILE", required=False,
                        help="Single domain or file with one domain per line")
    parser.add_argument("-o", "--output", default=None,
                        help="CSV output file")
    parser.add_argument("--update", action="store_true",
                        help="Update all vulnerability databases (WP + FriendsOfPHP)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Delay between targets in seconds (default: 1.0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose mode — show timing and debug info")
    parser.add_argument("--host", metavar="HOST", default=None,
                        help="Force Host header for virtual hosts (shared hosting)")
    parser.add_argument("--version", action="store_true",
                        help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"CMScan version {VERSION}")
        sys.exit(0)

    global VERBOSE, CUSTOM_HOST
    VERBOSE = args.verbose
    CUSTOM_HOST = args.host

    if args.update:
        update_wp_db()
        update_friendsofphp_db()
        if not args.L:
            sys.exit(0)

    if not args.L:
        parser.print_help()
        sys.exit(1)

    _check_db_age()

    if os.path.isfile(args.L):
        with open(args.L) as f:
            targets = [l.strip() for l in f
                       if l.strip() and not l.startswith("#")]
    else:
        targets = [args.L]

    from urllib.parse import urlparse
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        csv_out = args.output
    elif len(targets) == 1:
        hostname = urlparse(normalize_url(targets[0])).netloc or targets[0]
        hostname = re.sub(r'[^a-zA-Z0-9\.\-]', "_", hostname)[:40]
        csv_out = f"cmscan_{hostname}_{ts}.csv"
    else:
        csv_out = f"cmscan_campaign_{ts}.csv"

    print(f"\n{C.GREEN}[+] Targets: {len(targets)}{C.RST}")
    print(f"{C.GREEN}[+] CSV output: {csv_out}{C.RST}")

    all_results = []
    for i, t in enumerate(targets, 1):
        print(f"\n{C.DIM}[{i}/{len(targets)}]{C.RST}")
        try:
            r = scan(t, csv_out)
            all_results.append(r)
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[!] Interrupted{C.RST}")
            break
        except Exception as e:
            err(f"Error scanning {t}: {e}")
        if i < len(targets):
            time.sleep(args.delay)

    if len(all_results) > 1:
        total_v = sum(len(r.vulns) for r in all_results)
        total_c = sum(1 for r in all_results
                      for v in r.vulns if v.severity in ("CRITICAL","HIGH"))
        print(f"\n{C.CYAN}{C.BOLD}{'═'*66}{C.RST}")
        print(f"{C.CYAN}{C.BOLD}  CAMPAIGN SUMMARY — {len(all_results)} targets{C.RST}")
        print(f"{C.CYAN}{C.BOLD}{'═'*66}{C.RST}")
        print(f"  {C.RED}Total Critical/High : {total_c}{C.RST}")
        print(f"  {C.WHITE}Total vulns         : {total_v}{C.RST}")
        print(f"  {C.GREEN}CSV report          : {csv_out}{C.RST}\n")

def self_update():
    """Met à jour le script depuis GitHub."""
    if not os.path.exists(".git"):
        print("[!] Pas un dépôt git, impossible de s'auto-updater.")
        return
    try:
        import subprocess
        print("[*] Vérification des mises à jour...")
        subprocess.run(["git", "fetch", "--tags"], check=True, capture_output=True)
        current = subprocess.run(["git", "describe", "--tags", "--abbrev=0"], capture_output=True, text=True).stdout.strip()
        remote = subprocess.run(["git", "describe", "--tags", "--abbrev=0", "origin/main"], capture_output=True, text=True).stdout.strip()
        if current != remote:
            print(f"[*] Nouvelle version disponible : {remote} (actuelle : {current})")
            subprocess.run(["git", "pull"], check=True)
            print("[+] Mise à jour terminée, relancez le script.")
            sys.exit(0)
        else:
            print("[+] Déjà à jour.")
    except Exception as e:
        print(f"[!] Erreur : {e}")

if __name__ == "__main__":
    main()
