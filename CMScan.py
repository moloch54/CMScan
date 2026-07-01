#!/usr/bin/env python3
import sys
import os
import re
import json
import random
import argparse
import datetime
import time
from urllib.parse import urlparse

from lib.colors import C, ok, warn, err, section, sev_color
from lib.http import get, normalize_url, _cmseek_getsource, USER_AGENTS
from lib.meta import extract_meta
from lib.headers import audit_headers, display_headers_info
from lib.vuln import update_friendsofphp_db
from lib.csv_export import export_csv
VERBOSE = False

def auto_update():
    """Vérifie automatiquement les mises à jour sur GitHub et se relance si nécessaire."""
    if not os.path.exists(".git"):
        return
    try:
        import subprocess
        import urllib.request
        import time
        # Récupérer la version distante
        url = "https://raw.githubusercontent.com/moloch54/CMScan/main/version.txt"
        with urllib.request.urlopen(url, timeout=3) as response:
            remote_version = response.read().decode('utf-8').strip()
        # Lire la version locale
        if os.path.exists("version.txt"):
            with open("version.txt", "r") as f:
                local_version = f.read().strip()
        else:
            local_version = "0.0"
        if local_version != remote_version:
            print(f"\n{C.GREEN}{C.BOLD}[+] Nouvelle version disponible : {remote_version} (actuelle : {local_version}){C.RST}")
            print(f"{C.CYAN}[*] Téléchargement de la mise à jour...{C.RST}")
            subprocess.run(["git", "pull", "--quiet"], check=True)
            # Relire la version après pull
            with open("version.txt", "r") as f:
                new_version = f.read().strip()
            print(f"{C.GREEN}{C.BOLD}[✓] Mise à jour vers la version {new_version} effectuée !{C.RST}")
            print(f"{C.CYAN}[*] Redémarrage du script...{C.RST}\n")
            time.sleep(1)
            os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        # Silencieux en cas d'erreur (pas de blocage)
        pass
        
try:
    with open("version.txt", "r") as f:
        VERSION = f.read().strip()
except:
    VERSION = "3.4"

BANNER = f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║   CMScan v{VERSION} — Unified CMS Security Scanner             ║
║   Augmented CyberSecurity                                ║
╚══════════════════════════════════════════════════════════╝{C.RST}"""

# ──────────────────────────────────────────────────────────────
# 1. RÉCUPÉRATION DU HTML (fallback Playwright)
# ──────────────────────────────────────────────────────────────
def get_html(base):
    # 1. Essayer avec get() (requests)
    r = get(base)
    if r and r.status_code == 200:
        html = r.text
        headers = r.headers
        if 'sgcaptcha' not in html and 'challenge' not in html:
            return html, headers

    # 2. Fallback avec _cmseek_getsource (urllib.request, pas Playwright)
    ua = random.choice(USER_AGENTS)
    src = _cmseek_getsource(base, ua)
    if src[0] == '1':
        html = src[1]
        headers = {}
        for line in src[2].split('\n'):
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k.lower()] = v
        return html, headers

    return None, None

# ──────────────────────────────────────────────────────────────
# 2. EXTRACTION VERSION WORDPRESS (comme WPscrap)
# ──────────────────────────────────────────────────────────────
def _extract_wp_version(base):
    """Extrait la version WordPress avec toutes les méthodes possibles."""
    version = None

    # 1. Meta generator (page d'accueil)
    r_home = get(base)
    if r_home and r_home.status_code == 200:
        m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', r_home.text, re.I)
        if m:
            version = m.group(1)
            print(f"[DEBUG] Version WP via meta: {version}")

    # 2. /wp-admin/ (assets avec ver=)
    if not version:
        r_admin = get(base + "/wp-admin/")
        if r_admin and r_admin.status_code == 200:
            m = re.search(r'\/wp-admin\/([^/\"\';]+).*[?"\']ver=([\d]+\.[\d\.]+)', r_admin.text)
            if m:
                version = m.group(2)
                if "Download" in version or ".com" in version:
                    version = None
                print(f"[DEBUG] Version WP via wp-admin: {version}")

    # 3. /readme.html
    if not version:
        r_readme = get(base + "/readme.html")
        if r_readme and r_readme.status_code == 200:
            m = re.search(r'<br />(\d+\.\d+[\.\d]*)', r_readme.text)
            if not m:
                m = re.search(r'Version (\d+\.\d+[\.\d]*)', r_readme.text)
            if m:
                version = m.group(1)
                print(f"[DEBUG] Version WP via readme: {version}")

    # 4. /wp-links-opml.php
    if not version:
        r_opml = get(base + "/wp-links-opml.php")
        if r_opml and r_opml.status_code == 200:
            m = re.search(r'generator="WordPress/(\d+\.\d+[\.\d]*)"', r_opml.text)
            if m:
                version = m.group(1)
                print(f"[DEBUG] Version WP via opml: {version}")

    # 5. /feed (RSS)
    if not version:
        r_feed = get(base + "/feed")
        if r_feed and r_feed.status_code == 200:
            m = re.search(r'<generator>https://wordpress.org/\?v=([\d\.]+)</generator>', r_feed.text)
            if m:
                version = m.group(1)
                print(f"[DEBUG] Version WP via feed: {version}")

    # 6. /wp-includes/version.php
    if not version:
        r_ver = get(base + "/wp-includes/version.php")
        if r_ver and r_ver.status_code == 200:
            m = re.search(r"\$wp_version\s*=\s*'([\d\.]+)'", r_ver.text)
            if m:
                version = m.group(1)
                print(f"[DEBUG] Version WP via version.php: {version}")

    return version

# ──────────────────────────────────────────────────────────────
# 3. DÉTECTIONS PAR CMS
# ──────────────────────────────────────────────────────────────
def detect_wordpress(html, headers, base):
    if not ("wp-content" in html or "wp-includes" in html or "wordpress" in headers.get("x-powered-by", "").lower()):
        return None

    version = _extract_wp_version(base)
    return version if version is not None else ""

def detect_drupal(html, headers, base):
    if not ("Drupal" in html or "drupal" in headers.get("x-generator", "").lower() or "x-drupal-cache" in headers):
        return None

    version = None
    m = re.search(r'<meta name="Generator" content="Drupal ([\d.]+)"', html, re.I)
    if m:
        version = m.group(1)

    if not version:
        for p in ("/core/CHANGELOG.txt", "/CHANGELOG.txt"):
            r = get(base + p)
            if r and r.status_code == 200:
                m = re.search(r"Drupal (\d+\.\d+\.\d+)", r.text)
                if m:
                    version = m.group(1)
                    break

    if not version:
        r = get(base + "/core/package.json")
        if r and r.status_code == 200:
            try:
                data = json.loads(r.text)
                v = data.get("version", "")
                if re.match(r"\d+\.\d+\.\d+", v):
                    version = v
            except:
                pass

    return version if version is not None else ""

def find_joomla_base(base):
    common_paths = [
        "",
        "/joomla",
        "/site",
        "/cms",
        "/web",
        "/public",
        "/html",
        "/www",
        "/joomla2",
        "/joomla3",
        "/joomla4",
        "/admin",
        "/portal",
    ]
    for path in common_paths:
        test_url = base + path + "/administrator"
        r = get(test_url)
        if r and r.status_code in (200, 302, 301, 403):
            return base + path
    return base

def detect_joomla(html, headers, base):
    joomla_base = find_joomla_base(base)
    version = None

    # 1. Meta generator (dans le HTML)
    m = re.search(r'<meta name="generator" content="Joomla!([^"]+)"', html, re.I)
    if m:
        v_match = re.search(r'(\d+\.\d+\.\d+)', m.group(1))
        if v_match:
            return v_match.group(1)

    # 2. /administrator/manifests/files/joomla.xml
    r = get(joomla_base + '/administrator/manifests/files/joomla.xml')
    if r and r.status_code == 200:
        m = re.search(r'<version>([^<]+)</version>', r.text)
        if m:
            return m.group(1)
        m = re.search(r'<extension[^>]*version="([^"]+)"', r.text)
        if m:
            return m.group(1)

    # 3. /language/en-GB/en-GB.xml
    r = get(joomla_base + '/language/en-GB/en-GB.xml')
    if r and r.status_code == 200:
        m = re.search(r'<version>([^<]+)</version>', r.text)
        if m:
            return m.group(1)

    # 4. /libraries/src/Version.php
    r = get(joomla_base + '/libraries/src/Version.php')
    if r and r.status_code == 200:
        m = re.search(r"const\s+RELEASE\s*=\s*'([^']+)'", r.text)
        if m:
            version = m.group(1)
            m = re.search(r"const\s+DEV_LEVEL\s*=\s*'([^']+)'", r.text)
            if m:
                version = f"{version}.{m.group(1)}"
            return version

    # 5. /administrator
    r = get(joomla_base + "/administrator")
    if r and r.status_code == 200:
        m = re.search(r'Joomla! (\d+\.\d+\.\d+)', r.text)
        if m:
            return m.group(1)

    return ""   # Joomla détecté mais version inconnue

def detect_prestashop(html, headers, base):
    if not ("PrestaShop" in html or "prestashop" in headers.get("x-powered-by", "").lower()):
        return None

    version = None
    m = re.search(r'<meta name="generator" content="PrestaShop ([^"]+)"', html, re.I)
    if m:
        version = m.group(1)

    if not version:
        for path in ['/classes/Configuration.php', '/config/defines.inc.php']:
            r = get(base + path)
            if r and r.status_code == 200:
                m = re.search(r"_PS_VERSION_\s*=\s*'([^']+)'", r.text)
                if m:
                    version = m.group(1)
                    break

    return version if version is not None else ""

# ──────────────────────────────────────────────────────────────
# 4. DÉTECTION GÉNÉRIQUE (priorité WordPress sans Playwright)
# ──────────────────────────────────────────────────────────────
def detect_cms(base):
    print("[DEBUG] detect_cms: appelée pour", base)

    # ── 1. Test rapide WordPress (sans Playwright) ──
    # a) /wp-login.php
    r_login = get(base + "/wp-login.php")
    if r_login and r_login.status_code == 200:
        print("[DEBUG] WordPress détecté via /wp-login.php")
        version = _extract_wp_version(base)
        # Récupérer le HTML de la page d'accueil pour le module
        r_home = get(base)
        html = r_home.text if r_home else ""
        headers = r_home.headers if r_home else {}
        return {"cms": "wordpress", "version": version, "html": html, "resp_headers": headers}

        # b) /readme.html
    r_readme = get(base + "/readme.html")
    if r_readme and r_readme.status_code == 200 and "WordPress" in r_readme.text:
        if VERBOSE:
            print("[DEBUG] WordPress détecté via /readme.html")
        version = _extract_wp_version(base)
        # Récupérer la page d'accueil pour les métadonnées (emails, auteurs)
        r_home = get(base)
        home_html = r_home.text if r_home and r_home.status_code == 200 else ""
        home_headers = r_home.headers if r_home else {}
        if VERBOSE:
            print(f"[DEBUG] Page d'accueil récupérée: {len(home_html)} caractères")
        return {"cms": "wordpress", "version": version, "html": home_html, "resp_headers": home_headers}

    # c) Page d'accueil (get simple) avec filtrage des domaines externes
    r_home = get(base)
    if r_home and r_home.status_code == 200:
        html = r_home.text
        from urllib.parse import urlparse
        target_domain = urlparse(base).netloc
        wp_signals = ["wp-content", "wp-includes", "wp-json"]
        found = False
        for sig in wp_signals:
            if sig in html:
                # Vérifier si le signal est dans une URL externe
                idx = html.find(sig)
                # Extraire le contexte autour du signal (300 caractères)
                context = html[max(0, idx-100):min(len(html), idx+200)]
                # Chercher une URL complète dans le contexte
                url_match = re.search(r'(https?://[^\s"\']+)', context)
                if url_match:
                    full_url = url_match.group(1)
                    url_domain = urlparse(full_url).netloc
                    # Si le domaine est différent du domaine cible, ignorer
                    if url_domain and url_domain != target_domain:
                        print(f"[DEBUG] {sig} trouvé dans une URL externe ({url_domain}), ignoré")
                        continue
                # Si on arrive ici, le signal est valide (même domaine ou pas d'URL)
                found = True
                print(f"[DEBUG] WordPress détecté via page d'accueil (signal: {sig})")
                start = max(0, idx - 30)
                end = min(len(html), idx + len(sig) + 30)
                excerpt = html[start:end].replace('\n', ' ').strip()
                print(f"[DEBUG]     Extrait: ...{excerpt}...")
                version = _extract_wp_version(base)
                return {"cms": "wordpress", "version": version, "html": html, "resp_headers": r_home.headers}
        if not found:
            print("[DEBUG] Page d'accueil : aucun signal WordPress valide (même domaine) trouvé")
            
    # ── 2. Pour les autres CMS (Drupal, Joomla, PrestaShop) ──
    print("[DEBUG] Pas de WordPress, tentative Drupal/Joomla/PrestaShop")
    html, headers = get_html(base)
    if not html:
        return {"cms": "unknown", "version": None, "html": "", "resp_headers": {}}

    detectors = [
        ("drupal", detect_drupal),
        ("joomla", detect_joomla),
        ("prestashop", detect_prestashop),
    ]

    for cms_name, detector in detectors:
        version = detector(html, headers, base)
        if version is not None:
            return {"cms": cms_name, "version": version if version != "" else None, "html": html, "resp_headers": headers}

    return {"cms": "unknown", "version": None, "html": html, "resp_headers": headers}

# ──────────────────────────────────────────────────────────────
# 5. SCAN PRINCIPAL
# ──────────────────────────────────────────────────────────────
def scan(target, csv_out):
    base = normalize_url(target)

    print(BANNER)
    print(f"\n{C.CYAN}{C.BOLD}{'═'*66}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}  TARGET: {base}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}{'═'*66}{C.RST}")

    section("CMS Detection")
    cms_info = detect_cms(base)
    cms = cms_info["cms"]

    print(f"  CMS     : {cms.capitalize() if cms != 'unknown' else 'Unknown'}")
    if cms_info["version"]:
        print(f"  Version : {C.BOLD}{cms_info['version']}{C.RST}")
    else:
        warn("Version not detected")

    section("Meta / Site Info")
    meta = extract_meta(base, cms_info.get("html", ""))
    if meta["title"]:       print(f"  Title       : {meta['title']}")
    if meta["description"]: print(f"  Description : {meta['description']}")
    if meta["emails"]:      print(f"  {C.ORANGE}Emails : {', '.join(meta['emails'][:5])}{C.RST}")

    section("Security Headers")
    headers_issues = audit_headers(cms_info.get("resp_headers", {}))
    if not headers_issues:
        ok("All key security headers present")
    for h in headers_issues:
        col = sev_color(h["severity"])
        print(f"  {col}[{h['severity']}]{C.RST} {h['issue']}  {C.DIM}({h['header']}){C.RST}")
    display_headers_info(cms_info.get("resp_headers", {}))

    if cms == "wordpress":
        from modules.wordpress import WordPressModule
        module = WordPressModule(base, cms_info)
        result = module.scan()
    elif cms == "drupal":
        from modules.drupal import DrupalModule
        module = DrupalModule(base, cms_info)
        result = module.scan()
    elif cms == "joomla":
        from modules.joomla import JoomlaModule
        module = JoomlaModule(base, cms_info)
        result = module.scan()
    elif cms == "prestashop":
        from modules.prestashop import PrestaShopModule
        module = PrestaShopModule(base, cms_info)
        result = module.scan()
    else:
        warn("CMS not supported or not detected")
        return

    print(f"\n{C.CYAN}{C.BOLD}{'─'*66}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}  SUMMARY — {base}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}{'─'*66}{C.RST}")

    crit = [v for v in result.vulns if v.severity in ("CRITICAL","HIGH")]
    med  = [v for v in result.vulns if v.severity == "MEDIUM"]
    low  = [v for v in result.vulns if v.severity == "LOW"]

    print(f"  {C.RED}Critical/High vulns : {len(crit)}{C.RST}")
    print(f"  {C.ORANGE}Medium vulns        : {len(med)}{C.RST}")
    print(f"  {C.YELLOW}Low vulns           : {len(low)}{C.RST}")
    print(f"  {C.ORANGE}Header issues       : {len(headers_issues)}{C.RST}")
    if result.version:
        print(f"  {C.GREEN}{result.cms.capitalize()} version : {result.version}{C.RST}")
    export_csv(result, csv_out)
    print(f"{C.DIM}→ Results appended to {csv_out}{C.RST}")
    print("")

def main():
    parser = argparse.ArgumentParser(description="CMScan — Unified CMS Scanner")
    parser.add_argument("-L", metavar="TARGET", required=False, help="Target URL")
    parser.add_argument("-o", "--output", help="CSV output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("--update", action="store_true", help="Update vulnerability databases")
    args = parser.parse_args()

    global VERBOSE
    if args.verbose:
        VERBOSE = True
    auto_update()

    if args.update:
        print("[*] Updating vulnerability databases...")
        update_friendsofphp_db()
        sys.exit(0)

    if not args.L:
        parser.print_help()
        sys.exit(1)

    target = args.L
    if args.output:
        csv_out = args.output
    else:
        from lib.csv_export import generate_csv_filename
        csv_out = generate_csv_filename(target)

    scan(target, csv_out)

if __name__ == "__main__":
    main()