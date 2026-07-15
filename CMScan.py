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
import requests
from lib.colors import ok, warn, info, err
from concurrent.futures import ThreadPoolExecutor, as_completed

VERBOSE = False

import datetime
import os
import requests
from concurrent.futures import ThreadPoolExecutor
from lib.colors import info, ok, warn   # adapte si tu n'as pas ce module

# Fichier contenant la date de dernière mise à jour des vuln WordPress
WP_LAST_UPDATE_FILE = "last_update_vulnbase.txt"


def is_home_redirect(content, home_html):
    """
    Détecte si le contenu est celui de la page d'accueil (redirection ou rewriting).
    """
    if not home_html or not content:
        return False
    
    # Comparer les titres
    title_home = re.search(r'<title>([^<]+)</title>', home_html, re.I)
    title_content = re.search(r'<title>([^<]+)</title>', content, re.I)
    if title_home and title_content:
        if title_home.group(1).strip() == title_content.group(1).strip():
            return True
    
    # Comparer les meta generator
    gen_home = re.search(r'<meta name="generator" content="([^"]+)"', home_html, re.I)
    gen_content = re.search(r'<meta name="generator" content="([^"]+)"', content, re.I)
    if gen_home and gen_content:
        if gen_home.group(1) == gen_content.group(1):
            return True
    
    # Fallback : comparer les 500 premiers caractères si les titres sont vides
    if len(content) > 200 and len(home_html) > 200:
        if content[:500] == home_html[:500]:
            return True
    
    return False

def is_same_domain(domain1, domain2):
    """
    Vérifie si deux domaines sont équivalents :
    - identiques (ex: example.com == example.com)
    - ou l'un est un sous-domaine de l'autre (ex: www.example.com est sous-domaine de example.com)
    """
    if not domain1 or not domain2:
        return False
    d1 = domain1.lower()
    d2 = domain2.lower()
    # Identiques ?
    if d1 == d2:
        return True
    # Sous-domaine ?
    if d1.endswith("." + d2) or d2.endswith("." + d1):
        return True
    return False

def update_wordpress_vuln_db():
    """Met à jour la base WordPress via l'API et écrit la date dans le fichier."""
    info("Mise à jour de la base de données WordPress vulnérabilités...")
    updated = 0
    errors = 0
    tasks = []

    dirs = {
        "core": "vulnDatabase/coreVuln",
        "plugin": "vulnDatabase/pluginsVuln",
        "theme": "vulnDatabase/themesVuln"
    }

    for kind, path in dirs.items():
        if os.path.exists(path):
            for slug in os.listdir(path):
                tasks.append((kind, slug))

    if not tasks:
        warn("Aucun fichier de vulnérabilités WordPress trouvé.")
        # On écrit quand même la date pour ne pas retenter à chaque démarrage
        with open(WP_LAST_UPDATE_FILE, "w") as f:
            f.write(str(datetime.date.today()))
        return

    total = len(tasks)
    info(f"Total fichiers à mettre à jour : {total}")

    def update_one(kind, slug):
        nonlocal updated, errors
        url = f"https://www.wpvulnerability.net/{kind}/{slug}"
        try:
            r = requests.get(url, headers={"User-Agent": "CMScan"}, timeout=5)
            if r.status_code == 200:
                with open(os.path.join(dirs[kind], slug), "wb") as f:
                    f.write(r.content)
                updated += 1
                if updated % 50 == 0 or updated == total:
                    print(f"\r  Progression : {updated}/{total}", end="")
            else:
                errors += 1
        except Exception:
            errors += 1

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda t: update_one(t[0], t[1]), tasks)

    print()  # retour à la ligne

    # Écriture de la date de dernière mise à jour
    with open(WP_LAST_UPDATE_FILE, "w") as f:
        f.write(str(datetime.date.today()))

    if errors:
        warn(f"Mise à jour terminée : {updated} OK, {errors} erreurs")
    else:
        ok(f"Mise à jour terminée : {updated} fichiers à jour")


def needs_wp_vuln_update():
    """Retourne True si la mise à jour est nécessaire (>7j ou fichier absent)."""
    if not os.path.exists(WP_LAST_UPDATE_FILE):
        return True
    try:
        with open(WP_LAST_UPDATE_FILE, "r") as f:
            last_str = f.read().strip()
        last_date = datetime.datetime.strptime(last_str, "%Y-%m-%d").date()
        return (datetime.date.today() - last_date).days > 7
    except Exception:
        return True

def auto_update():
    """Vérifie automatiquement les mises à jour sur GitHub et se relance si nécessaire."""
    if not os.path.exists(".git"):
        return
    try:
        import subprocess
        import urllib.request
        import time

        url = "https://raw.githubusercontent.com/moloch54/CMScan/main/version.txt"
        with urllib.request.urlopen(url, timeout=3) as response:
            remote_version = response.read().decode('utf-8').strip()

        if os.path.exists("version.txt"):
            with open("version.txt", "r") as f:
                local_version = f.read().strip()
        else:
            local_version = "0.0"

        if local_version != remote_version:
            print(f"\n{C.GREEN}{C.BOLD}[+] Nouvelle version disponible : {remote_version} (actuelle : {local_version}){C.RST}")
            print(f"{C.CYAN}[*] Téléchargement de la mise à jour...{C.RST}")
            subprocess.run(["git", "pull", "--quiet"], check=True)

            # ═══ NOUVEAU : Mise à jour de la base WordPress après pull ═══
            update_wordpress_vuln_db()

            with open("version.txt", "r") as f:
                new_version = f.read().strip()
            print(f"{C.GREEN}{C.BOLD}[✓] Mise à jour vers la version {new_version} effectuée !{C.RST}")
            print(f"{C.CYAN}[*] Redémarrage du script...{C.RST}\n")
            time.sleep(1)
            os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        pass
        
try:
    with open("version.txt", "r") as f:
        VERSION = f.read().strip()
except:
    VERSION = "3.8"

BANNER = f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║   CMScan v{VERSION} — Unified CMS Security Scanner           ║
║   Augmented CyberSecurity                                ║
╚══════════════════════════════════════════════════════════╝{C.RST}"""

# ──────────────────────────────────────────────────────────────
# 1. RÉCUPÉRATION DU HTML (fallback Playwright)
# ──────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    # ... ajoute d'autres si besoin
]

# ──────────────────────────────────────────────────────────────
# 1. RÉCUPÉRATION DU HTML (avec fallback et verbose)
# ──────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────
# 1. RÉCUPÉRATION DU HTML (avec fallback, retry, SSL, verbose)
# ──────────────────────────────────────────────────────────────
def get_html(base, max_retries=3, timeout=8):
    """
    Récupère le HTML de l'URL avec :
      - timeout 8s
      - User-Agent aléatoire
      - retry si code != 200 ou page < 100 caractères
      - gestion SSL (WRONG_VERSION_NUMBER → HTTP)
      - fallback _cmseek_getsource
    """
    if VERBOSE:
        print(f"[VERBOSE] get_html() appelée pour {base}")
        print(f"[VERBOSE]   timeout={timeout}s, max_retries={max_retries}")

    original_base = base
    parsed = urlparse(base)
    current_scheme = parsed.scheme if parsed.scheme in ('https','http') else 'https'
    candidates = []
    if current_scheme == 'https':
        candidates.append(base)
        candidates.append(base.replace('https://', 'http://'))
    else:
        candidates.append(base)
        candidates.append(base.replace('http://', 'https://'))

    for url_to_try in candidates:
        for attempt in range(1, max_retries + 1):
            ua = random.choice(USER_AGENTS)
            headers = {'User-Agent': ua}
            if VERBOSE:
                print(f"[VERBOSE]   Tentative {attempt}/{max_retries} avec {url_to_try} (UA: {ua[:60]}...)")

            try:
                r = requests.get(url_to_try, headers=headers, timeout=timeout,
                                 allow_redirects=True, verify=False)
                status = r.status_code
                content_len = len(r.text)

                if VERBOSE:
                    print(f"[VERBOSE]     → Code HTTP : {status}")
                    print(f"[VERBOSE]     → Longueur : {content_len} caractères")
                    snippet = r.text[:200].replace('\n', ' ').replace('\r', '').strip()
                    print(f"[VERBOSE]     → Extrait : {snippet[:200]}...")

                if status == 200:
                    if content_len < 100:
                        if VERBOSE:
                            print(f"[VERBOSE]     ❌ Page trop courte (<100), on réessaie.")
                        continue
                    # ─── SUPPRESSION DES FILTRES CAPTCHA ───
                    # On accepte la page, même si elle contient "challenge" ou "sgcaptcha"
                    if VERBOSE:
                        print("[VERBOSE]     ✅ Succès !")
                    return r.text, dict(r.headers)
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ❌ Code HTTP {status} (non 200), on réessaie.")
                    continue

            except requests.exceptions.SSLError as e:
                if "WRONG_VERSION_NUMBER" in str(e):
                    if VERBOSE:
                        print(f"[VERBOSE]     ⚠️  SSL error, on passe au candidat suivant.")
                    break
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ❌ SSL error : {e}")
            except Exception as e:
                if VERBOSE:
                    print(f"[VERBOSE]     ❌ Exception : {type(e).__name__} - {e}")

            if attempt < max_retries:
                sleep_time = 2 ** attempt
                if VERBOSE:
                    print(f"[VERBOSE]   Attente de {sleep_time}s avant la prochaine tentative...")
                time.sleep(sleep_time)

        if VERBOSE:
            print(f"[VERBOSE]   Échec avec {url_to_try}, passage au candidat suivant")

    # ── Fallback ──
    if VERBOSE:
        print("[VERBOSE] ⚠️  Toutes les tentatives requests ont échoué, passage au fallback _cmseek_getsource")

    ua = random.choice(USER_AGENTS)
    src = _cmseek_getsource(original_base, ua)

    if src[0] == '1':
        html = src[1]
        headers = {}
        for line in src[2].split('\n'):
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k.lower()] = v

        if VERBOSE:
            print(f"[VERBOSE]   Fallback retourne {len(html)} caractères")
            snippet = html[:200].replace('\n', ' ').replace('\r', '').strip()
            print(f"[VERBOSE]   Extrait fallback : {snippet[:200]}...")

        # Ici aussi on ne filtre plus que sur la longueur
        if len(html) >= 100:
            if VERBOSE:
                print("[VERBOSE]   ✅ Fallback réussi.")
            return html, headers
        else:
            if VERBOSE:
                print("[VERBOSE]   ❌ Fallback : page trop courte.")
    else:
        if VERBOSE:
            print(f"[VERBOSE]   ❌ Fallback échoué : code {src[0]}")

    if VERBOSE:
        print("[VERBOSE] ❌ ÉCHEC TOTAL : aucun HTML valide récupéré.")
    return None, None
    
# ──────────────────────────────────────────────────────────────
# 2. EXTRACTION VERSION WORDPRESS (comme WPscrap)
# ──────────────────────────────────────────────────────────────

def _extract_wp_version(base):
    """
    Extrait la version WordPress avec les méthodes WPScan :
    - Feed RSS (/feed)
    - /wp-admin/install.php (cherche ?ver= dans les assets)
    - /wp-admin/ (assets)
    - Fichiers CSS core (/wp-includes/css/, /wp-admin/css/)
    - Meta generator (fallback)
    - readme.html (fallback)
    """
    version = None

    # 1. Feed RSS (le plus fiable)
    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: trying feed RSS")
    try:
        r = get(base + "/feed", timeout=5)
        if r and r.status_code == 200:
            m = re.search(r'<generator>https://wordpress.org/\?v=([\d\.]+)</generator>', r.text, re.I)
            if m:
                version = m.group(1)
                if VERBOSE:
                    print(f"[VERBOSE] Version WP via feed RSS: {version}")
                return version  # on retourne tout de suite
    except:
        pass

    # 2. /wp-admin/install.php (cherche les ?ver= dans les assets)
    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: trying /wp-admin/install.php")
    try:
        r = get(base + "/wp-admin/install.php", timeout=5)
        if r and r.status_code == 200:
            # Cherche les ?ver= dans les URLs des assets (seulement ceux de core)
            pattern = r'(?:href|src)=["\'](?:[^"\']*/(wp-includes|wp-admin)/[^"\']*)\?ver=([\d.]+)["\']'
            matches = re.findall(pattern, r.text, re.I)
            if matches:
                from collections import Counter
                versions = [v for _, v in matches]
                if versions:
                    v = Counter(versions).most_common(1)[0][0]
                    if re.match(r'\d+\.\d+(\.\d+)?', v):
                        if VERBOSE:
                            print(f"[VERBOSE] Version WP via install.php assets: {v}")
                        return v
            # Cherche "WordPress X.X" dans le texte
            m = re.search(r'WordPress\s+([\d.]+)', r.text, re.I)
            if m:
                version = m.group(1)
                if VERBOSE:
                    print(f"[VERBOSE] Version WP via install.php text: {version}")
                return version
    except:
        pass

    # 3. /wp-admin/ (cherche les ?ver=)
    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: trying /wp-admin/")
    try:
        r = get(base + "/wp-admin/", timeout=5)
        if r and r.status_code == 200:
            pattern = r'(?:href|src)=["\'](?:[^"\']*/(wp-includes|wp-admin)/[^"\']*)\?ver=([\d.]+)["\']'
            matches = re.findall(pattern, r.text, re.I)
            if matches:
                from collections import Counter
                versions = [v for _, v in matches]
                if versions:
                    v = Counter(versions).most_common(1)[0][0]
                    if re.match(r'\d+\.\d+(\.\d+)?', v):
                        if VERBOSE:
                            print(f"[VERBOSE] Version WP via /wp-admin/ assets: {v}")
                        return v
    except:
        pass

    # 4. Fichiers CSS individuels (comme WPScan)
    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: trying individual CSS files")
    css_files = [
        "/wp-includes/css/dashicons.min.css",
        "/wp-includes/css/buttons.min.css",
        "/wp-admin/css/forms.min.css",
        "/wp-admin/css/l10n.min.css",
        "/wp-admin/css/install.min.css",
    ]
    for css_path in css_files:
        try:
            r = get(base + css_path, timeout=3)
            if r and r.status_code == 200:
                # Cherche ?ver= dans le contenu
                m = re.search(r'ver=([\d.]+)', r.text, re.I)
                if m:
                    v = m.group(1)
                    if re.match(r'\d+\.\d+(\.\d+)?', v):
                        if VERBOSE:
                            print(f"[VERBOSE] Version WP from {css_path}: {v}")
                        return v
                # Cherche "WordPress X.X" dans le texte
                m = re.search(r'WordPress\s+([\d.]+)', r.text, re.I)
                if m:
                    v = m.group(1)
                    if VERBOSE:
                        print(f"[VERBOSE] Version WP from text in {css_path}: {v}")
                    return v
        except:
            pass

    # 5. Meta generator (fallback)
    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: trying meta generator")
    html, _ = get_html(base, max_retries=2, timeout=8)
    if html:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', html, re.I)
        if m:
            version = m.group(1)
            if VERBOSE:
                print(f"[VERBOSE] Version WP via meta: {version}")
            return version

    # 6. readme.html
    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: trying readme.html")
    try:
        r = get(base + "/readme.html", timeout=3)
        if r and r.status_code == 200:
            m = re.search(r'<br />(\d+\.\d+[\.\d]*)', r.text, re.I)
            if not m:
                m = re.search(r'Version (\d+\.\d+[\.\d]*)', r.text, re.I)
            if m:
                version = m.group(1)
                if VERBOSE:
                    print(f"[VERBOSE] Version WP via readme: {version}")
                return version
    except:
        pass

    if VERBOSE:
        print("[VERBOSE] _extract_wp_version: all methods failed")
    return None

# ──────────────────────────────────────────────────────────────
# 3. DÉTECTIONS PAR CMS
# ──────────────────────────────────────────────────────────────

def detect_drupal_score(base, home_html=None, home_headers=None):
    """
    Score de détection Drupal.
    Retourne un dict avec score, version, source.
    """
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] --- Scoring Drupal ---")

    # ===== TEST 1 : meta generator dans la page d'accueil =====
    if home_html:
        if VERBOSE:
            print("[VERBOSE]   Test 1 : recherche meta generator Drupal dans le HTML")

        m = re.search(r'<meta name="Generator" content="Drupal\s+([\d.]+)', home_html, re.I)
        if m:
            version = m.group(1)
            score += 3
            sources.append(f"meta generator Drupal (version {version})")
            if VERBOSE:
                print(f"[VERBOSE]     ✓ meta generator trouvé : version {version} → +2 points")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de meta generator Drupal")
    else:
        if VERBOSE:
            print("[VERBOSE]   Test 1 : pas de HTML pour tester meta generator")

    # ===== TEST 2 : /core/CHANGELOG.txt =====
    url = base + "/core/CHANGELOG.txt"
    if VERBOSE:
        print(f"[VERBOSE]   Test 2 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                m = re.search(r"Drupal (\d+\.\d+\.\d+)", content)
                if m:
                    version = m.group(1)
                    score += 2
                    sources.append(f"/core/CHANGELOG.txt (version {version})")
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                else:
                    score += 1
                    sources.append("/core/CHANGELOG.txt existe (pas de version)")
                    if VERBOSE:
                        print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 3 : /CHANGELOG.txt (à la racine, sans /core) =====
    if not version:
        url = base + "/CHANGELOG.txt"
        if VERBOSE:
            print(f"[VERBOSE]   Test 3 : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                    m = re.search(r"Drupal (\d+\.\d+\.\d+)", content)
                    if m:
                        version = m.group(1)
                        score += 2
                        sources.append(f"/CHANGELOG.txt (version {version})")
                        if VERBOSE:
                            print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                    else:
                        score += 1
                        sources.append("/CHANGELOG.txt existe (pas de version)")
                        if VERBOSE:
                            print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 4 : /core/package.json =====
    if not version:
        url = base + "/core/package.json"
        if VERBOSE:
            print(f"[VERBOSE]   Test 4 : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 50:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                    try:
                        data = json.loads(content)
                        v = data.get("version", "")
                        if v and re.match(r"\d+\.\d+\.\d+", v):
                            version = v
                            score += 2
                            sources.append(f"/core/package.json (version {version})")
                            if VERBOSE:
                                print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                        else:
                            score += 1
                            sources.append("/core/package.json existe (pas de version)")
                            if VERBOSE:
                                print("[VERBOSE]       ✗ pas de version valide, mais fichier existe → +1 point")
                    except json.JSONDecodeError:
                        if VERBOSE:
                            print("[VERBOSE]       ✗ JSON invalide")
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 5 : headers X-Generator et X-Drupal-Cache =====
    if VERBOSE:
        print("[VERBOSE]   Test 5 : vérification des headers")
    if home_headers:
        if "x-generator" in home_headers:
            if "drupal" in home_headers["x-generator"].lower():
                score += 1
                sources.append("X-Generator: Drupal")
                if VERBOSE:
                    print("[VERBOSE]     ✓ X-Generator contient 'drupal' → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ X-Generator présent mais pas 'drupal' : {home_headers['x-generator']}")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de X-Generator")

        if "x-drupal-cache" in home_headers:
            score += 1
            sources.append("X-Drupal-Cache présent")
            if VERBOSE:
                print("[VERBOSE]     ✓ X-Drupal-Cache présent → +1 point")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de X-Drupal-Cache")
    else:
        if VERBOSE:
            print("[VERBOSE]     ✗ pas de headers disponibles")

    # ===== TEST 6 : /misc/drupal.js =====
    url = base + "/misc/drupal.js"
    if VERBOSE:
        print(f"[VERBOSE]   Test 6 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/misc/drupal.js existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 7 : /core/misc/drupal.js (Drupal 8+) =====
    url = base + "/core/misc/drupal.js"
    if VERBOSE:
        print(f"[VERBOSE]   Test 7 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/core/misc/drupal.js existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 8 : attributs data-drupal dans le HTML (NOUVEAU) =====
    if home_html:
        if VERBOSE:
            print("[VERBOSE]   Test 8 : recherche d'attributs data-drupal dans le HTML")
        count = len(re.findall(r'data-drupal', home_html, re.I))
        if count > 0:
            # On ajoute un point par occurrence, limité à 5 pour éviter de trop gonfler
            points = min(count, 5)
            score += points
            sources.append(f"{count} occurrences de data-drupal (+{points} points)")
            if VERBOSE:
                print(f"[VERBOSE]     ✓ {count} occurrences de 'data-drupal' trouvées → +{points} points")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de 'data-drupal' trouvé")

    # Bonus si version trouvée
    if version:
        score += 1
        sources.append("version connue (bonus)")
        if VERBOSE:
            print(f"[VERBOSE]   Bonus : version connue → +1 point")

    source = " ; ".join(sources) if sources else "aucun test positif"
    if VERBOSE:
        print(f"[VERBOSE] Score final Drupal : {score}")

    return {'score': score, 'version': version, 'source': source}

def detect_joomla_score(base, home_html=None, home_headers=None):
    """
    Score de détection Joomla.
    Retourne un dict avec score, version, source.
    """
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] --- Scoring Joomla ---")

    # ===== ÉTAPE 1 : Trouver la base Joomla (sous-dossier éventuel) =====
    joomla_base = base
    if VERBOSE:
        print("[VERBOSE]   Recherche de la base Joomla (sous-dossiers possibles)")

    common_paths = ["", "/joomla", "/site", "/cms", "/web", "/public", "/html", "/www", "/admin", "/portal"]
    found_base = False
    for sub in common_paths:
        test_url = base + sub + "/administrator"
        if VERBOSE:
            print(f"[VERBOSE]     Test : {test_url}")
        try:
            r = get(test_url)
            if r and r.status_code in (200, 302, 301, 403):
                if r.status_code == 200 and len(r.text) > 100:
                    joomla_base = base + sub
                    found_base = True
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ Base trouvée : {joomla_base} (code 200, contenu significatif)")
                    break
                elif r.status_code in (302, 301):
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ Base probable : {base + sub} (redirection {r.status_code})")
                    joomla_base = base + sub
                    found_base = True
                    break
                elif r.status_code == 403:
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ Base probable : {base + sub} (accès interdit 403, signe de présence)")
                    joomla_base = base + sub
                    found_base = True
                    break
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]       ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]       ✗ erreur : {e}")

    if not found_base:
        joomla_base = base
        if VERBOSE:
            print("[VERBOSE]     Aucune base Joomla trouvée, utilisation de la base par défaut")

    if VERBOSE:
        print(f"[VERBOSE]   Base Joomla utilisée : {joomla_base}")

    # ===== TEST 2 : meta generator dans la page d'accueil =====
    if home_html:
        if VERBOSE:
            print("[VERBOSE]   Test 2 : recherche meta generator Joomla dans le HTML")
        m = re.search(r'<meta name="generator" content="Joomla!([^"]+)"', home_html, re.I)
        if m:
            v_match = re.search(r'(\d+\.\d+\.\d+)', m.group(1))
            if v_match:
                version = v_match.group(1)
                score += 2
                sources.append(f"meta generator Joomla (version {version})")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ meta generator trouvé : version {version} → +2 points")
            else:
                score += 1
                sources.append("meta generator Joomla (pas de version)")
                if VERBOSE:
                    print("[VERBOSE]     ✓ meta generator trouvé mais pas de version → +1 point")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de meta generator Joomla")
    else:
        if VERBOSE:
            print("[VERBOSE]   Test 2 : pas de HTML pour tester meta generator")

    # ===== TEST 3 : /administrator/manifests/files/joomla.xml =====
    url = joomla_base + "/administrator/manifests/files/joomla.xml"
    if VERBOSE:
        print(f"[VERBOSE]   Test 3 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                m = re.search(r'<version>([^<]+)</version>', content)
                if m:
                    version = m.group(1)
                    score += 2
                    sources.append(f"joomla.xml (version {version})")
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                else:
                    m = re.search(r'<extension[^>]*version="([^"]+)"', content)
                    if m:
                        version = m.group(1)
                        score += 2
                        sources.append(f"joomla.xml (version {version})")
                        if VERBOSE:
                            print(f"[VERBOSE]       ✓ version trouvée (extension) : {version} → +2 points")
                    else:
                        score += 1
                        sources.append("joomla.xml existe (pas de version)")
                        if VERBOSE:
                            print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 4 : /language/en-GB/en-GB.xml =====
    if not version:
        url = joomla_base + "/language/en-GB/en-GB.xml"
        if VERBOSE:
            print(f"[VERBOSE]   Test 4 : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                    m = re.search(r'<version>([^<]+)</version>', content)
                    if m:
                        version = m.group(1)
                        score += 2
                        sources.append(f"en-GB.xml (version {version})")
                        if VERBOSE:
                            print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                    else:
                        score += 1
                        sources.append("en-GB.xml existe (pas de version)")
                        if VERBOSE:
                            print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 5 : /libraries/src/Version.php =====
    if not version:
        url = joomla_base + "/libraries/src/Version.php"
        if VERBOSE:
            print(f"[VERBOSE]   Test 5 : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                    m = re.search(r"const\s+RELEASE\s*=\s*'([^']+)'", content)
                    if m:
                        release = m.group(1)
                        m2 = re.search(r"const\s+DEV_LEVEL\s*=\s*'([^']+)'", content)
                        if m2:
                            version = f"{release}.{m2.group(1)}"
                        else:
                            version = release
                        score += 2
                        sources.append(f"Version.php (version {version})")
                        if VERBOSE:
                            print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                    else:
                        score += 1
                        sources.append("Version.php existe (pas de version)")
                        if VERBOSE:
                            print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 6 : /administrator (page de login) =====
    if not version:
        url = joomla_base + "/administrator"
        if VERBOSE:
            print(f"[VERBOSE]   Test 6 : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                    if "Joomla" in content:
                        m = re.search(r'Joomla! (\d+\.\d+\.\d+)', content)
                        if m:
                            version = m.group(1)
                            score += 2
                            sources.append(f"/administrator (login page, version {version})")
                            if VERBOSE:
                                print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                        else:
                            score += 1
                            sources.append("/administrator (login page, contient Joomla)")
                            if VERBOSE:
                                print("[VERBOSE]       ✓ contient Joomla mais pas de version → +1 point")
                    else:
                        if VERBOSE:
                            print("[VERBOSE]     ✗ ne contient pas Joomla")
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 7 : fichiers JS typiques =====
    if VERBOSE:
        print("[VERBOSE]   Test 7 : fichiers JS typiques Joomla")

    for path in ["/media/system/js/core.js", "/media/system/js/mootools-core.js"]:
        url = joomla_base + path
        if VERBOSE:
            print(f"[VERBOSE]     Test : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]       ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    score += 1
                    sources.append(f"{path} existe")
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ code 200, taille {len(content)} → +1 point")
                    break
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]       ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]       ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]       ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]       ✗ erreur : {e}")

    # ===== TEST 8 : headers X-Content-Encoded-By =====
    if VERBOSE:
        print("[VERBOSE]   Test 8 : vérification des headers")
    if home_headers:
        if "x-content-encoded-by" in home_headers:
            if "joomla" in home_headers["x-content-encoded-by"].lower():
                score += 1
                sources.append("X-Content-Encoded-By: Joomla")
                if VERBOSE:
                    print("[VERBOSE]     ✓ X-Content-Encoded-By contient 'joomla' → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ X-Content-Encoded-By présent mais pas 'joomla'")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de X-Content-Encoded-By")

        if "x-generator" in home_headers:
            if "joomla" in home_headers["x-generator"].lower():
                score += 1
                sources.append("X-Generator: Joomla")
                if VERBOSE:
                    print("[VERBOSE]     ✓ X-Generator contient 'joomla' → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ X-Generator présent mais pas 'joomla'")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de X-Generator")
    else:
        if VERBOSE:
            print("[VERBOSE]     ✗ pas de headers disponibles")

    # Bonus si version trouvée
    if version:
        score += 1
        sources.append("version connue (bonus)")
        if VERBOSE:
            print(f"[VERBOSE]   Bonus : version connue → +1 point")

    source = " ; ".join(sources) if sources else "aucun test positif"
    if VERBOSE:
        print(f"[VERBOSE] Score final Joomla : {score}")

    return {'score': score, 'version': version, 'source': source}

def detect_prestashop_score(base, home_html=None, home_headers=None):
    """
    Score de détection PrestaShop.
    Retourne un dict avec score, version, source.
    """
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] --- Scoring PrestaShop ---")

    # ===== TEST 1 : meta generator dans la page d'accueil =====
    if home_html:
        if VERBOSE:
            print("[VERBOSE]   Test 1 : recherche meta generator PrestaShop dans le HTML")
        m = re.search(r'<meta name="generator" content="PrestaShop ([^"]+)"', home_html, re.I)
        if m:
            version = m.group(1)
            score += 2
            sources.append(f"meta generator PrestaShop (version {version})")
            if VERBOSE:
                print(f"[VERBOSE]     ✓ meta generator trouvé : version {version} → +2 points")
        else:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de meta generator PrestaShop")
    else:
        if VERBOSE:
            print("[VERBOSE]   Test 1 : pas de HTML pour tester meta generator")

    # ===== TEST 2 : /classes/Configuration.php =====
    url = base + "/classes/Configuration.php"
    if VERBOSE:
        print(f"[VERBOSE]   Test 2 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                m = re.search(r"_PS_VERSION_\s*=\s*'([^']+)'", content)
                if m:
                    version = m.group(1)
                    score += 2
                    sources.append(f"Configuration.php (version {version})")
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                else:
                    score += 1
                    sources.append("Configuration.php existe (pas de version)")
                    if VERBOSE:
                        print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 3 : /config/defines.inc.php =====
    if not version:
        url = base + "/config/defines.inc.php"
        if VERBOSE:
            print(f"[VERBOSE]   Test 3 : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                    m = re.search(r"_PS_VERSION_\s*=\s*'([^']+)'", content)
                    if m:
                        version = m.group(1)
                        score += 2
                        sources.append(f"defines.inc.php (version {version})")
                        if VERBOSE:
                            print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                    else:
                        score += 1
                        sources.append("defines.inc.php existe (pas de version)")
                        if VERBOSE:
                            print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 4 : /img/logo.jpg =====
    url = base + "/img/logo.jpg"
    if VERBOSE:
        print(f"[VERBOSE]   Test 4 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.content
            # Vérifier si c'est une image ou du HTML (redirection)
            if home_html and len(content) > 100 and isinstance(content, bytes):
                # Comparer les premiers octets avec la page d'accueil
                if content[:100] == home_html[:100].encode():
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil (HTML), ignoré")
                    return
            if len(content) > 100:
                score += 1
                sources.append("/img/logo.jpg existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 5 : /themes/default/img/logo.jpg =====
    url = base + "/themes/default/img/logo.jpg"
    if VERBOSE:
        print(f"[VERBOSE]   Test 5 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.content
            if home_html and len(content) > 100 and isinstance(content, bytes):
                if content[:100] == home_html[:100].encode():
                    if VERBOSE:
                        print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil (HTML), ignoré")
                    return
            if len(content) > 100:
                score += 1
                sources.append("/themes/default/img/logo.jpg existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 6 : headers X-Powered-By =====
    if VERBOSE:
        print("[VERBOSE]   Test 6 : vérification des headers")
    if home_headers and "x-powered-by" in home_headers:
        if "prestashop" in home_headers["x-powered-by"].lower():
            score += 1
            sources.append("X-Powered-By: PrestaShop")
            if VERBOSE:
                print("[VERBOSE]     ✓ X-Powered-By contient 'prestashop' → +1 point")
        else:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ X-Powered-By présent mais pas 'prestashop' : {home_headers['x-powered-by']}")
    else:
        if VERBOSE:
            print("[VERBOSE]     ✗ pas de X-Powered-By")

    # ===== TEST 7 : fichiers JS typiques PrestaShop =====
    if VERBOSE:
        print("[VERBOSE]   Test 7 : fichiers JS typiques")

    for path in ["/js/jquery/jquery-1.7.2.js", "/js/jquery/jquery-1.7.2.min.js", "/js/jquery/jquery-1.11.0.min.js"]:
        url = base + path
        if VERBOSE:
            print(f"[VERBOSE]     Test : {url}")
        try:
            r = get(url)
            if r and r.status_code == 200:
                content = r.text
                if home_html and is_home_redirect(content, home_html):
                    if VERBOSE:
                        print(f"[VERBOSE]       ✗ {url} redirige vers la page d'accueil, ignoré")
                elif len(content) > 100:
                    score += 1
                    sources.append(f"{path} existe")
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ code 200, taille {len(content)} → +1 point")
                    break
                else:
                    if VERBOSE:
                        print(f"[VERBOSE]       ✗ contenu trop court ({len(content)})")
            elif r and r.status_code == 403:
                if VERBOSE:
                    print(f"[VERBOSE]       ✗ {url} -> 403 (ignoré)")
            else:
                code = r.status_code if r else "N/A"
                if VERBOSE:
                    print(f"[VERBOSE]       ✗ code {code}")
        except Exception as e:
            if VERBOSE:
                print(f"[VERBOSE]       ✗ erreur : {e}")

    # ===== TEST 8 : /js/tools.js (fichier PrestaShop) =====
    url = base + "/js/tools.js"
    if VERBOSE:
        print(f"[VERBOSE]   Test 8 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/js/tools.js existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # Bonus si version trouvée
    if version:
        score += 1
        sources.append("version connue (bonus)")
        if VERBOSE:
            print(f"[VERBOSE]   Bonus : version connue → +1 point")

    source = " ; ".join(sources) if sources else "aucun test positif"
    if VERBOSE:
        print(f"[VERBOSE] Score final PrestaShop : {score}")

    return {'score': score, 'version': version, 'source': source}

def detect_magento_score(base, home_html=None, home_headers=None):
    """
    Score de détection Magento (Magento 1 et 2).
    Retourne un dict avec score, version, source.
    """
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] --- Scoring Magento ---")

    # ===== TEST 1 : meta generator dans la page d'accueil =====
    if home_html:
        if VERBOSE:
            print("[VERBOSE]   Test 1 : recherche meta generator Magento dans le HTML")
        m = re.search(r'<meta name="generator" content="Magento ([^"]+)"', home_html, re.I)
        if m:
            version = m.group(1)
            score += 2
            sources.append(f"meta generator Magento (version {version})")
            if VERBOSE:
                print(f"[VERBOSE]     ✓ meta generator trouvé : version {version} → +2 points")
        else:
            m2 = re.search(r'<meta name="generator" content="Magento 2[^"]*"', home_html, re.I)
            if m2:
                v_match = re.search(r'(\d+\.\d+\.\d+)', m2.group(0))
                if v_match:
                    version = v_match.group(1)
                else:
                    version = "2.x"
                score += 2
                sources.append(f"meta generator Magento (version {version})")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ meta generator Magento 2 trouvé : version {version} → +2 points")
            else:
                if VERBOSE:
                    print("[VERBOSE]     ✗ pas de meta generator Magento")
    else:
        if VERBOSE:
            print("[VERBOSE]   Test 1 : pas de HTML pour tester meta generator")

    # ===== TEST 2 : /app/etc/local.xml (Magento 1) =====
    url = base + "/app/etc/local.xml"
    if VERBOSE:
        print(f"[VERBOSE]   Test 2 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                if "<config>" in content and "Magento" in content:
                    score += 2
                    sources.append("/app/etc/local.xml (Magento 1 config)")
                    if VERBOSE:
                        print("[VERBOSE]       ✓ fichier de config Magento 1 détecté → +2 points")
                else:
                    score += 1
                    sources.append("/app/etc/local.xml existe")
                    if VERBOSE:
                        print("[VERBOSE]       ✗ fichier existe mais pas de config Magento → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 3 : /app/etc/env.php (Magento 2) =====
    url = base + "/app/etc/env.php"
    if VERBOSE:
        print(f"[VERBOSE]   Test 3 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                if "Magento" in content or "env.php" in content:
                    score += 2
                    sources.append("/app/etc/env.php (Magento 2 config)")
                    if VERBOSE:
                        print("[VERBOSE]       ✓ fichier de config Magento 2 détecté → +2 points")
                else:
                    score += 1
                    sources.append("/app/etc/env.php existe")
                    if VERBOSE:
                        print("[VERBOSE]       ✗ fichier existe mais pas de contenu Magento → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 4 : /js/varien/js.js (Magento 1) =====
    url = base + "/js/varien/js.js"
    if VERBOSE:
        print(f"[VERBOSE]   Test 4 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/js/varien/js.js existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 5 : /pub/static/_requirejs/frontend/Magento/luma/en_US/js/require.js (Magento 2) =====
    url = base + "/pub/static/_requirejs/frontend/Magento/luma/en_US/js/require.js"
    if VERBOSE:
        print(f"[VERBOSE]   Test 5 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/pub/static/_requirejs/.../require.js (Magento 2)")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 6 : /skin/frontend/default/default/css/styles.css (Magento 1) =====
    url = base + "/skin/frontend/default/default/css/styles.css"
    if VERBOSE:
        print(f"[VERBOSE]   Test 6 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/skin/frontend/default/default/css/styles.css existe")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 7 : /pub/static/frontend/Magento/luma/en_US/css/styles-l.css (Magento 2) =====
    url = base + "/pub/static/frontend/Magento/luma/en_US/css/styles-l.css"
    if VERBOSE:
        print(f"[VERBOSE]   Test 7 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100:
                score += 1
                sources.append("/pub/static/frontend/Magento/luma/.../styles-l.css (Magento 2)")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)} → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 8 : headers X-Magento-* =====
    if VERBOSE:
        print("[VERBOSE]   Test 8 : vérification des headers Magento")
    if home_headers:
        found_magento_header = False
        for h in home_headers:
            if "x-magento" in h.lower():
                score += 1
                sources.append(f"Header {h} présent")
                found_magento_header = True
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ header {h} présent → +1 point")
                break
        if not found_magento_header:
            if VERBOSE:
                print("[VERBOSE]     ✗ pas de header X-Magento-*")
    else:
        if VERBOSE:
            print("[VERBOSE]     ✗ pas de headers disponibles")

    # ===== TEST 9 : /Magento/Version (si accessible) =====
    url = base + "/Magento/Version"
    if VERBOSE:
        print(f"[VERBOSE]   Test 9 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 10:
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, taille {len(content)}")
                m = re.search(r'(\d+\.\d+\.\d+)', content)
                if m:
                    version = m.group(1)
                    score += 2
                    sources.append(f"/Magento/Version (version {version})")
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ version trouvée : {version} → +2 points")
                else:
                    score += 1
                    sources.append("/Magento/Version existe (pas de version)")
                    if VERBOSE:
                        print("[VERBOSE]       ✗ pas de version trouvée, mais fichier existe → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # Bonus si version trouvée
    if version:
        score += 1
        sources.append("version connue (bonus)")
        if VERBOSE:
            print(f"[VERBOSE]   Bonus : version connue → +1 point")

    source = " ; ".join(sources) if sources else "aucun test positif"
    if VERBOSE:
        print(f"[VERBOSE] Score final Magento : {score}")

    return {'score': score, 'version': version, 'source': source}

def detect_wordpress_score(base, home_html=None, home_headers=None):
    """
    Détection WordPress.
    Retourne un dict avec score, version, source.
    """
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] ═══ Scoring WordPress ═══")
        print(f"[VERBOSE] Cible : {base}")

    # ===== TEST 0 : Extraction de la version depuis meta generator et assets =====
    if home_html:
        # 1. Meta generator
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', home_html, re.I)
        if m:
            version = m.group(1)
            sources.append(f"meta generator: {version}")
            score += 2
            if VERBOSE:
                print(f"[VERBOSE]   Version extraite depuis meta generator: {version} → +2 points")
        else:
            # 2. Fallback assets (ver=) : uniquement ceux du core
            pattern = r'(?:href|src)=["\'](?:[^"\']*/(wp-includes|wp-admin)/[^"\']*)\?ver=([\d.]+)["\']'
            matches = re.findall(pattern, home_html, re.I)
            if matches:
                from collections import Counter
                versions = [v for _, v in matches]
                if versions:
                    v = Counter(versions).most_common(1)[0][0]
                    if re.match(r'\d+\.\d+(\.\d+)?', v):
                        version = v
                        sources.append(f"assets core ver: {version}")
                        score += 2
                        if VERBOSE:
                            print(f"[VERBOSE]   Version extraite depuis assets core: {version} → +2 points")

    # ===== TEST 1 : /wp-login.php =====
    url = base + "/wp-login.php"
    if VERBOSE:
        print(f"[VERBOSE]   Test 1 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100 and "wordpress" in content.lower():
                score += 2
                sources.append(f"{url} (contient 'wordpress')")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, contient 'wordpress' (taille {len(content)}) → +2 points")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code 200 mais contenu vide ou sans 'wordpress'")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 2 : /readme.html =====
    url = base + "/readme.html"
    if VERBOSE:
        print(f"[VERBOSE]   Test 2 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 100 and "WordPress" in content:
                score += 1
                sources.append(f"{url} (contient 'WordPress')")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ code 200, contient 'WordPress' → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ code 200 mais pas de 'WordPress'")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 3 : /wp-includes/version.php =====
    url = base + "/wp-includes/version.php"
    if VERBOSE:
        print(f"[VERBOSE]   Test 3 : {url}")
    try:
        r = get(url)
        if r and r.status_code == 200:
            content = r.text
            if home_html and is_home_redirect(content, home_html):
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ {url} redirige vers la page d'accueil, ignoré")
            elif len(content) > 50:
                m = re.search(r"\$wp_version\s*=\s*'([\d.]+)'", content)
                if m:
                    version = m.group(1)  # priorité à cette version si elle est plus précise
                    score += 2
                    sources.append(f"{url} (version extraite {version})")
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ version extraite : {version} → +2 points")
                else:
                    score += 1
                    sources.append(f"{url} existe (pas de version)")
                    if VERBOSE:
                        print(f"[VERBOSE]     ✓ fichier existe, pas de version → +1 point")
            else:
                if VERBOSE:
                    print(f"[VERBOSE]     ✗ contenu trop court ({len(content)})")
        elif r and r.status_code == 403:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ {url} -> 403 (ignoré)")
        else:
            code = r.status_code if r else "N/A"
            if VERBOSE:
                print(f"[VERBOSE]     ✗ code {code}")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE]     ✗ erreur : {e}")

    # ===== TEST 4 : headers X-Powered-By =====
    if VERBOSE:
        print("[VERBOSE]   Test 4 : Headers X-Powered-By")
    if home_headers and "x-powered-by" in home_headers:
        if "wordpress" in home_headers["x-powered-by"].lower():
            score += 1
            sources.append("X-Powered-By: WordPress")
            if VERBOSE:
                print(f"[VERBOSE]     ✓ contient 'wordpress' → +1 point")
        else:
            if VERBOSE:
                print(f"[VERBOSE]     ✗ présent mais pas 'wordpress' : {home_headers['x-powered-by']}")
    else:
        if VERBOSE:
            print("[VERBOSE]     ✗ absent")

    # ===== TEST 5 : signaux HTML (UNIQUEMENT INTERNES) =====
    if VERBOSE:
        print("[VERBOSE]   Test 5 : Signaux HTML (seulement internes)")

    target_domain = urlparse(base).netloc
    if target_domain.startswith("www."):
        target_domain = target_domain[4:]
    if VERBOSE:
        print(f"[VERBOSE]     Domaine cible (sans www) : {target_domain}")

    internal_found = 0
    external_found = 0

    if home_html:
        signals = ["/wp-content/", "/wp-includes/", "wp-json"]
        for sig in signals:
            pos = 0
            while True:
                idx = home_html.lower().find(sig, pos)
                if idx == -1:
                    break
                start = max(0, idx - 80)
                end = min(len(home_html), idx + len(sig) + 80)
                context = home_html[start:end]
                url_match = re.search(r'(https?://[^\s"\']+)', context)
                if url_match:
                    full_url = url_match.group(1)
                    url_domain = urlparse(full_url).netloc
                    if url_domain.startswith("www."):
                        url_domain = url_domain[4:]
                    if url_domain and url_domain == target_domain:
                        internal_found += 1
                        if VERBOSE:
                            print(f"[VERBOSE]       ✓ Occurrence de '{sig}' → URL interne : {full_url}")
                    else:
                        external_found += 1
                        if VERBOSE:
                            print(f"[VERBOSE]       ✗ Occurrence de '{sig}' → URL externe ignorée : {full_url}")
                else:
                    internal_found += 1
                    if VERBOSE:
                        print(f"[VERBOSE]       ✓ Occurrence de '{sig}' → pas d'URL, considérée interne")
                pos = idx + len(sig)

        if VERBOSE:
            print(f"[VERBOSE]     Résultat : {internal_found} interne(s), {external_found} externe(s) ignorée(s)")

        if internal_found >= 2:
            score += internal_found
            sources.append(f"{internal_found} signaux HTML internes (+{internal_found} points)")
            if VERBOSE:
                print(f"[VERBOSE]   +{internal_found} points pour {internal_found} signaux internes")
        elif internal_found == 1:
            score += 1
            sources.append(f"1 signal HTML interne")
            if VERBOSE:
                print(f"[VERBOSE]   +1 point : 1 signal interne")
    else:
        if VERBOSE:
            print("[VERBOSE]     ✗ pas de HTML")

    # Bonus version
    if version:
        score += 1
        sources.append("version connue (bonus)")
        if VERBOSE:
            print(f"[VERBOSE]   Bonus +1 point pour version connue")

    source = " ; ".join(sources) if sources else "aucun test positif"
    if VERBOSE:
        print(f"[VERBOSE]   Score final : {score}")
        print("[VERBOSE] ═══ Fin scoring WordPress ═══")

    return {'score': score, 'version': version, 'source': source}


import re
import json

def detect_shopify_score(base, home_html=None, home_headers=None, verbose=False):
    """
    Score de détection Shopify basé sur l'analyse du HTML et des en-têtes.
    Retourne un dict avec score, version, source.
    """
    score = 0
    version = None
    sources = []
    total_indicators = 0

    if verbose:
        print("[VERBOSE] --- Scoring Shopify ---")

    if not home_html:
        if verbose:
            print("[VERBOSE]   Pas de HTML fourni, score=0")
        return {'score': 0, 'version': None, 'source': 'pas de HTML'}

    html = home_html.lower()

    # -------- INDICATEURS STRUCTURELS (forts) --------
    strong_indicators = [
        (r'<meta name="shopify-checkout-api-token"', "meta checkout token"),
        (r'<meta name="shopify-digital-wallet"', "meta digital wallet"),
        (r'window\.Shopify\s*=', "objet global Shopify"),
        (r'cdn\.shopify\.com', "CDN Shopify"),
        (r'cdn\.shopifycloud\.com', "CDN Shopify Cloud"),
        (r'myshopify\.com', "domaine myshopify.com"),
        (r'shopify\.shop', "domaine shopify.shop"),
        (r'<link rel="canonical"[^>]*myshopify\.com', "canonique myshopify"),
        (r'"shopify"', "mot-clé shopify dans un attribut ou contenu"),
    ]

    for pattern, label in strong_indicators:
        if re.search(pattern, html, re.I):
            score += 2
            sources.append(label)
            total_indicators += 1
            if verbose:
                print(f"[VERBOSE]   ✓ {label} → +2 points")

    # -------- INDICATEURS SCRIPT (fréquents) --------
    script_sources = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', home_html, re.I)
    shopify_script_count = 0
    for src in script_sources:
        if 'shopify' in src.lower() or 'shopifycloud' in src.lower() or 'cdn.shopify.com' in src.lower():
            shopify_script_count += 1
    if shopify_script_count >= 3:
        score += 3
        sources.append(f"{shopify_script_count} scripts Shopify")
        if verbose:
            print(f"[VERBOSE]   ✓ {shopify_script_count} scripts Shopify → +3 points")
    elif shopify_script_count >= 1:
        score += 1
        sources.append(f"{shopify_script_count} script(s) Shopify")
        if verbose:
            print(f"[VERBOSE]   ✓ {shopify_script_count} script(s) Shopify → +1 point")

    # -------- INDICATEURS DE CSS/CLASSES --------
    class_patterns = ['shopify-section', 'shopify-payment-button', 'product-form', 'cart-drawer']
    found_classes = [p for p in class_patterns if p in html]
    if found_classes:
        score += len(found_classes)
        sources.append(f"classes Shopify: {', '.join(found_classes)}")
        if verbose:
            print(f"[VERBOSE]   ✓ classes Shopify trouvées ({len(found_classes)}) → +{len(found_classes)} points")

    # -------- INDICATEURS DE META (autres) --------
    meta_patterns = [
        (r'<meta name="google-site-verification"', "meta google verification"),
        (r'<meta name="shopify"', "meta shopify"),
        (r'<link rel="alternate" hreflang="[^"]*" href="[^"]*myshopify\.com', "alternate myshopify"),
    ]
    for pattern, label in meta_patterns:
        if re.search(pattern, html, re.I):
            score += 1
            sources.append(label)
            if verbose:
                print(f"[VERBOSE]   ✓ {label} → +1 point")

    # -------- DÉTECTION DE VERSION --------
    # via header
    if home_headers and 'x-shopify-version' in home_headers:
        version = home_headers['x-shopify-version']
        score += 1
        sources.append(f"version header: {version}")
        if verbose:
            print(f"[VERBOSE]   ✓ version depuis header ({version}) → +1 point")
    else:
        # via JS
        m = re.search(r'Shopify\.version\s*=\s*["\']([\d.]+)["\']', home_html, re.I)
        if m:
            version = m.group(1)
            score += 1
            sources.append(f"version JS: {version}")
            if verbose:
                print(f"[VERBOSE]   ✓ version depuis JS ({version}) → +1 point")

        # via données JSON dans script
        m = re.search(r'<script[^>]*type="application/json"[^>]*>.*?"version":\s*"([\d.]+)".*?</script>', home_html, re.I)
        if m and not version:
            version = m.group(1)
            score += 1
            sources.append(f"version JSON: {version}")
            if verbose:
                print(f"[VERBOSE]   ✓ version depuis JSON ({version}) → +1 point")

    # -------- BONUS SI BEAUCOUP D'INDICATEURS --------
    if total_indicators >= 5:
        score += 2
        sources.append("bonus pour nombreux indicateurs")
        if verbose:
            print("[VERBOSE]   Bonus +2 points pour 5+ indicateurs")
    elif total_indicators >= 3:
        score += 1
        sources.append("bonus pour indicateurs modérés")
        if verbose:
            print("[VERBOSE]   Bonus +1 point pour 3+ indicateurs")

    # -------- SEUIL MINIMUM POUR ÉVITER LES FAUX POSITIFS --------
    # Si le score est < 2, on le met à 0 pour être sûr
    if score < 2:
        score = 0
        sources = ["aucun indicateur fiable"]

    if verbose:
        print(f"[VERBOSE] Score final Shopify : {score}")

    return {
        'score': score,
        'version': version,
        'source': ' ; '.join(sources) if sources else 'aucun test positif'
    }

def detect_typo3_score(base, home_html=None, home_headers=None):
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] --- Scoring TYPO3 ---")

    # 1. Meta generator
    if home_html:
        m = re.search(r'<meta name="generator" content="TYPO3 CMS(?:[\s]+([\d.]+))?"', home_html, re.I)
        if m:
            if m.group(1):
                version = m.group(1)
                score += 2
                sources.append(f"meta generator TYPO3 (version {version})")
            else:
                score += 2
                sources.append("meta generator TYPO3 (pas de version)")
            if VERBOSE:
                print(f"[VERBOSE]   ✓ meta generator TYPO3 → +2 points" + (f" (version {version})" if version else ""))

    # 2. Chemins typiques /typo3conf/ext/
    if home_html:
        count_ext = len(re.findall(r'/typo3conf/ext/[^/]+/', home_html, re.I))
        if count_ext > 0:
            points = min(count_ext, 3)  # max 3 points
            score += points
            sources.append(f"{count_ext} occurrences de /typo3conf/ext/ (+{points} points)")
            if VERBOSE:
                print(f"[VERBOSE]   ✓ {count_ext} occurrences de /typo3conf/ext/ → +{points} points")

    # 3. Chemins /typo3temp/assets/compressed/
    if home_html:
        count_temp = len(re.findall(r'/typo3temp/assets/compressed/', home_html, re.I))
        if count_temp > 0:
            score += 1
            sources.append(f"{count_temp} occurrences de /typo3temp/assets/compressed/ (+1 point)")
            if VERBOSE:
                print(f"[VERBOSE]   ✓ {count_temp} occurrences de /typo3temp/assets/compressed/ → +1 point")

    # 4. Commentaires TYPO3SEARCH
    if home_html:
        if re.search(r'<!--TYPO3SEARCH_begin-->', home_html, re.I):
            score += 1
            sources.append("commentaire TYPO3SEARCH_begin/end (+1 point)")
            if VERBOSE:
                print("[VERBOSE]   ✓ commentaires TYPO3SEARCH → +1 point")

    # 5. Headers X-TYPO3-*
    if home_headers:
        found_typo3_header = False
        for h in home_headers:
            if h.lower().startswith('x-typo3-'):
                score += 1
                sources.append(f"header {h} (+1 point)")
                found_typo3_header = True
                if VERBOSE:
                    print(f"[VERBOSE]   ✓ header {h} présent → +1 point")
                break
        if not found_typo3_header and VERBOSE:
            print("[VERBOSE]   ✗ pas de header X-TYPO3-*")

    # 6. Classes CSS spécifiques (ex: bloc--, js-animation--, tns-)
    if home_html:
        typo3_classes = ['bloc--services', 'js-animation--scroll', 'tns-controls']
        found = [c for c in typo3_classes if c in home_html.lower()]
        if len(found) >= 2:
            score += 1
            sources.append(f"classes TYPO3: {', '.join(found)} (+1 point)")
            if VERBOSE:
                print(f"[VERBOSE]   ✓ classes TYPO3 trouvées ({', '.join(found)}) → +1 point")

    # Bonus version
    if version:
        score += 1
        sources.append("version connue (bonus)")
        if VERBOSE:
            print("[VERBOSE]   Bonus +1 point pour version connue")

    source = " ; ".join(sources) if sources else "aucun test positif"
    if VERBOSE:
        print(f"[VERBOSE] Score final TYPO3 : {score}")

    return {'score': score, 'version': version, 'source': source}


def detect_opencart_score(base, home_html=None, home_headers=None):
    """
    Score de détection OpenCart avec logs des requêtes HTTP via lib.http.get().
    """
    score = 0
    version = None
    sources = []

    if VERBOSE:
        print("[VERBOSE] --- Scoring OpenCart ---")

    if not home_html:
        if VERBOSE:
            print("[VERBOSE]   Pas de HTML fourni")
        return {'score': 0, 'version': None, 'source': 'pas de HTML'}

    html = home_html.lower()

    # 1. Meta generator
    m = re.search(r'<meta name="generator" content="OpenCart(?:[\s]+([\d.]+))?"', home_html, re.I)
    if m:
        if m.group(1):
            version = m.group(1)
            score += 2
            sources.append(f"meta generator (version {version})")
            if VERBOSE:
                print(f"[VERBOSE]   ✓ meta generator → +2 (version {version})")
        else:
            score += 2
            sources.append("meta generator (pas de version)")
            if VERBOSE:
                print("[VERBOSE]   ✓ meta generator → +2")

    # 2. Chemins /catalog/ ou /image/
    if '/catalog/view/' in html or '/image/' in html:
        score += 2
        sources.append("/catalog/ ou /image/")
        if VERBOSE:
            print("[VERBOSE]   ✓ /catalog/ ou /image/ → +2")

    # 3. Routes OpenCart
    if 'route=common/home' in html or 'route=product/category' in html or 'route=product/product' in html:
        score += 2
        sources.append("routes OpenCart")
        if VERBOSE:
            print("[VERBOSE]   ✓ routes OpenCart → +2")

    # 4. Classes CSS typiques
    opencart_classes = ['product-layout', 'product-grid', 'product-list', 'btn-cart', 'cart-total']
    found = [c for c in opencart_classes if c in html]
    if len(found) >= 2:
        score += 2
        sources.append(f"classes: {', '.join(found)}")
        if VERBOSE:
            print(f"[VERBOSE]   ✓ classes OpenCart → +2")
    elif len(found) == 1:
        score += 1
        sources.append(f"classe: {found[0]}")
        if VERBOSE:
            print(f"[VERBOSE]   ✓ classe OpenCart → +1")

    # 5. Footer "Powered by OpenCart"
    if 'powered by opencart' in html or 'opencart' in html:
        score += 2
        sources.append("Powered by OpenCart")
        if VERBOSE:
            print("[VERBOSE]   ✓ 'Powered by OpenCart' → +2")

    # 6. Requêtes HTTP avec lib.http.get (logs intégrés)
    # 6.1 /admin/index.php
    url_admin = base + "/admin/index.php"
    if VERBOSE:
        print(f"[VERBOSE]   HTTP GET: {url_admin}")
    r_admin = get(url_admin)
    if r_admin:
        if VERBOSE:
            print(f"[VERBOSE]     → {r_admin.status_code}")
        if r_admin.status_code == 200 and ("OpenCart" in r_admin.text or "Administration" in r_admin.text):
            score += 2
            sources.append("/admin/index.php (200, contient OpenCart)")
            if VERBOSE:
                print("[VERBOSE]     ✓ +2 (contient OpenCart)")
        elif r_admin.status_code == 200:
            score += 1
            sources.append("/admin/index.php (200, sans signature)")
            if VERBOSE:
                print("[VERBOSE]     ✓ +1 (200)")
        elif r_admin.status_code == 403:
            score += 1
            sources.append("/admin/index.php (403)")
            if VERBOSE:
                print("[VERBOSE]     ✓ +1 (403)")
    elif VERBOSE:
        print("[VERBOSE]     ✗ requête échouée (None)")

    # 6.2 /system/startup.php
    url_startup = base + "/system/startup.php"
    if VERBOSE:
        print(f"[VERBOSE]   HTTP GET: {url_startup}")
    r_startup = get(url_startup)
    if r_startup:
        if VERBOSE:
            print(f"[VERBOSE]     → {r_startup.status_code}")
        if r_startup.status_code == 200:
            m = re.search(r"define\s*\(\s*'VERSION'\s*,\s*'([\d.]+)'\s*\)", r_startup.text)
            if m:
                version = m.group(1)
                score += 2
                sources.append(f"/system/startup.php (version {version})")
                if VERBOSE:
                    print(f"[VERBOSE]     ✓ +2 (version {version})")
            else:
                score += 1
                sources.append("/system/startup.php (200)")
                if VERBOSE:
                    print("[VERBOSE]     ✓ +1 (200)")
    elif VERBOSE:
        print("[VERBOSE]     ✗ requête échouée (None)")

    # 6.3 /install/
    url_install = base + "/install/"
    if VERBOSE:
        print(f"[VERBOSE]   HTTP GET: {url_install}")
    r_install = get(url_install)
    if r_install:
        if VERBOSE:
            print(f"[VERBOSE]     → {r_install.status_code}")
        if r_install.status_code == 200:
            score += 1
            sources.append("/install/ accessible")
            if VERBOSE:
                print("[VERBOSE]     ✓ +1")
    elif VERBOSE:
        print("[VERBOSE]     ✗ requête échouée (None)")

    # 6.4 /config.php
    url_config = base + "/config.php"
    if VERBOSE:
        print(f"[VERBOSE]   HTTP GET: {url_config}")
    r_config = get(url_config)
    if r_config:
        if VERBOSE:
            print(f"[VERBOSE]     → {r_config.status_code}")
        if r_config.status_code == 200:
            score += 2
            sources.append("/config.php (200)")
            if VERBOSE:
                print("[VERBOSE]     ✓ +2")
        elif r_config.status_code == 403:
            score += 1
            sources.append("/config.php (403)")
            if VERBOSE:
                print("[VERBOSE]     ✓ +1")
    elif VERBOSE:
        print("[VERBOSE]     ✗ requête échouée (None)")

    # 7. Détection de version depuis les assets
    versions = re.findall(r'[?&]v=([\d.]+)', home_html)
    if versions:
        from collections import Counter
        v = Counter(versions).most_common(1)[0][0]
        if re.match(r'\d+\.\d+\.\d+', v):
            if not version:
                version = v
            score += 1
            sources.append(f"version assets: {v}")
            if VERBOSE:
                print(f"[VERBOSE]   ✓ version depuis assets: {v} → +1")

    # Bonus version
    if version:
        score += 1
        sources.append("bonus version")
        if VERBOSE:
            print("[VERBOSE]   Bonus +1 point pour version")

    source = " ; ".join(sources) if sources else "aucun test"
    if VERBOSE:
        print(f"[VERBOSE] Score final OpenCart : {score}")

    return {'score': score, 'version': version, 'source': source}
    

# ──────────────────────────────────────────────────────────────
# 4. DÉTECTION GÉNÉRIQUE (priorité WordPress sans Playwright)
# ──────────────────────────────────────────────────────────────
def detect_cms(base):
    """
    Détecte tous les CMS présents sur la cible via scoring.
    """
    if VERBOSE:
        print(f"[VERBOSE] detect_cms: appelée pour {base}")

    # ─── UTILISER get_html AU LIEU DE get ───
    home_html = None
    home_headers = {}
    try:
        html, headers = get_html(base, max_retries=3, timeout=8)  # <-- ICI
        if html and len(html.strip()) > 100:
            home_html = html
            home_headers = headers or {}
            if VERBOSE:
                print(f"[VERBOSE] Page d'accueil récupérée via get_html ({len(home_html)} caractères)")
        else:
            if VERBOSE:
                print(f"[VERBOSE] Page d'accueil trop courte ou vide (get_html a retourné {len(html) if html else 0} caractères)")
    except Exception as e:
        if VERBOSE:
            print(f"[VERBOSE] Erreur récupération page d'accueil avec get_html : {e}")

    # === ARRÊT IMMÉDIAT SI PAS DE HTML ===
    if not home_html:
        if VERBOSE:
            print("[VERBOSE] Pas de HTML récupéré, aucun CMS détecté")
        return []

    # ... (le reste de la fonction ne change pas)
    SEUIL = 3
    detected = []

    detectors = [
        ("wordpress", detect_wordpress_score),
        ("drupal", detect_drupal_score),
        ("joomla", detect_joomla_score),
        ("prestashop", detect_prestashop_score),
        ("magento", detect_magento_score),
        ("shopify", detect_shopify_score),
        ("typo3", detect_typo3_score),
        ("opencart", detect_opencart_score),
    ]

    results = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_name = {
            executor.submit(detector, base, home_html, home_headers): name
            for name, detector in detectors
        }
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                if result is None:
                    results[name] = {'score': 0, 'version': None, 'source': ''}
                else:
                    results[name] = result
            except Exception as e:
                if VERBOSE:
                    print(f"[VERBOSE] Erreur pour {name} : {e}")
                results[name] = {'score': 0, 'version': None, 'source': ''}

    for name, result in results.items():
        if result['score'] >= SEUIL:
            version = result['version']
            # Pour WordPress, on utilise _extract_wp_version comme source fiable
            if name == "wordpress":
                version = _extract_wp_version(base)
                if VERBOSE:
                    print(f"[VERBOSE] ✅ {name.capitalize()} détecté (score {result['score']}, version '{version}') via {result['source']} (scoring version was '{result['version']}')")
            else:
                if VERBOSE:
                    print(f"[VERBOSE] ✅ {name.capitalize()} détecté (score {result['score']}, version '{version}') via {result['source']}")
            detected.append({
                'cms': name,
                'version': version,
                'html': home_html or "",
                'resp_headers': home_headers or {},
                'source': result['source'],
                'score': result['score']
            })
    unique = {}
    for d in detected:
        cms = d['cms']
        if cms not in unique or d['score'] > unique[cms]['score']:
            unique[cms] = d
    detected = list(unique.values())

    if VERBOSE:
        if detected:
            print(f"[VERBOSE] CMS détectés au total : {', '.join([d['cms'] for d in detected])}")
        else:
            print("[VERBOSE] Aucun CMS reconnu détecté (score < seuil)")

    return detected

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
    cms_list = detect_cms(base)

    if not cms_list:
        warn("No CMS detected or supported")
        return

    # Afficher la liste des CMS détectés (sans version, elle sera affichée après le scan)
    for idx, cms_info in enumerate(cms_list):
        cms = cms_info['cms']
        score = cms_info.get('score', '?')
        print(f"  [{idx+1}] CMS     : {cms.capitalize()} (score {score})")
    # ------------------------------------------------------------
    # 1. On prépare des variables pour cumuler les infos
    # ------------------------------------------------------------
    all_vulns = []
    all_headers_issues = []
    all_authors = []
    all_emails = []
    all_paths = []
    first_cms = True
    meta = {}          # pour stocker les meta extraites
    headers_issues = []  # pour les headers

    # ------------------------------------------------------------
    # 2. Boucle sur chaque CMS détecté
    # ------------------------------------------------------------
    for cms_info in cms_list:
        cms = cms_info['cms']
        print(f"\n{C.CYAN}{C.BOLD}── Scanning {cms.capitalize()} ──{C.RST}")

        # ==== Meta et Headers : une seule fois (pour le premier CMS) ====
        if first_cms:
            section("Meta / Site Info")
            meta = extract_meta(base, cms_info.get("html", ""))
            if meta["title"]:       print(f"  Title       : {meta['title']}")
            if meta["description"]: print(f"  Description : {meta['description']}")
            if meta["emails"]:
                print(f"  {C.ORANGE}Emails : {', '.join(meta['emails'][:5])}{C.RST}")
                all_emails = meta.get("emails", [])
            if meta.get("authors"):
                all_authors = meta.get("authors", [])

            section("Security Headers")
            headers_issues = audit_headers(cms_info.get("resp_headers", {}))
            all_headers_issues = headers_issues
            if not headers_issues:
                ok("All key security headers present")
            else:
                for h in headers_issues:
                    col = sev_color(h["severity"])
                    print(f"  {col}[{h['severity']}]{C.RST} {h['issue']}  {C.DIM}({h['header']}){C.RST}")
                display_headers_info(cms_info.get("resp_headers", {}))
            first_cms = False

        # ==== Lancer le module spécifique ====
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
        elif cms == "magento":
            from modules.magento import MagentoModule
            module = MagentoModule(base, cms_info)
            result = module.scan()
        elif cms == "shopify":
            from modules.shopify import ShopifyModule
            module = ShopifyModule(base, cms_info)
            result = module.scan()
        elif cms == "typo3":
            from modules.typo3 import Typo3Module
            module = Typo3Module(base, cms_info)
            result = module.scan()
        elif cms == "opencart":
            from modules.opencart import OpenCartModule
            module = OpenCartModule(base, cms_info)
            result = module.scan()

        else:
            warn(f"Module for {cms} not available")
            continue

        # ==== ON MET À JOUR LA VERSION DANS cms_info POUR LE SUMMARY ====
        if result.version:
            cms_info['version'] = result.version   # <--- AJOUTE CETTE LIGNE

        # ==== ON INJECTE TOUTES LES INFOS DANS result ====
        result.emails = all_emails
        result.headers = headers_issues
        result.authors = all_authors
        # On cumule aussi les paths si le module en a trouvé
        if result.paths:
            all_paths.extend(result.paths)
        else:
            result.paths = []   # pour éviter None

        # Cumul des vulnérabilités
        all_vulns.extend(result.vulns)

    # ------------------------------------------------------------
    # 3. Résumé global
    # ------------------------------------------------------------
    print(f"\n{C.CYAN}{C.BOLD}{'─'*66}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}  SUMMARY — {base}{C.RST}")
    print(f"{C.CYAN}{C.BOLD}{'─'*66}{C.RST}")

    crit = [v for v in all_vulns if v.severity in ("CRITICAL","HIGH")]
    med  = [v for v in all_vulns if v.severity == "MEDIUM"]
    low  = [v for v in all_vulns if v.severity == "LOW"]

    print(f"  {C.RED}Critical/High vulns : {len(crit)}{C.RST}")
    print(f"  {C.ORANGE}Medium vulns        : {len(med)}{C.RST}")
    print(f"  {C.YELLOW}Low vulns           : {len(low)}{C.RST}")
    print(f"  {C.ORANGE}Header issues       : {len(all_headers_issues)}{C.RST}")
    print(f"  {C.CYAN}Authors             : {len(all_authors)}{C.RST}")
    print(f"  {C.CYAN}Emails              : {len(all_emails)}{C.RST}")
    print(f"  {C.CYAN}Exposed paths       : {len(all_paths)}{C.RST}")

    # Affichage des versions
    version_str = ", ".join([f"{d['cms']} ({d['version'] or '?'})" for d in cms_list])
    print(f"  {C.GREEN}Detected CMS versions : {version_str}{C.RST}")

    # ------------------------------------------------------------
    # 4. Export CSV combiné (avec TOUTES les données)
    # ------------------------------------------------------------
    class CombinedResult:
        def __init__(self, vulns, cms_list, authors, emails, paths, headers):
            self.vulns = vulns
            self.cms = "multiple"
            self.version = ", ".join([f"{d['cms']} {d['version'] or '?'}" for d in cms_list])
            self.authors = authors
            self.emails = emails
            self.paths = paths
            self.headers = headers
            self.target = base

    combined = CombinedResult(
        vulns=all_vulns,
        cms_list=cms_list,
        authors=all_authors,
        emails=all_emails,
        paths=all_paths,
        headers=all_headers_issues
    )
    export_csv(combined, csv_out)
    print(f"{C.DIM}→ Results appended to {csv_out}{C.RST}")
    print("")
    

def main():
    parser = argparse.ArgumentParser(description="CMScan — Unified CMS Scanner")
    parser.add_argument("-L", metavar="TARGET", required=False, help="Target URL or file with list of URLs (e.g. sites.txt)")
    parser.add_argument("-o", "--output", help="CSV output file (ignored if -L is a file, uses auto-generated names)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("--update", action="store_true", help="Update vulnerability databases")
    args = parser.parse_args()

    global VERBOSE
    if args.verbose:
        VERBOSE = True

    import lib.http
    import random
    lib.http.FIXED_UA = random.choice(lib.http.USER_AGENTS)
    import lib.paths
    import modules.wordpress
    lib.paths.VERBOSE = VERBOSE
    modules.wordpress.VERBOSE = VERBOSE

    auto_update()
    
    if needs_wp_vuln_update():
        update_wordpress_vuln_db()
    
    if args.update:
        print("[*] Updating vulnerability databases...")
        update_wordpress_vuln_db()
        update_friendsofphp_db()
        sys.exit(0)

    if not args.L:
        parser.print_help()
        sys.exit(1)

    # ===== GESTION DU FICHIER =====
    from lib.csv_export import generate_csv_filename

    target_input = args.L
    if not os.path.isfile(target_input):
        # essai relatif au script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, target_input)
        if os.path.isfile(alt_path):
            target_input = alt_path
            print(f"[DEBUG] trouvé via alt_path = '{alt_path}'")

    if os.path.isfile(target_input):
        print("file found")
        with open(target_input, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        if not targets:
            warn("No targets found in file.")
            sys.exit(1)
        for target in targets:
            csv_out = generate_csv_filename(target)
            scan(target, csv_out)
    else:
        # C'est une URL unique
        if args.output:
            csv_out = args.output
        else:
            csv_out = generate_csv_filename(target_input)
        scan(target_input, csv_out)

if __name__ == "__main__":
    main()