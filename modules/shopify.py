import re
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.colors import C, ok, warn, section, print_vuln
from lib.http import get
from lib.paths import check_paths, SHOPIFY_SENSITIVE_PATHS
from modules.base import BaseModule, Vuln

# ============================================================
# 1. FONCTION DE DÉTECTION (déjà existante, améliorée)
# ============================================================
def detect_shopify_score(base, home_html=None, home_headers=None, verbose=False):
    score = 0
    version = None
    sources = []
    total_indicators = 0

    if verbose:
        print("[VERBOSE] --- Scoring Shopify ---")

    if home_html is None:
        try:
            if verbose:
                print("[VERBOSE]   Récupération de la page /")
            response = requests.get(base, timeout=10, verify=False)
            home_html = response.text
            home_headers = response.headers
        except Exception as e:
            if verbose:
                print(f"[VERBOSE]   Erreur fetch: {e}")
            return {'score': 0, 'version': None, 'source': 'fetch error'}

    if not home_html:
        return {'score': 0, 'version': None, 'source': 'pas de HTML'}

    html = home_html.lower()

    strong_indicators = [
        (r'<meta name="shopify-checkout-api-token"', "meta checkout token"),
        (r'<meta name="shopify-digital-wallet"', "meta digital wallet"),
        (r'window\.Shopify\s*=', "objet global Shopify"),
        (r'cdn\.shopify\.com', "CDN Shopify"),
        (r'cdn\.shopifycloud\.com', "CDN Shopify Cloud"),
        (r'myshopify\.com', "domaine myshopify.com"),
        (r'shopify\.shop', "domaine shopify.shop"),
        (r'<link rel="canonical"[^>]*myshopify\.com', "canonique myshopify"),
        (r'"shopify"', "mot-clé shopify"),
    ]

    for pattern, label in strong_indicators:
        if re.search(pattern, html, re.I):
            score += 2
            sources.append(label)
            total_indicators += 1
            if verbose:
                print(f"[VERBOSE]   ✓ {label} → +2 points")

    script_sources = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', home_html, re.I)
    shopify_script_count = 0
    for src in script_sources:
        if 'shopify' in src.lower() or 'shopifycloud' in src.lower() or 'cdn.shopify.com' in src.lower():
            shopify_script_count += 1
    if shopify_script_count >= 3:
        score += 3
        sources.append(f"{shopify_script_count} scripts Shopify")
    elif shopify_script_count >= 1:
        score += 1
        sources.append(f"{shopify_script_count} script(s) Shopify")

    class_patterns = ['shopify-section', 'shopify-payment-button', 'product-form', 'cart-drawer']
    found_classes = [p for p in class_patterns if p in html]
    if found_classes:
        score += len(found_classes)
        sources.append(f"classes: {', '.join(found_classes)}")

    meta_patterns = [
        (r'<meta name="google-site-verification"', "meta google verification"),
        (r'<meta name="shopify"', "meta shopify"),
        (r'<link rel="alternate" hreflang="[^"]*" href="[^"]*myshopify\.com', "alternate myshopify"),
    ]
    for pattern, label in meta_patterns:
        if re.search(pattern, html, re.I):
            score += 1
            sources.append(label)

    # --- VERSION : on essaie de l'extraire via plusieurs moyens ---
    if home_headers and 'x-shopify-version' in home_headers:
        version = home_headers['x-shopify-version']
        score += 1
        sources.append(f"version header: {version}")
    else:
        # depuis JS
        m = re.search(r'Shopify\.version\s*=\s*["\']([\d.]+)["\']', home_html, re.I)
        if m:
            version = m.group(1)
            score += 1
            sources.append(f"version JS: {version}")
        # depuis JSON dans les scripts
        if not version:
            m = re.search(r'<script[^>]*type="application/json"[^>]*>.*?"version":\s*"([\d.]+)".*?</script>', home_html, re.I)
            if m:
                version = m.group(1)
                score += 1
                sources.append(f"version JSON: {version}")
        # depuis les assets ?v=...
        if not version:
            version_matches = re.findall(r'/[^"\']*[?&]v=([\d.]+)', home_html)
            if version_matches:
                from collections import Counter
                version = Counter(version_matches).most_common(1)[0][0]
                score += 1
                sources.append(f"version assets: {version}")

    if total_indicators >= 5:
        score += 2
        sources.append("bonus 5+ indicateurs")
    elif total_indicators >= 3:
        score += 1
        sources.append("bonus 3+ indicateurs")

    if score < 2:
        score = 0
        sources = ["aucun indicateur fiable"]

    if verbose:
        print(f"[VERBOSE] Score final Shopify : {score}")

    return {
        'score': score,
        'version': version,
        'source': ' ; '.join(sources) if sources else 'aucun test'
    }


# ============================================================
# 2. MODULE SHOPIFY
# ============================================================
class ShopifyModule(BaseModule):
    def __init__(self, base, cms_info):
        super().__init__(base, cms_info)
        self.base = base
        self.home_html = cms_info.get('home_html') if cms_info else None
        self.home_headers = cms_info.get('resp_headers') if cms_info else None

        if self.home_html is None:
            try:
                resp = requests.get(base, timeout=10, verify=False)
                self.home_html = resp.text
                self.home_headers = resp.headers
            except Exception:
                self.home_html = ""
                self.home_headers = {}

        # Détection de la version (appel à la fonction)
        detection = detect_shopify_score(
            self.base,
            self.home_html,
            self.home_headers,
            verbose=False
        )
        self.version = detection.get('version')
        self.score = detection.get('score', 0)
        self.result.version = self.version
        self.result.cms = "shopify"

    def scan(self):
        """Méthode principale du scan Shopify."""
        self._paths_scan()
        self._core_scan()
        self._apps_scan()
        # Pour l'instant, on ne scanne pas les "authors" car Shopify n'a pas d'auteurs exposés comme WordPress
        return self.result

    def _paths_scan(self):
        """Vérifie les chemins sensibles Shopify (comme /admin, /cart, /checkout)."""
        # On définit quelques chemins typiques pour Shopify
        sensitive_paths = [
            {"path": "/admin", "severity": "MEDIUM", "description": "Admin panel accessible"},
            {"path": "/cart", "severity": "LOW", "description": "Cart page"},
            {"path": "/checkout", "severity": "LOW", "description": "Checkout page"},
            {"path": "/collections/all", "severity": "LOW", "description": "All products collection"},
            {"path": "/products.json", "severity": "LOW", "description": "Products JSON endpoint"},
            {"path": "/collections/all/products.json", "severity": "LOW", "description": "Products JSON from collections"},
        ]
        findings = []
        for sp in sensitive_paths:
            url = self.base + sp["path"]
            try:
                r = requests.get(url, timeout=5, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    findings.append({
                        "url": url,
                        "severity": sp["severity"],
                        "description": sp["description"],
                        "status": r.status_code
                    })
            except:
                pass
        if findings:
            section("Exposed Paths")
            for p in findings:
                col = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.ORANGE, "LOW": C.YELLOW}.get(p["severity"], C.WHITE)
                print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']} (code {p['status']})")
            self.result.paths = findings
        else:
            ok("No obvious exposed sensitive paths")

    def _core_scan(self):
        """Cherche les vulnérabilités Shopify via l'API NVD."""
        section("Shopify Core Vulnerabilities")

        if not self.version:
            warn("Version not detected. Searching for all known Shopify vulnerabilities (may include false positives).")
            search_keyword = "shopify"
        else:
            ok(f"Version: {C.BOLD}{self.version}{C.RST}")
            search_keyword = f"shopify {self.version}"

        vulns = self._fetch_vulns_from_nvd(search_keyword)

        if not vulns:
            warn("No known vulnerabilities found for this version")
            return

        for v in vulns:
            self.result.vulns.append(v)
            print_vuln(v)

    def _fetch_vulns_from_nvd(self, keyword):
        """Interroge l'API NVD avec un mot-clé (ex: 'shopify') et retourne une liste de Vuln."""
        vulns = []
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=50"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []
            data = response.json()
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')
                if not cve_id:
                    continue
                # Descriptions
                desc = ""
                for d in cve_data.get('descriptions', []):
                    if d.get('lang') == 'en':
                        desc = d.get('value', '')
                        break
                # CVSS score & severity
                cvss_score = None
                severity = "UNKNOWN"
                metrics = cve_data.get('metrics', {})
                for metric in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric in metrics and metrics[metric]:
                        cvss = metrics[metric][0].get('cvssData', {})
                        cvss_score = cvss.get('baseScore')
                        if cvss_score is not None:
                            break
                if cvss_score is not None:
                    if cvss_score >= 9.0:   severity = "CRITICAL"
                    elif cvss_score >= 7.0: severity = "HIGH"
                    elif cvss_score >= 4.0: severity = "MEDIUM"
                    else:                   severity = "LOW"
                # Lien
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                published = cve_data.get('published', '')[:10]
                # On filtre les vulns qui ne concernent pas directement Shopify
                # On peut aussi garder toutes les vulns contenant "shopify" dans le titre ou la description
                if "shopify" not in desc.lower() and "shopify" not in cve_id.lower():
                    # On garde quand même si le mot-clé est présent dans le CVE ID ou dans la description
                    if "shopify" not in keyword.lower():
                        continue
                vulns.append(Vuln(
                    id=cve_id,
                    name=desc[:140],
                    cve=cve_id,
                    link=link,
                    severity=severity,
                    privileges='n',  # non renseigné
                    cvss_score=cvss_score,
                    fixed_version='',  # pas disponible via NVD
                    poc=[],
                    published=published,
                    package="shopify"
                ))
        except Exception as e:
            warn(f"Error fetching NVD: {e}")
        return vulns

    def _apps_scan(self):
        """Tente de détecter les apps Shopify installées via des URLs courantes."""
        section("Apps / Plugins")
        apps = []
        # Quelques noms d'apps populaires, mais mieux vaut essayer de lister depuis /admin/apps ?
        # On va simplement checker quelques endpoints connus pour les apps.
        common_app_paths = [
            "/apps/",
            "/admin/apps",
            "/shopify/apps",
            "/api/apps",
            "/app/storefront",
            "/apps/oauth",
            "/admin/oauth/authorize",
        ]
        for path in common_app_paths:
            url = self.base + path
            try:
                r = requests.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    # Si la page contient "app" ou "shopify" c'est un indice
                    apps.append(url)
                    print(f"  {C.GREEN}✓{C.RST} {url} (accessible)")
                elif r.status_code == 403:
                    apps.append(url + " (403)")
                    print(f"  {C.ORANGE}?{C.RST} {url} (403 - forbidden)")
            except:
                pass
        if not apps:
            warn("No apps detected (or unable to enumerate)")
        else:
            # On pourrait aussi rechercher des vulnérabilités pour ces apps dans le futur
            pass

    def get_info(self):
        return {
            'name': 'Shopify',
            'version': self.version,
            'score': self.score,
            'source': 'détection HTML/headers'
        }