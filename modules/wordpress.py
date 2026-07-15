import os
import re
import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.colors import C, sev_color, sev_label, ok, warn, section, print_vuln
from lib.version import version_le, version_ge, parse_version
from lib.http import get, _cmseek_getsource
from lib.paths import check_paths, WP_SENSITIVE_PATHS
from lib.vuln import check_vulns_friendsofphp
from modules.base import BaseModule, Vuln
import urllib.request
import time
import lib.http
VERBOSE = False

class WordPressModule(BaseModule):
    def __init__(self, base_url, cms_info):
        super().__init__(base_url, cms_info)
        self.CORE_DIR = "vulnDatabase/coreVuln"
        self.PLUGINS_DIR = "vulnDatabase/pluginsVuln"
        self.THEMES_DIR = "vulnDatabase/themesVuln"
        self.TEMPLATES_DIR = "vulnDatabase/templates"
        self.SPIDERS_DIR = "vulnDatabase/spiders"
        self._plugin_versions_from_meta = {}
        self._plugin_versions_from_comment = {}

    def scan(self):
 
        self._paths_scan()
        self._core_scan()
        self._themes_scan()
        self._plugins_scan()
        time.sleep(2)
        self._authors_scan()

        return self.result

    def _get_wp_rocket_version(self):
        """Extrait la version de wp-rocket depuis rocket.pot ou readme.txt."""
        # 1. rocket.pot
        url = self.base + "/wp-content/plugins/wp-rocket/languages/rocket.pot"
        try:
            r = get(url)
            if r and r.status_code == 200:
                m = re.search(r'Project-Id-Version:\s*WP Rocket\s+([\d.]+)', r.text, re.I)
                if m:
                    return m.group(1)
        except:
            pass

        # 2. readme.txt
        url = self.base + "/wp-content/plugins/wp-rocket/readme.txt"
        try:
            r = get(url)
            if r and r.status_code == 200:
                m = re.search(r'Stable tag:\s*([\d.]+)', r.text, re.I)
                if m:
                    return m.group(1)
        except:
            pass

        return None

    def _core_version_from_assets(self):
        """Dernier fallback : méthode WPScan (Query Parameter In Install Page)."""
        if VERBOSE:
            print("[VERBOSE] Core version: fallback WPScan method...")
        
        # ═══ NOUVEAU : Feed RSS (comme WPScan) ═══
        if VERBOSE:
            print("[VERBOSE]   Trying feed RSS...")
        try:
            r = get(self.base + "/feed", timeout=5)
            if r and r.status_code == 200:
                m = re.search(r'<generator>https://wordpress.org/\?v=([\d\.]+)</generator>', r.text, re.I)
                if m:
                    version = m.group(1)
                    if VERBOSE:
                        print(f"[VERBOSE] Core version from feed RSS: {version}")
                    return version
        except:
            pass

        # 1. Télécharger /wp-admin/install.php
        url = self.base + "/wp-admin/install.php"
        try:
            r = get(url, timeout=5)
            if r and r.status_code == 200:
                pattern = r'(?:href|src)=["\'][^"\']*?ver=([\d.]+)["\']'
                matches = re.findall(pattern, r.text, re.I)
                if matches:
                    from collections import Counter
                    version = Counter(matches).most_common(1)[0][0]
                    if re.match(r'\d+\.\d+(\.\d+)?', version):
                        if VERBOSE:
                            print(f"[VERBOSE] Core version from install.php: {version}")
                        return version
                m = re.search(r'WordPress\s+([\d.]+)', r.text, re.I)
                if m:
                    version = m.group(1)
                    if VERBOSE:
                        print(f"[VERBOSE] Core version from install.php text: {version}")
                    return version
        except:
            pass

        # 2. Fallback : les fichiers CSS individuels (comme WPScan)
        css_files = [
            "/wp-includes/css/dashicons.min.css",
            "/wp-includes/css/buttons.min.css",
            "/wp-admin/css/forms.min.css",
            "/wp-admin/css/l10n.min.css",
            "/wp-admin/css/install.min.css",
        ]
        for css_path in css_files:
            url = self.base + css_path
            try:
                r = get(url, timeout=5)
                if r and r.status_code == 200:
                    m = re.search(r'ver=([\d.]+)', r.text, re.I)
                    if m:
                        version = m.group(1)
                        if re.match(r'\d+\.\d+(\.\d+)?', version):
                            if VERBOSE:
                                print(f"[VERBOSE] Core version from {css_path}: {version}")
                            return version
                    m = re.search(r'WordPress\s+([\d.]+)', r.text, re.I)
                    if m:
                        version = m.group(1)
                        if VERBOSE:
                            print(f"[VERBOSE] Core version from text in {css_path}: {version}")
                        return version
            except:
                pass

        if VERBOSE:
            print("[VERBOSE] Core version: WPScan fallback failed")
        return None

    def _core_scan(self):
        core_version = self.version
        
        # Fallback : version depuis les assets (méthode WPScan)
        if not core_version:
            core_version = self._core_version_from_assets()
        
        section("WordPress Core")
        if core_version:
            ok(f"Version: {C.BOLD}{core_version}{C.RST}")
            self.result.version = core_version  # <--- AJOUT

            path = self._ensure_wp_vuln(core_version, "core")
            vulns = self._wp_vuln_from_file(path, core_version)
            for v in vulns:
                v.package = f"WP core {core_version}"
                self.result.vulns.append(v)
                print_vuln(v)
        else:
            warn("Core version not detected")

    def _themes_scan(self):
        html = self.html
        theme_slugs = self._wp_slugs_from_html(html, "theme")
        theme_versions = {}
        for slug in theme_slugs:
            theme_versions[slug] = self._wp_ver_from_html(html, slug, "theme", self.version)
        for slug in theme_slugs:
            if not theme_versions.get(slug):
                ver = self._wp_fetch_version_txt(self.base + f"/wp-content/themes/{slug}/style.css")
                if ver:
                    theme_versions[slug] = ver
        section("Themes")
        if not theme_slugs:
            warn("No themes detected")
        for slug in theme_slugs:
            ver = theme_versions.get(slug, "")
            print(f"  {C.WHITE}{C.BOLD}{slug}{C.RST}  {C.DIM}{ver or '?'}{C.RST}")
            if ver:
                vulns = self._wp_vuln_from_file(self._ensure_wp_vuln(slug, "theme"), ver)
                for v in vulns:
                    v.package = f"theme:{slug}"
                    self.result.vulns.append(v)
                    print_vuln(v)

    def _plugins_scan(self):
        html = self.html
        plugin_slugs = self._wp_slugs_from_html(html, "plugin")
        
        # ═══ Détection passive des plugins depuis le HTML ═══
        # Meta tags (ex: google-site-kit)
        meta_matches = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        for meta in meta_matches:
            # Ex: "Site Kit by Google 1.183.0"
            m = re.search(r'Site Kit by Google\s+([\d.]+)', meta, re.I)
            if m:
                if 'google-site-kit' not in plugin_slugs:
                    plugin_slugs.append('google-site-kit')
                self._plugin_versions_from_meta['google-site-kit'] = m.group(1)
                if VERBOSE:
                    print(f"[VERBOSE] Plugin detected from meta: google-site-kit {m.group(1)}")
        
        # Commentaires (ex: wordpress-seo)
        comment_matches = re.findall(r'<!--[^>]*optimized with the Yoast SEO plugin v([\d.]+)[^>]*-->', html, re.I)
        if comment_matches:
            version = comment_matches[0]
            if 'wordpress-seo' not in plugin_slugs:
                plugin_slugs.append('wordpress-seo')
            self._plugin_versions_from_comment['wordpress-seo'] = version
            if VERBOSE:
                print(f"[VERBOSE] Plugin detected from comment: wordpress-seo {version}")
        
        templates = self._load_templates()
        for tpl in templates:
            regex = tpl[0].rstrip("\n")
            tname = tpl[2].rstrip("\n") if len(tpl) > 2 else None
            for name, ver in self._extract_with_template(html, regex, "1", tname):
                if name and name not in plugin_slugs:
                    plugin_slugs.append(name)
        spiders = self._load_spiders()
        for sp in spiders:
            if len(sp) < 3: continue
            name = sp[0].rstrip("\n")
            url = self.base + sp[1].rstrip("\n")
            regex = sp[2].rstrip("\n")
            try:
                r = get(url)
                if r and r.status_code == 200:
                    m = re.search(regex, r.text)
                    if m:
                        ver = m.group(1)
                        if name not in plugin_slugs:
                            plugin_slugs.append(name)
            except: pass
        plugin_slugs = sorted(set(plugin_slugs))
        
        plugin_versions = {}
        
        # D'abord, on récupère les versions depuis le HTML (rapide)
        for slug in plugin_slugs:
            # Vérifier si on a une version depuis meta ou commentaire
            if slug in self._plugin_versions_from_meta:
                plugin_versions[slug] = self._plugin_versions_from_meta[slug]
            elif slug in self._plugin_versions_from_comment:
                plugin_versions[slug] = self._plugin_versions_from_comment[slug]
            else:
                ver = self._wp_ver_from_html(html, slug, "plugin", self.version)
                if ver:
                    plugin_versions[slug] = ver
        
        # Ensuite, pour ceux qui n'ont pas de version, on fetch les readme.txt avec max 2 workers
        slugs_to_fetch = [slug for slug in plugin_slugs if slug not in plugin_versions or not plugin_versions[slug]]
        if slugs_to_fetch:
            if VERBOSE:
                print(f"[VERBOSE] Fetching readme.txt for {len(slugs_to_fetch)} plugins with 2 workers...")
            
            def fetch_version(slug):
                ver = self._wp_fetch_version_txt(self.base + f"/wp-content/plugins/{slug}/readme.txt")
                return slug, ver
            
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(fetch_version, slug): slug for slug in slugs_to_fetch}
                for future in as_completed(futures):
                    slug, ver = future.result()
                    if ver:
                        plugin_versions[slug] = ver

        # Détection spécifique de wp-rocket
        if 'wp-rocket' in plugin_slugs:
            rocket_ver = self._get_wp_rocket_version()
            if rocket_ver:
                plugin_versions['wp-rocket'] = rocket_ver
                if VERBOSE:
                    print(f"[VERBOSE] wp-rocket version: {rocket_ver}")

        section("Plugins")
        if not plugin_slugs:
            warn("No plugins detected")
        for slug in plugin_slugs:
            ver = plugin_versions.get(slug, "")
            print(f"  {C.WHITE}{C.BOLD}{slug}{C.RST}  {C.DIM}{ver or '?'}{C.RST}")
            if ver:
                vulns = self._wp_vuln_from_file(self._ensure_wp_vuln(slug, "plugin"), ver)
                for v in vulns:
                    v.package = f"plugin:{slug}"
                    self.result.vulns.append(v)
                    print_vuln(v)

    def _authors_scan(self):
        time.sleep(3)
        section("Authors")
        usernames = self._harvest_usernames_wp()
        if usernames:
            for idx, name in enumerate(sorted(usernames), 1):
                print(f"    {C.WHITE}{idx}:{C.RST} {name}")
                self.result.authors.append(name)
        else:
            warn("No authors found")

    def _paths_scan(self):
        section("Exposed Paths")
        findings = check_paths(self.base, WP_SENSITIVE_PATHS, home_content=self.html)
        if not findings:
            ok("No obviously exposed sensitive paths")
        for p in findings:
            col = sev_color(p["severity"])
            print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")
        self.result.paths = findings

    def _ensure_wp_vuln(self, slug, kind):
        dirmap = {"core": self.CORE_DIR, "plugin": self.PLUGINS_DIR, "theme": self.THEMES_DIR}
        path = os.path.join(dirmap[kind], slug)
        if not os.path.exists(path):
            try:
                r = get(f"https://www.wpvulnerability.net/{kind}/{slug}")
                if r and r.status_code == 200:
                    with open(path, "wb") as f:
                        f.write(r.content)
            except: pass
        return path

    def _wp_vuln_from_file(self, path, item_version):
        results = []
        # 1. Récupérer les vulns locales (wpvulnerability.net)
        try:
            with open(path) as f:
                data = json.load(f)
            for v in data.get("data", {}).get("vulnerability", []):
                src = v.get("source", [{}])[0]
                cve = src.get("id", "")
                if "CVE" not in cve:
                    continue
                impact = v.get("impact", {})
                cvss = impact.get("cvss", {})
                sev = cvss.get("severity", "")
                priv = cvss.get("pr", "")
                if sev not in ("c", "h") or priv not in ("n", "l"):
                    continue
                op = v.get("operator", {})
                min_v = op.get("min_version", "0")
                max_v = op.get("max_version", "")
                if min_v in ("", "null", None): min_v = "0"
                if max_v in ("", "null", None): max_v = ""
                affected_ver = ""
                if not max_v:
                    for src in v.get("source", []):
                        desc = src.get("description", "")
                        m = re.search(r"(?:<=?|through|up to)\s*([\d]+\.[\d]+\.?[\d]*)", desc, re.I)
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
                display_max = max_v if max_v and max_v != "1000000" else affected_ver
                results.append(Vuln(
                    id=cve,
                    name=src.get("description", "")[:120],
                    cve=cve,
                    link=src.get("link", ""),
                    severity=sev_label(sev),
                    privileges=priv,
                    cvss_score=float(cvss.get("score", 0)) if cvss.get("score") else None,
                    fixed_version=display_max,
                    package=os.path.basename(path)
                ))
        except Exception:
            pass

        # 2. Récupérer les vulns FriendsOfPHP (toujours)
        from lib.vuln import check_vulns_friendsofphp
        if 'core' in path:
            package = 'wordpress/wordpress'
        elif 'plugin' in path:
            slug = os.path.basename(path)
            package = f'wordpress/plugins/{slug}'
        else:
            package = 'wordpress/themes/' + os.path.basename(path)
        fophp = check_vulns_friendsofphp('wordpress', package, item_version)

        # 3. Fusionner les deux listes (dédoublonner par CVE, garder la sévérité max)
        merged = {}
        for v in results + fophp:
            key = v.cve if v.cve else v.id
            if key not in merged or self._severity_rank(v.severity) > self._severity_rank(merged[key].severity):
                merged[key] = v

        return list(merged.values())

    def _severity_rank(self, sev):
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        return order.get(sev, 4)

    def _harvest_usernames_wp(self):
        import requests
        import time
        import random
        usernames = set()
 
        ua = lib.http.FIXED_UA  
        if VERBOSE:
            print(f"[DEBUG] _harvest_usernames_wp: début pour {self.base}")

        # Pause initiale (comme WPscrap)
        time.sleep(2)

        # 3. Feed RSS (avec retry sur 503)
        if VERBOSE:
            print("[DEBUG]   → Source 3: feed RSS")
        feed_ok = False
        for attempt in range(3):
            try:
                headers = {'User-Agent': ua}
                r = requests.get(self.base + "/feed", headers=headers, timeout=15)
                if r.status_code == 200:
                    feed_users = re.findall(r'<dc:creator>[\n\s]*<!\[CDATA\[([\w\s\-]+)\]', r.text)
                    if not feed_users:
                        feed_users = re.findall(r"<dc:creator>([^<]+)<", r.text)
                    if VERBOSE:
                        print(f"[DEBUG]   → Feed RSS OK, {len(feed_users)} utilisateurs")
                    for username in feed_users:
                        username = username.strip()
                        if username and username not in usernames:
                            usernames.add(username)
                            print(f"    {C.GREEN}[+]{C.RST} Found user from feed: {C.BOLD}{username}{C.RST}")
                    feed_ok = True
                    break
                elif r.status_code == 503:
                    if VERBOSE:
                        print(f"[DEBUG]   → Feed RSS 503, tentative {attempt+1}/3, attente {2 ** attempt}s")
                    time.sleep(2 ** attempt)  # 2s, 4s, 8s
                else:
                    if VERBOSE:
                        print(f"[DEBUG]   → Feed RSS échoué (status {r.status_code})")
                    break
            except Exception as e:
                if VERBOSE:
                    print(f"[DEBUG]   → Feed RSS tentative {attempt+1} exception: {e}")
                time.sleep(2 ** attempt)
        if not feed_ok and VERBOSE:
            print("[DEBUG]   → Feed RSS abandonné après 3 tentatives")

        # 2. API REST
        if VERBOSE:
            print("[DEBUG]   → Source 2: wp-json API")
        try:
            headers = {'User-Agent': ua}
            r = requests.get(self.base + "/wp-json/wp/v2/users", headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for user in data:
                    slug = user.get("slug", "")
                    if slug:
                        usernames.add(slug)
                        print(f"    {C.GREEN}[+]{C.RST} Found user from wp-json: {C.BOLD}{slug}{C.RST}")
                if VERBOSE:
                    print(f"[DEBUG]   → wp-json OK, {len(data)} utilisateurs")
            else:
                if VERBOSE:
                    print(f"[DEBUG]   → wp-json échoué (status {r.status_code})")
        except Exception as e:
            if VERBOSE:
                print(f"[DEBUG]   → wp-json exception: {e}")

        # 3. ?author= redirection (bruteforce, après le feed)
        if VERBOSE:
            print("[DEBUG]   → Source 3: ?author= redirection (1 à 20)")
        for i in range(1, 21):
            try:
                headers = {'User-Agent': ua}
                r = requests.get(self.base + f"/?author={i}", headers=headers, timeout=10, allow_redirects=True)
                if r.status_code == 200:
                    final_url = r.url
                    if "/author/" in final_url:
                        m = re.search(r"/author/([^/]+)/", final_url)
                        if m:
                            username = m.group(1)
                            if username not in usernames:
                                usernames.add(username)
                                print(f"    {C.GREEN}[+]{C.RST} Found user from ?author={i}: {C.BOLD}{username}{C.RST}")
                            continue
                    if "/author/" in r.text:
                        m = re.search(r"/author/([^/]+)/", r.text)
                        if m:
                            username = m.group(1)
                            if username not in usernames:
                                usernames.add(username)
                                print(f"    {C.GREEN}[+]{C.RST} Found user from ?author={i} (source): {C.BOLD}{username}{C.RST}")
                            continue
                elif r.status_code == 302:
                    location = r.headers.get("Location", "")
                    if "/author/" in location:
                        m = re.search(r"/author/([^/]+)/", location)
                        if m:
                            username = m.group(1)
                            if username not in usernames:
                                usernames.add(username)
                                print(f"    {C.GREEN}[+]{C.RST} Found user from ?author={i} (Location): {C.BOLD}{username}{C.RST}")
                            continue
            except Exception as e:
                if i <= 3 and VERBOSE:
                    print(f"[DEBUG]   → ?author={i} échec: {e}")

        if VERBOSE:
            print(f"[DEBUG] _harvest_usernames_wp: fin, {len(usernames)} utilisateur(s)")
        return {u for u in usernames if u}

    def _wp_slugs_from_html(self, html, kind):
        pat = re.compile(rf'/wp-content/{kind}s/([a-z0-9][a-z0-9_\-]+)/', re.I)
        return sorted(set(pat.findall(html)))

    def _wp_ver_from_html(self, html, slug, kind, core_ver):
        pat = re.compile(rf'/wp-content/{kind}s/{re.escape(slug)}/[^"\']*[?&]ver=([\d.]+)', re.I)
        versions = [v for v in pat.findall(html) if v != core_ver and "." in v]
        if versions:
            from collections import Counter
            return Counter(versions).most_common(1)[0][0]
        return ""

    def _wp_fetch_version_txt(self, url):
        try:
            r = get(url, timeout=3)
            if r and r.status_code == 200:
                m = re.search(r'Stable tag:\s*([\d.]+)', r.text, re.I)
                if m and m.group(1).lower() != "trunk":
                    return m.group(1)
                m = re.search(r'(?m)^Version:\s*([\d.]+)', r.text)
                if m:
                    return m.group(1)
        except: pass
        return ""

    def _load_templates(self):
        templates = []
        if not os.path.isdir(self.TEMPLATES_DIR):
            return templates
        for fname in os.listdir(self.TEMPLATES_DIR):
            with open(os.path.join(self.TEMPLATES_DIR, fname)) as f:
                lines = f.readlines()
                if lines:
                    templates.append(lines)
        return templates

    def _load_spiders(self):
        spiders = []
        if not os.path.isdir(self.SPIDERS_DIR):
            return spiders
        for fname in os.listdir(self.SPIDERS_DIR):
            with open(os.path.join(self.SPIDERS_DIR, fname)) as f:
                lines = f.readlines()
                if lines:
                    spiders.append(lines)
        return spiders

    def _extract_with_template(self, html, regex, nb_group, template_name):
        result = []
        seen = set()
        regex = regex.rstrip("\n")
        try:
            pat = re.compile(regex)
        except:
            return result
        for line in html.splitlines():
            if len(line) > 2000:
                continue
            try:
                m = pat.search(line)
                if m:
                    groups = m.groups()
                    name = template_name if template_name else groups[0]
                    version = groups[1] if len(groups) > 1 else ""
                    if name and name not in seen:
                        seen.add(name)
                        result.append((name, version))
            except: pass
        return result