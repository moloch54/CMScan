import os
import re
import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.colors import C, sev_color, sev_label, ok, warn, section, print_vuln, info
from lib.version import version_le, version_ge, parse_version
from lib.http import get, _cmseek_getsource
from lib.paths import check_paths, JOOMLA_SENSITIVE_PATHS
from lib.vuln import check_vulns_friendsofphp
from modules.base import BaseModule, Vuln

class JoomlaModule(BaseModule):
    def __init__(self, base_url, cms_info):
        super().__init__(base_url, cms_info)
        self.OSV_BATCH = "https://api.osv.dev/v1/querybatch"
        self.OSV_QUERY = "https://api.osv.dev/v1/query"
        self.OSV_VULN  = "https://api.osv.dev/v1/vulns/{}"
        if not self.version:
            self.version = self._extract_joomla_version()
            self.result.version = self.version

    def scan(self):
        self._paths_scan()
        self._core_scan()
        self._extensions_scan()
        self._authors_scan()
        return self.result

    def _paths_scan(self):
        from lib.paths import check_paths, JOOMLA_SENSITIVE_PATHS
        from lib.colors import section, ok, sev_color
        section("Exposed Paths")
        findings = check_paths(self.base, JOOMLA_SENSITIVE_PATHS)
        if not findings:
            ok("No obviously exposed sensitive paths")
        for p in findings:
            col = sev_color(p["severity"])
            print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")
        self.result.paths = findings

    def _extract_joomla_version(self):
        base = self.base
        html = self.html
        ua = random.choice(["Mozilla/5.0"])
        src = _cmseek_getsource(base + '/administrator/manifests/files/joomla.xml', ua)
        if src[0] == '1':
            m = re.search(r'<version>([^<]+)</version>', src[1])
            if m:
                return m.group(1)
        src = _cmseek_getsource(base + '/language/en-GB/en-GB.xml', ua)
        if src[0] == '1':
            m = re.search(r'<version>([^<]+)</version>', src[1])
            if m:
                return m.group(1)
        src = _cmseek_getsource(base + '/libraries/src/Version.php', ua)
        if src[0] == '1':
            m = re.search(r"const\s+RELEASE\s*=\s*'([^']+)'", src[1])
            if m:
                version = m.group(1)
                m = re.search(r"const\s+DEV_LEVEL\s*=\s*'([^']+)'", src[1])
                if m:
                    return f"{version}.{m.group(1)}"
                return version
        r = get(base + "/administrator")
        if r and r.status_code == 200:
            m = re.search(r'Joomla! (\d+\.\d+\.\d+)', r.text)
            if m:
                return m.group(1)
        m = re.search(r'<meta name="generator" content="Joomla!([^"]+)"', html, re.I)
        if m:
            v_match = re.search(r'(\d+\.\d+\.\d+)', m.group(1))
            if v_match:
                return v_match.group(1)
        return None

    def _core_scan(self):
        version = self.version
        section("Joomla Core")
        if not version:
            warn("Core version not detected")
            return

        ok(f"Version: {C.BOLD}{version}{C.RST}")
        all_vulns = []

        # 1. NVD (source principale)
        nvd_vulns = self._nvd_core_vulns(version)
        all_vulns.extend(nvd_vulns)

        # 2. FriendsOfPHP (fallback)
        fophp_vulns = check_vulns_friendsofphp('joomla', 'joomla/joomla', version)
        all_vulns.extend(fophp_vulns)

        # 3. OSV (fallback)
        osv_vulns = self._osv_core_vulns(version)
        all_vulns.extend(osv_vulns)

        if not all_vulns:
            warn("No known vulnerabilities found for this version")
            return

        # Dédoublonner par CVE
        seen = {}
        for v in all_vulns:
            key = v.cve if v.cve else v.id
            if key not in seen:
                seen[key] = v

        # Trier par sévérité
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        sorted_vulns = sorted(seen.values(), key=lambda x: severity_order.get(x.severity, 4))

        for v in sorted_vulns:
            self.result.vulns.append(v)
            print_vuln(v)

    def _osv_core_vulns(self, version):
        payload = {
            "version": version,
            "package": {"name": "joomla/joomla", "ecosystem": "Packagist"}
        }
        try:
            r = get(self.OSV_QUERY, json=payload)
            if r and r.status_code == 200:
                data = r.json()
                ids = [v.get("id") for v in data.get("vulns", []) if v.get("id")]
                if not ids:
                    return []
                full_records = {}
                with ThreadPoolExecutor(max_workers=10) as ex:
                    futs = {ex.submit(self._osv_fetch_full, vid): vid for vid in ids}
                    for fut in as_completed(futs, timeout=10):
                        vid = futs[fut]
                        try:
                            rec = fut.result(timeout=2)
                            if rec:
                                full_records[vid] = rec
                        except:
                            pass
                vulns = []
                for vid, rec in full_records.items():
                    v = self._parse_osv_vuln(rec, "joomla/joomla")
                    if v:
                        vulns.append(v)
                return vulns
        except Exception:
            pass
        return []
        
    def _nvd_core_vulns(self, version):
        """Interroge l'API NVD pour les vulnérabilités Joomla core."""
        import urllib.request
        import json
        vulns = []
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=joomla%20{version}"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                if not cve_id:
                    continue
                # Extraire la description
                desc = ""
                for d in cve.get('descriptions', []):
                    if d.get('lang') == 'en':
                        desc = d.get('value', '')
                        break
                # Extraire le CVSS score
                cvss_score = None
                metrics = cve.get('metrics', {})
                for metric in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric in metrics and metrics[metric]:
                        cvss = metrics[metric][0].get('cvssData', {})
                        cvss_score = cvss.get('baseScore')
                        if cvss_score:
                            break
                # Sévérité
                sev = "UNKNOWN"
                if cvss_score is not None:
                    if cvss_score >= 9.0: sev = "CRITICAL"
                    elif cvss_score >= 7.0: sev = "HIGH"
                    elif cvss_score >= 4.0: sev = "MEDIUM"
                    else: sev = "LOW"
                # Lien
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                # Date de publication
                published = cve.get('published', '')[:10]
                vulns.append(Vuln(
                    id=cve_id,
                    name=desc[:140],
                    cve=cve_id,
                    link=link,
                    severity=sev,
                    privileges='n',
                    cvss_score=cvss_score,
                    fixed_version='',  # NVD ne donne pas toujours la version fixe
                    poc=[],
                    published=published,
                    package="joomla/joomla"
                ))
        except Exception as e:
            print(f"[DEBUG] NVD error: {e}")
        return vulns

        def _osv_fetch_full(self, vuln_id):
            try:
                r = get(self.OSV_VULN.format(vuln_id))
                if r and r.status_code == 200:
                    return r.json()
            except:
                pass
            return {}

    def _parse_osv_vuln(self, v, package):
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
                cvss_score = float(score_raw); break
            except:
                pass
        if cvss_score is None:
            for key in ("cvss", "cvss_score", "cvss_v3", "base_score"):
                try:
                    cvss_score = float(db[key]); break
                except:
                    pass
        if cvss_score is not None:
            if cvss_score >= 9.0:   sev = "CRITICAL"
            elif cvss_score >= 7.0: sev = "HIGH"
            elif cvss_score >= 4.0: sev = "MEDIUM"
            else:                   sev = "LOW"
        if sev == "UNKNOWN":
            sev = SEV_MAP.get((db.get("severity") or "").lower(), "UNKNOWN")
        refs = []
        poc = []
        for ref in v.get("references", []):
            url = ref.get("url", "")
            rtyp = ref.get("type", "")
            if not url: continue
            refs.append(url)
            if rtyp in ("EVIDENCE", "EXPLOIT") or any(x in url.lower() for x in
                    ("exploit", "poc", "proof", "nuclei", "metasploit",
                     "packetstorm", "edb.id", "exploitdb")):
                poc.append(url)
        advisory = next((u for u in refs if "joomla.org/" in u or "github.com/advisories" in u), refs[0] if refs else "")
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

    def _extensions_scan(self):
        html = self.html
        extensions = self._extract_joomla_extensions(html)
        templates = self._extract_templates(html)
        section("Templates")
        if templates:
            for name, data in templates.items():
                hash_ver = f" (hash: {data['hash'][:8]})" if data['hash'] else ""
                print(f"  {C.WHITE}{C.BOLD}{name}{C.RST}  {C.DIM}{hash_ver}{C.RST}")
        else:
            warn("No templates detected")
        section("Extensions (Components, Modules, Plugins)")
        if not extensions:
            warn("No extensions detected")
            return
        for name, info in extensions.items():
            ver = info.get("version", "")
            typ = info.get("type", "unknown")
            print(f"  {C.WHITE}{C.BOLD}{name}{C.RST}  {C.DIM}[{typ}] {ver or '?'}{C.RST}")

    def _authors_scan(self):
        section("Authors")
        authors = set()
        r = get(self.base + "/api/index.php/v1/users")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for user in data.get("data", []):
                    name = user.get("attributes", {}).get("username", "")
                    if name:
                        authors.add(name)
                        print(f"    {C.WHITE}{name}{C.RST}")
            except: pass
        for i in range(1, 11):
            r = get(self.base + f"/index.php?option=com_users&view=profile&user_id={i}")
            if r and r.status_code == 200:
                m = re.search(r'<h1[^>]*>([^<]+)</h1>', r.text, re.I)
                if m:
                    name = m.group(1).strip()
                    if name:
                        authors.add(name)
                        print(f"    {C.WHITE}{name}{C.RST}")
        r = get(self.base + "/index.php?format=feed&type=rss")
        if r and r.status_code == 200:
            feed_authors = re.findall(r'<dc:creator>([^<]+)<', r.text)
            for a in feed_authors:
                if a.strip():
                    authors.add(a.strip())
                    print(f"    {C.WHITE}{a.strip()}{C.RST}")
        if not authors:
            warn("No authors found")
        self.result.authors = list(authors)

    def _extract_templates(self, html):
        templates = {}
        ua = random.choice(["Mozilla/5.0"])

        # 1. Détection via le HTML de la page d'accueil
        for m in re.finditer(r'/templates/([a-z0-9_\-]+)/', html, re.I):
            name = m.group(1)
            if name not in templates:
                templates[name] = {"version": None, "hash": None}
                for asset in re.finditer(r'/templates/' + re.escape(name) + r'/[^"\']*\?([a-f0-9]{32})', html, re.I):
                    templates[name]["hash"] = asset.group(1)

        # 2. Détection via templateDetails.xml (fallback)
        for name in list(templates.keys()):
            src = _cmseek_getsource(self.base + f'/templates/{name}/templateDetails.xml', ua)
            if src[0] == '1':
                m = re.search(r'<version>([^<]+)</version>', src[1])
                if m:
                    templates[name]["version"] = m.group(1)

        # 3. Détection via /administrator (templates admin)
        r_admin = get(self.base + "/administrator")
        if r_admin and r_admin.status_code == 200:
            admin_html = r_admin.text
            for m in re.finditer(r'/templates/([a-z0-9_\-]+)/', admin_html, re.I):
                name = m.group(1)
                if name not in templates:
                    templates[name] = {"version": None, "hash": None}
                    # Chercher la version via templateDetails.xml
                    src = _cmseek_getsource(self.base + f'/templates/{name}/templateDetails.xml', ua)
                    if src[0] == '1':
                        m2 = re.search(r'<version>([^<]+)</version>', src[1])
                        if m2:
                            templates[name]["version"] = m2.group(1)

        return templates

    def _extract_joomla_extensions(self, html):
        extensions = {}
        ua = random.choice(["Mozilla/5.0"])

        # 1. Composants
        for m in re.finditer(r'/component/com_([a-z0-9_\-]+)/', html, re.I):
            name = m.group(1)
            if name not in extensions:
                version = self._get_joomla_extension_version(name, "component")
                if not version:
                    version = self._extract_version_from_assets(html, name, "component")
                extensions[name] = {"type": "component", "version": version}

        # 2. Modules
        for m in re.finditer(r'/modules/mod_([a-z0-9_\-]+)/', html, re.I):
            name = m.group(1)
            if name not in extensions:
                version = self._get_joomla_extension_version(name, "module")
                if not version:
                    version = self._extract_version_from_assets(html, name, "module")
                extensions[name] = {"type": "module", "version": version}

        # 3. Plugins (détection via les URLs)
        for m in re.finditer(r'/plugins/([a-z0-9_\-]+)/([a-z0-9_\-]+)/[^"\']+\.(css|js|png|jpg|gif)', html, re.I):
            plugin_type = m.group(1)
            plugin_name = m.group(2)
            if plugin_name not in extensions:
                version = self._get_plugin_version(plugin_name, plugin_type)
                if not version:
                    version = self._extract_version_from_assets(html, plugin_name, "plugin")
                extensions[plugin_name] = {"type": f"plugin ({plugin_type})", "version": version}

        # 4. Détection via /administrator
        r_admin = get(self.base + "/administrator")
        if r_admin and r_admin.status_code == 200:
            admin_html = r_admin.text
            for m in re.finditer(r'/components/com_([a-z0-9_\-]+)/', admin_html, re.I):
                name = m.group(1)
                if name not in extensions:
                    version = self._get_joomla_extension_version(name, "component")
                    if not version:
                        version = self._extract_version_from_assets(admin_html, name, "component")
                    extensions[name] = {"type": "component", "version": version}
            for m in re.finditer(r'/modules/mod_([a-z0-9_\-]+)/', admin_html, re.I):
                name = m.group(1)
                if name not in extensions:
                    version = self._get_joomla_extension_version(name, "module")
                    if not version:
                        version = self._extract_version_from_assets(admin_html, name, "module")
                    extensions[name] = {"type": "module", "version": version}
            for m in re.finditer(r'/plugins/([a-z0-9_\-]+)/([a-z0-9_\-]+)/', admin_html, re.I):
                plugin_type = m.group(1)
                plugin_name = m.group(2)
                if plugin_name not in extensions:
                    version = self._get_plugin_version(plugin_name, plugin_type)
                    if not version:
                        version = self._extract_version_from_assets(admin_html, plugin_name, "plugin")
                    extensions[plugin_name] = {"type": f"plugin ({plugin_type})", "version": version}

        # 5. Pour chaque extension sans version, essayer de la trouver via les URLs des assets
        for name, info in extensions.items():
            if not info.get("version"):
                version = self._extract_version_from_assets(html, name, info.get("type", ""))
                if version:
                    info["version"] = version

        return extensions

    def _get_joomla_extension_version(self, name, typ):
        paths = {
            "component": f"/administrator/components/com_{name}/com_{name}.xml",
            "module": f"/modules/mod_{name}/mod_{name}.xml",
            "plugin": f"/plugins/system/{name}/{name}.xml",
        }
        path = paths.get(typ)
        if not path:
            return ""
        try:
            r = get(self.base + path)
            if r and r.status_code == 200:
                m = re.search(r'<version>([^<]+)</version>', r.text)
                if m:
                    return m.group(1)
        except: pass
        return ""

    def _get_plugin_version(self, plugin_name, plugin_type="system"):
        """Tente de récupérer la version d'un plugin Joomla."""
        # Chemins possibles pour les plugins
        path = f"/plugins/{plugin_type}/{plugin_name}/{plugin_name}.xml"
        try:
            r = get(self.base + path)
            if r and r.status_code == 200:
                m = re.search(r'<version>([^<]+)</version>', r.text)
                if m:
                    return m.group(1)
        except:
            pass
        # Fallback : on essaie le dossier directement
        try:
            src = _cmseek_getsource(self.base + f'/plugins/{plugin_type}/{plugin_name}/{plugin_name}.xml', random.choice(["Mozilla/5.0"]))
            if src[0] == '1':
                m = re.search(r'<version>([^<]+)</version>', src[1])
                if m:
                    return m.group(1)
        except:
            pass
        return ""

    def _extract_version_from_assets(self, html, name, typ="module"):
        """Extrait la version d'une extension depuis les URLs des assets CSS/JS."""
        patterns = []
        if typ.startswith("component"):
            patterns = [
                rf'/components/com_{re.escape(name)}/[^"\']*[?&]v=([\d.]+)',
                rf'/components/com_{re.escape(name)}/[^"\']*[?&]ver=([\d.]+)',
                rf'/components/com_{re.escape(name)}/[^"\']*[?&]version=([\d.]+)',
                rf'/administrator/components/com_{re.escape(name)}/[^"\']*[?&]v=([\d.]+)',
            ]
        elif typ.startswith("module"):
            patterns = [
                rf'/modules/mod_{re.escape(name)}/[^"\']*[?&]v=([\d.]+)',
                rf'/modules/mod_{re.escape(name)}/[^"\']*[?&]ver=([\d.]+)',
                rf'/modules/mod_{re.escape(name)}/[^"\']*[?&]version=([\d.]+)',
            ]
        elif typ.startswith("plugin"):
            # Pour les plugins, on cherche dans /plugins/type/name/
            patterns = [
                rf'/plugins/[^/]+/{re.escape(name)}/[^"\']*[?&]v=([\d.]+)',
                rf'/plugins/[^/]+/{re.escape(name)}/[^"\']*[?&]ver=([\d.]+)',
                rf'/plugins/[^/]+/{re.escape(name)}/[^"\']*[?&]version=([\d.]+)',
            ]
        # Patterns génériques
        patterns.append(rf'/{re.escape(name)}/[^"\']*[?&]v=([\d.]+)')
        patterns.append(rf'/{re.escape(name)}/[^"\']*[?&]ver=([\d.]+)')

        for pattern in patterns:
            m = re.search(pattern, html, re.I)
            if m:
                return m.group(1)
        return ""