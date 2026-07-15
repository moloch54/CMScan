import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.colors import C, ok, warn, section, print_vuln, sev_color
from lib.http import get
from lib.paths import check_paths, OPENCART_SENSITIVE_PATHS
from modules.base import BaseModule, Vuln

class OpenCartModule(BaseModule):
    def __init__(self, base_url, cms_info):
        super().__init__(base_url, cms_info)
        self.OSV_QUERY = "https://api.osv.dev/v1/query"
        self.OSV_VULN  = "https://api.osv.dev/v1/vulns/{}"
        if not self.version:
            self.version = self._extract_opencart_version()
            self.result.version = self.version

    def scan(self):
        self._paths_scan()
        self._core_scan()
        self._extensions_scan()
        self._authors_scan()
        return self.result

    def _extract_opencart_version(self):
        """Extrait la version OpenCart avec plusieurs méthodes."""
        base = self.base
        html = self.html
        version = None

        # 1. /admin/index.php (version dans le JS ou HTML)
        r = get(base + "/admin/index.php")
        if r and r.status_code == 200:
            # Version dans le footer ou JS
            m = re.search(r'OpenCart\s+([\d.]+)', r.text, re.I)
            if m:
                return m.group(1)
            m = re.search(r'version\s*[:=]\s*["\']([\d.]+)["\']', r.text, re.I)
            if m:
                return m.group(1)

        # 2. /system/startup.php
        r = get(base + "/system/startup.php")
        if r and r.status_code == 200:
            m = re.search(r"define\s*\(\s*'VERSION'\s*,\s*'([\d.]+)'\s*\)", r.text)
            if m:
                return m.group(1)

        # 3. /composer.json (si accessible)
        r = get(base + "/composer.json")
        if r and r.status_code == 200:
            try:
                data = json.loads(r.text)
                v = data.get("version", "")
                if re.match(r"\d+\.\d+\.\d+", v):
                    return v
            except:
                pass

        # 4. Meta generator
        m = re.search(r'<meta name="generator" content="OpenCart[\s]+([\d.]+)"', html, re.I)
        if m:
            return m.group(1)

        # 5. Assets ?v= (fallback)
        versions = re.findall(r'[?&]v=([\d.]+)', html)
        if versions:
            from collections import Counter
            v = Counter(versions).most_common(1)[0][0]
            if re.match(r'\d+\.\d+\.\d+', v):
                return v

        return None

    def _paths_scan(self):
        section("Exposed Paths")
        findings = check_paths(self.base, OPENCART_SENSITIVE_PATHS, home_content=self.html)
        if not findings:
            ok("No obviously exposed sensitive paths")
        for p in findings:
            col = sev_color(p["severity"])
            print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")
        self.result.paths = findings

    def _core_scan(self):
        version = self.version
        section("OpenCart Core")
        if not version:
            warn("Core version not detected")
            return
        ok(f"Version: {C.BOLD}{version}{C.RST}")

        vulns = self._osv_query_packages(["opencart/opencart"], version)
        core_vulns = vulns.get("opencart/opencart", [])
        for v in core_vulns:
            self.result.vulns.append(v)
            print_vuln(v)
        if not core_vulns:
            ok("No known vulnerabilities found for this core version")

    def _extensions_scan(self):
        section("Extensions (OpenCart)")
        html = self.html
        extensions = set()

        # Modules
        for m in re.finditer(r'/admin/controller/extension/module/([^/]+)\.php', html, re.I):
            extensions.add(("module", m.group(1)))
        for m in re.finditer(r'/catalog/controller/extension/module/([^/]+)\.php', html, re.I):
            extensions.add(("module", m.group(1)))

        # Themes
        for m in re.finditer(r'/catalog/view/theme/([^/]+)/', html, re.I):
            extensions.add(("theme", m.group(1)))

        # Payments
        for m in re.finditer(r'/admin/controller/extension/payment/([^/]+)\.php', html, re.I):
            extensions.add(("payment", m.group(1)))

        if not extensions:
            warn("No extensions detected")
            return

        for ext_type, ext_name in sorted(extensions):
            print(f"  {C.WHITE}{C.BOLD}{ext_type}:{ext_name}{C.RST}")

    def _authors_scan(self):
        section("Authors")
        authors = set()

        # Chercher dans les commentaires HTML
        if self.html:
            for m in re.finditer(r'<!--\s*Author:\s*([^<]+?)\s*-->', self.html, re.I):
                authors.add(m.group(1).strip())

        # Essayer /admin/index.php
        r = get(self.base + "/admin/index.php")
        if r and r.status_code == 200:
            for m in re.finditer(r'<span[^>]*>([^<]+)</span>', r.text):
                name = m.group(1).strip()
                if name and len(name) < 50 and not re.search(r'[{}()\[\]]', name):
                    authors.add(name)

        if authors:
            for a in sorted(authors):
                print(f"    {C.WHITE}{a}{C.RST}")
            self.result.authors = list(authors)
        else:
            warn("No authors found")

    def _osv_query_packages(self, packages, version):
        """Interroge OSV pour plusieurs packages avec une version spécifique."""
        if not packages or not version:
            return {}
        queries = [
            {"package": {"name": p, "ecosystem": "Packagist"}, "version": version}
            for p in packages
        ]
        try:
            r = get(self.OSV_QUERY, json={"queries": queries})
            if r and r.status_code != 200:
                return {}
            results = {}
            for i, item in enumerate(r.json().get("results", [])):
                pkg = packages[i]
                ids = [v.get("id") for v in item.get("vulns", []) if v.get("id")]
                if ids:
                    results[pkg] = self._osv_fetch_details(ids)
            return results
        except:
            return {}

    def _osv_fetch_details(self, ids):
        """Récupère les détails complets des vulnérabilités OSV."""
        full = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(self._osv_fetch_one, vid): vid for vid in ids}
            for fut in as_completed(futs, timeout=20):
                try:
                    rec = fut.result(timeout=2)
                    if rec:
                        full.append(rec)
                except:
                    pass
        return [self._parse_osv_vuln(v) for v in full]

    def _osv_fetch_one(self, vuln_id):
        try:
            r = get(self.OSV_VULN.format(vuln_id))
            if r and r.status_code == 200:
                return r.json()
        except:
            pass
        return {}

    def _parse_osv_vuln(self, v):
        """Transforme une réponse OSV en objet Vuln."""
        cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        cvss_score = None
        sev = "UNKNOWN"
        db = v.get("database_specific") or {}

        for s in v.get("severity") or []:
            score_raw = s.get("score", "")
            try:
                cvss_score = float(score_raw)
                break
            except:
                pass
        if cvss_score is None:
            for key in ("cvss", "cvss_score", "base_score"):
                try:
                    cvss_score = float(db[key])
                    break
                except:
                    pass
        if cvss_score is not None:
            if cvss_score >= 9.0:   sev = "CRITICAL"
            elif cvss_score >= 7.0: sev = "HIGH"
            elif cvss_score >= 4.0: sev = "MEDIUM"
            else:                   sev = "LOW"
        else:
            sev = db.get("severity", "UNKNOWN").upper()

        refs = [ref.get("url", "") for ref in v.get("references", []) if ref.get("url")]
        advisory = next((u for u in refs if "opencart.com" in u or "github.com/advisories" in u), refs[0] if refs else "")
        fixed = None
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev and ev["fixed"]:
                        fixed = ev["fixed"]
        summary = v.get("summary", "")[:140]
        return Vuln(
            id=v.get("id", ""),
            name=summary,
            cve=cves[0] if cves else v.get("id", ""),
            link=advisory,
            severity=sev,
            privileges="n",
            cvss_score=cvss_score,
            fixed_version=fixed,
            poc=[],
            published=v.get("published", "")[:10] if v.get("published") else '',
            package="opencart"
        )