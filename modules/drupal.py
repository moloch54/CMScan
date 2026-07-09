import os
import re
import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.colors import C, sev_color, sev_label, ok, warn, section, print_vuln, info
from lib.version import version_le, version_ge, parse_version
from lib.http import get, _cmseek_getsource
from lib.paths import check_paths, DRUPAL_SENSITIVE_PATHS
from lib.vuln import check_vulns_friendsofphp
from modules.base import BaseModule, Vuln

import sys
VERBOSE = getattr(sys.modules.get('__main__'), 'VERBOSE', False)

class DrupalModule(BaseModule):
    def __init__(self, base_url, cms_info):
        super().__init__(base_url, cms_info)
        self.verbose = VERBOSE  # variable globale importée
        self.OSV_BATCH = "https://api.osv.dev/v1/querybatch"
        self.OSV_QUERY = "https://api.osv.dev/v1/query"
        self.OSV_VULN  = "https://api.osv.dev/v1/vulns/{}"
        detailed_version = self._extract_drupal_version()
        if detailed_version:
            if not self.version or len(self.version.split('.')) < len(detailed_version.split('.')):
                if VERBOSE:
                    print(f"[VERBOSE] Drupal: version améliorée: {self.version} -> {detailed_version}")
                self.version = detailed_version
                self.result.version = self.version

    def scan(self):
        detailed_version = self._extract_drupal_version()
        if detailed_version:
            if not self.version or len(self.version.split('.')) < len(detailed_version.split('.')):
                print(f"[DEBUG] Drupal: version améliorée: {self.version} -> {detailed_version}")
                self.version = detailed_version
                self.result.version = self.version
                self.cms_info_version = detailed_version

        self._paths_scan()
        self._core_scan()
        self._modules_scan()
        self._authors_scan()
        return self.result

    def _paths_scan(self):
        from lib.paths import check_paths, DRUPAL_SENSITIVE_PATHS
        from lib.colors import section, ok, sev_color
        section("Exposed Paths")
        findings = check_paths(self.base, DRUPAL_SENSITIVE_PATHS, home_content=self.html)
        if not findings:
            ok("No obviously exposed sensitive paths")
        for p in findings:
            col = sev_color(p["severity"])
            print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")
        self.result.paths = findings

    def _extract_drupal_version(self):
        import sys
        main = sys.modules.get('__main__')
        verbose = getattr(main, 'VERBOSE', False) if main else False

        base = self.base
        html = self.html
        candidates = []

        if verbose:
            print("[VERBOSE] Drupal: extraction de la version...")

        # 1. CHANGELOG
        for p in ("/core/CHANGELOG.txt", "/CHANGELOG.txt"):
            cr = get(base + p)
            if cr and cr.status_code == 200:
                m = re.search(r"Drupal (\d+\.\d+\.\d+)", cr.text)
                if m:
                    candidates.append(m.group(1))
                    if verbose:
                        print(f"[VERBOSE]   CHANGELOG: {m.group(1)}")

        # 2. package.json
        pj = get(base + "/core/package.json")
        if pj and pj.status_code == 200:
            try:
                pkg = json.loads(pj.text)
                v = pkg.get("version", "")
                if re.match(r"\d+\.\d+\.\d+", v):
                    candidates.append(v)
                    if verbose:
                        print(f"[VERBOSE]   package.json: {v}")
            except:
                pass

        # 3. drupalSettings
        m = re.search(r'drupalSettings\.data[^}]*"version"\s*:\s*"(\d+\.\d+\.\d+)"', html)
        if m:
            candidates.append(m.group(1))
            if verbose:
                print(f"[VERBOSE]   drupalSettings: {m.group(1)}")

        # 4. assets (home)
        versions = re.findall(r"/core/[^\x22\x27]+[?&]v=(\d+\.\d+\.\d+)", html)
        if versions:
            candidates.extend(versions)
            if verbose:
                print(f"[VERBOSE]   assets (home): {', '.join(set(versions))}")

        # 5. meta generator (page d'accueil)
        m = re.search(r'<meta name="Generator" content="Drupal ([\d.]+)"', html, re.I)
        if m and "." in m.group(1):
            candidates.append(m.group(1))
            if verbose:
                print(f"[VERBOSE]   meta generator: {m.group(1)}")

        # 6. X-Generator header
        gen = {k.lower(): v for k, v in self.headers.items()}.get("x-generator", "")
        if gen:
            m = re.search(r"Drupal (\d+\.?[\d.]*)", gen, re.I)
            if m:
                candidates.append(m.group(1).rstrip("."))
                if verbose:
                    print(f"[VERBOSE]   X-Generator: {m.group(1).rstrip('.')}")

        # 7. /core/install.php (avec comptage de fréquence)
        if verbose:
            print("[VERBOSE]   /core/install.php: tentative...")
        install = get(base + "/core/install.php")
        if install and install.status_code == 200:
            install_html = install.text
            if verbose:
                print("[VERBOSE]   /core/install.php: accessible (200 OK)")
            # Compteur de versions dans les assets de install.php
            install_versions = {}
            for src in re.findall(r'<script[^>]*src="([^"]+)"', install_html):
                m = re.search(r'[?&]v=([\d.]+)', src)
                if m:
                    ver = m.group(1)
                    # Ne compter que les assets du core Drupal, pas les vendors
                    if '/core/' in src and '/vendor/' not in src:
                        install_versions[ver] = install_versions.get(ver, 0) + 1
            if install_versions:
                best_install = max(install_versions, key=install_versions.get)
                candidates.append(best_install)
                if verbose:
                    print(f"[VERBOSE]   install.php version la plus fréquente: {best_install} ({install_versions[best_install]} occurrences)")
            # (on garde aussi les autres méthodes: meta, text, etc.)
            inst_versions = re.findall(r"/core/[^\x22\x27]+[?&]v=(\d+\.\d+\.\d+)", install_html)
            if inst_versions:
                candidates.extend(inst_versions)
                if verbose:
                    print(f"[VERBOSE]   install.php assets: {', '.join(set(inst_versions))}")
            # Meta generator de install.php
            m = re.search(r'<meta name="Generator" content="Drupal ([\d.]+)"', install_html, re.I)
            if m and "." in m.group(1):
                candidates.append(m.group(1))
                if verbose:
                    print(f"[VERBOSE]   install.php meta: {m.group(1)}")
            # Texte "Drupal X.Y.Z"
            m = re.search(r'Drupal\s+(\d+\.\d+\.\d+)', install_html, re.I)
            if m:
                candidates.append(m.group(1))
                if verbose:
                    print(f"[VERBOSE]   install.php text: {m.group(1)}")
            # Version majeure
            m = re.search(r'Drupal\s+(\d+)', install_html, re.I)
            if m:
                candidates.append(m.group(1) + ".0.0")
                if verbose:
                    print(f"[VERBOSE]   install.php major: {m.group(1)}.0.0")
        else:
            if verbose:
                print(f"[VERBOSE]   /core/install.php: code {install.status_code if install else 'N/A'}")

        # Filtrer les versions vides
        candidates = [v for v in candidates if v and re.search(r'\d', v)]
        if not candidates:
            if verbose:
                print("[VERBOSE]   Aucune version trouvée.")
            return None

        # NOUVEAU : compter les fréquences et prendre la plus fréquente
        from collections import Counter
        freq = Counter(candidates)
        # Si une version apparaît plus d'une fois ou qu'elle est la seule, on la prend
        if len(freq) == 1:
            best = next(iter(freq))
        else:
            # Prendre celle avec le plus grand nombre d'occurrences
            best = max(freq, key=freq.get)
        if verbose:
            print(f"[VERBOSE]   Version la plus fréquente: {best} ({freq[best]} occurrences parmi {len(candidates)} candidats)")

        # Si la version la plus fréquente est < 7 (ex: 4.0.0), on essaie de trouver une majeure >= 7
        if best.startswith(('0.', '1.', '2.', '3.', '4.', '5.', '6.')):
            # Filtrer les versions avec majeure >= 7
            drupal_versions = [v for v in candidates if v.startswith(('7.', '8.', '9.', '10.', '11.'))]
            if drupal_versions:
                # Prendre la plus fréquente parmi celles-ci
                drupal_freq = Counter(drupal_versions)
                best = max(drupal_freq, key=drupal_freq.get)
                if verbose:
                    print(f"[VERBOSE]   Version Drupal la plus fréquente: {best} ({drupal_freq[best]} occurrences)")

        return best

        def version_parts(v):
            return len(v.split('.'))

        best = max(candidates, key=version_parts)
        if VERBOSE:
            print(f"[VERBOSE]   Meilleure version: {best} (parmi {len(candidates)} candidats)")
        return best


    def _core_scan(self):
        version = self.version
        section("Drupal Core")
        if version:
            ok(f"Version: {C.BOLD}{version}{C.RST}")
            # Vérifier via OSV
            ids_raw = []
            try:
                payload = {"version": version, "package": {"name": "drupal/core", "ecosystem": "Packagist"}}
                r = get(self.OSV_QUERY, json=payload)
                if r and r.status_code == 200:
                    ids_raw = r.json().get("vulns", [])
            except: pass
            if ids_raw:
                all_ids = [v.get("id") for v in ids_raw if v.get("id")]
                full_records = {}
                with ThreadPoolExecutor(max_workers=10) as ex:
                    futs = {ex.submit(self._osv_fetch_full, vid): vid for vid in all_ids}
                    for fut in as_completed(futs, timeout=20):
                        vid = futs[fut]
                        try:
                            rec = fut.result(timeout=2)
                            if rec:
                                full_records[vid] = rec
                        except: pass
                core_vulns_raw = [full_records[vid] for vid in all_ids if vid in full_records]
                _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
                core_parsed = [self._parse_osv_vuln(v, "drupal/core") for v in core_vulns_raw]
                _seen_cve = {}
                for vuln in core_parsed:
                    key = vuln.cve or vuln.id
                    if key not in _seen_cve or _sev_order.get(vuln.severity, 4) < _sev_order.get(_seen_cve[key].severity, 4):
                        _seen_cve[key] = vuln
                core_parsed = sorted(_seen_cve.values(), key=lambda x: _sev_order.get(x.severity, 4))
                for v in core_parsed:
                    self.result.vulns.append(v)
                    print_vuln(v)
        else:
            warn("Core version not detected")

    def _modules_scan(self):
        html = self.html
        modules = self._extract_drupal_modules()
        contrib_mods = sorted(n for n, i in modules.items() if i["contrib"] == "contrib" and i["type"] == "module")
        contrib_themes = sorted(n for n, i in modules.items() if i["contrib"] == "contrib" and i["type"] == "theme")
        custom_items = sorted(n for n, i in modules.items() if i["contrib"] == "custom")
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
        osv_results = self._osv_query_packages([f"drupal/{m}" for m in contrib_mods]) if contrib_mods else {}
        for name in contrib_mods:
            ver = modules[name]["version"]
            pkg = f"drupal/{name}"
            vulns_raw = osv_results.get(pkg, []) if ver else []
            print(f"  {C.WHITE}{C.BOLD}{name}{C.RST}  {C.DIM}{ver or '?'}{C.RST}", flush=True)
            if not vulns_raw: continue
            _sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            parsed = [self._parse_osv_vuln(v, pkg) for v in vulns_raw]
            _seen = {}
            for vuln in parsed:
                key = vuln.cve or vuln.id
                if key not in _seen or _sev_ord.get(vuln.severity, 4) < _sev_ord.get(_seen[key].severity, 4):
                    _seen[key] = vuln
            parsed = sorted(_seen.values(), key=lambda x: _sev_ord.get(x.severity, 4))
            for v in parsed:
                self.result.vulns.append(v)
                print_vuln(v)

    def _authors_scan(self):
        section("Authors")
        authors = {}
        # JSON API
        r = get(self.base + "/jsonapi/user/user")
        if r and r.status_code == 200:
            try:
                data = r.json().get("data", [])
                for u in data[:20]:
                    name = u.get("attributes", {}).get("name", "")
                    if name:
                        authors[f"json_{name}"] = name
            except: pass
        # Pages utilisateur
        for i in range(1, 11):
            r = get(self.base + f"/user/{i}")
            if r and r.status_code == 200:
                m = re.search(r'<h1[^>]*>([^<]+)</h1>', r.text, re.I)
                if m:
                    name = m.group(1).strip()
                    if name and name not in authors.values():
                        authors[f"user_{i}"] = name
        # RSS
        r = get(self.base + "/rss.xml")
        if r and r.status_code == 200:
            feed_authors = re.findall(r'<dc:creator>([^<]+)<', r.text)
            for a in feed_authors:
                if a not in authors.values():
                    authors[f"feed_{a}"] = a
        if authors:
            for uid, name in sorted(authors.items()):
                print(f"    {C.WHITE}{uid}:{C.RST} {name}")
                self.result.authors.append(name)
        else:
            warn("No authors found")

    def _osv_fetch_full(self, vuln_id):
        try:
            r = get(self.OSV_VULN.format(vuln_id))
            if r and r.status_code == 200:
                return r.json()
        except: pass
        return {}

    def _osv_query_packages(self, packages):
        if not packages: return {}
        queries = [{"package": {"name": p, "ecosystem": "Packagist"}} for p in packages]
        try:
            r = get(self.OSV_BATCH, json={"queries": queries})
            if r and r.status_code != 200: return {}
            pkg_ids = {}
            for i, item in enumerate(r.json().get("results", [])):
                ids = [v.get("id") for v in item.get("vulns", []) if v.get("id")]
                if ids:
                    pkg_ids[packages[i]] = ids
        except: return {}
        if not pkg_ids: return {}
        all_ids = list({vid for ids in pkg_ids.values() for vid in ids})
        id_to_full = {}
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(self._osv_fetch_full, vid): vid for vid in all_ids}
            for fut in as_completed(futs, timeout=20):
                vid = futs[fut]
                try:
                    full = fut.result(timeout=2)
                    if full: id_to_full[vid] = full
                except: pass
        out = {}
        for pkg, ids in pkg_ids.items():
            full_vulns = [id_to_full[vid] for vid in ids if vid in id_to_full]
            if full_vulns: out[pkg] = full_vulns
        return out

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
            except: pass
            m = re.search(r"(\d+\.\d+)$", score_raw)
            if m:
                cvss_score = float(m.group(1)); break
        if cvss_score is None:
            for key in ("cvss", "cvss_score", "cvss_v3", "base_score"):
                try:
                    cvss_score = float(db[key]); break
                except: pass
        if cvss_score is None:
            for aff in v.get("affected") or []:
                aff_db = aff.get("database_specific") or {}
                for key in ("cvss", "cvss_score", "base_score"):
                    try:
                        cvss_score = float(aff_db[key]); break
                    except: pass
                if cvss_score is not None: break
        if cvss_score is not None:
            if cvss_score >= 9.0:   sev = "CRITICAL"
            elif cvss_score >= 7.0: sev = "HIGH"
            elif cvss_score >= 4.0: sev = "MEDIUM"
            else:                   sev = "LOW"
        if sev == "UNKNOWN":
            sev = SEV_MAP.get((db.get("severity") or "").lower(), "UNKNOWN")
        if sev == "UNKNOWN" and v.get("id","").startswith("DRUPAL-"):
            sev = "MEDIUM"
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

    def _extract_drupal_modules(self):
        found = {}
        pages = ["/", "/user/login", "/node"]
        type_pat = re.compile(r'(modules/contrib|modules/custom|themes/contrib|themes/custom)/([a-z0-9_\-]+)/', re.I)
        for page in pages:
            r = get(self.base + page)
            src = r.text if r else self.html
            for m in type_pat.finditer(src):
                kind = "module" if "module" in m.group(1) else "theme"
                contrib = "contrib" if "contrib" in m.group(1) else "custom"
                name = m.group(2).lower()
                if name not in found:
                    found[name] = {"type": kind, "contrib": contrib, "version": "", "paths": set()}
                found[name]["paths"].add(m.group(0))
        def fetch_ver(item):
            name, info = item
            return (name, self._fetch_drupal_module_version(name, info["type"]))
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(fetch_ver, item): item[0] for item in found.items() if item[1]["contrib"] == "contrib"}
            try:
                for fut in as_completed(futs, timeout=30):
                    try:
                        name, ver = fut.result(timeout=5)
                        if ver:
                            found[name]["version"] = ver
                    except TimeoutError:
                        continue
                    except Exception:
                        continue
            except TimeoutError:
                pass
        for v in found.values():
            v["paths"] = list(v["paths"])
        return found

    def _fetch_drupal_module_version(self, name, kind):
        paths = [
            f"/modules/contrib/{name}/{name}.info.yml",
            f"/themes/contrib/{name}/{name}.info.yml",
            f"/modules/contrib/{name}/{name}.info",
            f"/themes/contrib/{name}/{name}.info",
        ]
        for p in paths:
            try:
                r = get(self.base + p)
                if r and r.status_code == 200:
                    m = re.search(r"version\s*[:=]\s*['\"\s]*([\d]+\.x-[\d]+\.[\d]+|[\d]+\.[\d]+\.[\d]+)", r.text)
                    if m: return m.group(1)
            except: pass
        return ""