import re
from lib.colors import C, ok, warn, section, print_vuln
from lib.http import get
from lib.paths import check_paths, PRESTASHOP_SENSITIVE_PATHS
from lib.vuln import check_vulns_friendsofphp
from modules.base import BaseModule

class PrestaShopModule(BaseModule):
    def __init__(self, base_url, cms_info):
        super().__init__(base_url, cms_info)
        if not self.version:
            self.version = self._extract_prestashop_version()
            self.result.version = self.version

    def scan(self):
        self._paths_scan()
        self._core_scan()
        self._modules_scan()
        self._authors_scan()
        return self.result

    def _paths_scan(self):
        section("Exposed Paths")
        findings = check_paths(self.base, PRESTASHOP_SENSITIVE_PATHS)
        if not findings:
            ok("No obviously exposed sensitive paths")
        for p in findings:
            col = {"LOW": C.YELLOW, "MEDIUM": C.ORANGE, "HIGH": C.RED, "CRITICAL": C.RED}.get(p["severity"], C.WHITE)
            print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")
        self.result.paths = findings

    def _extract_prestashop_version(self):
        base = self.base
        html = self.html
        version = None
        m = re.search(r'<meta name="generator" content="PrestaShop ([^"]+)"', html, re.I)
        if m:
            return m.group(1)
        r = get(base + "/classes/Configuration.php")
        if r and r.status_code == 200:
            m = re.search(r"_PS_VERSION_\s*=\s*'([^']+)'", r.text)
            if m:
                return m.group(1)
        r = get(base + "/config/defines.inc.php")
        if r and r.status_code == 200:
            m = re.search(r"_PS_VERSION_\s*=\s*'([^']+)'", r.text)
            if m:
                return m.group(1)
        m = re.search(r'var\s+prestashop\s*=\s*{[^}]*"version"\s*:\s*"([^"]+)"', html, re.I)
        if m:
            return m.group(1)
        return None

    def _core_scan(self):
        version = self.version
        section("PrestaShop Core")
        if not version:
            warn("Core version not detected")
            return
        ok(f"Version: {C.BOLD}{version}{C.RST}")
        all_vulns = check_vulns_friendsofphp('prestashop', 'prestashop/prestashop', version)
        if not all_vulns:
            warn("No known vulnerabilities found for this version")
            return
        seen = {}
        for v in all_vulns:
            key = v.cve if v.cve else v.id
            if key not in seen:
                seen[key] = v
        for v in seen.values():
            self.result.vulns.append(v)
            print_vuln(v)

    def _modules_scan(self):
        section("Modules (PrestaShop)")
        warn("PrestaShop modules enumeration not implemented yet")

    def _authors_scan(self):
        section("Authors")
        authors = set()
        r = get(self.base + "/api/employees")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for user in data.get("employees", []):
                    name = user.get("firstname", "") + " " + user.get("lastname", "")
                    if name.strip():
                        authors.add(name.strip())
                        print(f"    {C.WHITE}{name.strip()}{C.RST}")
            except:
                pass
        if not authors:
            warn("No authors found")
        self.result.authors = list(authors)