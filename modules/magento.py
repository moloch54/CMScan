import re
import requests
from lib.colors import C, ok, warn, section, print_vuln
from lib.http import get
from lib.paths import check_paths, MAGENTO_SENSITIVE_PATHS
from modules.base import BaseModule, Vuln

class MagentoModule(BaseModule):
    def __init__(self, base_url, cms_info):
        super().__init__(base_url, cms_info)
        if not self.version:
            self.version = self._extract_magento_version()
            self.result.version = self.version

    def scan(self):
        self._paths_scan()
        self._core_scan()
        self._modules_scan()
        self._authors_scan()
        return self.result

    def _paths_scan(self):
        section("Exposed Paths")
        findings = check_paths(self.base, MAGENTO_SENSITIVE_PATHS, home_content=self.html)
        if not findings:
            ok("No obviously exposed sensitive paths")
        for p in findings:
            col = {"LOW": C.YELLOW, "MEDIUM": C.ORANGE, "HIGH": C.RED, "CRITICAL": C.RED}.get(p["severity"], C.WHITE)
            print(f"  {col}[{p['severity']}]{C.RST} {p['url']}  — {p['description']}")
        self.result.paths = findings

    def _extract_magento_version(self):
        base = self.base
        html = self.html
        version = None

        m = re.search(r'<meta name="generator" content="Magento ([^"]+)"', html, re.I)
        if m:
            return m.group(1)

        r = get(base + "/app/etc/local.xml")
        if r and r.status_code == 200:
            m = re.search(r'<version>([^<]+)</version>', r.text)
            if m:
                return m.group(1)

        r = get(base + "/app/etc/env.php")
        if r and r.status_code == 200:
            m = re.search(r"'version'\s*=>\s*'([^']+)'", r.text)
            if m:
                return m.group(1)

        r = get(base + "/Magento/Version")
        if r and r.status_code == 200:
            m = re.search(r'(\d+\.\d+\.\d+)', r.text)
            if m:
                return m.group(1)

        r = get(base + "/js/varien/js.js")
        if r and r.status_code == 200:
            m = re.search(r'Magento (\d+\.\d+\.\d+)', r.text)
            if m:
                return m.group(1)

        return None

    def _core_scan(self):
        version = self.version
        section("Magento Core")
        if not version:
            warn("Core version not detected")
            return
        ok(f"Version: {C.BOLD}{version}{C.RST}")

        vulns = self._fetch_vulns_from_nvd(version)

        if not vulns:
            warn("No known vulnerabilities found for this version")
            return

        for v in vulns:
            self.result.vulns.append(v)
            print_vuln(v)

    def _fetch_vulns_from_nvd(self, version):
        """Récupère les CVE pour Magento via l'API NVD"""
        vulns = []
        
        cpe_names = [
            f"cpe:2.3:a:magento:magento2:{version}:*:*:*:*:*:*:*",
            f"cpe:2.3:a:magento:magento:{version}:*:*:*:*:*:*:*",
            f"cpe:2.3:a:magento:commerce:{version}:*:*:*:*:*:*:*"
        ]
        
        for cpe in cpe_names:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for cve in data.get("vulnerabilities", []):
                        cve_data = cve.get("cve", {})
                        cve_id = cve_data.get("id", "Unknown")
                        description = cve_data.get("descriptions", [{}])[0].get("value", "No description")
                        
                        metrics = cve_data.get("metrics", {})
                        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                        
                        severity = "UNKNOWN"
                        if cvss_v3:
                            severity = cvss_v3.get("baseSeverity", "UNKNOWN")
                        elif cvss_v2:
                            severity = cvss_v2.get("severity", "UNKNOWN")
                        
                        severity_map = {
                            "CRITICAL": "CRITICAL",
                            "HIGH": "HIGH",
                            "MEDIUM": "MEDIUM",
                            "LOW": "LOW"
                        }
                        severity = severity_map.get(severity, "UNKNOWN")
                        
                        vuln = Vuln(
                            cve=cve_id,
                            description=description[:200] + ("..." if len(description) > 200 else ""),
                            severity=severity,
                            link=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        )
                        vulns.append(vuln)
                    if vulns:
                        break
            except Exception as e:
                warn(f"Error fetching NVD for {cpe}: {e}")
                continue

        if not vulns:
            keyword = f"magento {version}"
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for cve in data.get("vulnerabilities", []):
                        cve_data = cve.get("cve", {})
                        descriptions = cve_data.get("descriptions", [])
                        desc_text = " ".join([d.get("value", "") for d in descriptions])
                        if "magento" in desc_text.lower():
                            cve_id = cve_data.get("id", "Unknown")
                            severity = "UNKNOWN"
                            metrics = cve_data.get("metrics", {})
                            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                            if cvss_v3:
                                severity = cvss_v3.get("baseSeverity", "UNKNOWN")
                            severity_map = {
                                "CRITICAL": "CRITICAL",
                                "HIGH": "HIGH",
                                "MEDIUM": "MEDIUM",
                                "LOW": "LOW"
                            }
                            severity = severity_map.get(severity, "UNKNOWN")
                            vuln = Vuln(
                                cve=cve_id,
                                description=desc_text[:200] + ("..." if len(desc_text) > 200 else ""),
                                severity=severity,
                                link=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                            )
                            vulns.append(vuln)
            except Exception as e:
                warn(f"Error fetching NVD by keyword: {e}")

        seen = set()
        unique_vulns = []
        for v in vulns:
            if v.cve not in seen:
                seen.add(v.cve)
                unique_vulns.append(v)
        return unique_vulns

    def _modules_scan(self):
        section("Modules (Magento)")
        warn("Magento modules enumeration not implemented yet")

    def _authors_scan(self):
        section("Authors")
        authors = set()
        r = get(self.base + "/api/rest/customers")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for user in data.get("items", []):
                    name = user.get("firstname", "") + " " + user.get("lastname", "")
                    if name.strip():
                        authors.add(name.strip())
                        print(f"    {C.WHITE}{name.strip()}{C.RST}")
            except:
                pass
        if not authors:
            warn("No authors found")
        self.result.authors = list(authors)