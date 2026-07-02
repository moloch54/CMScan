from lib.vuln import VulnerabilityResult

class MagentoModule:
    def __init__(self, base, cms_info):
        self.base = base
        self.cms_info = cms_info
        self.vulns = []

    def scan(self):
        # placeholder initial
        # tu ajouteras CVE / plugins / configs plus tard
        return VulnerabilityResult(
            cms="magento",
            version=self.cms_info.get("version"),
            vulns=self.vulns
        )