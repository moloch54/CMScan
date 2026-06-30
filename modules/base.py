from dataclasses import dataclass, field
from typing import Optional
@dataclass
class Vuln:
    id: str; name: str; cve: str; link: str; severity: str; privileges: str
    cvss_score: Optional[float] = None; fixed_version: Optional[str] = None
    poc: list = field(default_factory=list); published: str = ""; package: str = ""
@dataclass
class ScanResult:
    target: str; cms: str = "unknown"; version: str = ""; title: str = ""
    authors: list = field(default_factory=list); emails: list = field(default_factory=list)
    vulns: list = field(default_factory=list); paths: list = field(default_factory=list)
    headers: list = field(default_factory=list); request_count: int = 0
class BaseModule:
    def __init__(self, base_url, cms_info):
        self.base = base_url
        self.version = cms_info.get("version")
        self.html = cms_info.get("html", "")
        self.headers = cms_info.get("resp_headers", {})
        self.result = ScanResult(target=base_url, cms=cms_info.get("cms","unknown"), version=self.version)
    def scan(self):
        raise NotImplementedError("Each CMS module must implement scan()")
