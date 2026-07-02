import csv
import os
import re
from datetime import datetime
from urllib.parse import urlparse

def sanitize_filename(name):
    """Nettoie une chaîne pour en faire un nom de fichier valide."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)[:50]

def generate_csv_filename(target, base_name="cmscan"):
    """Génère un nom de fichier CSV avec site + date/heure, dans le dossier results/."""
    parsed = urlparse(target)
    domain = parsed.netloc or target
    domain = domain.replace('www.', '').split(':')[0]
    domain = sanitize_filename(domain)
    if not domain:
        domain = "unknown"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join("results", f"{base_name}_{domain}_{timestamp}.csv")
      
def export_csv(res, outfile):
    rows = []
    for v in res.vulns:
        rows.append({
            "target": res.target,
            "cms": res.cms,
            "type": "vuln",
            "package": v.package,
            "id": v.id,
            "cve": v.cve,
            "severity": v.severity,
            "cvss": v.cvss_score or "",
            "privileges": v.privileges,
            "summary": v.name,
            "fixed": v.fixed_version or "",
            "link": v.link,
            "poc": "|".join(v.poc[:2]),
            "published": v.published,
        })
    for p in res.paths:
        rows.append({
            "target": res.target,
            "cms": res.cms,
            "type": "exposed_path",
            "package": "",
            "id": p["path"],
            "cve": "",
            "severity": p["severity"],
            "cvss": "",
            "privileges": "n",
            "summary": p["description"],
            "fixed": "",
            "link": p["url"],
            "poc": p["url"],
            "published": "",
        })
    for h in res.headers:
        rows.append({
            "target": res.target,
            "cms": res.cms,
            "type": "missing_header",
            "package": "",
            "id": h["header"],
            "cve": "",
            "severity": h["severity"],
            "cvss": "",
            "privileges": "n",
            "summary": h["issue"],
            "fixed": "",
            "link": "",
            "poc": "",
            "published": "",
        })
    if not rows:
        return
    write_hdr = not os.path.exists(outfile)
    with open(outfile, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if write_hdr:
            w.writeheader()
        w.writerows(rows)