import csv
import os
import re
from datetime import datetime
from urllib.parse import urlparse

def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)[:50]

def generate_csv_filename(target, base_name="cmscan"):
    parsed = urlparse(target)
    domain = parsed.netloc or target
    domain = domain.replace('www.', '').split(':')[0]
    domain = sanitize_filename(domain) or "unknown"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("results", exist_ok=True)
    return os.path.join("results", f"{base_name}_{domain}_{timestamp}.csv")

def export_csv(res, outfile):
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    write_hdr = not os.path.exists(outfile)
    rows = []

    # 1. Vulnérabilités
    for v in res.vulns:
        rows.append({
            "target": res.target,
            "cms": res.cms,
            "version": res.version,
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

    # 2. Auteurs
    authors = getattr(res, "authors", [])
    if authors:
        for author in authors:
            rows.append({
                "target": res.target, "cms": res.cms, "version": res.version, "type": "author",
                "summary": author, "package": "", "id": "", "cve": "", "severity": "",
                "cvss": "", "privileges": "", "fixed": "", "link": "", "poc": "", "published": "",
            })
    else:
        rows.append({
            "target": res.target, "cms": res.cms, "version": res.version, "type": "author",
            "summary": "No authors found", "package": "", "id": "", "cve": "", "severity": "",
            "cvss": "", "privileges": "", "fixed": "", "link": "", "poc": "", "published": "",
        })

    # 3. Emails
    emails = getattr(res, "emails", [])
    if emails:
        for email in emails:
            rows.append({
                "target": res.target, "cms": res.cms, "version": res.version, "type": "email",
                "summary": email, "package": "", "id": "", "cve": "", "severity": "",
                "cvss": "", "privileges": "", "fixed": "", "link": "", "poc": "", "published": "",
            })
    else:
        rows.append({
            "target": res.target, "cms": res.cms, "version": res.version, "type": "email",
            "summary": "No emails found", "package": "", "id": "", "cve": "", "severity": "",
            "cvss": "", "privileges": "", "fixed": "", "link": "", "poc": "", "published": "",
        })

    # 4. Chemins exposés
    paths = getattr(res, "paths", [])
    if paths:
        for p in paths:
            rows.append({
                "target": res.target, "cms": res.cms, "version": res.version, "type": "exposed_path",
                "summary": p.get("description", ""), "severity": p.get("severity", ""),
                "link": p.get("url", ""), "package": "", "id": p.get("path", p.get("url", "")),
                "cve": "", "cvss": "", "privileges": "", "fixed": "", "poc": "", "published": "",
            })
    else:
        rows.append({
            "target": res.target, "cms": res.cms, "version": res.version, "type": "exposed_path",
            "summary": "No exposed paths found", "severity": "", "link": "",
            "package": "", "id": "", "cve": "", "cvss": "", "privileges": "", "fixed": "", "poc": "", "published": "",
        })

    # 5. Headers
    headers = getattr(res, "headers", [])
    if headers:
        for h in headers:
            rows.append({
                "target": res.target, "cms": res.cms, "version": res.version, "type": "header",
                "summary": h.get("issue", ""), "severity": h.get("severity", ""),
                "id": h.get("header", ""), "package": "", "cve": "", "cvss": "", "privileges": "",
                "fixed": "", "link": "", "poc": "", "published": "",
            })
    else:
        rows.append({
            "target": res.target, "cms": res.cms, "version": res.version, "type": "header",
            "summary": "No header issues", "severity": "", "id": "",
            "package": "", "cve": "", "cvss": "", "privileges": "", "fixed": "", "link": "", "poc": "", "published": "",
        })

    # 6. Résumé
    rows.append({
        "target": res.target, "cms": res.cms, "version": res.version, "type": "cms_info",
        "summary": f"CMS: {res.cms} | Version: {res.version or '?'} | Authors: {len(authors)} | Emails: {len(emails)} | Paths: {len(paths)} | Vulns: {len(res.vulns)}",
        "package": "", "id": "", "cve": "", "severity": "", "cvss": "", "privileges": "", "fixed": "", "link": "", "poc": "", "published": "",
    })

    if rows:
        with open(outfile, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            if write_hdr:
                w.writeheader()
            w.writerows(rows)