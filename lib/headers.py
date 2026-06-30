import re
from lib.colors import C, sev_color

EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS missing — MitM/downgrade risk",
    "content-security-policy":   "CSP missing — XSS risk",
    "x-frame-options":           "Clickjacking protection absent",
    "x-content-type-options":    "MIME sniffing not blocked",
    "referrer-policy":           "Referrer-Policy not set",
    "permissions-policy":        "Permissions-Policy not set",
}

def audit_headers(resp_headers: dict) -> list:
    lower = {k.lower(): v for k, v in resp_headers.items()}
    issues = []
    for h, msg in EXPECTED_HEADERS.items():
        if h not in lower:
            issues.append({"header": h, "issue": msg, "severity": "MEDIUM"})
    if "strict-transport-security" in lower:
        m = re.search(r"max-age=(\d+)", lower["strict-transport-security"])
        if m and int(m.group(1)) < 31536000:
            issues.append({"header": "strict-transport-security",
                           "issue": "HSTS max-age < 1 year", "severity": "LOW"})
    return issues

def display_headers_info(resp_headers):
    from lib.colors import C, sev_color
    lower_h = {k.lower(): v for k, v in resp_headers.items()}
    for k in ("x-generator", "x-drupal-cache", "x-frame-options",
              "x-content-type-options", "server", "x-powered-by"):
        if k in lower_h:
            print(f"  {C.DIM}{k}: {lower_h[k][:80]}{C.RST}")
