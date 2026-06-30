import re

def extract_meta(base: str, html: str) -> dict:
    info = {"title": None, "description": None, "authors": [],
            "emails": [], "og": {}, "dns_prefetch": []}
    m = re.search(r"<title>([^<]+)</title>", html, re.I)
    if m: info["title"] = m.group(1).strip()
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if m: info["description"] = m.group(1).strip()[:200]
    for prop in ("og:site_name", "og:title", "article:author"):
        m = re.search(rf'property=["\']{{prop}}["\'][^>]+content=["\']([^"\']+)'.format(prop=prop), html, re.I)
        if m: info["og"][prop] = m.group(1).strip()
    info["emails"] = list(set(
        e for e in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html)
        if not e.lower().endswith((".png", ".jpg", ".css", ".js", ".svg"))
    ))[:10]
    info["dns_prefetch"] = re.findall(
        r'<link[^>]+rel=["\']dns-prefetch["\'][^>]+href=["\']([^"\']+)', html, re.I)[:5]
    return info
