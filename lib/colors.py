class C:
    RED    = "\033[91m"
    ORANGE = "\033[33m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"
    BOLD   = "\033[1m"
    RST    = "\033[0m"
def sev_color(sev: str) -> str:
    s = sev.upper()
    if s in ("CRITICAL", "C", "HIGH", "H"): return C.RED
    if s in ("MEDIUM", "M"):                return C.ORANGE
    if s in ("LOW", "L"):                   return C.YELLOW
    return C.WHITE
def sev_label(sev: str) -> str:
    MAP = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW",
           "n": "INFO", "critical": "CRITICAL", "high": "HIGH",
           "medium": "MEDIUM", "low": "LOW", "unknown": "UNKNOWN"}
    return MAP.get(sev.lower(), sev.upper())

def ok(msg):   print(f"  {C.GREEN}[+]{C.RST} {msg}")
def warn(msg): print(f"  {C.YELLOW}[-]{C.RST} {msg}")
def err(msg):  print(f"  {C.RED}[!]{C.RST} {msg}")
def section(title: str):
    print(f"{C.BLUE}{C.BOLD}[{title}]{C.RST}", flush=True)

def print_vuln(v):
    from lib.colors import C, sev_color
    col = sev_color(v.severity)
    id_str = v.cve if v.cve and v.cve != v.id else v.id
    priv = "UNAUTHENTICATED" if v.privileges in ("n", "none", "") else "AUTHENTICATED"
    priv_col = C.RED if priv == "UNAUTHENTICATED" else C.ORANGE
    if v.fixed_version:
        extra = f"  {C.DIM}<= {v.fixed_version}{C.RST}"
    elif v.cvss_score:
        extra = f"  {C.DIM}CVSS:{v.cvss_score:.1f}{C.RST}"
    else:
        extra = ""
    print(f"        {col}{C.BOLD}[{v.severity}]{C.RST}  "
          f"{priv_col}[ {priv} ]{C.RST}  "
          f"{C.WHITE}{C.BOLD}{id_str}{C.RST}{extra}")
    if v.name:
        print(f"                  {C.DIM}{v.name}{C.RST}")
    if v.link:
        print(f"                  {C.DIM}{v.link}{C.RST}")
    for p in v.poc[:2]:
        print(f"                  {C.ORANGE}⚡ {p}{C.RST}")

def info(msg): print(f"  {C.DIM}    {msg}{C.RST}")

def info(msg): print(f"  {C.DIM}    {msg}{C.RST}")
