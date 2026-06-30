try:
    from packaging import version as pkg_version
    HAS_PKG_VERSION = True
except ImportError:
    HAS_PKG_VERSION = False
def parse_version(v: str):
    if not v: return None
    v = v.strip()
    if v.lower().startswith('v'): v = v[1:]
    if HAS_PKG_VERSION:
        try: return pkg_version.parse(v)
        except: pass
    if '-' in v: v = v.split('-')[0]
    if '+' in v: v = v.split('+')[0]
    parts = v.split('.')
    try: return tuple(int(p) for p in parts)
    except: return (0,)
def version_le(v1, v2):
    p1 = parse_version(v1); p2 = parse_version(v2)
    if p1 is None or p2 is None: return False
    if HAS_PKG_VERSION: return p1 <= p2
    return p1 <= p2
def version_ge(v1, v2):
    p1 = parse_version(v1); p2 = parse_version(v2)
    if p1 is None or p2 is None: return False
    if HAS_PKG_VERSION: return p1 >= p2
    return p1 >= p2
