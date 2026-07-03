import urllib.request
import random
import requests
import warnings
import urllib3
from http.cookiejar import CookieJar
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def get(url, **kw):
    timeout = kw.get("timeout", 6)
    allow_redirects = kw.get("allow_redirects", True)
    headers = kw.get("headers", {})
    headers["User-Agent"] = random.choice(USER_AGENTS)
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=allow_redirects, headers=headers)
        return r
    except:
        return None
def is_redirect_to_home(content, home_html):
    """
    Vérifie si le contenu est celui de la page d'accueil (redirection ou rewriting).
    """
    if not home_html or not content:
        return False
    # Si les contenus sont identiques (ou très proches), on considère que c'est une redirection
    if len(content) == len(home_html) and content == home_html:
        return True
    # Si les longueurs sont proches et le titre est le même, on peut aussi détecter
    # On vérifie aussi la présence de balises communes comme <html>, <head>, etc.
    # On peut faire une comparaison de similarité simple (ex: ratio de Jaccard)
    # Ici, on va comparer les 200 premiers caractères pour éviter les différences mineures
    if len(content) > 100 and len(home_html) > 100:
        if content[:200] == home_html[:200]:
            return True
    return False
    
def _cmseek_getsource(url, ua):
    try:
        # 1. Essayer curl_cffi (si disponible)
        try:
            from curl_cffi import requests as cffi_requests
            r = cffi_requests.get(url, impersonate="chrome120", timeout=10, verify=False)
            if r.status_code == 200:
                return ('1', r.text, str(r.headers), r.url)
        except ImportError:
            pass
        except Exception:
            pass

        # 2. Fallback sur urllib.request avec ssl
        import ssl
        context = ssl._create_unverified_context()
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                'Accept-Language': 'en-US,en;q=0.8',
                'Connection': 'keep-alive'
            }
        )
        response = urllib.request.urlopen(req, timeout=10, context=context)
        source = response.read().decode('utf-8', errors='ignore')
        headers = str(response.info())
        final_url = response.geturl()
        return ('1', source, headers, final_url)
    except Exception as e:
        return ('0', str(e), '', '')

def normalize_url(t: str) -> str:
    t = t.strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")