import urllib.request
import random
import requests
import warnings
import urllib3
from http.cookiejar import CookieJar
from urllib.parse import urlparse
from lib.colors import C
import time

# Supprimer les warnings SSL
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

def _cmseek_getsource(url, ua):
    import time
    try:
        # 1. Essayer curl_cffi
        try:
            from curl_cffi import requests as cffi_requests
            r = cffi_requests.get(url, impersonate="chrome120", timeout=8, verify=False)
            if r.status_code == 200 and 'sgcaptcha' not in r.text and 'challenge' not in r.text:
                return ('1', r.text, str(r.headers), r.url)
        except:
            pass

        # 2. Essayer urllib
        ckreq = urllib.request.Request(
            url,
            data=None,
            headers={
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                'Accept-Language': 'en-US,en;q=0.8',
                'Connection': 'keep-alive'
            }
        )
        cj = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        with opener.open(ckreq, timeout=8) as response:
            source = response.read().decode('utf-8', errors='ignore')
            headers = str(response.info())
            final_url = response.geturl()
        if 'sgcaptcha' not in source and 'challenge' not in source:
            return ('1', source, headers, final_url)

        # 3. Fallback Playwright
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=ua,
                    ignore_https_errors=True,
                    extra_http_headers={
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.8',
                    }
                )
                page = context.new_page()
                page.goto(url, timeout=10000, wait_until="domcontentloaded")
                page.wait_for_timeout(3000)
                content = page.content()
                browser.close()
                return ('1', content, '', page.url)
        except ImportError:
            pass
        except Exception as e:
            return ('0', f"Playwright error: {e}", '', '')

        return ('0', 'All methods failed', '', '')
    except Exception as e:
        return ('0', str(e), '', '')
        
def normalize_url(t: str) -> str:
    t = t.strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")
