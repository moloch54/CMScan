import threading
import random
import re
from lib.http import _cmseek_getsource
from lib.colors import C, sev_color
VERBOSE = False

USER_AGENTS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; Trident/5.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)'
]

WP_SENSITIVE_PATHS = [
    ("/wp-config.php.bak",                  "wp-config backup exposed",                  "CRITICAL"),
    ("/wp-config.php~",                     "wp-config backup exposed",                  "CRITICAL"),
    ("/wp-config.php.old",                  "wp-config backup exposed",                  "CRITICAL"),
    ("/wp-config.php.save",                 "wp-config backup exposed",                  "CRITICAL"),
    ("/.git/config",                        "Git repo exposed",                          "CRITICAL"),
    ("/.env",                               ".env file exposed",                         "CRITICAL"),
    ("/wp-content/debug.log",               "debug.log exposed — may contain creds",     "CRITICAL"),
    ("/wp-content/uploads/error_log",       "PHP error_log exposed",                     "HIGH"),
    ("/xmlrpc.php",                         "xmlrpc.php accessible (brute/DoS/SSRF)",    "HIGH"),
    ("/wp-includes/",                       "wp-includes/ directory listing",            "HIGH"),
    ("/wp-content/",                        "wp-content/ directory listing",             "HIGH"),
    ("/wp-admin/install.php",               "install.php accessible — reinstall risk",   "HIGH"),
    ("/wp-admin/setup-config.php",          "setup-config.php accessible",               "HIGH"),
    ("/wp-content/uploads/.htaccess",       ".htaccess missing in uploads (PHP exec)",   "HIGH"),
    ("/wp-content/uploads/phpinfo.php",     "phpinfo.php in uploads",                    "CRITICAL"),
    ("/php.ini",                            "php.ini exposed",                           "HIGH"),
    ("/error_log",                          "error_log exposed in webroot",              "HIGH"),
    ("/wp-admin/",                          "wp-admin accessible",                       "MEDIUM"),
    ("/wp-json/wp/v2/users",                "User enumeration via REST API",             "MEDIUM"),
    ("/wp-login.php",                       "wp-login.php exposed (brute-force target)", "MEDIUM"),
    ("/wp-cron.php",                        "wp-cron.php publicly accessible",           "MEDIUM"),
    ("/wp-content/plugins/",               "plugins/ directory listing",                "MEDIUM"),
    ("/wp-content/themes/",                "themes/ directory listing",                 "MEDIUM"),
    ("/.htaccess",                          ".htaccess exposed",                         "MEDIUM"),
    ("/wp-admin/admin-ajax.php",            "admin-ajax.php exposed",                    "MEDIUM"),
    ("/readme.html",                        "Version disclosure via readme.html",        "LOW"),
    ("/license.txt",                        "license.txt exposed",                       "LOW"),
    ("/wp-mail.php",                        "wp-mail.php accessible",                    "LOW"),
    ("/wp-trackback.php",                   "wp-trackback.php accessible",               "LOW"),
]

DRUPAL_SENSITIVE_PATHS = [
    ("/CHANGELOG.txt",                   "Version disclosure",              "MEDIUM"),
    ("/core/CHANGELOG.txt",              "Version disclosure (core)",       "MEDIUM"),
    ("/.git/config",                     "Git repo exposed",                "HIGH"),
    ("/.env",                            ".env file exposed",               "HIGH"),
    ("/sites/default/settings.php",      "settings.php accessible",        "HIGH"),
    ("/update.php",                       "update.php accessible",          "HIGH"),
    ("/install.php",                      "install.php accessible",         "HIGH"),
    ("/xmlrpc.php",                       "xmlrpc.php exposed",             "MEDIUM"),
    ("/admin",                            "Admin path accessible",          "MEDIUM"),
    ("/user/register",                    "User registration open",         "LOW"),
    ("/sites/default/files/backup_migrate/", "Backup files exposed",       "HIGH"),
]

JOOMLA_SENSITIVE_PATHS = [
    ("/configuration.php",               "Configuration file exposed",                "CRITICAL"),
    ("/configuration.php.dist",          "Configuration template exposed",            "HIGH"),
    ("/.git/config",                     "Git repo exposed",                          "HIGH"),
    ("/.env",                            ".env file exposed",                         "HIGH"),
    ("/administrator/index.php",         "Admin panel accessible",                    "MEDIUM"),
    ("/administrator/logs/",             "Admin logs directory listing",              "MEDIUM"),
    ("/administrator/components/",       "Admin components directory listing",        "MEDIUM"),
    ("/modules/",                        "Modules directory listing",                 "MEDIUM"),
    ("/plugins/",                        "Plugins directory listing",                 "MEDIUM"),
    ("/templates/",                      "Templates directory listing",               "MEDIUM"),
    ("/cli/",                            "CLI directory listing",                     "LOW"),
    ("/README.txt",                      "Readme file exposed",                       "LOW"),
    ("/LICENSE.txt",                     "License file exposed",                      "LOW"),
]

PRESTASHOP_SENSITIVE_PATHS = [
    {"path": "/admin", "severity": "LOW", "description": "Admin directory"},
    {"path": "/admin-dev", "severity": "LOW", "description": "Admin dev directory"},
    {"path": "/install", "severity": "HIGH", "description": "Install directory (should be removed)"},
    {"path": "/install-dev", "severity": "HIGH", "description": "Install dev directory"},
    {"path": "/config/settings.inc.php", "severity": "HIGH", "description": "Config file with DB credentials"},
    {"path": "/config/defines.inc.php", "severity": "MEDIUM", "description": "Config defines"},
    {"path": "/classes/Configuration.php", "severity": "LOW", "description": "Configuration class"},
    {"path": "/override", "severity": "LOW", "description": "Override directory"},
    {"path": "/cache", "severity": "LOW", "description": "Cache directory"},
    {"path": "/logs", "severity": "LOW", "description": "Logs directory"},
    {"path": "/vendor", "severity": "LOW", "description": "Vendor directory"},
    {"path": "/composer.json", "severity": "LOW", "description": "Composer file"},
    {"path": "/composer.lock", "severity": "LOW", "description": "Composer lock file"},
    {"path": "/.gitignore", "severity": "LOW", "description": "Gitignore file"},
    {"path": "/.htaccess", "severity": "LOW", "description": "HTAccess file"},
    {"path": "/img/logo.jpg", "severity": "LOW", "description": "Logo image"},
    {"path": "/js/jquery/jquery-1.7.2.js", "severity": "LOW", "description": "jQuery file"},
    {"path": "/js/tools.js", "severity": "LOW", "description": "Tools JS"},
    {"path": "/themes/default/img/logo.jpg", "severity": "LOW", "description": "Default theme logo"},
]

MAGENTO_SENSITIVE_PATHS = [
    {"path": "/admin", "severity": "LOW", "description": "Admin directory"},
    {"path": "/admin-dev", "severity": "LOW", "description": "Admin dev directory"},
    {"path": "/install", "severity": "HIGH", "description": "Install directory (should be removed)"},
    {"path": "/app/etc/local.xml", "severity": "HIGH", "description": "Magento 1 config file with DB credentials"},
    {"path": "/app/etc/env.php", "severity": "HIGH", "description": "Magento 2 config file with DB credentials"},
    {"path": "/composer.json", "severity": "LOW", "description": "Composer file"},
    {"path": "/composer.lock", "severity": "LOW", "description": "Composer lock file"},
    {"path": "/.gitignore", "severity": "LOW", "description": "Gitignore file"},
    {"path": "/.htaccess", "severity": "LOW", "description": "HTAccess file"},
    {"path": "/js/varien/js.js", "severity": "LOW", "description": "Varien JS file"},
    {"path": "/skin/frontend/default/default/css/styles.css", "severity": "LOW", "description": "Default CSS"},
    {"path": "/pub/static/frontend/Magento/luma/en_US/css/styles-l.css", "severity": "LOW", "description": "Magento 2 CSS"},
]

SHOPIFY_SENSITIVE_PATHS = [
    {"path": "/admin", "severity": "MEDIUM", "description": "Admin panel"},
    {"path": "/admin/themes", "severity": "LOW", "description": "Themes management"},
    {"path": "/admin/products", "severity": "LOW", "description": "Products"},
    {"path": "/admin/collections", "severity": "LOW", "description": "Collections"},
    {"path": "/admin/customers", "severity": "LOW", "description": "Customers"},
    {"path": "/admin/orders", "severity": "LOW", "description": "Orders"},
    {"path": "/admin/settings", "severity": "MEDIUM", "description": "Settings"},
    {"path": "/admin/pages", "severity": "LOW", "description": "Pages"},
    {"path": "/admin/blog", "severity": "LOW", "description": "Blog"},
    {"path": "/admin/assets", "severity": "LOW", "description": "Assets"},
    {"path": "/admin/analytics", "severity": "LOW", "description": "Analytics"},
    {"path": "/admin/reports", "severity": "LOW", "description": "Reports"},
    {"path": "/admin/emails", "severity": "LOW", "description": "Emails"},
    {"path": "/admin/shipping", "severity": "LOW", "description": "Shipping"},
    {"path": "/admin/payments", "severity": "LOW", "description": "Payments"},
    {"path": "/admin/taxes", "severity": "LOW", "description": "Taxes"},
    {"path": "/admin/oauth", "severity": "LOW", "description": "OAuth"},
    {"path": "/admin/apps", "severity": "LOW", "description": "Apps"},
    {"path": "/admin/charges", "severity": "LOW", "description": "Charges"},
    {"path": "/admin/webhooks", "severity": "LOW", "description": "Webhooks"},
    {"path": "/cart", "severity": "LOW", "description": "Cart"},
    {"path": "/checkout", "severity": "LOW", "description": "Checkout"},
    {"path": "/collections", "severity": "LOW", "description": "Collections listing"},
    {"path": "/products", "severity": "LOW", "description": "Products listing"},
    {"path": "/pages", "severity": "LOW", "description": "Pages listing"},
    {"path": "/blogs", "severity": "LOW", "description": "Blogs"},
]

TYPO3_SENSITIVE_PATHS = [
    ("/typo3conf/LocalConfiguration.php", "TYPO3 LocalConfiguration.php (credentials)", "HIGH"),
    ("/typo3conf/AdditionalConfiguration.php", "TYPO3 AdditionalConfiguration.php", "HIGH"),
    ("/typo3/sysext/core/Classes/Information/Typo3Version.php", "TYPO3 version file (info)", "LOW"),
    ("/typo3/README.md", "TYPO3 README (version info)", "LOW"),
    ("/typo3/sysext/core/composer.json", "TYPO3 composer.json (version)", "LOW"),
    ("/typo3temp/", "TYPO3 temp folder (cache, assets)", "MEDIUM"),
    ("/typo3conf/ext/", "TYPO3 extensions folder", "MEDIUM"),
]

OPENCART_SENSITIVE_PATHS = [
    ("/config.php", "config.php exposed (credentials)", "CRITICAL"),
    ("/admin/config.php", "admin config.php exposed", "CRITICAL"),
    ("/system/startup.php", "system startup.php exposed", "HIGH"),
    ("/system/library/session.php", "session library exposed", "MEDIUM"),
    ("/system/storage/", "storage directory listing", "HIGH"),
    ("/install/", "install directory (should be removed)", "HIGH"),
    ("/admin/index.php", "admin panel accessible", "MEDIUM"),
    ("/catalog/", "catalog directory listing", "MEDIUM"),
    ("/image/", "image directory listing", "MEDIUM"),
    ("/download/", "download directory listing", "MEDIUM"),
    ("/vendor/", "vendor directory listing", "LOW"),
    ("/composer.json", "composer.json exposed", "LOW"),
    ("/composer.lock", "composer.lock exposed", "LOW"),
    ("/admin/controller/extension/", "extension directory listing", "MEDIUM"),
    ("/admin/model/extension/", "extension model listing", "MEDIUM"),
]




def _is_404(text):
    patterns = ["404 Not Found", "Page not found", "The requested URL was not found",
                "Sorry, the page you are looking for", "Error 404"]
    return any(p in text for p in patterns)

_PATH_SIGNATURES = {
    "/readme.html":                      "WordPress",
    "/license.txt":                      ["GNU", "WordPress", "MIT"],
    "/.git/config":                      "[core]",
    "/.env":                             ["APP_", "DB_", "SECRET", "PASSWORD"],
    "/wp-config.php.bak":                "DB_",
    "/wp-config.php~":                   "DB_",
    "/wp-config.php.old":                "DB_",
    "/wp-config.php.save":               "DB_",
    "/xmlrpc.php":                       "XML-RPC",
    "/wp-content/debug.log":             ["PHP", "Warning", "Error", "WordPress"],
    "/error_log":                        ["PHP", "Warning", "Error"],
    "/wp-content/uploads/error_log":     ["PHP", "Warning", "Error"],
    "/php.ini":                          ["php", "extension", "memory_limit"],
    "/wp-content/uploads/phpinfo.php":   "PHP Version",
    "/.htaccess":                        ["RewriteEngine", "Options", "Allow", "Deny"],
    "/wp-includes/":                     None,
    "/wp-content/":                      None,
    "/wp-content/plugins/":              None,
    "/wp-content/themes/":               None,
    "/wp-admin/":                        None,
    "/wp-admin/install.php":             None,
    "/wp-admin/setup-config.php":        None,
    "/wp-admin/admin-ajax.php":          None,
    "/wp-login.php":                     None,
    "/wp-cron.php":                      None,
    "/wp-mail.php":                      None,
    "/wp-trackback.php":                 None,
    "/wp-json/wp/v2/users":              None,
    "/CHANGELOG.txt":                    re.compile(r"Drupal \d+\.\d+\.\d+"),
    "/core/CHANGELOG.txt":               re.compile(r"Drupal \d+\.\d+\.\d+"),
    "/user/register":                    None,
    "/update.php":                       None,
    "/install.php":                      None,
}

def check_paths(base, path_list, home_content=None):
    findings = []
    lock = threading.Lock()

    def is_error_page(content):
        patterns = [
            "404 Not Found", "Page not found", "The requested URL was not found",
            "Sorry, the page you are looking for", "Error 404",
            "403 Forbidden", "Access denied", "Forbidden",
            "500 Internal Server Error", "Internal Server Error"
        ]
        return any(p in content for p in patterns)

    def check_one(entry):
        path, desc, sev = entry
        url = base + path
        if VERBOSE:
            print(f"[VERBOSE]   Path test: {url}")
        ua = random.choice(USER_AGENTS)
        src = _cmseek_getsource(url, ua)
        if src[0] != '1':
            if VERBOSE:
                print(f"[VERBOSE]     → {url} : source non récupérée (code {src[0]})")
            return None
        content = src[1]
        if len(content.strip()) < 20:
            if VERBOSE:
                print(f"[VERBOSE]     → {url} : contenu trop court ({len(content.strip())})")
            return None

        if is_error_page(content):
            if VERBOSE:
                print(f"[VERBOSE]     → {url} : page d'erreur (403/404/500) ignorée")
            return None

        if home_content and len(content) > 100 and content == home_content:
            if VERBOSE:
                print(f"[VERBOSE]     → {url} : redirige vers page d'accueil (identique) ignoré")
            return None
        if home_content and len(content) > 100 and len(home_content) > 100:
            if content[:200] == home_content[:200]:
                if VERBOSE:
                    print(f"[VERBOSE]     → {url} : redirige vers page d'accueil (similaire) ignoré")
                return None

        sig = _PATH_SIGNATURES.get(path)
        if sig is None:
            pass
        elif hasattr(sig, "search"):
            if not sig.search(content):
                if VERBOSE:
                    print(f"[VERBOSE]     → {url} : signature non trouvée, ignoré")
                return None
        elif isinstance(sig, list):
            if not any(kw in content for kw in sig):
                if VERBOSE:
                    print(f"[VERBOSE]     → {url} : signature non trouvée (liste), ignoré")
                return None
        else:
            if sig not in content:
                if VERBOSE:
                    print(f"[VERBOSE]     → {url} : signature '{sig}' non trouvée, ignoré")
                return None

        if VERBOSE:
            print(f"[VERBOSE]     → {url} : OK (exposé)")

        with lock:
            findings.append({
                "path": path,
                "url": url,
                "description": desc,
                "severity": sev,
                "status": 200
            })

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(check_one, entry): entry for entry in path_list}
        for future in as_completed(futures):
            try:
                future.result(timeout=8)
            except Exception:
                pass

    sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_ord.get(x["severity"], 4))
    return findings