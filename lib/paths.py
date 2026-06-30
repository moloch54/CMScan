import threading
import random
import re
from lib.http import _cmseek_getsource
from lib.colors import C, sev_color

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

def check_paths(base, path_list):
    findings = []
    lock = threading.Lock()
    def check_one(entry):
        path, desc, sev = entry
        ua = random.choice(["Mozilla/5.0"])
        src = _cmseek_getsource(base + path, ua)
        if src[0] != '1':
            return None
        content = src[1]
        if len(content.strip()) < 20:
            return None
        sig = _PATH_SIGNATURES.get(path)
        if sig is None:
            if _is_404(content):
                return None
        elif hasattr(sig, "search"):
            if not sig.search(content):
                return None
        elif isinstance(sig, list):
            if not any(kw in content for kw in sig):
                return None
        else:
            if sig not in content:
                return None
        with lock:
            findings.append({"path": path, "url": base + path,
                             "description": desc, "severity": sev,
                             "status": 200})
    threads = []
    for entry in path_list:
        t = threading.Thread(target=check_one, args=(entry,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=8)
    sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_ord.get(x["severity"], 4))
    return findings
