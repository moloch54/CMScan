# CMScan

![CMScan screenshot](CMScan.png)

**CMScan** is a unified security scanner for WordPress, Drupal, Joomla, PrestaShop, Shopify, Magento, TYPO3, and OpenCart websites. 

**No api-key, no limitation**   
It detects CMS versions, enumerates users, checks for known vulnerabilities, and exports the results to CSV.

## Features

- ✅ Vulnerability checking through:
    - [wpvulnerability.net](https://www.wpvulnerability.net/)
    - [OSV.dev](https://osv.dev/)
    - [FriendsOfPHP Security Advisories](https://github.com/FriendsOfPHP/security-advisories)
    - [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- ✅ Detection of sensitive files and paths (wp-config, .git, .env, etc.)
- ✅ Security header auditing (HSTS, CSP, X-Frame-Options, etc.)
- ✅ Comprehensive CSV export
- ✅ `--host` mode support for shared hosting environments
- ✅ Automatic 403 bypass using User-Agent rotation

## Installation

### Using the installer (recommended)

```bash
git clone https://github.com/moloch54/CMScan
cd CMScan
chmod +x install.sh
./install.sh
```

## Usage

```bash
python3 CMScan.py -L target.com  
```

# 📖 CMScan Documentation

CMScan is a multi-CMS security scanner designed to detect CMS installations, versions, themes, plugins/modules, known vulnerabilities, and exposed sensitive paths.

---

# Command-line Options

| Option | Description |
|--------|-------------|
| `-L <TARGET>` | Scan a single URL or a text file containing multiple URLs. |
| `-v`, `--verbose` | Verbose mode. Display every HTTP request and detection. |
| `--force` | Force scanning of all supported CMSs, even if WordPress is detected first. |
| `--stealth` | Disable exposed-path checks to reduce the number of HTTP requests and make scans more discreet. |
| `-o`, `--output` | Output CSV filename (default: automatically generated). |
| `--update` | Update vulnerability databases (WordPress and FriendsOfPHP). |

---

# Usage Examples

### Scan a single website

```bash
python3 CMScan.py -L https://example.com
```

### Verbose mode

```bash
python3 CMScan.py -L https://example.com -v
```

### Scan multiple targets

```bash
python3 CMScan.py -L targets.txt
```

### Stealth mode

```bash
python3 CMScan.py -L https://example.com --stealth
```

### Force detection of every supported CMS

```bash
python3 CMScan.py -L https://example.com --force
```

### Combine multiple options

```bash
python3 CMScan.py -L https://example.com -v --stealth --force
```

### Update vulnerability databases

```bash
python3 CMScan.py --update
```

---

# Version Detection Priority

CMScan attempts to determine the CMS version using the following priority order:

1. `readme.txt` / `README.txt`
2. Translation files (`*.pot`, `Project-Id-Version`)
3. ES module imports (e.g. `workbox-v7.3.0`)
4. HTML meta tags and comments (passive detection)
5. `?ver=` parameters in asset URLs (fallback)

---

# Automatic Updates

CMScan can automatically check GitHub for new releases.

When a newer version is available, it downloads the update and restarts automatically.

---

# Generated Files

```
results/
└── cmscan_*.csv
```

The CSV report includes:

- CMS detection
- Version
- Themes
- Plugins / Modules
- Known vulnerabilities
- Exposed paths
- Authors
- Additional security findings

---

# Stealth Mode (`--stealth`)

Stealth mode disables exposed-path enumeration to reduce the number of HTTP requests and lower the scan footprint.

Typical skipped paths include:

- `/wp-config.php.*`
- `/.git/`
- `/.env`
- `/wp-content/debug.log`
- `/wp-content/uploads/`
- `/xmlrpc.php`
- `/wp-admin/`
- `/wp-login.php`
- `/wp-cron.php`
- `/wp-content/plugins/`
- `/wp-content/themes/`
- `/readme.html`
- `/license.txt`
- and many others.

---

# Supported CMS

| CMS | Features |
|------|----------|
| ✅ WordPress | Core version, themes, plugins, vulnerabilities |
| ✅ Drupal | Version, modules, exposed paths |
| ✅ Joomla | Version, extensions, exposed paths |
| ✅ PrestaShop | Version, modules, exposed paths |
| ✅ Magento | Version, extensions, exposed paths |
| ✅ Shopify | Theme detection |
| ✅ TYPO3 | Version, extensions |
| ✅ OpenCart | Version, extensions |

---

# Legal Notice

CMScan should only be used against systems that you own or for which you have explicit written authorization.

Unauthorized security testing may violate applicable laws.

---

# License

CMScan is released under the **MIT License**.

You are free to use, modify, and redistribute it in accordance with the license terms.
