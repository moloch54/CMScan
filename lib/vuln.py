import os
import json
from lib.colors import sev_label
from modules.base import Vuln

FOPHP_DIR = "vulnDatabase/friendsOfPhp"

def check_vulns_friendsofphp(cms_group, package, version):
    if not version:
        return []
    repo_path = FOPHP_DIR
    file_path = os.path.join(repo_path, cms_group, package, f"{version}.json")
    if not os.path.exists(file_path):
        if cms_group == 'drupal' and package == 'drupal/drupal':
            alt = os.path.join(repo_path, 'drupal', 'core', f"{version}.json")
            if os.path.exists(alt):
                file_path = alt
        if not os.path.exists(file_path):
            return []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except:
        return []
    vulns = []
    for vuln in data.get('advisories', []):
        cve = vuln.get('cve', '')
        if not cve:
            cve = vuln.get('title', '')[:20]
        sev_raw = vuln.get('severity', 'medium').lower()
        sev = sev_label(sev_raw)
        cvss = vuln.get('cvss', None)
        if cvss:
            try:
                cvss = float(cvss)
            except:
                cvss = None
        fixed = ''
        branches = vuln.get('branches', {})
        if branches:
            for branch, info in branches.items():
                if 'versions' in info and info['versions']:
                    fixed = info['versions'][0]
                    break
        vulns.append(Vuln(
            id=cve,
            name=vuln.get('title', ''),
            cve=cve,
            link=vuln.get('link', ''),
            severity=sev,
            privileges='n',
            cvss_score=cvss,
            fixed_version=fixed,
            poc=[],
            published=vuln.get('published', '')[:10] if vuln.get('published') else '',
            package=package
        ))
    return vulns

def update_friendsofphp_db():
    import subprocess
    import os
    import shutil
    from lib.colors import ok, warn, info
    print("[*] Updating FriendsOfPHP security-advisories...")
    repo_path = FOPHP_DIR
    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", "https://github.com/FriendsOfPHP/security-advisories", repo_path], check=True)
            ok("Cloned FriendsOfPHP repository")
        except Exception as e:
            warn(f"Clone failed: {e}")
            return
    else:
        try:
            lock_path = os.path.join(repo_path, ".git", "index.lock")
            if os.path.exists(lock_path):
                os.remove(lock_path)
                info("Removed index.lock")
            subprocess.run(["git", "-C", repo_path, "pull"], check=True)
            ok("Updated FriendsOfPHP repository")
        except Exception as e:
            warn(f"Pull failed: {e}, removing and recloning...")
            shutil.rmtree(repo_path)
            try:
                subprocess.run(["git", "clone", "https://github.com/FriendsOfPHP/security-advisories", repo_path], check=True)
                ok("Recloned FriendsOfPHP repository")
            except Exception as e2:
                warn(f"Reclone failed: {e2}")