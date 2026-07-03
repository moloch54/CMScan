# CMScan

**CMScan** est un scanner de sécurité unifié pour sites WordPress, Drupal, Joomla et PrestaShop.  
Il détecte les versions, énumère les utilisateurs, vérifie les vulnérabilités et exporte les résultats en CSV.

## Fonctionnalités

- ✅ Détection de 5 CMS : WordPress, Drupal, Joomla, PrestaShop, Magento
- ✅ Énumération des utilisateurs (méthodes WP, Drupal, Joomla, PrestaShop)
- ✅ Vérification des vulnérabilités via :
    - [wpvulnerability.net](https://www.wpvulnerability.net/) (WordPress)
    - [OSV.dev](https://osv.dev/) (Drupal)
    - [FriendsOfPHP](https://github.com/FriendsOfPHP/security-advisories) (WP, Drupal, Joomla, PrestaShop)
    - [NVD API](https://nvd.nist.gov/developers/vulnerabilities) (Joomla)
- ✅ Détection des chemins sensibles (wp-config, git, env, etc.)
- ✅ Audit des en‑têtes de sécurité (HSTS, CSP, X‑Frame‑Options, etc.)
- ✅ Recherche d’exploits via Searchsploit
- ✅ Export CSV complet
- ✅ Support du mode `--host` pour serveurs mutualisés
- ✅ Compteur de requêtes HTTP (hors API externes)
- ✅ Gestion des 403 via rotation d’user‑agents

## Installation

### Via l'installateur (recommandé)

```bash
git clone https://github.com/moloch54/CMScan
cd CMScan
chmod +x install.sh
./install.sh
