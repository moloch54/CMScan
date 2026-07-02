#!/bin/bash
# ────────────────────────────────────────────────────────────────
# CMScan Installer
# Usage: ./install.sh
# ────────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║         CMScan — Installation automatique               ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Vérification de Python ──────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Vérification de Python..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!]${RESET} Python3 n'est pas installé."
    echo -e "    ${YELLOW}sudo apt install python3 python3-venv python3-pip${RESET}"
    exit 1
fi
echo -e "${GREEN}[+]${RESET} Python $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') détecté"

# ── Vérification de pip ─────────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Vérification de pip..."
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!]${RESET} pip3 non trouvé, installation..."
    sudo apt install -y python3-pip
fi
echo -e "${GREEN}[+]${RESET} pip3 disponible"

# ── Vérification de git ──────────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Vérification de git..."
if ! command -v git &> /dev/null; then
    echo -e "${YELLOW}[!]${RESET} git non trouvé, installation..."
    sudo apt install -y git
fi
echo -e "${GREEN}[+]${RESET} git disponible"

# ── Création du venv ─────────────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Création de l'environnement virtuel..."
if [ -d ".venv" ]; then
    echo -e "${YELLOW}[!]${RESET} .venv existe déjà, suppression..."
    rm -rf .venv
fi
python3 -m venv .venv
echo -e "${GREEN}[+]${RESET} .venv créé"

# ── Activation du venv ───────────────────────────────────────────
source .venv/bin/activate

# ── Mise à jour de pip ───────────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Mise à jour de pip..."
pip install --upgrade pip --quiet
echo -e "${GREEN}[+]${RESET} pip à jour"

# ── Installation des dépendances ────────────────────────────────
echo -e "${CYAN}[*]${RESET} Installation des dépendances..."
DEPS=("requests" "gitpython" "packaging" "curl-cffi" "urllib3")
for dep in "${DEPS[@]}"; do
    echo -e "    ${CYAN}→${RESET} Installation de ${YELLOW}${dep}${RESET}..."
    pip install "$dep" --quiet
done
echo -e "${GREEN}[+]${RESET} Dépendances installées"

# ── Rendre CMScan.py exécutable ─────────────────────────────────
if [ -f "CMScan.py" ]; then
    chmod +x CMScan.py
    echo -e "${GREEN}[+]${RESET} CMScan.py rendu exécutable"
    # Créer un lien symbolique pour compatibilité
    ln -sf CMScan.py cmscan.py
    echo -e "${GREEN}[+]${RESET} Lien créé : cmscan.py -> CMScan.py"
else
    echo -e "${RED}[!]${RESET} CMScan.py non trouvé !"
    exit 1
fi

# ── Création de la structure des vulnérabilités WordPress ──────
echo -e "${CYAN}[*]${RESET} Création de la structure de la base de données WordPress..."
mkdir -p vulnDatabase/{coreVuln,pluginsVuln,themesVuln,templates,spiders,exploits}
mkdir -p results
echo -e "${GREEN}[+]${RESET} Dossiers créés : coreVuln, pluginsVuln, themesVuln, templates, spiders, exploits, results"

# ── Création du fichier de suivi des mises à jour WordPress ────
if [ ! -f "last_update_vulnbase.txt" ]; then
    date +%Y-%m-%d > last_update_vulnbase.txt
    echo -e "${GREEN}[+]${RESET} Fichier last_update_vulnbase.txt créé avec la date du jour"
fi

# ── Vérification du fichier version.txt ─────────────────────────
if [ ! -f "version.txt" ]; then
    echo "0.0" > version.txt
    echo -e "${YELLOW}[!]${RESET} version.txt créé avec 0.0 par défaut"
fi

# ── Téléchargement de la base FriendsOfPHP ─────────────────────
echo -e "${CYAN}[*]${RESET} Téléchargement de la base FriendsOfPHP..."
mkdir -p vulnDatabase
cd vulnDatabase
if [ -d "friendsOfPhp" ]; then
    echo -e "${YELLOW}[!]${RESET} Base existante, mise à jour..."
    cd friendsOfPhp && git pull && cd ..
else
    git clone --depth 1 https://github.com/FriendsOfPHP/security-advisories friendsOfPhp
fi
cd ..
echo -e "${GREEN}[+]${RESET} Base FriendsOfPHP prête"

# ── Lien symbolique (optionnel) ──────────────────────────────────
if [ -d "/usr/local/bin" ]; then
    echo -e "${CYAN}[*]${RESET} Création du lien symbolique..."
    sudo ln -sf "$(pwd)/CMScan.py" /usr/local/bin/cmscan
    echo -e "${GREEN}[+]${RESET} Lien créé : ${YELLOW}cmscan${RESET}"
fi

# ── Final ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  ✅  Installation terminée avec succès !               ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Lancer CMScan :${RESET}"
echo -e "    ${YELLOW}./CMScan.py${RESET} ${CYAN}-L target.com${RESET}"
echo -e "    ${YELLOW}./cmscan.py${RESET} ${CYAN}-L target.com${RESET} (alias)"
echo -e "    ${YELLOW}cmscan${RESET} ${CYAN}-L target.com${RESET} (si lien créé)"
echo ""