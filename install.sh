#!/bin/bash
# ────────────────────────────────────────────────────────────────
# CMScan Installer — compatible Linux / macOS / WSL
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

# ── Détection de l'OS ──────────────────────────────────────────
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    INSTALL_CMD="brew install"
else
    OS="linux"
    INSTALL_CMD="sudo apt install -y"
fi
echo -e "${CYAN}[*]${RESET} Système détecté : ${YELLOW}${OS}${RESET}"

# ── Vérification de Python ──────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Vérification de Python..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!]${RESET} Python3 n'est pas installé."
    if [[ "$OS" == "macos" ]]; then
        echo -e "    ${YELLOW}brew install python3${RESET}"
    else
        echo -e "    ${YELLOW}sudo apt install python3 python3-venv python3-pip${RESET}"
    fi
    exit 1
fi
echo -e "${GREEN}[+]${RESET} Python $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') détecté"

# ── Vérification de pip ─────────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Vérification de pip..."
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!]${RESET} pip3 non trouvé, installation..."
    if [[ "$OS" == "macos" ]]; then
        python3 -m ensurepip --upgrade
    else
        $INSTALL_CMD python3-pip
    fi
fi
echo -e "${GREEN}[+]${RESET} pip3 disponible"

# ── Vérification de git ──────────────────────────────────────────
echo -e "${CYAN}[*]${RESET} Vérification de git..."
if ! command -v git &> /dev/null; then
    echo -e "${YELLOW}[!]${RESET} git non trouvé, installation..."
    if [[ "$OS" == "macos" ]]; then
        brew install git
    else
        $INSTALL_CMD git
    fi
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

# ── Rendre CMScan.py exécutable + créer l'alias ─────────────────
if [ -f "CMScan.py" ]; then
    chmod +x CMScan.py
    echo -e "${GREEN}[+]${RESET} CMScan.py rendu exécutable"

    # Supprimer tout ancien alias cassé
    rm -f cmscan.py

    if [[ "$OS" == "macos" ]]; then
        # macOS (BSD ln) : -h empêche de suivre le lien existant
        ln -sh CMScan.py cmscan.py
    else
        # Linux / WSL (GNU ln)
        ln -sf CMScan.py cmscan.py
    fi
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

# ── Final ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  ✅  Installation terminée avec succès !               ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Lancer CMScan :${RESET}"
echo -e "    ${YELLOW}./CMScan.py${RESET} ${CYAN}-L target.com${RESET}"
echo -e "    ${YELLOW}./cmscan.py${RESET} ${CYAN}-L target.com${RESET} (alias)"
echo ""
