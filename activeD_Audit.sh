#!/bin/bash
#===============================================================================
# BLOODHOUND COLLECTOR
# Usage: ./bloodhound_collector.sh <username> <dc_ip>
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <dc_ip>"
    echo ""
    echo "Exemple: $0 admin 192.168.1.10"
    exit 1
fi

USER="$1"
DC_IP="$2"

# Saisie sécurisée du mot de passe
echo -n "Password: "
read -s PASSWORD
echo ""

if [ -z "$PASSWORD" ]; then
    print_error "Mot de passe requis"
    exit 1
fi

# Vérifier bloodhound-python
if ! command -v bloodhound-python &>/dev/null; then
    print_error "bloodhound-python non installé"
    echo "pip install bloodhound --break-system-packages"
    exit 1
fi

# Auto-détection du domaine
print_info "Détection du domaine AD..."

DOMAIN=""

# Méthode 1: ldapsearch
if command -v ldapsearch &>/dev/null && [ -z "$DOMAIN" ]; then
    DOMAIN=$(ldapsearch -x -H "ldap://${DC_IP}" -s base defaultNamingContext 2>/dev/null | grep "defaultNamingContext:" | sed 's/defaultNamingContext: //;s/DC=//g;s/,/./g')
fi

# Méthode 2: nmap
if command -v nmap &>/dev/null && [ -z "$DOMAIN" ]; then
    DOMAIN=$(nmap -p 389 --script ldap-rootdse "${DC_IP}" 2>/dev/null | grep -i "ldapServiceName" | grep -oP '(?<=@)[^,]+' | head -1 | tr '[:upper:]' '[:lower:]')
fi

# Méthode 3: netexec/crackmapexec
if [ -z "$DOMAIN" ]; then
    if command -v netexec &>/dev/null; then
        DOMAIN=$(netexec smb "${DC_IP}" 2>/dev/null | grep -oP '(?<=domain:)[^\)]+' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
    elif command -v crackmapexec &>/dev/null; then
        DOMAIN=$(crackmapexec smb "${DC_IP}" 2>/dev/null | grep -oP '(?<=domain:)[^\)]+' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
    fi
fi

if [ -z "$DOMAIN" ]; then
    print_error "Impossible de détecter le domaine"
    echo "Installer ldap-utils: apt install ldap-utils"
    exit 1
fi

DOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
print_success "Domaine détecté: ${DOMAIN}"

# Récupérer le FQDN du DC
print_info "Résolution du DC..."
DC_FQDN=$(nslookup "${DC_IP}" "${DC_IP}" 2>/dev/null | grep -i "name" | head -1 | awk '{print $NF}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')

if [ -z "${DC_FQDN}" ] || [[ ! "${DC_FQDN}" == *"."* ]]; then
    DC_FQDN="dc.${DOMAIN}"
fi

# Ajouter au /etc/hosts si nécessaire
if ! grep -q "${DC_FQDN}" /etc/hosts 2>/dev/null; then
    print_info "Ajout de ${DC_FQDN} dans /etc/hosts..."
    echo "${DC_IP} ${DC_FQDN}" >> /etc/hosts
    print_success "Entrée DNS ajoutée"
fi

print_success "DC: ${DC_FQDN}"

OUTPUT_DIR="./bloodhound_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${OUTPUT_DIR}"

echo ""
print_info "User   : ${USER}"
print_info "Domain : ${DOMAIN}"
print_info "DC     : ${DC_IP} → ${DC_FQDN}"
print_info "Output : ${OUTPUT_DIR}"
echo ""
print_info "🚀 Collecte en cours..."

cd "${OUTPUT_DIR}"

bloodhound-python -c All -d "${DOMAIN}" -u "${USER}" -p "${PASSWORD}" -dc "${DC_FQDN}" -ns "${DC_IP}" --zip 2>&1 | tee bloodhound.log

PASSWORD=""
unset PASSWORD

echo ""
if ls *.zip 1>/dev/null 2>&1; then
    print_success "Collecte réussie!"
    ls -lh *.zip *.json 2>/dev/null
else
    print_error "Échec - voir bloodhound.log"
    tail -10 bloodhound.log
fi
