#!/bin/bash
#===============================================================================
# BLOODHOUND DEPENDENCIES INSTALLER
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }

# Vérifier root
if [ "$EUID" -ne 0 ]; then
    print_error "Exécuter en root: sudo $0"
    exit 1
fi

echo ""
echo "=========================================="
echo "  BloodHound Dependencies Installer"
echo "=========================================="
echo ""

# Mise à jour apt
print_info "Mise à jour des paquets..."
apt update -qq

# Dépendances système
print_info "Installation des dépendances système..."
apt install -y python3 python3-pip ldap-utils nmap dnsutils > /dev/null 2>&1
print_success "Dépendances système installées"

# Python packages
print_info "Installation de bloodhound-python..."
pip install bloodhound --break-system-packages -q
print_success "bloodhound-python installé"

print_info "Installation de impacket..."
pip install impacket --break-system-packages -q
print_success "impacket installé"

print_info "Installation de ldap3..."
pip install ldap3 --break-system-packages -q
print_success "ldap3 installé"

# Vérification
echo ""
echo "=========================================="
echo "  Vérification"
echo "=========================================="

if command -v bloodhound-python &>/dev/null; then
    print_success "bloodhound-python OK"
else
    print_error "bloodhound-python FAILED"
fi

if python3 -c "import impacket" 2>/dev/null; then
    print_success "impacket OK"
else
    print_error "impacket FAILED"
fi

if python3 -c "import ldap3" 2>/dev/null; then
    print_success "ldap3 OK"
else
    print_error "ldap3 FAILED"
fi

if command -v ldapsearch &>/dev/null; then
    print_success "ldap-utils OK"
else
    print_error "ldap-utils FAILED"
fi

if command -v nmap &>/dev/null; then
    print_success "nmap OK"
else
    print_error "nmap FAILED"
fi

echo ""
print_success "Installation terminée!"