#!/bin/bash
#===============================================================================
# AD AUDIT FRAMEWORK — DEPENDENCY INSTALLER v4.0
#
# Supports: Debian/Kali/Ubuntu, Arch, Fedora/RHEL
# Usage: sudo ./requirements.sh [--check-only]
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }

CHECK_ONLY=false
[[ "$1" == "--check-only" ]] && CHECK_ONLY=true

#===============================================================================
# OS DETECTION
#===============================================================================

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_NAME="${PRETTY_NAME}"
    elif command -v lsb_release &>/dev/null; then
        OS_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        OS_NAME=$(lsb_release -sd)
    else
        OS_ID="unknown"
        OS_NAME="Unknown"
    fi
    print_info "Système détecté: ${OS_NAME} (${OS_ID})"
}

#===============================================================================
# PACKAGE MANAGER
#===============================================================================

install_system_packages() {
    local packages=("python3" "python3-pip" "ldap-utils" "nmap" "dnsutils" "tar" "gnupg")

    case "${OS_ID}" in
        debian|ubuntu|kali|parrot|linuxmint)
            print_info "Gestionnaire: apt"
            apt update -qq 2>/dev/null
            for pkg in "${packages[@]}"; do
                if dpkg -l "${pkg}" &>/dev/null; then
                    print_success "${pkg}: déjà installé"
                else
                    apt install -y "${pkg}" >/dev/null 2>&1 && \
                        print_success "${pkg}: installé" || \
                        print_warning "${pkg}: échec installation"
                fi
            done
            ;;
        arch|manjaro)
            print_info "Gestionnaire: pacman"
            pacman -Sy --noconfirm python python-pip openldap nmap bind gnupg tar >/dev/null 2>&1
            print_success "Paquets système installés"
            ;;
        fedora|rhel|centos|rocky|alma)
            print_info "Gestionnaire: dnf"
            dnf install -y python3 python3-pip openldap-clients nmap bind-utils tar gnupg2 >/dev/null 2>&1
            print_success "Paquets système installés"
            ;;
        *)
            print_warning "OS non reconnu (${OS_ID}). Installez manuellement: ${packages[*]}"
            ;;
    esac
}

#===============================================================================
# PYTHON PACKAGES
#===============================================================================

install_python_packages() {
    local pip_packages=(
        "bloodhound==1.7.2"
        "impacket>=0.11.0"
        "ldap3>=2.9"
    )

    print_info "Installation des packages Python..."

    for pkg in "${pip_packages[@]}"; do
        local pkg_name="${pkg%%[>=<]*}"
        if python3 -c "import ${pkg_name}" 2>/dev/null; then
            print_success "${pkg_name}: déjà installé"
        else
            pip install "${pkg}" --break-system-packages -q 2>/dev/null && \
                print_success "${pkg_name}: installé" || \
                print_warning "${pkg_name}: échec (essayez: pip install ${pkg} --break-system-packages)"
        fi
    done
}

#===============================================================================
# OPTIONAL TOOLS
#===============================================================================

install_optional_tools() {
    print_info "Installation des outils optionnels..."

    # NetExec via pipx (preferred) or pip
    if command -v nxc &>/dev/null; then
        print_success "NetExec (nxc): déjà installé"
    else
        if command -v pipx &>/dev/null; then
            pipx install netexec 2>/dev/null && \
                print_success "NetExec: installé via pipx" || \
                print_warning "NetExec: échec pipx"
        else
            pip install netexec --break-system-packages -q 2>/dev/null && \
                print_success "NetExec: installé via pip" || \
                print_warning "NetExec: échec (optionnel)"
        fi
    fi

    # Certipy
    if command -v certipy &>/dev/null; then
        print_success "Certipy: déjà installé"
    else
        pip install certipy-ad --break-system-packages -q 2>/dev/null && \
            print_success "Certipy: installé" || \
            print_warning "Certipy: échec (optionnel — pour audit ADCS)"
    fi

    # enum4linux-ng
    if command -v enum4linux-ng &>/dev/null; then
        print_success "enum4linux-ng: déjà installé"
    else
        pip install enum4linux-ng --break-system-packages -q 2>/dev/null && \
            print_success "enum4linux-ng: installé" || \
            print_warning "enum4linux-ng: échec (optionnel)"
    fi
}

#===============================================================================
# VERIFICATION
#===============================================================================

verify_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  VÉRIFICATION DES OUTILS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════${NC}"

    local status=0
    local tools=(
        "nmap:CRITIQUE"
        "ldapsearch:CRITIQUE"
        "python3:CRITIQUE"
        "bloodhound-python:CRITIQUE"
        "nxc:OPTIONNEL"
        "crackmapexec:OPTIONNEL"
        "certipy:OPTIONNEL"
        "enum4linux-ng:OPTIONNEL"
        "gpg:OPTIONNEL"
    )

    for entry in "${tools[@]}"; do
        local tool="${entry%%:*}"
        local level="${entry##*:}"

        if command -v "${tool}" &>/dev/null; then
            print_success "${tool}: OK"
        else
            if [ "${level}" = "CRITIQUE" ]; then
                print_error "${tool}: MANQUANT (${level})"
                status=1
            else
                print_warning "${tool}: non trouvé (${level})"
            fi
        fi
    done

    # Python imports
    echo ""
    local py_modules=("impacket" "ldap3")
    for mod in "${py_modules[@]}"; do
        if python3 -c "import ${mod}" 2>/dev/null; then
            local ver
            ver=$(python3 -c "import ${mod}; print(getattr(${mod}, '__version__', 'OK'))" 2>/dev/null)
            print_success "Python ${mod}: ${ver}"
        else
            print_error "Python ${mod}: MANQUANT"
            status=1
        fi
    done

    echo ""
    if [ ${status} -eq 0 ]; then
        print_success "Tous les outils critiques sont disponibles ✅"
    else
        print_error "Des outils critiques sont manquants ❌"
    fi

    return ${status}
}

#===============================================================================
# MAIN
#===============================================================================

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   AD AUDIT FRAMEWORK — Dependency Installer v4.0            ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

detect_os

if [ "${CHECK_ONLY}" = true ]; then
    print_info "Mode vérification uniquement (--check-only)"
    verify_tools
    exit $?
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    print_error "Exécuter en root: sudo $0"
    exit 1
fi

install_system_packages
echo ""
install_python_packages
echo ""
install_optional_tools
echo ""
verify_tools

echo ""
print_success "Installation terminée! 🎉"
echo ""
echo -e "${BLUE}Utilisation:${NC}"
echo "  ./activeD_Audit.sh -t <DC_IP> -d <DOMAIN> -u <user>"
echo "  ./activeD_Audit.sh --config audit.conf -u <user>"
echo ""