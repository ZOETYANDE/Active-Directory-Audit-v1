#!/bin/bash
# lib/config.sh — CLI parsing, config loading, auto-detection, requirements, environment setup

#===============================================================================
# AUTO-DETECTION FUNCTIONS
#===============================================================================

auto_detect_network() {
    if [ -n "${NETWORK}" ]; then return 0; fi
    if [ -z "${DC_IP}" ]; then return 1; fi

    local base
    base=$(echo "${DC_IP}" | sed 's/\.[0-9]*$/.0/')
    NETWORK="${base}/24"
    log "INFO" "Auto-detected network: ${NETWORK}"
    print_info "🔍 Réseau auto-détecté: ${NETWORK}"
}

auto_detect_domain() {
    if [ -n "${DOMAIN}" ]; then return 0; fi
    if [ -z "${DC_IP}" ]; then return 1; fi

    print_info "🔍 Tentative de détection automatique du domaine..."

    local root_dse
    root_dse=$(ldapsearch -x -H "ldap://${DC_IP}" -b "" -s base \
        "(objectClass=*)" defaultNamingContext 2>/dev/null | \
        grep "defaultNamingContext:" | awk '{print $2}')

    if [ -n "${root_dse}" ]; then
        DOMAIN=$(echo "${root_dse}" | sed 's/DC=//g; s/,/./g' | tr '[:lower:]' '[:upper:]')
        log "INFO" "Domain auto-detected via rootDSE: ${DOMAIN}"
        print_info "✓ Domaine détecté: ${DOMAIN}"
        return 0
    fi

    local nmap_domain
    nmap_domain=$(nmap -T4 -Pn -p 389 --script ldap-rootdse "${DC_IP}" 2>/dev/null | \
        grep -i "namingContexts" | head -1 | grep -oP 'DC=\K[^,]+' | head -1)

    if [ -n "${nmap_domain}" ]; then
        DOMAIN=$(echo "${nmap_domain}" | tr '[:lower:]' '[:upper:]')
        print_info "✓ Domaine détecté via nmap: ${DOMAIN}"
        return 0
    fi

    print_error "Impossible de détecter le domaine. Utilisez -d/--domain"
    return 1
}

#===============================================================================
# CONFIG FILE LOADER
#===============================================================================

load_config() {
    local config="$1"

    if [ ! -f "${config}" ]; then
        print_error "Fichier de configuration introuvable: ${config}"
        exit 1
    fi

    log "INFO" "Chargement de la configuration: ${config}"

    while IFS='=' read -r key value; do
        [[ "${key}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${key}" ]] && continue

        key=$(echo "${key}" | xargs)
        value=$(echo "${value}" | xargs)

        case "${key}" in
            DC_IP)            DC_IP="${value}" ;;
            DC_HOSTNAME)      DC_HOSTNAME="${value}" ;;
            DOMAIN)           DOMAIN="${value}" ;;
            NETWORK)          NETWORK="${value}" ;;
            LDAPS)            LDAPS_MODE="${value}" ;;
            INACTIVITY_DAYS)  INACTIVITY_DAYS="${value}" ;;
            ENCRYPT_OUTPUT)   ENCRYPT_OUTPUT="${value}" ;;
        esac
    done < "${config}"

    print_info "✓ Configuration chargée depuis ${config}"
}

#===============================================================================
# REQUIREMENTS CHECK
#===============================================================================

check_requirements() {
    print_section "VÉRIFICATION DES PRÉREQUIS"

    local critical_tools=("nmap" "ldapsearch")
    local optional_tools_list=("nxc:NetExec" "crackmapexec:CrackMapExec" "enum4linux-ng:Enum4Linux-NG" "bloodhound-python:BloodHound" "certipy:Certipy-AD" "gpg:GPG" "smbclient:SMBClient" "rpcdump.py:RPCDump" "dig:DNS-Dig")

    print_info "Vérification des outils critiques..."
    for tool in "${critical_tools[@]}"; do
        print_test "Disponibilité de ${tool}"
        if command_exists "$tool"; then
            local version
            version=$(${tool} --version 2>&1 | head -n1 || echo "version inconnue")
            print_success "${tool} disponible (${version})"
        else
            print_error "${tool} MANQUANT (critique)"
            return 1
        fi
    done

    print_info "Détection des outils optionnels..."
    for entry in "${optional_tools_list[@]}"; do
        local tool="${entry%%:*}"
        local name="${entry##*:}"

        if command_exists "$tool"; then
            print_info "✓ ${name}: Disponible"
            case "${tool}" in
                nxc)                HAS_NXC=true ;;
                crackmapexec)       HAS_CME=true ;;
                enum4linux-ng)      HAS_ENUM4LINUX=true ;;
                bloodhound-python)  HAS_BLOODHOUND=true ;;
                certipy)            HAS_CERTIPY=true ;;
                smbclient)          HAS_SMBCLIENT=true ;;
                rpcdump.py)         HAS_RPCDUMP=true ;;
                dig)                HAS_DIG=true ;;
            esac
        else
            print_info "○ ${name}: Non disponible (optionnel)"
        fi
    done

    if [ "${HAS_NXC}" = true ]; then
        print_info "🔧 Outil SMB principal: NetExec (nxc)"
    elif [ "${HAS_CME}" = true ]; then
        print_info "🔧 Outil SMB principal: CrackMapExec (legacy)"
    else
        print_info "⚠ Aucun outil SMB — validation via LDAP uniquement"
    fi

    return 0
}

#===============================================================================
# ENVIRONMENT SETUP
#===============================================================================

setup_environment() {
    umask 077

    if [ -n "${CUSTOM_OUTPUT_DIR}" ]; then
        OUTPUT_DIR="${CUSTOM_OUTPUT_DIR}"
    else
        local prefix="AD_Audit"
        [ -n "${DOMAIN}" ] && prefix="${DOMAIN}_Audit"
        OUTPUT_DIR="${prefix}_${TIMESTAMP}"
    fi

    LOG_FILE="${OUTPUT_DIR}/audit_execution.log"
    REPORT_FILE="${OUTPUT_DIR}/RAPPORT_AUDIT_AD.txt"
    SUMMARY_FILE="${OUTPUT_DIR}/00_RESUME_SECURITE.txt"
    LOG_SUMMARY_FILE="${OUTPUT_DIR}/log_summary.txt"
    HTML_REPORT="${OUTPUT_DIR}/RAPPORT_AUDIT_AD.html"
    JSON_REPORT="${OUTPUT_DIR}/findings.json"
    REMEDIATION_FILE="${OUTPUT_DIR}/REMEDIATION.ps1"
    PASSWORD_FILE="${OUTPUT_DIR}/.secure_password"

    log "INFO" "Création de la structure de répertoires"

    mkdir -p "${OUTPUT_DIR}"/{01_Inventaire,02_Configuration_DC,03_Comptes_Utilisateurs,04_Groupes_Privileges,05_Politique_Mots_de_Passe,06_GPO,07_Partages,08_Vulnerabilites,09_BloodHound,10_Hardening,11_Ordinateurs,12_Delegation,13_ACL,14_Trusts,15_LAPS,16_Certificats,17_DNS}
    chmod 700 "${OUTPUT_DIR}"

    if [ -n "${DOMAIN}" ] && [ -z "${BASE_DN}" ]; then
        BASE_DN=$(domain_to_base_dn "${DOMAIN}")
        log "INFO" "Base DN: ${BASE_DN}"
    fi

    print_section "PRÉPARATION DE L'ENVIRONNEMENT"
    print_info "Structure créée: ${OUTPUT_DIR} (mode 700)"
    print_info "Base DN: ${BASE_DN}"
}

#===============================================================================
# CONNECTIVITY TEST
#===============================================================================

test_connectivity() {
    print_section "TEST DE CONNECTIVITÉ"
    start_timer "connectivity"

    print_test "Ping vers ${DC_IP}"
    if ping -c 3 -W 5 "${DC_IP}" >/dev/null 2>&1; then
        print_success "DC accessible via ICMP"
    else
        print_warning "ICMP bloqué (peut être normal si firewall actif)"
    fi

    local ad_ports=("88:Kerberos" "389:LDAP" "445:SMB" "636:LDAPS" "3268:GC" "3269:GC-SSL")

    for port_info in "${ad_ports[@]}"; do
        local port="${port_info%%:*}"
        local service="${port_info##*:}"

        print_test "Port ${port} (${service})"
        if timeout 3 bash -c "echo >/dev/tcp/${DC_IP}/${port}" 2>/dev/null; then
            print_success "Port ${port} ouvert"
            log_data "Port ${port}" "OUVERT" "test TCP"
        else
            print_warning "Port ${port} fermé/filtré"
            log_data "Port ${port}" "FERMÉ" "test TCP"
        fi
    done

    stop_timer "connectivity"
}
