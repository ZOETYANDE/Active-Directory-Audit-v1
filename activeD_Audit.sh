#!/bin/bash

#===============================================================================
#
# ACTIVE DIRECTORY SECURITY AUDIT FRAMEWORK v4.0
#
# Enterprise-grade AD security assessment tool
# Supports: Dynamic config, NetExec, LDAPS, BloodHound, ADCS, GPO, LAPS
#
# Usage: ./activeD_Audit.sh -t <DC_IP> -d <DOMAIN> [-u <user>] [OPTIONS]
#        ./activeD_Audit.sh --config audit.conf [-u <user>]
#
#===============================================================================

set -u

#===============================================================================
# CONFIGURATION DEFAULTS (overridden by CLI args or config file)
#===============================================================================
readonly SCRIPT_VERSION="1.4.01"
readonly AUDIT_REF="Audit - Sécurité Active Directory"

# Target config — set via CLI or config file
DC_IP=""
DC_HOSTNAME=""
DOMAIN=""
NETWORK=""
BASE_DN=""

# Options
LDAPS_MODE=false
ENCRYPT_OUTPUT=false
INACTIVITY_DAYS=90
CUSTOM_OUTPUT_DIR=""
CONFIG_FILE=""

# Runtime
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=""
LOG_FILE=""
REPORT_FILE=""
SUMMARY_FILE=""
LOG_SUMMARY_FILE=""
HTML_REPORT=""
PASSWORD_FILE=""

# Colours
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Counters
declare -i TESTS_TOTAL=0
declare -i TESTS_PASSED=0
declare -i TESTS_FAILED=0
declare -i TESTS_WARNING=0
declare -i TEST_IN_PROGRESS=0

# Findings for HTML report
declare -a FINDINGS_SEVERITY=()
declare -a FINDINGS_TITLE=()
declare -a FINDINGS_DESC=()
declare -a FINDINGS_EVIDENCE=()

# Performance
declare -A PERF_TIMERS

# Modes
DEBUG_MODE=false
VERBOSE_MODE=false

# Tool detection cache
HAS_NXC=false
HAS_CME=false
HAS_ENUM4LINUX=false
HAS_BLOODHOUND=false
HAS_CERTIPY=false

# Background PIDs for cleanup
declare -a BG_PIDS=()

#===============================================================================
# LOGGING SYSTEM
#===============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    [ -d "${OUTPUT_DIR}" ] || mkdir -p "${OUTPUT_DIR}"

    if [ ! -f "${LOG_FILE}" ]; then
        cat > "${LOG_FILE}" <<EOF
================================================================================
LOG D'EXÉCUTION - AUDIT AD v${SCRIPT_VERSION}
================================================================================
Date démarrage : $(date '+%Y-%m-%d %H:%M:%S')
Version script : ${SCRIPT_VERSION}
Mode debug     : ${DEBUG_MODE}
Mode verbose   : ${VERBOSE_MODE}
Domaine        : ${DOMAIN}
Contrôleur DC  : ${DC_IP}
Réseau         : ${NETWORK}
LDAPS          : ${LDAPS_MODE}
================================================================================

EOF
    fi

    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

log_debug() {
    [ "$DEBUG_MODE" = true ] || return 0
    log "DEBUG" "$*"
}

log_command() {
    local description="$1"
    shift
    local cmd="$*"

    log "CMD" "${description}"
    log_debug "Commande exacte: ${cmd}"

    local start_time
    start_time=$(date +%s)
    eval "$cmd"
    local exit_code=$?
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ ${exit_code} -eq 0 ]; then
        log "CMD" "✓ Code retour: ${exit_code} (succès) - Durée: ${duration}s"
    else
        log "CMD" "✗ Code retour: ${exit_code} (ÉCHEC) - Durée: ${duration}s"
        log "WARNING" "Échec de la commande: ${description}"
    fi

    return ${exit_code}
}

log_file_info() {
    local file="$1"
    local description="$2"

    if [ ! -f "${file}" ]; then
        log "FILE" "${description}: FICHIER MANQUANT - ${file}"
        return 1
    fi

    local size
    size=$(stat -c%s "${file}" 2>/dev/null || echo "0")
    local lines
    lines=$(wc -l < "${file}" 2>/dev/null || echo "0")

    log "FILE" "${description}: ${file} (${size} octets, ${lines} lignes)"

    if [ "$DEBUG_MODE" = true ] && [ -s "${file}" ]; then
        log "DEBUG" "Aperçu ${file} (5 premières lignes):"
        head -n 5 "${file}" 2>/dev/null | while IFS= read -r line; do
            log "DEBUG" "  | ${line}"
        done
    fi

    return 0
}

log_parallel() {
    local pid="$1"
    local description="$2"
    local status="${3:-LANCÉ}"
    log "PARALLEL" "PID ${pid} [${description}]: ${status}"
}

log_data() {
    local description="$1"
    local value="$2"
    local source="${3:-}"

    if [ -n "${source}" ]; then
        log "DATA" "${description}: ${value} (source: ${source})"
    else
        log "DATA" "${description}: ${value}"
    fi
}

#===============================================================================
# DISPLAY FUNCTIONS
#===============================================================================

print_header() {
    echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}\n"
    log "HEADER" "$*"
}

print_section() {
    echo -e "\n${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│ $*${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    log "SECTION" "$*"
}

print_info() {
    echo -e "${BLUE}[ℹ]${NC} $*"
    log "INFO" "$*"
}

print_test() {
    if [ ${TEST_IN_PROGRESS} -eq 1 ]; then
        log "WARNING" "Test précédent sans résultat - auto-comptage comme échec"
        ((TESTS_FAILED++)) || true
    fi
    echo -e "${CYAN}[TEST]${NC} $*"
    log "TEST" "$*"
    ((TESTS_TOTAL++)) || true
    TEST_IN_PROGRESS=1
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $*"
    log "SUCCESS" "$*"
    if [ ${TEST_IN_PROGRESS} -eq 1 ]; then
        ((TESTS_PASSED++)) || true
        TEST_IN_PROGRESS=0
    fi
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $*"
    log "WARNING" "$*"
    if [ ${TEST_IN_PROGRESS} -eq 1 ]; then
        ((TESTS_WARNING++)) || true
        TEST_IN_PROGRESS=0
    fi
}

print_error() {
    echo -e "${RED}[✗]${NC} $*"
    log "ERROR" "$*"
    if [ ${TEST_IN_PROGRESS} -eq 1 ]; then
        ((TESTS_FAILED++)) || true
        TEST_IN_PROGRESS=0
    fi
}

#===============================================================================
# FINDINGS TRACKER (for HTML report)
#===============================================================================

add_finding() {
    local severity="$1"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    local title="$2"
    local desc="$3"
    local evidence="${4:-}"

    FINDINGS_SEVERITY+=("${severity}")
    FINDINGS_TITLE+=("${title}")
    FINDINGS_DESC+=("${desc}")
    FINDINGS_EVIDENCE+=("${evidence}")

    log "FINDING" "[${severity}] ${title}: ${desc}"
}

#===============================================================================
# TIMERS
#===============================================================================

start_timer() {
    local name="$1"
    PERF_TIMERS["${name}_start"]=$(date +%s)
    log "PERF" "Timer démarré: ${name}"
}

stop_timer() {
    local name="$1"
    local start_time=${PERF_TIMERS["${name}_start"]:-0}
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    PERF_TIMERS["${name}_duration"]=${duration}

    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    if [ ${minutes} -gt 0 ]; then
        print_info "⏱️  Durée ${name}: ${minutes}m ${seconds}s"
        log "PERF" "Timer arrêté: ${name} - ${duration}s (${minutes}m ${seconds}s)"
    else
        print_info "⏱️  Durée ${name}: ${seconds}s"
        log "PERF" "Timer arrêté: ${name} - ${duration}s"
    fi
}

#===============================================================================
# PASSWORD HANDLING
#===============================================================================

secure_password_prompt() {
    local username="$1"
    local password

    echo -e "${YELLOW}[SÉCURITÉ]${NC} Saisie du mot de passe (non affiché):" >&2
    read -s -p "Mot de passe pour ${username}: " password
    echo "" >&2

    touch "${PASSWORD_FILE}"
    chmod 600 "${PASSWORD_FILE}"
    printf '%s' "${password}" > "${PASSWORD_FILE}"

    log "INFO" "Mot de passe stocké dans fichier sécurisé (mode 600)"
    echo "${PASSWORD_FILE}"
}

cleanup_password() {
    if [ -f "${PASSWORD_FILE}" ]; then
        dd if=/dev/urandom of="${PASSWORD_FILE}" bs=1 count=100 2>/dev/null || true
        rm -f "${PASSWORD_FILE}"
        log "INFO" "Fichier de mot de passe supprimé de manière sécurisée"
    fi
}

#===============================================================================
# SIGNAL HANDLER — kill bg processes, cleanup, generate partial report
#===============================================================================

cleanup_all() {
    echo ""
    echo -e "${YELLOW}[!] Interruption détectée — nettoyage en cours...${NC}"
    log "WARNING" "Script interrompu — nettoyage"

    # Kill all background processes
    for pid in "${BG_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            log "INFO" "Processus ${pid} terminé"
        fi
    done

    cleanup_password

    if [ -n "${OUTPUT_DIR}" ] && [ -d "${OUTPUT_DIR}" ]; then
        echo -e "${YELLOW}[!] Résultats partiels dans: ${OUTPUT_DIR}${NC}"
    fi

    exit 130
}

#===============================================================================
# SAFE UTILITY FUNCTIONS
#===============================================================================

safe_count() {
    local pattern="$1"
    local file="$2"

    if [ ! -f "${file}" ]; then
        echo "0"
        return 0
    fi

    local count
    count=$(grep -c "${pattern}" "${file}" 2>/dev/null || echo "0")

    if ! [[ "${count}" =~ ^[0-9]+$ ]]; then
        echo "0"
        return 0
    fi

    echo "${count}"
}

safe_divide() {
    local numerator=${1:-0}
    local denominator=${2:-1}

    if [ "${denominator}" -eq 0 ]; then
        echo "0"
        return 0
    fi

    echo "$((numerator * 100 / denominator))"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Derive LDAP base DN from domain name: CORP.LOCAL → DC=CORP,DC=LOCAL
domain_to_base_dn() {
    local domain="$1"
    echo "${domain}" | sed 's/\./,DC=/g; s/^/DC=/' | tr '[:lower:]' '[:upper:]'
}

# Get LDAP URI based on LDAPS mode
get_ldap_uri() {
    if [ "${LDAPS_MODE}" = true ]; then
        echo "ldaps://${DC_IP}"
    else
        echo "ldap://${DC_IP}"
    fi
}

# Paginated ldapsearch wrapper
ldap_search() {
    local bind_user="$1"
    local pwd_file="$2"
    local filter="$3"
    local attrs="$4"
    local output_file="$5"

    local uri
    uri=$(get_ldap_uri)

    ldapsearch -x -H "${uri}" \
        -D "${bind_user}@${DOMAIN}" -y "${pwd_file}" \
        -b "${BASE_DN}" \
        -E pr=1000/noprompt \
        "${filter}" ${attrs} \
        > "${output_file}" 2>&1 || true

    log_file_info "${output_file}" "LDAP query: ${filter}"
}

# Detect best SMB tool: nxc > crackmapexec > none
smb_tool_exec() {
    local args="$*"
    if [ "${HAS_NXC}" = true ]; then
        eval "nxc smb ${args}"
    elif [ "${HAS_CME}" = true ]; then
        eval "crackmapexec smb ${args}"
    else
        log "WARNING" "No SMB tool available (nxc/crackmapexec)"
        return 1
    fi
}

#===============================================================================
# AUTO-DETECTION FUNCTIONS
#===============================================================================

auto_detect_network() {
    if [ -n "${NETWORK}" ]; then return 0; fi
    if [ -z "${DC_IP}" ]; then return 1; fi

    # Derive /24 from DC IP
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

    # Try LDAP rootDSE
    local root_dse
    root_dse=$(ldapsearch -x -H "ldap://${DC_IP}" -b "" -s base \
        "(objectClass=*)" defaultNamingContext 2>/dev/null | \
        grep "defaultNamingContext:" | awk '{print $2}')

    if [ -n "${root_dse}" ]; then
        # DC=SAARCI,DC=LAN → [DOMAIN]
        DOMAIN=$(echo "${root_dse}" | sed 's/DC=//g; s/,/./g' | tr '[:lower:]' '[:upper:]')
        log "INFO" "Domain auto-detected via rootDSE: ${DOMAIN}"
        print_info "✓ Domaine détecté: ${DOMAIN}"
        return 0
    fi

    # Try nmap
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
        # Skip comments and empty lines
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
    local optional_tools_list=("nxc:NetExec" "crackmapexec:CrackMapExec" "enum4linux-ng:Enum4Linux-NG" "bloodhound-python:BloodHound" "certipy:Certipy-AD" "gpg:GPG")

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
    # Set restrictive umask
    umask 077

    # Resolve output directory
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
    PASSWORD_FILE="${OUTPUT_DIR}/.secure_password"

    log "INFO" "Création de la structure de répertoires"

    mkdir -p "${OUTPUT_DIR}"/{01_Inventaire,02_Configuration_DC,03_Comptes_Utilisateurs,04_Groupes_Privileges,05_Politique_Mots_de_Passe,06_GPO,07_Partages,08_Vulnerabilites,09_BloodHound,10_Preuves,11_Ordinateurs,12_Delegation,13_ACL,14_Trusts,15_LAPS,16_Certificats}
    chmod 700 "${OUTPUT_DIR}"

    # Derive Base DN
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

#===============================================================================
# AUDIT 1: INVENTORY (PARALLEL NMAP)
#===============================================================================

audit_inventory() {
    print_section "AUDIT 1: INVENTAIRE (MODE PARALLÈLE)"
    local output_dir="${OUTPUT_DIR}/01_Inventaire"
    start_timer "inventory"

    print_info "Lancement de 4 scans nmap en parallèle..."

    nmap -T4 -sn "${NETWORK}" \
        -oN "${output_dir}/hosts_alive.txt" \
        -oX "${output_dir}/hosts_alive.xml" \
        >/dev/null 2>&1 &
    local pid1=$!
    BG_PIDS+=("${pid1}")
    log_parallel "${pid1}" "discovery" "LANCÉ"

    nmap -T4 -Pn -p 88,389,445,636,3268 "${NETWORK}" --open \
        -oN "${output_dir}/ad_services.txt" \
        -oX "${output_dir}/ad_services.xml" \
        >/dev/null 2>&1 &
    local pid2=$!
    BG_PIDS+=("${pid2}")
    log_parallel "${pid2}" "services AD" "LANCÉ"

    nmap -T4 -Pn -sV -sC -p 53,88,135,139,389,445,464,636,3268,3269,3389 "${DC_IP}" \
        -oN "${output_dir}/dc_full_scan.txt" \
        -oX "${output_dir}/dc_full_scan.xml" \
        >/dev/null 2>&1 &
    local pid3=$!
    BG_PIDS+=("${pid3}")
    log_parallel "${pid3}" "DC complet" "LANCÉ"

    nmap -T4 -Pn -p 445 --script smb-protocols,smb2-protocols "${DC_IP}" \
        -oN "${output_dir}/smb_version.txt" \
        >/dev/null 2>&1 &
    local pid4=$!
    BG_PIDS+=("${pid4}")
    log_parallel "${pid4}" "SMB" "LANCÉ"

    sleep 2.5
    local running=0
    for p in ${pid1} ${pid2} ${pid3} ${pid4}; do
        ps -p ${p} >/dev/null 2>&1 && ((running++)) || true
    done
    print_info "✅ État: ${running}/4 scans actifs"

    wait ${pid1} ${pid2} ${pid3} ${pid4} 2>/dev/null || true

    print_test "Découverte réseau"
    if [ -f "${output_dir}/hosts_alive.txt" ] && [ -s "${output_dir}/hosts_alive.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    print_test "Services AD"
    if [ -f "${output_dir}/ad_services.txt" ] && [ -s "${output_dir}/ad_services.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    print_test "Scan DC"
    if [ -f "${output_dir}/dc_full_scan.txt" ] && [ -s "${output_dir}/dc_full_scan.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    print_test "Versions SMB"
    if [ -f "${output_dir}/smb_version.txt" ] && [ -s "${output_dir}/smb_version.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    local hosts_count
    hosts_count=$(safe_count "Host is up" "${output_dir}/hosts_alive.txt")
    print_info "📊 Hôtes découverts: ${hosts_count}"

    local dc_count
    dc_count=$(safe_count "88/tcp" "${output_dir}/ad_services.txt")
    print_info "📊 Contrôleurs potentiels: ${dc_count}"

    stop_timer "inventory"
}

#===============================================================================
# AUDIT 2: DC CONFIGURATION
#===============================================================================

audit_dc_config() {
    print_section "AUDIT 2: CONFIGURATION DC"
    local output_dir="${OUTPUT_DIR}/02_Configuration_DC"
    start_timer "dc_config"

    print_test "Détection SMBv1"
    nmap -T4 -Pn -p 445 --script smb-protocols "${DC_IP}" \
        -oN "${output_dir}/smb_version.txt" 2>/dev/null || true

    if [ -f "${output_dir}/smb_version.txt" ]; then
        if grep -qi "SMBv1" "${output_dir}/smb_version.txt"; then
            print_error "🔴 SMBv1 activé - VULNÉRABILITÉ CRITIQUE"
            add_finding "CRITICAL" "SMBv1 Activé" "Le protocole SMBv1 est activé sur ${DC_IP}. Vulnérable à EternalBlue (MS17-010)." "${output_dir}/smb_version.txt"
        else
            print_success "SMBv1 désactivé"
            add_finding "INFO" "SMBv1 Désactivé" "SMBv1 est correctement désactivé." ""
        fi
    else
        print_warning "Impossible de vérifier SMB"
    fi

    print_test "Signature SMB"
    nmap -T4 -Pn -p 445 --script smb-security-mode "${DC_IP}" \
        -oN "${output_dir}/smb_signing.txt" 2>/dev/null || true

    if [ -f "${output_dir}/smb_signing.txt" ]; then
        if grep -qi "signing.*required" "${output_dir}/smb_signing.txt"; then
            print_success "Signature SMB requise"
            add_finding "INFO" "Signature SMB Requise" "La signature SMB est correctement requise." ""
        else
            print_warning "Signature SMB non requise - Risque NTLM relay"
            add_finding "HIGH" "Signature SMB Non Requise" "La signature SMB n'est pas requise. Risque d'attaque NTLM relay." "${output_dir}/smb_signing.txt"
        fi
    else
        print_warning "Impossible de vérifier signature"
    fi

    # LDAP Signing check
    print_test "Signature LDAP"
    local ldap_result
    ldap_result=$(ldapsearch -x -H "ldap://${DC_IP}" -b "" -s base \
        "(objectClass=*)" 2>&1 || true)

    if echo "${ldap_result}" | grep -qi "result: 0"; then
        print_warning "LDAP non signé accepté — risque d'interception"
        add_finding "MEDIUM" "LDAP Binding Non Signé" "Le serveur accepte les connexions LDAP sans signature. Risque de MITM." ""
    else
        print_success "LDAP sécurisé"
    fi

    stop_timer "dc_config"
}

#===============================================================================
# AUDIT 3: LDAP ANONYMOUS
#===============================================================================

audit_ldap_unauth() {
    print_section "AUDIT 3: LDAP NON AUTHENTIFIÉ"
    local output_dir="${OUTPUT_DIR}/03_Comptes_Utilisateurs"
    start_timer "ldap_unauth"

    local uri
    uri=$(get_ldap_uri)

    print_test "Énumération LDAP anonyme"
    ldapsearch -x -H "${uri}" -b "${BASE_DN}" \
        "(objectclass=user)" sAMAccountName \
        > "${output_dir}/ldap_anon.txt" 2>&1

    local user_count
    user_count=$(safe_count "sAMAccountName:" "${output_dir}/ldap_anon.txt")

    if [ "${user_count}" -gt 0 ]; then
        print_error "🔴 LDAP anonyme autorisé! ${user_count} comptes exposés"
        add_finding "CRITICAL" "LDAP Anonyme Autorisé" "${user_count} comptes utilisateurs exposés via LDAP anonyme." "${output_dir}/ldap_anon.txt"
    else
        print_success "LDAP anonyme restreint"
        add_finding "INFO" "LDAP Anonyme Restreint" "L'accès LDAP anonyme est correctement restreint." ""
    fi

    stop_timer "ldap_unauth"
}

#===============================================================================
# AUDIT 4: AUTHENTICATED — ORCHESTRATOR
#===============================================================================

audit_authenticated() {
    local username="$1"
    local pwd_file="$2"

    print_section "AUDIT 4: ÉNUMÉRATION AUTHENTIFIÉE"
    start_timer "authenticated"

    local password
    password=$(<"${pwd_file}")

    # Credential validation
    print_test "Validation des identifiants (${username})"

    if [ "${HAS_NXC}" = true ] || [ "${HAS_CME}" = true ]; then
        smb_tool_exec "\"${DC_IP}\" -u \"${username}\" -p \"${password}\" -d \"${DOMAIN}\"" \
            > "${OUTPUT_DIR}/cred_test.txt" 2>&1

        if grep -qE "\[\+\]" "${OUTPUT_DIR}/cred_test.txt"; then
            print_success "Identifiants valides"
        else
            print_error "Identifiants invalides"
            stop_timer "authenticated"
            return 1
        fi
    else
        local uri
        uri=$(get_ldap_uri)
        if ldapsearch -x -H "${uri}" -D "${username}@${DOMAIN}" \
            -y "${pwd_file}" -b "${BASE_DN}" "(objectClass=domain)" dn >/dev/null 2>&1; then
            print_success "Identifiants valides (LDAP)"
        else
            print_error "Identifiants invalides"
            stop_timer "authenticated"
            return 1
        fi
    fi

    # Run all sub-audits
    audit_users "${username}" "${pwd_file}"
    audit_groups "${username}" "${pwd_file}"
    audit_inactive_users "${username}" "${pwd_file}"
    audit_inactive_computers "${username}" "${pwd_file}"
    audit_password_policy "${username}" "${pwd_file}"
    audit_gpo "${username}" "${pwd_file}"
    audit_delegation "${username}" "${pwd_file}"
    audit_acl_abuse "${username}" "${pwd_file}"
    audit_trusts "${username}" "${pwd_file}"
    audit_laps "${username}" "${pwd_file}"
    audit_adcs "${username}" "${pwd_file}"
    audit_bloodhound "${username}" "${pwd_file}"

    stop_timer "authenticated"
}

#===============================================================================
# AUDIT 4.1: USER ACCOUNTS
#===============================================================================

audit_users() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/03_Comptes_Utilisateurs"

    print_section "AUDIT 4.1: COMPTES UTILISATEURS"
    start_timer "users"

    # Parallel LDAP queries
    {
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
            "sAMAccountName" "${output_dir}/users_pwd_never_expires.txt"
    } &
    local pid_pwd=$!
    BG_PIDS+=("${pid_pwd}")

    {
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
            "sAMAccountName" "${output_dir}/users_asrep.txt"
    } &
    local pid_asrep=$!
    BG_PIDS+=("${pid_asrep}")

    # Disabled accounts
    {
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
            "sAMAccountName" "${output_dir}/users_disabled.txt"
    } &
    local pid_disabled=$!
    BG_PIDS+=("${pid_disabled}")

    wait ${pid_pwd} ${pid_asrep} ${pid_disabled} 2>/dev/null || true

    print_test "Comptes avec mot de passe permanent"
    local never_expires
    never_expires=$(safe_count "sAMAccountName:" "${output_dir}/users_pwd_never_expires.txt")

    if [ "${never_expires}" -gt 0 ]; then
        print_warning "⚠️  ${never_expires} comptes"
        add_finding "MEDIUM" "Mots de Passe Permanents" "${never_expires} comptes ont un mot de passe qui n'expire jamais." "${output_dir}/users_pwd_never_expires.txt"
    else
        print_success "Aucun"
    fi

    print_test "Comptes vulnérables AS-REP Roasting"
    local asrep
    asrep=$(safe_count "sAMAccountName:" "${output_dir}/users_asrep.txt")

    if [ "${asrep}" -gt 0 ]; then
        print_error "🔴 ${asrep} comptes vulnérables"
        add_finding "HIGH" "AS-REP Roasting" "${asrep} comptes vulnérables à l'AS-REP Roasting (pré-auth désactivée)." "${output_dir}/users_asrep.txt"
    else
        print_success "Aucun"
    fi

    print_test "Comptes désactivés"
    local disabled
    disabled=$(safe_count "sAMAccountName:" "${output_dir}/users_disabled.txt")
    print_info "📊 ${disabled} comptes désactivés"
    if [ "${disabled}" -gt 0 ]; then
        print_success "${disabled} comptes désactivés trouvés"
    else
        print_warning "Aucun compte désactivé trouvé"
    fi

    stop_timer "users"
}

#===============================================================================
# AUDIT 4.2: PRIVILEGED GROUPS
#===============================================================================

audit_groups() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/04_Groupes_Privileges"

    print_section "AUDIT 4.2: GROUPES PRIVILÉGIÉS"
    start_timer "groups"

    local priv_groups=("Domain Admins" "Enterprise Admins" "Administrators" "Schema Admins" "Account Operators" "Backup Operators" "DnsAdmins" "Server Operators")

    for group in "${priv_groups[@]}"; do
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectClass=group)(cn=${group}))" \
            "member" "${output_dir}/group_${group// /_}.txt"

        local member_count
        member_count=$(safe_count "member:" "${output_dir}/group_${group// /_}.txt")
        print_info "Groupe '${group}': ${member_count} membres"

        if [[ "${group}" =~ ^(Domain Admins|Enterprise Admins|Schema Admins)$ ]] && [ "${member_count}" -gt 5 ]; then
            add_finding "HIGH" "Groupe ${group} Surdimensionné" "${member_count} membres dans ${group}. Recommandé: ≤5." "${output_dir}/group_${group// /_}.txt"
        fi
    done

    print_test "Comptes avec SPN (Kerberoastables)"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
        "sAMAccountName servicePrincipalName" "${output_dir}/users_spn.txt"

    local spn_count
    spn_count=$(safe_count "sAMAccountName:" "${output_dir}/users_spn.txt")

    if [ "${spn_count}" -gt 0 ]; then
        print_warning "⚠️  ${spn_count} comptes avec SPN"
        add_finding "HIGH" "Kerberoasting" "${spn_count} comptes utilisateurs avec SPN — vulnérables au Kerberoasting." "${output_dir}/users_spn.txt"
    else
        print_success "Aucun compte avec SPN"
    fi

    stop_timer "groups"
}

#===============================================================================
# AUDIT 4.3: INACTIVE USERS
#===============================================================================

audit_inactive_users() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/03_Comptes_Utilisateurs"

    print_section "AUDIT: COMPTES INACTIFS"
    start_timer "inactive_users"

    local days_ago
    days_ago=$(date -d "-${INACTIVITY_DAYS} days" +%s 2>/dev/null || echo "0")
    local ldap_timestamp=$(((${days_ago} * 10000000) + 116444736000000000))

    print_test "Comptes inactifs (>${INACTIVITY_DAYS}j)"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=${ldap_timestamp}))" \
        "sAMAccountName memberOf" "${output_dir}/users_inactive.txt"

    local inactive_count
    inactive_count=$(safe_count "sAMAccountName:" "${output_dir}/users_inactive.txt")

    if [ "${inactive_count}" -gt 0 ]; then
        print_warning "⚠️  ${inactive_count} comptes inactifs"
        add_finding "MEDIUM" "Comptes Inactifs" "${inactive_count} comptes actifs n'ont pas été utilisés depuis ${INACTIVITY_DAYS} jours." "${output_dir}/users_inactive.txt"
    else
        print_success "Aucun compte inactif"
    fi

    stop_timer "inactive_users"
}

#===============================================================================
# AUDIT 4.4: INACTIVE COMPUTERS
#===============================================================================

audit_inactive_computers() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/11_Ordinateurs"

    print_section "AUDIT: ORDINATEURS"
    start_timer "inactive_computers"

    print_test "Énumération des ordinateurs"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=computer)" \
        "sAMAccountName operatingSystem operatingSystemVersion" "${output_dir}/all_computers.txt"

    local total
    total=$(safe_count "sAMAccountName:" "${output_dir}/all_computers.txt")

    if [ "${total}" -gt 0 ]; then
        print_success "${total} ordinateurs trouvés"
    else
        print_warning "Aucun ordinateur trouvé"
    fi

    print_test "OS obsolètes"
    grep -i "operatingSystem:" "${output_dir}/all_computers.txt" | \
        grep -iE "Windows 7|Windows XP|Server 2003|Server 2008[^R]|Windows Vista" \
        > "${output_dir}/obsolete_os.txt" 2>/dev/null || true

    local obsolete
    obsolete=$(wc -l < "${output_dir}/obsolete_os.txt" 2>/dev/null || echo "0")

    if [ "${obsolete}" -gt 0 ]; then
        print_error "🔴 ${obsolete} OS obsolètes"
        add_finding "CRITICAL" "Systèmes Obsolètes" "${obsolete} machines avec OS obsolète (XP/Vista/7/2003/2008) — plus de support sécurité." "${output_dir}/obsolete_os.txt"
    else
        print_success "Aucun OS obsolète"
    fi

    stop_timer "inactive_computers"
}

#===============================================================================
# AUDIT 4.5: PASSWORD POLICY  [NEW]
#===============================================================================

audit_password_policy() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/05_Politique_Mots_de_Passe"

    print_section "AUDIT: POLITIQUE DE MOTS DE PASSE"
    start_timer "password_policy"

    local uri
    uri=$(get_ldap_uri)

    # Default Domain Policy
    print_test "Politique de mot de passe par défaut"
    ldapsearch -x -H "${uri}" -D "${username}@${DOMAIN}" -y "${pwd_file}" \
        -b "${BASE_DN}" -s base \
        "(objectClass=domain)" \
        minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold lockoutDuration lockoutObservationWindow pwdProperties \
        > "${output_dir}/default_policy.txt" 2>&1 || true

    if [ -f "${output_dir}/default_policy.txt" ]; then
        local min_len
        min_len=$(grep "minPwdLength:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        local lockout
        lockout=$(grep "lockoutThreshold:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        local history
        history=$(grep "pwdHistoryLength:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")

        print_info "📊 Longueur min: ${min_len:-N/A} | Verrouillage: ${lockout:-N/A} | Historique: ${history:-N/A}"

        if [ -n "${min_len}" ] && [ "${min_len}" -lt 12 ] 2>/dev/null; then
            print_warning "Longueur minimale < 12 caractères (${min_len})"
            add_finding "HIGH" "Mot de Passe Trop Court" "La longueur minimale est de ${min_len} caractères. Recommandation: ≥12." "${output_dir}/default_policy.txt"
        elif [ -n "${min_len}" ]; then
            print_success "Longueur minimale acceptable: ${min_len}"
        fi

        if [ -n "${lockout}" ] && [ "${lockout}" -eq 0 ] 2>/dev/null; then
            print_warning "Aucun verrouillage de compte configuré!"
            add_finding "HIGH" "Pas de Verrouillage" "Aucun seuil de verrouillage de compte. Brute-force possible." "${output_dir}/default_policy.txt"
        elif [ -n "${lockout}" ]; then
            print_success "Verrouillage après ${lockout} tentatives"
        fi
    else
        print_warning "Impossible de lire la politique"
    fi

    # Fine-Grained Password Policies
    print_test "Politiques de mot de passe granulaires (FGPP)"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=msDS-PasswordSettings)" \
        "cn msDS-MinimumPasswordLength msDS-LockoutThreshold msDS-PasswordSettingsPrecedence" \
        "${output_dir}/fgpp.txt"

    local fgpp_count
    fgpp_count=$(safe_count "cn:" "${output_dir}/fgpp.txt")
    print_info "📊 ${fgpp_count} FGPP trouvées"

    if [ "${fgpp_count}" -gt 0 ]; then
        print_success "${fgpp_count} politiques granulaires"
    else
        print_info "Aucune FGPP — politique par défaut uniquement"
    fi

    stop_timer "password_policy"
}

#===============================================================================
# AUDIT 4.6: GPO  [NEW]
#===============================================================================

audit_gpo() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/06_GPO"

    print_section "AUDIT: OBJETS DE STRATÉGIE DE GROUPE (GPO)"
    start_timer "gpo"

    # List all GPOs
    print_test "Énumération des GPO"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=groupPolicyContainer)" \
        "displayName gPCFileSysPath flags" "${output_dir}/all_gpos.txt"

    local gpo_count
    gpo_count=$(safe_count "displayName:" "${output_dir}/all_gpos.txt")
    print_info "📊 ${gpo_count} GPO trouvées"

    if [ "${gpo_count}" -gt 0 ]; then
        print_success "${gpo_count} GPO énumérées"
    else
        print_warning "Aucune GPO trouvée"
    fi

    # Check for GPP Passwords (MS14-025)
    print_test "Vérification GPP Passwords (MS14-025)"
    local password
    password=$(<"${pwd_file}")

    if [ "${HAS_NXC}" = true ]; then
        nxc smb "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" \
            -M gpp_password > "${output_dir}/gpp_passwords.txt" 2>&1 || true
    elif [ "${HAS_CME}" = true ]; then
        crackmapexec smb "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" \
            -M gpp_password > "${output_dir}/gpp_passwords.txt" 2>&1 || true
    fi

    if [ -f "${output_dir}/gpp_passwords.txt" ] && grep -qi "password" "${output_dir}/gpp_passwords.txt"; then
        print_error "🔴 Mots de passe GPP trouvés!"
        add_finding "CRITICAL" "Mots de Passe GPP (MS14-025)" "Des mots de passe en clair ont été trouvés dans les préférences de stratégie de groupe." "${output_dir}/gpp_passwords.txt"
    else
        print_success "Aucun mot de passe GPP"
    fi

    stop_timer "gpo"
}

#===============================================================================
# AUDIT 4.7: DELEGATION  [NEW]
#===============================================================================

audit_delegation() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/12_Delegation"

    print_section "AUDIT: DÉLÉGATION KERBEROS"
    start_timer "delegation"

    # Unconstrained Delegation
    print_test "Délégation non contrainte"
    ldap_search "${username}" "${pwd_file}" \
        "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" \
        "sAMAccountName userAccountControl" "${output_dir}/unconstrained.txt"

    local unc_count
    unc_count=$(safe_count "sAMAccountName:" "${output_dir}/unconstrained.txt")

    if [ "${unc_count}" -gt 0 ]; then
        print_error "🔴 ${unc_count} objets avec délégation non contrainte"
        add_finding "CRITICAL" "Délégation Non Contrainte" "${unc_count} objets (hors DCs) avec délégation non contrainte. Risque de compromission du domaine." "${output_dir}/unconstrained.txt"
    else
        print_success "Aucune délégation non contrainte"
    fi

    # Constrained Delegation
    print_test "Délégation contrainte"
    ldap_search "${username}" "${pwd_file}" \
        "(msDS-AllowedToDelegateTo=*)" \
        "sAMAccountName msDS-AllowedToDelegateTo" "${output_dir}/constrained.txt"

    local con_count
    con_count=$(safe_count "sAMAccountName:" "${output_dir}/constrained.txt")

    if [ "${con_count}" -gt 0 ]; then
        print_warning "⚠️  ${con_count} objets avec délégation contrainte"
        add_finding "MEDIUM" "Délégation Contrainte" "${con_count} objets configurés avec délégation contrainte." "${output_dir}/constrained.txt"
    else
        print_success "Aucune délégation contrainte"
    fi

    # Resource-Based Constrained Delegation (RBCD)
    print_test "Délégation contrainte basée sur les ressources (RBCD)"
    ldap_search "${username}" "${pwd_file}" \
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "sAMAccountName" "${output_dir}/rbcd.txt"

    local rbcd_count
    rbcd_count=$(safe_count "sAMAccountName:" "${output_dir}/rbcd.txt")

    if [ "${rbcd_count}" -gt 0 ]; then
        print_warning "⚠️  ${rbcd_count} objets avec RBCD"
        add_finding "HIGH" "RBCD Configurée" "${rbcd_count} objets avec délégation RBCD. Vérifier si légitime." "${output_dir}/rbcd.txt"
    else
        print_success "Aucune RBCD"
    fi

    stop_timer "delegation"
}

#===============================================================================
# AUDIT 4.8: ACL ABUSE  [NEW]
#===============================================================================

audit_acl_abuse() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/13_ACL"

    print_section "AUDIT: PERMISSIONS ACL DANGEREUSES"
    start_timer "acl"

    # AdminSDHolder protected objects
    print_test "Objets protégés par AdminSDHolder"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(adminCount=1))" \
        "sAMAccountName distinguishedName" "${output_dir}/admincount.txt"

    local admin_count
    admin_count=$(safe_count "sAMAccountName:" "${output_dir}/admincount.txt")
    print_info "📊 ${admin_count} objets avec adminCount=1"

    if [ "${admin_count}" -gt 20 ]; then
        print_warning "⚠️  Nombre élevé d'objets protégés (${admin_count})"
        add_finding "MEDIUM" "AdminCount Élevé" "${admin_count} objets avec adminCount=1. Vérifier pour stale adminCount." "${output_dir}/admincount.txt"
    else
        print_success "${admin_count} objets protégés (normal)"
    fi

    # Users who can replicate (DCSync risk)
    print_test "Droits de réplication (DCSync)"
    if [ "${HAS_NXC}" = true ] || [ "${HAS_CME}" = true ]; then
        local password
        password=$(<"${pwd_file}")
        smb_tool_exec "\"${DC_IP}\" -u \"${username}\" -p \"${password}\" -d \"${DOMAIN}\" --users" \
            > "${output_dir}/users_enum.txt" 2>&1 || true
        print_info "Énumération ACL complétée via SMB tool (analyse manuelle recommandée)"
    fi

    # BloodHound handles deep ACL analysis — note this
    print_info "💡 Analyse ACL approfondie disponible via BloodHound (section 5)"
    add_finding "INFO" "Analyse ACL" "Les ACL complexes sont mieux analysées via BloodHound. Voir section 09_BloodHound." ""

    stop_timer "acl"
}

#===============================================================================
# AUDIT 4.9: TRUST RELATIONSHIPS  [NEW]
#===============================================================================

audit_trusts() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/14_Trusts"

    print_section "AUDIT: RELATIONS D'APPROBATION"
    start_timer "trusts"

    print_test "Énumération des trusts"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=trustedDomain)" \
        "cn trustDirection trustType trustAttributes flatName securityIdentifier" "${output_dir}/trusts.txt"

    local trust_count
    trust_count=$(safe_count "cn:" "${output_dir}/trusts.txt")

    if [ "${trust_count}" -gt 0 ]; then
        print_info "📊 ${trust_count} relations d'approbation"

        # Check for dangerous trust attributes
        if grep -q "trustAttributes: 0" "${output_dir}/trusts.txt" 2>/dev/null; then
            print_warning "⚠️  Trusts sans filtrage SID détectés"
            add_finding "HIGH" "Trust Sans Filtrage SID" "Des trusts sans filtrage SID (SID History) ont été détectés. Risque d'escalade inter-forêt." "${output_dir}/trusts.txt"
        fi

        print_success "${trust_count} trusts énumérés"
    else
        print_success "Aucun trust externe"
    fi

    stop_timer "trusts"
}

#===============================================================================
# AUDIT 4.10: LAPS  [NEW]
#===============================================================================

audit_laps() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/15_LAPS"

    print_section "AUDIT: LAPS (LOCAL ADMIN PASSWORD SOLUTION)"
    start_timer "laps"

    # Check if LAPS schema is present
    print_test "Présence du schéma LAPS"
    ldap_search "${username}" "${pwd_file}" \
        "(attributeID=1.2.840.113556.1.4.2311)" \
        "cn" "${output_dir}/laps_schema_legacy.txt"

    # Also check for Windows LAPS (new)
    ldap_search "${username}" "${pwd_file}" \
        "(attributeID=1.2.840.113556.1.4.2340)" \
        "cn" "${output_dir}/laps_schema_new.txt"

    local has_legacy_laps=false
    local has_new_laps=false

    if grep -q "cn:" "${output_dir}/laps_schema_legacy.txt" 2>/dev/null; then
        has_legacy_laps=true
    fi
    if grep -q "cn:" "${output_dir}/laps_schema_new.txt" 2>/dev/null; then
        has_new_laps=true
    fi

    if [ "${has_legacy_laps}" = true ] || [ "${has_new_laps}" = true ]; then
        print_success "LAPS déployé"

        # Count computers WITH LAPS password
        print_test "Couverture LAPS"
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))" \
            "sAMAccountName" "${output_dir}/laps_covered.txt"

        local covered
        covered=$(safe_count "sAMAccountName:" "${output_dir}/laps_covered.txt")
        local total_computers
        total_computers=$(safe_count "sAMAccountName:" "${OUTPUT_DIR}/11_Ordinateurs/all_computers.txt")

        print_info "📊 LAPS: ${covered}/${total_computers} ordinateurs couverts"

        if [ "${total_computers}" -gt 0 ] && [ "${covered}" -lt "${total_computers}" ]; then
            local uncovered=$((total_computers - covered))
            print_warning "⚠️  ${uncovered} ordinateurs sans LAPS"
            add_finding "MEDIUM" "Couverture LAPS Partielle" "${covered}/${total_computers} ordinateurs couverts par LAPS. ${uncovered} manquants." "${output_dir}/laps_covered.txt"
        else
            print_success "Couverture LAPS complète"
        fi
    else
        print_error "🔴 LAPS non déployé!"
        add_finding "HIGH" "LAPS Non Déployé" "LAPS n'est pas déployé. Les mots de passe administrateur local sont probablement identiques." ""
    fi

    stop_timer "laps"
}

#===============================================================================
# AUDIT 4.11: ADCS (CERTIFICATE SERVICES)  [NEW]
#===============================================================================

audit_adcs() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/16_Certificats"

    print_section "AUDIT: SERVICES DE CERTIFICATS (ADCS)"
    start_timer "adcs"

    # Find CA servers
    print_test "Détection des autorités de certification"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=pKIEnrollmentService)" \
        "cn dNSHostName certificateTemplates" "${output_dir}/ca_servers.txt"

    local ca_count
    ca_count=$(safe_count "cn:" "${output_dir}/ca_servers.txt")

    if [ "${ca_count}" -gt 0 ]; then
        print_success "${ca_count} CA trouvées"

        # Enumerate certificate templates
        print_test "Modèles de certificats"
        ldap_search "${username}" "${pwd_file}" \
            "(objectClass=pKICertificateTemplate)" \
            "cn msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pKIExtendedKeyUsage msPKI-RA-Signature" \
            "${output_dir}/cert_templates.txt"

        local tpl_count
        tpl_count=$(safe_count "cn:" "${output_dir}/cert_templates.txt")
        print_info "📊 ${tpl_count} modèles de certificats"

        # ESC1: Templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth
        if grep -q "msPKI-Certificate-Name-Flag: 1" "${output_dir}/cert_templates.txt" 2>/dev/null; then
            print_warning "⚠️  Modèles avec ENROLLEE_SUPPLIES_SUBJECT détectés (ESC1 potentiel)"
            add_finding "CRITICAL" "ESC1 — Certificate Template Abuse" "Des modèles permettant au demandeur de spécifier le sujet ont été trouvés. Risque d'usurpation d'identité." "${output_dir}/cert_templates.txt"
        else
            print_success "Pas de template ESC1 évident"
        fi

        # Run certipy if available
        if [ "${HAS_CERTIPY}" = true ]; then
            print_test "Analyse Certipy (ESC1-ESC8)"
            local password
            password=$(<"${pwd_file}")

            certipy find -u "${username}@${DOMAIN}" -p "${password}" \
                -dc-ip "${DC_IP}" -vulnerable -stdout \
                > "${output_dir}/certipy_vulnerable.txt" 2>&1 || true

            if grep -qi "ESC" "${output_dir}/certipy_vulnerable.txt" 2>/dev/null; then
                local esc_findings
                esc_findings=$(grep -ci "ESC" "${output_dir}/certipy_vulnerable.txt" || echo "0")
                print_error "🔴 ${esc_findings} vulnérabilités ADCS détectées!"
                add_finding "CRITICAL" "Vulnérabilités ADCS (Certipy)" "${esc_findings} findings ESC détectés par Certipy." "${output_dir}/certipy_vulnerable.txt"
            else
                print_success "Aucune vulnérabilité ESC détectée"
            fi
        else
            print_info "💡 Installez certipy-ad pour une analyse ADCS complète"
        fi
    else
        print_info "Aucune CA — ADCS non déployé"
    fi

    stop_timer "adcs"
}

#===============================================================================
# AUDIT 5: BLOODHOUND — FQDN AUTO-RESOLUTION
#===============================================================================

audit_bloodhound() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/09_BloodHound"

    print_section "AUDIT 5: BLOODHOUND (ANALYSE GRAPHIQUE AD)"
    start_timer "bloodhound"

    mkdir -p "${output_dir}"

    # Check bloodhound-python
    print_test "Vérification bloodhound-python"
    if [ "${HAS_BLOODHOUND}" != true ]; then
        print_error "bloodhound-python non installé"
        print_info "💡 Installation: pip install bloodhound --break-system-packages"
        stop_timer "bloodhound"
        return 0
    fi

    local bh_version
    bh_version=$(bloodhound-python --version 2>&1 | head -1)
    print_success "BloodHound disponible: ${bh_version}"

    # Check impacket
    print_test "Vérification impacket"
    if ! python3 -c "import impacket" 2>/dev/null; then
        print_error "Impacket manquant"
        stop_timer "bloodhound"
        return 0
    fi
    print_success "Impacket installé"

    # Resolve DC FQDN
    print_info "🔍 Résolution du FQDN du DC..."
    local dc_fqdn=""
    local domain_lower
    domain_lower=$(echo "${DOMAIN}" | tr '[:upper:]' '[:lower:]')

    if [ -n "${DC_HOSTNAME}" ]; then
        dc_fqdn="${DC_HOSTNAME}.${domain_lower}"
        print_info "✓ FQDN configuré: ${dc_fqdn}"
    else
        # Try reverse DNS
        local ptr_result
        ptr_result=$(host "${DC_IP}" 2>/dev/null | grep -i "pointer" | awk '{print $NF}' | sed 's/\.$//')
        if [ -n "${ptr_result}" ]; then
            dc_fqdn="${ptr_result}"
            print_info "✓ FQDN via DNS inverse: ${dc_fqdn}"
        else
            # Try LDAP
            local ldap_hostname
            ldap_hostname=$(ldapsearch -x -H "ldap://${DC_IP}" \
                -D "${username}@${DOMAIN}" -y "${pwd_file}" \
                -b "${BASE_DN}" "(objectClass=computer)" dNSHostName 2>/dev/null | \
                grep -i "dNSHostName:" | head -1 | awk '{print $2}')
            if [ -n "${ldap_hostname}" ]; then
                dc_fqdn="${ldap_hostname}"
                print_info "✓ FQDN via LDAP: ${dc_fqdn}"
            else
                # Try SRV
                local srv_result
                srv_result=$(host -t SRV "_ldap._tcp.${domain_lower}" "${DC_IP}" 2>/dev/null | \
                    grep -i "SRV" | head -1 | awk '{print $NF}' | sed 's/\.$//')
                if [ -n "${srv_result}" ]; then
                    dc_fqdn="${srv_result}"
                    print_info "✓ FQDN via SRV: ${dc_fqdn}"
                fi
            fi
        fi
    fi

    print_test "FQDN du contrôleur de domaine"
    if [ -z "${dc_fqdn}" ]; then
        print_error "❌ Impossible de déterminer le FQDN du DC"
        print_info "🛠️  Éditez DC_HOSTNAME dans le fichier de config ou utilisez --dc-hostname"
        stop_timer "bloodhound"
        return 0
    fi
    print_success "FQDN résolu: ${dc_fqdn}"

    # Validate password
    print_test "Validation du mot de passe"
    local password
    password=$(<"${pwd_file}")
    if [ -z "${password}" ]; then
        print_error "Mot de passe vide"
        stop_timer "bloodhound"
        return 1
    fi
    print_success "Mot de passe chargé (${#password} caractères)"

    # Execute BloodHound
    print_info "🚀 Lancement de la collecte BloodHound..."
    print_info "   Domaine: ${domain_lower} | DC: ${dc_fqdn} | DNS: ${DC_IP}"

    local original_dir
    original_dir=$(pwd)
    cd "${output_dir}" || { print_error "Erreur de répertoire"; stop_timer "bloodhound"; return 1; }

    print_test "Collecte BloodHound"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ EXÉCUTION BLOODHOUND — bloodhound-python -c All            │${NC}"
    echo -e "${YELLOW}│ DC: ${dc_fqdn}${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    bloodhound-python \
        -c All \
        -d "${domain_lower}" \
        -u "${username}" \
        -p "${password}" \
        -dc "${dc_fqdn}" \
        -ns "${DC_IP}" \
        --zip 2>&1 | tee bloodhound_output.log

    local exit_code=${PIPESTATUS[0]}

    local json_count zip_count
    json_count=$(find . -maxdepth 1 -name "*.json" -type f 2>/dev/null | wc -l)
    zip_count=$(find . -maxdepth 1 -name "*.zip" -type f 2>/dev/null | wc -l)

    # Retry without --zip if needed
    if [ ${zip_count} -eq 0 ] && [ ${json_count} -eq 0 ] && [ ${exit_code} -ne 0 ]; then
        print_warning "Retry sans --zip..."
        bloodhound-python -c All -d "${domain_lower}" -u "${username}" \
            -p "${password}" -dc "${dc_fqdn}" -ns "${DC_IP}" 2>&1 | tee -a bloodhound_output.log
        json_count=$(find . -maxdepth 1 -name "*.json" -type f 2>/dev/null | wc -l)
        zip_count=$(find . -maxdepth 1 -name "*.zip" -type f 2>/dev/null | wc -l)
    fi

    cd "${original_dir}" || true

    if [ ${json_count} -gt 0 ] || [ ${zip_count} -gt 0 ]; then
        print_success "✅ ${json_count} JSON + ${zip_count} ZIP créés"
        add_finding "INFO" "BloodHound Collecté" "${json_count} fichiers JSON et ${zip_count} archives ZIP générés." "${output_dir}"

        print_info "📁 Fichiers générés:"
        find "${output_dir}" -maxdepth 1 \( -name "*.json" -o -name "*.zip" \) -type f 2>/dev/null | while read -r file; do
            local size_kb=$(( $(stat -c%s "${file}" 2>/dev/null || echo "0") / 1024 ))
            print_info "   - $(basename "${file}") (${size_kb} KB)"
        done

        echo ""
        print_info "📊 Importer dans BloodHound GUI: sudo neo4j start && bloodhound"
    else
        print_error "❌ Aucun fichier généré"
        add_finding "MEDIUM" "BloodHound Échoué" "La collecte BloodHound n'a pas produit de résultats." "${output_dir}/bloodhound_output.log"
        if [ -f "${output_dir}/bloodhound_output.log" ]; then
            print_info "📋 Dernières lignes:"
            tail -10 "${output_dir}/bloodhound_output.log" | while IFS= read -r line; do echo "   ${line}"; done
        fi
    fi

    stop_timer "bloodhound"
}

#===============================================================================
# HTML REPORT GENERATION
#===============================================================================

generate_html_report() {
    print_section "GÉNÉRATION DU RAPPORT HTML"

    local risk_score=$((TESTS_FAILED * 3 + TESTS_WARNING))
    local risk_level risk_color
    if [ "$risk_score" -lt 5 ]; then
        risk_level="FAIBLE"; risk_color="#22c55e"
    elif [ "$risk_score" -lt 10 ]; then
        risk_level="MODÉRÉ"; risk_color="#f59e0b"
    elif [ "$risk_score" -lt 20 ]; then
        risk_level="ÉLEVÉ"; risk_color="#ef4444"
    else
        risk_level="CRITIQUE"; risk_color="#dc2626"
    fi

    local total_duration="${PERF_TIMERS[total_duration]:-0}"

    # Count findings by severity
    local crit=0 high=0 med=0 low=0 info=0
    local j
    for ((j=0; j<${#FINDINGS_SEVERITY[@]}; j++)); do
        case "${FINDINGS_SEVERITY[$j]}" in
            CRITICAL) ((crit++)) || true ;;
            HIGH) ((high++)) || true ;;
            MEDIUM) ((med++)) || true ;;
            LOW) ((low++)) || true ;;
            INFO) ((info++)) || true ;;
        esac
    done

    cat > "${HTML_REPORT}" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport d'Audit Active Directory</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
.container{max-width:1100px;margin:0 auto}
h1{font-size:1.8rem;margin-bottom:.5rem}
h2{font-size:1.3rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.header{text-align:center;padding:2rem;background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--border);border-radius:12px;margin-bottom:2rem}
.header .subtitle{color:var(--muted);font-size:.95rem}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1.5rem 0}
.meta-item{background:var(--card);padding:1rem;border-radius:8px;border:1px solid var(--border)}
.meta-item .label{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.meta-item .value{font-size:1.1rem;font-weight:600;margin-top:.25rem}
.risk-badge{display:inline-block;font-size:1.5rem;font-weight:700;padding:.5rem 1.5rem;border-radius:8px;margin-top:.5rem}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}
.stat{text-align:center;padding:1.2rem;background:var(--card);border-radius:8px;border:1px solid var(--border)}
.stat .num{font-size:2rem;font-weight:700}
.stat .lbl{font-size:.8rem;color:var(--muted)}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.75rem 1rem;text-align:left;border-bottom:1px solid var(--border)}
th{background:var(--card);font-size:.85rem;text-transform:uppercase;color:var(--muted);letter-spacing:.03em}
tr:hover{background:rgba(59,130,246,.05)}
.sev{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:600;text-transform:uppercase}
.sev-critical{background:#dc2626;color:#fff}
.sev-high{background:#ef4444;color:#fff}
.sev-medium{background:#f59e0b;color:#000}
.sev-low{background:#3b82f6;color:#fff}
.sev-info{background:#64748b;color:#fff}
.perf{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.75rem}
.perf-item{background:var(--card);padding:.75rem;border-radius:6px;border:1px solid var(--border);font-size:.9rem}
.footer{text-align:center;margin-top:3rem;padding:1.5rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--border)}
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    # Header section
    cat >> "${HTML_REPORT}" <<EOF
<div class="header">
<h1>🛡️ Rapport d'Audit Active Directory</h1>
<p class="subtitle">${AUDIT_REF} — ${DOMAIN}</p>
<div class="risk-badge" style="background:${risk_color};color:#fff">Risque: ${risk_level} (score: ${risk_score})</div>
</div>

<div class="meta">
<div class="meta-item"><div class="label">Domaine</div><div class="value">${DOMAIN}</div></div>
<div class="meta-item"><div class="label">Contrôleur DC</div><div class="value">${DC_IP}</div></div>
<div class="meta-item"><div class="label">Date</div><div class="value">$(date '+%Y-%m-%d %H:%M')</div></div>
<div class="meta-item"><div class="label">Version</div><div class="value">${SCRIPT_VERSION}</div></div>
</div>

<h2>📈 Statistiques</h2>
<div class="stats">
<div class="stat"><div class="num">${TESTS_TOTAL}</div><div class="lbl">Tests</div></div>
<div class="stat"><div class="num" style="color:#22c55e">${TESTS_PASSED}</div><div class="lbl">Réussis</div></div>
<div class="stat"><div class="num" style="color:#f59e0b">${TESTS_WARNING}</div><div class="lbl">Avertissements</div></div>
<div class="stat"><div class="num" style="color:#ef4444">${TESTS_FAILED}</div><div class="lbl">Échecs</div></div>
</div>

<h2>📊 Résumé des Findings (${crit} Critique, ${high} Élevé, ${med} Moyen)</h2>
<table>
<thead><tr><th>Sévérité</th><th>Finding</th><th>Description</th></tr></thead>
<tbody>
EOF

    # Add findings rows
    local i
    for ((i=0; i<${#FINDINGS_SEVERITY[@]}; i++)); do
        local sev="${FINDINGS_SEVERITY[$i]}"
        local sev_class
        case "${sev}" in
            CRITICAL) sev_class="sev-critical" ;;
            HIGH)     sev_class="sev-high" ;;
            MEDIUM)   sev_class="sev-medium" ;;
            LOW)      sev_class="sev-low" ;;
            *)        sev_class="sev-info" ;;
        esac

        # Escape HTML
        local title="${FINDINGS_TITLE[$i]//</&lt;}"
        local desc="${FINDINGS_DESC[$i]//</&lt;}"

        cat >> "${HTML_REPORT}" <<EOF
<tr><td><span class="sev ${sev_class}">${sev}</span></td><td><strong>${title}</strong></td><td>${desc}</td></tr>
EOF
    done

    cat >> "${HTML_REPORT}" <<EOF
</tbody></table>

<h2>⏱️ Performance</h2>
<div class="perf">
EOF

    # Performance metrics
    for key in "${!PERF_TIMERS[@]}"; do
        if [[ "$key" == *"_duration" ]]; then
            local name="${key%_duration}"
            local dur="${PERF_TIMERS[$key]}"
            local m=$((dur / 60))
            local s=$((dur % 60))
            echo "<div class=\"perf-item\"><strong>${name}</strong>: ${m}m ${s}s</div>" >> "${HTML_REPORT}"
        fi
    done

    cat >> "${HTML_REPORT}" <<EOF
</div>

<div class="footer">
<p>Généré par AD Audit Framework v${SCRIPT_VERSION} — $(date '+%Y-%m-%d %H:%M:%S')</p>
<p>Réf: ${AUDIT_REF} | Règlement CIMA N°010-2024 — Article 7</p>
</div>
</div>
</body>
</html>
EOF

    print_success "Rapport HTML: ${HTML_REPORT}"
    log "INFO" "HTML report generated: ${HTML_REPORT}"
}

#===============================================================================
# TEXT SUMMARY & REPORT GENERATION
#===============================================================================

generate_security_summary() {
    print_section "GÉNÉRATION DU RÉSUMÉ"

    local total_results=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))
    [ ${TESTS_TOTAL} -ne ${total_results} ] && TESTS_TOTAL=${total_results}

    local risk_score=$((TESTS_FAILED * 3 + TESTS_WARNING))
    local risk_level
    if [ "$risk_score" -lt 5 ]; then risk_level="✅ FAIBLE"
    elif [ "$risk_score" -lt 10 ]; then risk_level="⚠️  MODÉRÉ"
    elif [ "$risk_score" -lt 20 ]; then risk_level="🔴 ÉLEVÉ"
    else risk_level="🔴 CRITIQUE"; fi

    cat > "${SUMMARY_FILE}" <<EOF
════════════════════════════════════════════════════════════════
                📊 RÉSUMÉ DE SÉCURITÉ
                 Audit Active Directory
════════════════════════════════════════════════════════════════

📅 Date: $(date '+%Y-%m-%d %H:%M:%S')
🏢 Domaine: ${DOMAIN}
🖥️  DC: ${DC_IP}
📦 Version: ${SCRIPT_VERSION}

┌─ 📈 STATISTIQUES
│  Tests exécutés: ${TESTS_TOTAL}
│  ✅ Réussis: ${TESTS_PASSED}
│  ⚠️  Avertissements: ${TESTS_WARNING}
│  🔴 Échecs: ${TESTS_FAILED}
└─

Score de risque: ${risk_score}
Niveau: ${risk_level}

════════════════════════════════════════════════════════════════
EOF

    print_success "Résumé: ${SUMMARY_FILE}"
    cat "${SUMMARY_FILE}"
}

generate_log_summary() {
    print_section "RÉSUMÉ DES LOGS"

    cat > "${LOG_SUMMARY_FILE}" <<EOF
════════════════════════════════════════════════════════════════
            📋 RÉSUMÉ DES LOGS D'AUDIT
════════════════════════════════════════════════════════════════
Date: $(date '+%Y-%m-%d %H:%M:%S')
Fichier log: ${LOG_FILE}

STATISTIQUES DES ÉVÉNEMENTS
────────────────────────────
EOF

    local levels=("INFO" "TEST" "SUCCESS" "WARNING" "ERROR" "CMD" "PERF" "PARALLEL" "FINDING")
    for level in "${levels[@]}"; do
        local count
        count=$(grep -c "\[${level}\]" "${LOG_FILE}" 2>/dev/null || echo "0")
        printf "%-15s : %d\n" "${level}" "${count}" >> "${LOG_SUMMARY_FILE}"
    done

    echo "" >> "${LOG_SUMMARY_FILE}"
    echo "ERREURS" >> "${LOG_SUMMARY_FILE}"
    echo "───────" >> "${LOG_SUMMARY_FILE}"
    grep "\[ERROR\]" "${LOG_FILE}" >> "${LOG_SUMMARY_FILE}" 2>/dev/null || echo "Aucune" >> "${LOG_SUMMARY_FILE}"

    echo "" >> "${LOG_SUMMARY_FILE}"
    echo "PERFORMANCE" >> "${LOG_SUMMARY_FILE}"
    echo "───────────" >> "${LOG_SUMMARY_FILE}"
    grep "\[PERF\].*arrêté" "${LOG_FILE}" >> "${LOG_SUMMARY_FILE}" 2>/dev/null || echo "N/A" >> "${LOG_SUMMARY_FILE}"

    print_success "Résumé logs: ${LOG_SUMMARY_FILE}"
}

generate_report() {
    print_section "GÉNÉRATION DU RAPPORT TEXTE"
    start_timer "report"

    cat > "${REPORT_FILE}" <<EOF
================================================================================
               📋 RAPPORT D'AUDIT AD v${SCRIPT_VERSION}
================================================================================

Référence: ${AUDIT_REF}
Date: $(date '+%Y-%m-%d %H:%M:%S')
Domaine: ${DOMAIN}
DC: ${DC_IP}
Réseau: ${NETWORK}
LDAPS: ${LDAPS_MODE}
Règlement: CIMA N°010-2024 — Article 7

STATISTIQUES
────────────
Tests: ${TESTS_TOTAL}
✅ Réussis: ${TESTS_PASSED}
⚠️  Avertissements: ${TESTS_WARNING}
🔴 Échecs: ${TESTS_FAILED}

PERFORMANCE
───────────
EOF

    for key in "${!PERF_TIMERS[@]}"; do
        if [[ "$key" == *"_duration" ]]; then
            local name="${key%_duration}"
            local dur="${PERF_TIMERS[$key]}"
            printf "%-25s : %ds\n" "$name" "$dur" >> "${REPORT_FILE}"
        fi
    done

    cat >> "${REPORT_FILE}" <<EOF

FINDINGS (${#FINDINGS_SEVERITY[@]})
────────
EOF

    local i
    for ((i=0; i<${#FINDINGS_SEVERITY[@]}; i++)); do
        echo "[${FINDINGS_SEVERITY[$i]}] ${FINDINGS_TITLE[$i]}: ${FINDINGS_DESC[$i]}" >> "${REPORT_FILE}"
    done

    echo "" >> "${REPORT_FILE}"
    echo "================================================================================" >> "${REPORT_FILE}"
    echo "FIN DU RAPPORT" >> "${REPORT_FILE}"
    echo "================================================================================" >> "${REPORT_FILE}"

    print_success "Rapport texte: ${REPORT_FILE}"
    stop_timer "report"
}

#===============================================================================
# ARCHIVE & INTEGRITY
#===============================================================================

generate_checksums() {
    print_info "🔒 Génération des checksums SHA256..."
    find "${OUTPUT_DIR}" -type f ! -name "checksums.sha256" | sort | while read -r f; do
        sha256sum "${f}" >> "${OUTPUT_DIR}/checksums.sha256" 2>/dev/null || true
    done
    log "INFO" "Checksums generated: ${OUTPUT_DIR}/checksums.sha256"
    print_success "Checksums: ${OUTPUT_DIR}/checksums.sha256"
}

create_archive() {
    local archive="${OUTPUT_DIR}.tar.gz"
    print_info "📦 Création de l'archive: ${archive}"
    tar -czf "${archive}" "${OUTPUT_DIR}" 2>/dev/null || true
    chmod 600 "${archive}" 2>/dev/null || true

    if [ -f "${archive}" ]; then
        local size_mb=$(( $(stat -c%s "${archive}" 2>/dev/null || echo "0") / 1048576 ))
        print_success "Archive créée: ${archive} (${size_mb} MB)"

        if [ "${ENCRYPT_OUTPUT}" = true ] && command_exists gpg; then
            print_info "🔐 Chiffrement GPG..."
            gpg --symmetric --cipher-algo AES256 "${archive}" 2>/dev/null && \
                rm -f "${archive}" && \
                print_success "Archive chiffrée: ${archive}.gpg" || \
                print_warning "Chiffrement GPG échoué"
        fi
    fi
}

#===============================================================================
# MAIN
#===============================================================================

show_help() {
    cat <<EOF
╔═══════════════════════════════════════════════════════════════╗
║  AD AUDIT FRAMEWORK v${SCRIPT_VERSION}                               ║
╚═══════════════════════════════════════════════════════════════╝

Usage: $0 [OPTIONS] [username]

TARGET (required — via args, config, or auto-detect):
  -t, --target <IP>         DC IP address
  -d, --domain <DOMAIN>     AD domain (e.g. CORP.LOCAL)
  -n, --network <CIDR>      Network range (default: auto from DC IP)
  --dc-hostname <NAME>      DC hostname for BloodHound (e.g. DC01)

AUTHENTICATION:
  -u, --user <username>     AD username
  --unauth-only             Non-authenticated tests only

OPTIONS:
  --config <file>           Load config from file
  --output-dir <path>       Custom output directory
  --ldaps                   Use LDAPS (port 636)
  --encrypt                 GPG encrypt final archive
  --inactivity-days <N>     Inactive threshold (default: 90)

DEBUG:
  --debug                   Debug mode (detailed logs)
  --verbose                 Verbose output
  -h, --help                Show this help

EXAMPLES:
  $0 -t [IP_ADDRESS] -d [DOMAIN] -u [USERNAME]
  $0 -t 10.0.0.1 -d CORP.LOCAL --ldaps --user admin
  $0 --config audit.conf -u auditor
  $0 -t [IP_ADDRESS] -d [DOMAIN] --unauth-only
  $0 -t [IP_ADDRESS] --debug -u admin    # auto-detect domain
EOF
}

main() {
    local username=""
    local pwd_file=""
    local unauth_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--target)
                DC_IP="$2"; shift 2
                ;;
            -d|--domain)
                DOMAIN="$2"; shift 2
                ;;
            -n|--network)
                NETWORK="$2"; shift 2
                ;;
            --dc-hostname)
                DC_HOSTNAME="$2"; shift 2
                ;;
            -u|--user)
                username="$2"; shift 2
                ;;
            --unauth-only)
                unauth_only=true; shift
                ;;
            --config)
                CONFIG_FILE="$2"; shift 2
                ;;
            --output-dir)
                CUSTOM_OUTPUT_DIR="$2"; shift 2
                ;;
            --ldaps)
                LDAPS_MODE=true; shift
                ;;
            --encrypt)
                ENCRYPT_OUTPUT=true; shift
                ;;
            --inactivity-days)
                INACTIVITY_DAYS="$2"; shift 2
                ;;
            --debug)
                DEBUG_MODE=true; shift
                ;;
            --verbose)
                VERBOSE_MODE=true; shift
                ;;
            -*)
                echo "Option inconnue: $1"
                show_help
                exit 1
                ;;
            *)
                # Positional: treat as username for backward compat
                username="$1"; shift
                ;;
        esac
    done

    # Banner
    echo -e "${CYAN}"
    cat <<'EOF'
╔═══════════════════════════════════════════════════════════════╗
║     🛡️  AUDIT DE SÉCURITÉ ACTIVE DIRECTORY — v4.0            ║
║     Enterprise AD Security Assessment Framework              ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    [ "$DEBUG_MODE" = true ] && echo -e "${YELLOW}[MODE DEBUG ACTIVÉ]${NC}\n"

    # Load config file if specified
    if [ -n "${CONFIG_FILE}" ]; then
        load_config "${CONFIG_FILE}"
    fi

    # Validate target
    if [ -z "${DC_IP}" ]; then
        echo -e "${RED}[✗] Cible requise. Utilisez -t/--target <IP> ou --config <file>${NC}"
        echo ""
        show_help
        exit 1
    fi

    # Auto-detect domain if needed
    if [ -z "${DOMAIN}" ]; then
        auto_detect_domain || {
            echo -e "${RED}[✗] Domaine requis. Utilisez -d/--domain <DOMAIN>${NC}"
            exit 1
        }
    fi

    # Auto-detect network
    auto_detect_network

    start_timer "total"

    # Setup environment (creates dirs, sets paths)
    setup_environment

    # Trap for cleanup
    trap cleanup_all EXIT INT TERM

    # Print config summary
    print_info "🎯 Cible: ${DC_IP} | Domaine: ${DOMAIN} | Réseau: ${NETWORK}"
    print_info "📂 Sortie: ${OUTPUT_DIR} | LDAPS: ${LDAPS_MODE}"

    # Requirements
    if ! check_requirements; then
        print_error "Prérequis non satisfaits"
        exit 1
    fi

    # Connectivity
    test_connectivity

    if [ "$unauth_only" = true ]; then
        print_header "MODE NON AUTHENTIFIÉ"
        audit_inventory
        audit_dc_config
        audit_ldap_unauth
    else
        # Get credentials
        if [ -z "$username" ]; then
            read -p "Nom d'utilisateur: " username
        fi
        [ -z "$username" ] && { print_error "Username requis"; exit 1; }

        pwd_file=$(secure_password_prompt "${username}")
        print_info "🔐 Mot de passe stocké de manière sécurisée (mode 600)"

        print_header "AUDIT COMPLET — ${DOMAIN}"
        log "INFO" "Audit complet démarré — user: ${username} | domain: ${DOMAIN} | dc: ${DC_IP}"

        audit_inventory
        audit_dc_config
        audit_ldap_unauth
        audit_authenticated "$username" "$pwd_file"
    fi

    # Validation
    local total_results=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))
    [ ${TESTS_TOTAL} -ne ${total_results} ] && TESTS_TOTAL=${total_results}

    # Reports
    generate_security_summary
    generate_log_summary
    generate_report
    generate_html_report
    generate_checksums
    create_archive

    stop_timer "total"

    # Final summary
    echo ""
    print_header "✅ AUDIT TERMINÉ"
    echo -e "${GREEN}📁 Résultats:      ${OUTPUT_DIR}${NC}"
    echo -e "${GREEN}📊 Résumé:         ${SUMMARY_FILE}${NC}"
    echo -e "${GREEN}📋 Logs:           ${LOG_SUMMARY_FILE}${NC}"
    echo -e "${GREEN}📝 Log complet:    ${LOG_FILE}${NC}"
    echo -e "${GREEN}📄 Rapport:        ${REPORT_FILE}${NC}"
    echo -e "${GREEN}🌐 Rapport HTML:   ${HTML_REPORT}${NC}"
    echo -e "${GREEN}🔒 Checksums:      ${OUTPUT_DIR}/checksums.sha256${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
    echo -e "  📊 STATISTIQUES FINALES"
    echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
    echo -e "  Tests: ${TESTS_TOTAL}"
    echo -e "  ${GREEN}✅ Réussis: ${TESTS_PASSED}${NC}"
    echo -e "  ${YELLOW}⚠️  Avertissements: ${TESTS_WARNING}${NC}"
    echo -e "  ${RED}🔴 Échecs: ${TESTS_FAILED}${NC}"
    echo -e "  Findings: ${#FINDINGS_SEVERITY[@]}"
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
    echo ""

    log "INFO" "════════════════════════════════════════════════════"
    log "INFO" "AUDIT TERMINÉ — Tests: ${TESTS_TOTAL} | Réussis: ${TESTS_PASSED} | Warnings: ${TESTS_WARNING} | Échecs: ${TESTS_FAILED} | Findings: ${#FINDINGS_SEVERITY[@]}"
    log "INFO" "════════════════════════════════════════════════════"
}

main "$@"
