#!/bin/bash

#===============================================================================
#
# ACTIVE DIRECTORY SECURITY AUDIT FRAMEWORK v2.0
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
readonly SCRIPT_VERSION="2.0"
readonly AUDIT_REF="Audit - Sécurité Active Directory"

# Resolve lib directory relative to script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
JSON_REPORT=""
REMEDIATION_FILE=""
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

# Findings for reports
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
HAS_SMBCLIENT=false
HAS_RPCDUMP=false
HAS_DIG=false

# Module selector
SELECTED_MODULES=""
SKIP_MODULES=""

# Progress tracking
declare -i TOTAL_MODULES=0
declare -i CURRENT_MODULE=0

# Background PIDs for cleanup
declare -a BG_PIDS=()

# Remediation commands for PowerShell script
declare -a REMEDIATION_CMDS=()
declare -a REMEDIATION_LABELS=()

#===============================================================================
# LOAD LIBRARIES
#===============================================================================

source "${SCRIPT_DIR}/lib/core.sh"
source "${SCRIPT_DIR}/lib/config.sh"

# Load all audit modules
for _mod_file in "${SCRIPT_DIR}"/lib/modules/*.sh; do
    [ -f "${_mod_file}" ] && source "${_mod_file}"
done

# Load all reporting modules
for _rpt_file in "${SCRIPT_DIR}"/lib/reporting/*.sh; do
    [ -f "${_rpt_file}" ] && source "${_rpt_file}"
done

unset _mod_file _rpt_file

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

MODULES:
  --modules <list>          Comma-separated modules to run (e.g. users,groups,bloodhound)
  --skip <list>             Comma-separated modules to skip (e.g. bloodhound,adcs)
  --list-modules            Show available modules

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
  $0 -t 10.0.0.1 -d CORP.LOCAL -u admin --modules users,groups,bloodhound
  $0 -t 10.0.0.1 -d CORP.LOCAL -u admin --skip bloodhound,adcs
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
            --modules)
                SELECTED_MODULES="$2"; shift 2
                ;;
            --skip)
                SKIP_MODULES="$2"; shift 2
                ;;
            --list-modules)
                echo "Available modules:"
                echo "  inventory, dc_config, ldap_unauth, smb_unauth, dns"
                echo "  users, groups, inactive, computers, password, gpo"
                echo "  shares, delegation, acl, trusts, laps, adcs"
                echo "  vulns, misc, bloodhound"
                exit 0
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
║     🛡️  AUDIT DE SÉCURITÉ ACTIVE DIRECTORY — v2.0            ║
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

    # Trap for cleanup — separate normal exit from interrupt
    trap cleanup_normal EXIT
    trap cleanup_interrupted INT TERM

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
        TOTAL_MODULES=5
        CURRENT_MODULE=0
        print_header "MODE NON AUTHENTIFIÉ"
        should_run_module "inventory" && { show_progress "Inventaire"; audit_inventory; }
        should_run_module "dc_config" && { show_progress "Configuration DC"; audit_dc_config; }
        should_run_module "ldap_unauth" && { show_progress "LDAP Anonyme"; audit_ldap_unauth; }
        should_run_module "smb_unauth" && { show_progress "SMB Anonyme"; audit_smb_unauth; }
        should_run_module "dns" && { show_progress "Sécurité DNS"; audit_dns; }
    else
        TOTAL_MODULES=20
        CURRENT_MODULE=0
        # Get credentials
        if [ -z "$username" ]; then
            read -p "Nom d'utilisateur: " username
        fi
        [ -z "$username" ] && { print_error "Username requis"; exit 1; }

        pwd_file=$(secure_password_prompt "${username}")
        print_info "🔐 Mot de passe stocké de manière sécurisée (mode 600)"

        print_header "AUDIT COMPLET — ${DOMAIN}"
        log "INFO" "Audit complet démarré — user: ${username} | domain: ${DOMAIN} | dc: ${DC_IP}"

        # Credential quick test BEFORE dc_config to enable SMB signing cross-validation
        local password
        password=$(<"${pwd_file}")
        if [ "${HAS_NXC}" = true ] || [ "${HAS_CME}" = true ]; then
            smb_tool_exec "\"${DC_IP}\" -u \"${username}\" -p \"${password}\" -d \"${DOMAIN}\"" \
                > "${OUTPUT_DIR}/cred_test.txt" 2>&1 || true
            sed -i "s/${password}/[REDACTED]/g" "${OUTPUT_DIR}/cred_test.txt" 2>/dev/null || true
        fi

        # Unauthenticated modules first
        should_run_module "inventory" && { show_progress "Inventaire"; audit_inventory; }
        should_run_module "dc_config" && { show_progress "Configuration DC"; audit_dc_config; }
        should_run_module "ldap_unauth" && { show_progress "LDAP Anonyme"; audit_ldap_unauth; }
        should_run_module "smb_unauth" && { show_progress "SMB Anonyme"; audit_smb_unauth; }
        should_run_module "dns" && { show_progress "Sécurité DNS"; audit_dns; }

        # Authenticated modules
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
    generate_json_report
    generate_remediation_script
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
    echo -e "${GREEN}📊 Findings JSON:  ${JSON_REPORT}${NC}"
    echo -e "${GREEN}🔧 Remédiation:    ${REMEDIATION_FILE}${NC}"
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
