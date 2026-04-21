#!/bin/bash
# lib/core.sh — Logging, display, findings, timers, password handling, utilities

#===============================================================================
# LOGGING SYSTEM
#===============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # PROTECTION : Ne rien faire si OUTPUT_DIR n'est pas encore défini
    if [ -z "${OUTPUT_DIR}" ]; then
        return 0
    fi

    # Création sécurisée du répertoire
    [ -d "${OUTPUT_DIR}" ] || mkdir -p "${OUTPUT_DIR}" 2>/dev/null

    # Initialisation du fichier de log s'il n'existe pas
    if [ ! -f "${LOG_FILE}" ]; then
        # Utilisation de <<-EOF pour permettre l'indentation avec des TABULATIONS si besoin
        # Mais attention : EOF doit être strictement collé au début de ligne
        cat > "${LOG_FILE}" <<EOF
================================================================================
LOG D'EXÉCUTION - AUDIT AD v${SCRIPT_VERSION:-"1.0"}
================================================================================
Date démarrage : ${timestamp}
Version script : ${SCRIPT_VERSION:-"1.0"}
Mode debug     : ${DEBUG_MODE:-false}
Mode verbose   : ${VERBOSE_MODE:-false}
Domaine        : ${DOMAIN:-"N/A"}
Contrôleur DC  : ${DC_IP:-"N/A"}
Réseau         : ${NETWORK:-"N/A"}
LDAPS          : ${LDAPS_MODE:-false}
================================================================================

EOF
    fi

    # Écriture dans le fichier de log
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
# FINDINGS TRACKER
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

add_finding_remediation() {
    local severity="$1" title="$2" desc="$3" evidence="${4:-}" remediation="${5:-}"
    add_finding "${severity}" "${title}" "${desc}" "${evidence}"
    if [ -n "${remediation}" ]; then
        REMEDIATION_LABELS+=("${severity}: ${title}")
        REMEDIATION_CMDS+=("${remediation}")
    fi
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
# SIGNAL HANDLERS
#===============================================================================

cleanup_normal() {
    cleanup_password
}

cleanup_interrupted() {
    echo ""
    echo -e "${YELLOW}[!] Interruption détectée — nettoyage en cours...${NC}"
    log "WARNING" "Script interrompu — nettoyage"

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

domain_to_base_dn() {
    local domain="$1"
    echo "${domain}" | sed 's/\./,DC=/g; s/^/DC=/' | tr '[:lower:]' '[:upper:]'
}

get_ldap_uri() {
    if [ "${LDAPS_MODE}" = true ]; then
        echo "ldaps://${DC_IP}"
    else
        echo "ldap://${DC_IP}"
    fi
}

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

smb_tool_exec() {
    if [ "${HAS_NXC}" = true ]; then
        nxc smb "$@"
    elif [ "${HAS_CME}" = true ]; then
        crackmapexec smb "$@"
    else
        log "WARNING" "No SMB tool available (nxc/crackmapexec)"
        return 1
    fi
}

show_progress() {
    local module_name="$1"
    ((CURRENT_MODULE++)) || true
    local pct=$((CURRENT_MODULE * 100 / TOTAL_MODULES))
    local filled=$((pct / 5))
    local empty=$((20 - filled))
    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    local start_time=${PERF_TIMERS[total_start]:-0}
    local elapsed=0
    if [ "${start_time}" -gt 0 ]; then
        elapsed=$(( $(date +%s) - start_time ))
    fi
    printf "\r${CYAN}[${bar}] %3d%% │ %d/%d: %s │ %ds${NC}        " \
        "$pct" "$CURRENT_MODULE" "$TOTAL_MODULES" "$module_name" "$elapsed" >&2
    echo "" >&2
}

should_run_module() {
    local module="$1"
    if [ -n "${SELECTED_MODULES}" ]; then
        echo ",${SELECTED_MODULES}," | grep -q ",${module}," && return 0 || return 1
    fi
    if [ -n "${SKIP_MODULES}" ]; then
        echo ",${SKIP_MODULES}," | grep -q ",${module}," && return 1 || return 0
    fi
    return 0
}
