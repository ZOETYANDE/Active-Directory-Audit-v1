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
Auteur: ZOETYANDE MOHAMED
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
    # Utilise "$@" au lieu de eval pour éviter les injections de commandes
    log "CMD" "${description}"
    log_debug "Commande: $*"

    local start_time
    start_time=$(date +%s)
    "$@"
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

#===============================================================================
# THROTTLING (rate-limiting des requêtes réseau)
#===============================================================================

# Délai inter-requêtes en secondes (0 = désactivé, configurable via LDAP_DELAY)
LDAP_DELAY="${LDAP_DELAY:-0}"

throttle_request() {
    if [ "${LDAP_DELAY}" -gt 0 ] 2>/dev/null; then
        sleep "${LDAP_DELAY}"
    fi
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
        echo "ldaps://${DC_IP}:636"
    else
        echo "ldap://${DC_IP}:389"
    fi
}

ldap_search() {
    local bind_user="$1"
    local pwd_file="$2"
    local filter="$3"
    local attrs="$4"
    local output_file="$5"
    local search_base="${6:-${BASE_DN}}"
    
    # === VALIDATIONS ===
    if [ -z "${bind_user}" ] || [ -z "${pwd_file}" ] || [ -z "${filter}" ]; then
        log "ERROR" "ldap_search: paramètres manquants (user, pwd_file ou filter)"
        return 1
    fi
    
    if [ ! -f "${pwd_file}" ]; then
        log "ERROR" "ldap_search: fichier mot de passe introuvable: ${pwd_file}"
        return 1
    fi
    
    if [ -z "${search_base}" ]; then
        log "ERROR" "ldap_search: BASE_DN non défini"
        return 1
    fi
    
    if [ -z "${DOMAIN}" ] || [ -z "${DC_IP}" ]; then
        log "ERROR" "ldap_search: DOMAIN ou DC_IP non définis"
        return 1
    fi
 
    local uri
    uri=$(get_ldap_uri)
    
    throttle_request
 
    # === TENTATIVE 1: LDAP simple (ou LDAPS si déjà activé) ===
    log "INFO" "Recherche LDAP: ${bind_user}@${DOMAIN} | URI: ${uri} | Base: ${search_base}"
    
    ldapsearch -x \
        -H "${uri}" \
        -D "${bind_user}@${DOMAIN}" \
        -y "${pwd_file}" \
        -b "${search_base}" \
        -E pr=1000/noprompt \
        -l 10 \
        "${filter}" ${attrs} \
        > "${output_file}" 2>&1 || true
    
    # === VÉRIFIER SI C'EST UN SUCCÈS ===
    if grep -qi "^dn:" "${output_file}" 2>/dev/null; then
        # ✓ SUCCÈS à la première tentative
        log_file_info "${output_file}" "LDAP query: ${filter}"
        return 0
    fi
    
    # === ANALYSE DES ERREURS ===
    local error_msg=""
    
    if grep -qi "Strong(er) authentication required" "${output_file}" 2>/dev/null; then
        error_msg="STRONG_AUTH_REQUIRED"
        log "WARNING" "Erreur: Signature LDAP requise — Fallback LDAPS..."
    elif grep -qi "Can't contact LDAP server\|Connection refused\|Couldn't open connection" "${output_file}" 2>/dev/null; then
        error_msg="CANT_CONTACT"
        log "WARNING" "Erreur: Impossible de contacter le serveur LDAP — Tentative LDAPS..."
    elif grep -qi "TLS handshake\|SSL_connect\|tlsv1 alert\|certificate verify failed" "${output_file}" 2>/dev/null; then
        error_msg="TLS_FAILURE"
        log "WARNING" "Erreur: Échec TLS — Tentative avec LDAPTLS_REQCERT=never..."
    elif grep -qi "Invalid DN syntax\|Invalid credentials\|authentication failed" "${output_file}" 2>/dev/null; then
        log "ERROR" "Erreur: Authentification échouée (vérifiez utilisateur/mot de passe)"
        log_file_info "${output_file}" "Erreur LDAP"
        return 1
    fi
 
    # === FALLBACK 1: LDAPS via IP avec port 636 ===
    if [ -n "${error_msg}" ]; then
        log "INFO" "Fallback 1: Tentative LDAPS via IP (port 636)..."
        
        LDAPTLS_REQCERT=never ldapsearch -x \
            -H "ldaps://${DC_IP}:636" \
            -D "${bind_user}@${DOMAIN}" \
            -y "${pwd_file}" \
            -b "${search_base}" \
            -E pr=1000/noprompt \
            -l 10 \
            "${filter}" ${attrs} \
            > "${output_file}" 2>&1 || true
        
        # Vérifier si le fallback a marché
        if grep -qi "^dn:" "${output_file}" 2>/dev/null; then
            log "SUCCESS" "Fallback 1 réussi (LDAPS/IP)!"
            log_file_info "${output_file}" "LDAP query (via LDAPS): ${filter}"
            return 0  # ✓ SUCCÈS - retour immédiat
        fi
        
        # === FALLBACK 2: LDAPS via FQDN du domaine ===
        if grep -qi "Can't contact\|TLS handshake\|SSL_connect" "${output_file}" 2>/dev/null; then
            log "INFO" "Fallback 2: Tentative LDAPS via FQDN (${DOMAIN}:636)..."
            
            LDAPTLS_REQCERT=never ldapsearch -x \
                -H "ldaps://${DOMAIN}:636" \
                -D "${bind_user}@${DOMAIN}" \
                -y "${pwd_file}" \
                -b "${search_base}" \
                -E pr=1000/noprompt \
                -l 10 \
                "${filter}" ${attrs} \
                > "${output_file}" 2>&1 || true
            
            # Vérifier si ce fallback a marché
            if grep -qi "^dn:" "${output_file}" 2>/dev/null; then
                log "SUCCESS" "Fallback 2 réussi (LDAPS/FQDN)!"
                log_file_info "${output_file}" "LDAP query (via LDAPS/FQDN): ${filter}"
                return 0  # ✓ SUCCÈS - retour immédiat
            fi
        fi
        
        # === TOUS LES FALLBACKS ONT ÉCHOUÉ ===
        log "ERROR" "Tous les fallbacks LDAP ont échoué"
        log_file_info "${output_file}" "LDAP query FAILED (tous les fallbacks échoués): ${filter}"
        return 1  # ✗ ÉCHEC
    fi
 
    # Si on arrive ici, on n'a pas d'erreur détectée mais pas de résultats non plus
    log "WARNING" "Requête LDAP sans résultats et sans erreur détectable"
    log_file_info "${output_file}" "LDAP query: ${filter}"
    return 0  # Retourner 0 car la requête s'est exécutée (même sans résultats)
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
