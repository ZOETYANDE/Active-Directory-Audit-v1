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

    local NMAP_T="T4"
    [ "${SAFE_MODE}" = true ] && NMAP_T="T2"

    local nmap_domain
    nmap_domain=$(nmap -${NMAP_T} -Pn -p 389 --script ldap-rootdse "${DC_IP}" 2>/dev/null | \
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
            LDAP_DELAY)       LDAP_DELAY="${value}" ;;
            SAFE_MODE)        SAFE_MODE="${value}" ;;
            ALLOWED_HOURS)    ALLOWED_HOURS="${value}" ;;
            MAX_CLOCK_SKEW)   MAX_CLOCK_SKEW="${value}" ;;
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
    local optional_tools_list=("nxc:NetExec" "crackmapexec:CrackMapExec" "enum4linux-ng:Enum4Linux-NG" "bloodhound-python:BloodHound" "certipy-ad:Certipy-AD" "gpg:GPG" "smbclient:SMBClient" "rpcdump.py:RPCDump" "dig:DNS-Dig" "dacledit.py:DACLEdit-Impacket")

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
                certipy-ad)         HAS_CERTIPY=true ;;
                smbclient)          HAS_SMBCLIENT=true ;;
                rpcdump.py)         HAS_RPCDUMP=true ;;
                dig)                HAS_DIG=true ;;
                dacledit.py)        HAS_DACLEDIT=true ;;
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

    print_test "Dérive temporelle (Clock Skew Kerberos)"
    local skew_output="${OUTPUT_DIR}/clock_skew.txt"
    local max_skew=${MAX_CLOCK_SKEW:-5}
    local max_skew_sec=$(( max_skew * 60 ))
    local skew_abs_sec=0
    local skew_source=""

    # ── Méthode 1 : LDAP rootDSE currentTime (port 389 — toujours dispo sur un DC) ──
    if command_exists ldapsearch; then
        local ldap_time_raw
        ldap_time_raw=$(ldapsearch -x -H "ldap://${DC_IP}" -b "" -s base \
            "(objectClass=*)" currentTime 2>/dev/null | \
            grep -i "currentTime:" | awk '{print $2}' | tr -d '\r\n')

        # Format LDAP: 20240508154820.0Z → timestamp unix
        if [ -n "${ldap_time_raw}" ]; then
            local ldap_clean
            ldap_clean=$(echo "${ldap_time_raw}" | sed 's/\\..*Z$//' | sed 's/Z$//')
            local server_ts local_ts
            server_ts=$(date -d "${ldap_clean:0:8} ${ldap_clean:8:2}:${ldap_clean:10:2}:${ldap_clean:12:2} UTC" +%s 2>/dev/null || echo "0")
            local_ts=$(date +%s)

            if [ "${server_ts:-0}" -gt 0 ] 2>/dev/null; then
                skew_abs_sec=$(( server_ts - local_ts ))
                [ "${skew_abs_sec}" -lt 0 ] && skew_abs_sec=$(( -skew_abs_sec ))
                skew_source="LDAP rootDSE (currentTime)"
                echo "Méthode: LDAP rootDSE | Serveur: ${ldap_time_raw} | Skew: ${skew_abs_sec}s" > "${skew_output}"
            fi
        fi
    fi

    # ── Méthode 2 : HTTP Date header via curl ───────────────────────────────────
    if [ "${skew_abs_sec}" -eq 0 ] && command_exists curl; then
        local server_date_raw
        server_date_raw=$(curl -sI --connect-timeout 3 --max-time 5 \
            "http://${DC_IP}" 2>/dev/null | grep -i "^Date:" | head -1 | \
            sed 's/[Dd]ate: //' | tr -d '\r')

        if [ -n "${server_date_raw}" ]; then
            local server_ts local_ts
            server_ts=$(date -d "${server_date_raw}" +%s 2>/dev/null || echo "0")
            local_ts=$(date +%s)

            if [ "${server_ts:-0}" -gt 0 ] 2>/dev/null; then
                skew_abs_sec=$(( server_ts - local_ts ))
                [ "${skew_abs_sec}" -lt 0 ] && skew_abs_sec=$(( -skew_abs_sec ))
                skew_source="HTTP Date header"
                echo "Méthode: HTTP Date | Serveur: ${server_date_raw} | Skew: ${skew_abs_sec}s" > "${skew_output}"
            fi
        fi
    fi

    # ── Méthode 3 : nmap smb-os-discovery (dernier recours) ────────────────────
    if [ "${skew_abs_sec}" -eq 0 ] && command_exists nmap; then
        local NMAP_T="T4"
        [ "${SAFE_MODE}" = true ] && NMAP_T="T2"
        nmap -${NMAP_T} -Pn -p 445 --script smb-os-discovery "${DC_IP}" \
            >> "${skew_output}" 2>/dev/null || true

        if grep -qi "clock-skew:" "${skew_output}"; then
            local nmap_skew_raw
            nmap_skew_raw=$(grep -i "clock-skew:" "${skew_output}" | \
                awk -F'clock-skew: ' '{print $2}' | awk '{print $1}')
            skew_abs_sec=$(echo "${nmap_skew_raw}" | grep -oE '-?[0-9]+' | head -1 | \
                tr -d '-' || echo "0")
            skew_abs_sec=${skew_abs_sec:-0}
            skew_source="nmap smb-os-discovery"
        fi
    fi

    # Commande de correction (sans echo -e pour éviter l'interprétation de \r)
    local fix_cmd="sudo date -s \"\$(curl -sI http://${DC_IP} | grep '^Date:' | sed 's/Date: //' | tr -d '\\r')\""

    # ── Évaluation du résultat ───────────────────────────────────────────────────
    if [ "${skew_abs_sec}" -gt 0 ] || [ -n "${skew_source}" ]; then
        local skew_min=$(( skew_abs_sec / 60 ))
        print_info "Clock Skew = ${skew_abs_sec}s (${skew_min}min) — source: ${skew_source}"
        log_data "Clock Skew" "${skew_abs_sec}s" "${skew_source}"

        if [ "${skew_abs_sec}" -ge "${max_skew_sec}" ] 2>/dev/null; then
            print_warning "⚠️  Clock Skew = ${skew_abs_sec}s > ${max_skew}min ! Kerberos va échouer (NXC, BloodHound, certipy-ad)."
            echo "   💡 Correction: ${fix_cmd}"
            log "WARNING" "Clock Skew hors tolérance: ${skew_abs_sec}s (max: ${max_skew_sec}s)"
        else
            print_success "Clock Skew acceptable: ${skew_abs_sec}s < ${max_skew_sec}s (limite Kerberos: ${max_skew}min)"
        fi
    else
        print_warning "Impossible de mesurer le Clock Skew (LDAP, curl et nmap sans résultat)"
        echo "   💡 Correction manuelle si Kerberos echoue:"
        echo "      ${fix_cmd}"
        log "WARNING" "Clock Skew non mesurable"
    fi

    stop_timer "connectivity"
}

