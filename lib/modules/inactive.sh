#!/bin/bash
# lib/modules/inactive.sh

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
