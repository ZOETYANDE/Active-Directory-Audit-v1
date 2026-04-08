#!/bin/bash
# lib/modules/ldap_unauth.sh — Anonymous LDAP bind test

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
