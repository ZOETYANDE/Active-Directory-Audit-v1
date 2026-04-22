#!/bin/bash
# lib/modules/ldap_unauth.sh — Anonymous LDAP bind test

audit_ldap_unauth() {
    print_section "AUDIT 3: LDAP NON AUTHENTIFIÉ"
    local output_dir="${OUTPUT_DIR}/02_Configuration_DC"
    start_timer "ldap_unauth"

    local uri
    uri=$(get_ldap_uri)

    print_test "Énumération LDAP anonyme"
    ldapsearch -x -H "${uri}" -b "${BASE_DN}" \
        "(objectclass=user)" sAMAccountName \
        > "${output_dir}/ldap_anon.txt" 2>&1 || true

    local user_count
    user_count=$(safe_count "sAMAccountName:" "${output_dir}/ldap_anon.txt")

    if [ "${user_count}" -gt 0 ]; then
        print_error "🔴 LDAP anonyme autorisé! ${user_count} comptes exposés"
        add_finding_remediation "CRITICAL" "LDAP Anonyme Autorisé" \
            "Le serveur autorise l'énumération d'objets via LDAP anonyme. ${user_count} comptes ont pu être listés sans authentification." \
            "${output_dir}/ldap_anon.txt" \
            "# Disable anonymous LDAP search\n# See KB257288 and set 'dsHeuristics' seventh character to '0' or '2'"
    else
        print_success "LDAP anonyme restreint"
    fi

    stop_timer "ldap_unauth"
}
