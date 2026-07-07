#!/bin/bash
# lib/modules/authenticated.sh — Authenticated audit orchestrator

audit_authenticated() {
    local username="$1"
    local pwd_file="$2"

    print_section "AUDIT 4: ÉNUMÉRATION AUTHENTIFIÉE"
    start_timer "authenticated"

    local password
    password=$(<"${pwd_file}")

    # Credential validation — la vérification fail-fast dans main() a déjà valide les identifiants
    print_test "Validation des identifiants (${username})"

    if [ -f "${OUTPUT_DIR}/cred_test.txt" ]; then
        # Déjà validé par le check fail-fast dans main() — on fait confiance
        print_success "Identifiants valides (pré-validés)"
    elif [ "${HAS_NXC}" = true ] || [ "${HAS_CME}" = true ]; then
        smb_tool_exec "${DC_IP}" -u "${username}" -p "@${pwd_file}" -d "${DOMAIN}" \
            > "${OUTPUT_DIR}/cred_test.txt" 2>&1

        if grep -qE "\[\+\]" "${OUTPUT_DIR}/cred_test.txt"; then
            print_success "Identifiants valides"
            redact_secret "${password}" "${OUTPUT_DIR}/cred_test.txt"
        else
            print_error "Identifiants invalides"
            redact_secret "${password}" "${OUTPUT_DIR}/cred_test.txt"
            stop_timer "authenticated"
            return 1
        fi
    else
        if ldap_search "${username}" "${pwd_file}" "(objectClass=domain)" "dn" "${OUTPUT_DIR}/auth_test_ldap.txt"; then
            print_success "Identifiants valides (LDAP)"
        else
            print_error "Identifiants invalides"
            stop_timer "authenticated"
            return 1
        fi
    fi


    # Run all sub-audits with module selector and progress tracking
    local -a auth_modules=(
        "users:audit_users:Comptes Utilisateurs"
        "groups:audit_groups:Groupes Privilégiés"
        "inactive:audit_inactive_users:Comptes Inactifs"
        "computers:audit_inactive_computers:Ordinateurs"
        "password:audit_password_policy:Politique MDP"
        "gpo:audit_gpo:Stratégies GPO"
        "shares:audit_shares:Partages SMB"
        "delegation:audit_delegation:Délégation Kerberos"
        "acl:audit_acl_abuse:Permissions ACL"
        "trusts:audit_trusts:Relations d'approbation"
        "laps:audit_laps:LAPS"
        "adcs:audit_adcs:Certificats ADCS"
        "vulns:audit_vulnerabilities:Vulnérabilités"
        "misc:audit_misc:Durcissement"
        "bloodhound:audit_bloodhound:BloodHound"
        "ad_enum:audit_ad_enum:Énumération NXC"
    )

    for entry in "${auth_modules[@]}"; do
        local mod_key="${entry%%:*}"
        local rest="${entry#*:}"
        local mod_func="${rest%%:*}"
        local mod_name="${rest#*:}"

        if should_run_module "${mod_key}"; then
            show_progress "${mod_name}"
            ${mod_func} "${username}" "${pwd_file}"
        else
            log "INFO" "Module ${mod_key} ignoré (sélection utilisateur)"
        fi
    done

    stop_timer "authenticated"
}
