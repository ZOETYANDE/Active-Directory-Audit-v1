#!/bin/bash
# lib/modules/gpo.sh

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

    if [ -f "${output_dir}/gpp_passwords.txt" ] && grep -qiE "\[\+\].*gpp|cpassword" "${output_dir}/gpp_passwords.txt" 2>/dev/null; then
        print_error "🔴 Mots de passe GPP trouvés!"
        add_finding "CRITICAL" "Mots de Passe GPP (MS14-025)" "Des mots de passe en clair ont été trouvés dans les préférences de stratégie de groupe." "${output_dir}/gpp_passwords.txt"
    else
        print_success "Aucun mot de passe GPP"
    fi

    stop_timer "gpo"
}

#===============================================================================
# AUDIT 4.7: DELEGATION  [NEW]
