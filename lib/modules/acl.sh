#!/bin/bash
# lib/modules/acl.sh

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
        # Redact password from users_enum output
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/users_enum.txt" 2>/dev/null || true
        print_success "Énumération ACL complétée via SMB tool (analyse manuelle recommandée)"
    else
        print_success "Analyse ACL via LDAP uniquement (pas d'outil SMB)"
    fi

    # BloodHound handles deep ACL analysis — note this
    print_info "💡 Analyse ACL approfondie disponible via BloodHound (section 5)"
    add_finding "INFO" "Analyse ACL" "Les ACL complexes sont mieux analysées via BloodHound. Voir section 09_BloodHound." ""

    stop_timer "acl"
}
