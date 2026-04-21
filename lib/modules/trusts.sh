#!/bin/bash
# lib/modules/trusts.sh

audit_trusts() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/14_Trusts"

    print_section "AUDIT: RELATIONS D'APPROBATION"
    start_timer "trusts"

    print_test "Énumération des trusts"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=trustedDomain)" \
        "cn trustDirection trustType trustAttributes flatName securityIdentifier" "${output_dir}/trusts.txt"

    local trust_count
    trust_count=$(safe_count "cn:" "${output_dir}/trusts.txt")

    if [ "${trust_count}" -gt 0 ]; then
        print_info "📊 ${trust_count} relations d'approbation"

        # Check for dangerous trust attributes
        if grep -q "trustAttributes: 0" "${output_dir}/trusts.txt" 2>/dev/null; then
            print_warning "⚠️  Trusts sans filtrage SID détectés"
            add_finding "HIGH" "Trust Sans Filtrage SID" "Des trusts sans filtrage SID (SID History) ont été détectés. Risque d'escalade inter-forêt." "${output_dir}/trusts.txt"
        fi

        print_success "${trust_count} trusts énumérés"
    else
        print_success "Aucun trust externe"
    fi

    stop_timer "trusts"
}
