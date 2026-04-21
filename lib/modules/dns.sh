#!/bin/bash
# lib/modules/dns.sh

audit_dns() {
    local output_dir="${OUTPUT_DIR}/17_DNS"

    print_section "AUDIT: SÉCURITÉ DNS"
    start_timer "dns"

    local domain_lower
    domain_lower=$(echo "${DOMAIN}" | tr '[:upper:]' '[:lower:]')

    # DNS Zone Transfer
    print_test "Transfert de zone DNS"
    if [ "${HAS_DIG}" = true ]; then
        dig axfr "${domain_lower}" "@${DC_IP}" > "${output_dir}/zone_transfer.txt" 2>&1 || true

        if grep -q "XFR size" "${output_dir}/zone_transfer.txt" 2>/dev/null; then
            local record_count
            record_count=$(grep -c "IN" "${output_dir}/zone_transfer.txt" 2>/dev/null || true)
            print_error "🔴 Transfert de zone autorisé! (${record_count} enregistrements)"
            add_finding_remediation "HIGH" "Transfert de Zone DNS" "Le transfert de zone DNS est autorisé. ${record_count} enregistrements DNS internes exposés." \
                "${output_dir}/zone_transfer.txt" \
                "# Restrict zone transfers to specific servers only\n# In DNS Manager: Zone Properties > Zone Transfers > Allow only to listed servers"
        else
            print_success "Transfert de zone DNS restreint"
        fi

        # DNS record enumeration
        print_test "Énumération DNS basique"
        dig any "${domain_lower}" "@${DC_IP}" > "${output_dir}/dns_any.txt" 2>&1 || true
        dig srv "_ldap._tcp.${domain_lower}" "@${DC_IP}" > "${output_dir}/dns_srv_ldap.txt" 2>&1 || true
        dig srv "_kerberos._tcp.${domain_lower}" "@${DC_IP}" > "${output_dir}/dns_srv_krb.txt" 2>&1 || true

        local srv_count
        srv_count=$(grep -c "SRV" "${output_dir}/dns_srv_ldap.txt" 2>/dev/null || true)
        print_success "DNS énuméré (${srv_count} enregistrements SRV)"

        # Wildcard DNS check
        print_test "Enregistrements DNS wildcard"
        local wild_result
        wild_result=$(dig "random-nonexistent-$(date +%s).${domain_lower}" "@${DC_IP}" +short 2>/dev/null || true)
        if [ -n "${wild_result}" ]; then
            print_warning "⚠️  Wildcard DNS détecté: ${wild_result}"
            add_finding "LOW" "DNS Wildcard" "Un enregistrement DNS wildcard résout vers ${wild_result}. Peut masquer des sous-domaines inexistants." ""
        else
            print_success "Pas de wildcard DNS"
        fi
    else
        print_warning "dig non disponible — tests DNS ignorés"
    fi

    stop_timer "dns"
}
