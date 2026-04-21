#!/bin/bash
# lib/modules/adcs.sh

audit_adcs() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/16_Certificats"

    print_section "AUDIT: SERVICES DE CERTIFICATS (ADCS)"
    start_timer "adcs"

    # Find CA servers
    print_test "Détection des autorités de certification"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=pKIEnrollmentService)" \
        "cn dNSHostName certificateTemplates" "${output_dir}/ca_servers.txt"

    local ca_count
    ca_count=$(safe_count "cn:" "${output_dir}/ca_servers.txt")

    if [ "${ca_count}" -gt 0 ]; then
        print_success "${ca_count} CA trouvées"

        # Enumerate certificate templates
        print_test "Modèles de certificats"
        ldap_search "${username}" "${pwd_file}" \
            "(objectClass=pKICertificateTemplate)" \
            "cn msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pKIExtendedKeyUsage msPKI-RA-Signature" \
            "${output_dir}/cert_templates.txt"

        local tpl_count
        tpl_count=$(safe_count "cn:" "${output_dir}/cert_templates.txt")
        print_info "📊 ${tpl_count} modèles de certificats"

        # ESC1: Templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth
        if grep -q "msPKI-Certificate-Name-Flag: 1" "${output_dir}/cert_templates.txt" 2>/dev/null; then
            print_warning "⚠️  Modèles avec ENROLLEE_SUPPLIES_SUBJECT détectés (ESC1 potentiel)"
            add_finding "CRITICAL" "ESC1 — Certificate Template Abuse" "Des modèles permettant au demandeur de spécifier le sujet ont été trouvés. Risque d'usurpation d'identité." "${output_dir}/cert_templates.txt"
        else
            print_success "Pas de template ESC1 évident"
        fi

        # Run certipy if available
        if [ "${HAS_CERTIPY}" = true ]; then
            print_test "Analyse Certipy (ESC1-ESC8)"
            local password
            password=$(<"${pwd_file}")

            certipy find -u "${username}@${DOMAIN}" -p "${password}" \
                -dc-ip "${DC_IP}" -vulnerable -stdout \
                > "${output_dir}/certipy_vulnerable.txt" 2>&1 || true

            if grep -qi "ESC" "${output_dir}/certipy_vulnerable.txt" 2>/dev/null; then
                local esc_findings
                esc_findings=$(grep -ci "ESC" "${output_dir}/certipy_vulnerable.txt" || echo "0")
                print_error "🔴 ${esc_findings} vulnérabilités ADCS détectées!"
                add_finding "CRITICAL" "Vulnérabilités ADCS (Certipy)" "${esc_findings} findings ESC détectés par Certipy." "${output_dir}/certipy_vulnerable.txt"
            else
                print_success "Aucune vulnérabilité ESC détectée"
            fi
        else
            print_info "💡 Installez certipy-ad pour une analyse ADCS complète"
        fi
    else
        print_success "Aucune CA — ADCS non déployé"
    fi

    stop_timer "adcs"
}
