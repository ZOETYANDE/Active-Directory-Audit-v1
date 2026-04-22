#!/bin/bash
# lib/modules/acl.sh — Analyse des permissions ACL dangereuses sur AD
# Référence: CIS Benchmark for Active Directory — Section 1.1, 1.2
#            ISO 27001:2022 — Contrôle A.8.2 (Droits d'accès privilégiés)

audit_acl_abuse() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/13_ACL"

    print_section "AUDIT: PERMISSIONS ACL DANGEREUSES"
    start_timer "acl"

    local password
    password=$(<"${pwd_file}")

    #---------------------------------------------------------------------------
    # 1. AdminSDHolder — objets protégés (via LDAP, toujours disponible)
    #---------------------------------------------------------------------------
    print_test "Objets protégés par AdminSDHolder (adminCount=1)"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(adminCount=1))" \
        "sAMAccountName distinguishedName" "${output_dir}/admincount.txt"

    local admin_count
    admin_count=$(safe_count "sAMAccountName:" "${output_dir}/admincount.txt")
    print_info "📊 ${admin_count} objets avec adminCount=1"

    if [ "${admin_count}" -gt 20 ]; then
        print_warning "⚠️  Nombre élevé d'objets protégés (${admin_count})"
        add_finding "MEDIUM" "AdminCount Élevé" \
            "${admin_count} objets avec adminCount=1. Risque de stale adminCount (comptes non-admins avec ACL héritées)." \
            "${output_dir}/admincount.txt"
    else
        print_success "${admin_count} objets protégés (acceptable)"
    fi

    #---------------------------------------------------------------------------
    # 2. Droits de réplication DCSync (via LDAP sur rootDSE)
    #    Détection indirecte: comptes non-DC avec msDS-AllowedToDelegateTo ou
    #    membership in specific privileged groups known for DCSync rights
    #---------------------------------------------------------------------------
    print_test "Droits de réplication potentiels (DCSync)"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(primaryGroupID=516))(!(primaryGroupID=521)))" \
        "sAMAccountName distinguishedName" "${output_dir}/potential_dcsync.txt"

    local dcsync_candidates
    dcsync_candidates=$(safe_count "sAMAccountName:" "${output_dir}/potential_dcsync.txt")

    if [ "${dcsync_candidates}" -gt 0 ]; then
        print_warning "⚠️  ${dcsync_candidates} comptes non-DC avec adminCount=1 — vérifier droits DCSync"
        add_finding "MEDIUM" "Candidats DCSync Potentiels" \
            "${dcsync_candidates} comptes utilisateurs avec adminCount=1 (hors DCs). Vérifier manuellement les droits de réplication." \
            "${output_dir}/potential_dcsync.txt"
    else
        print_success "Aucun candidat DCSync suspect détecté"
    fi

    #---------------------------------------------------------------------------
    # 3. Analyse ACL approfondie via dacledit.py (impacket) si disponible
    #    Référence: CIS AD Benchmark — Section 2.1 (Privileged Access)
    #---------------------------------------------------------------------------
    print_test "ACL dangereuses sur objets sensibles (dacledit.py)"

    if [ "${HAS_DACLEDIT}" = true ]; then
        local sensitive_objects=(
            "CN=Domain Admins,CN=Users,${BASE_DN}"
            "CN=AdminSDHolder,CN=System,${BASE_DN}"
            "CN=Domain Controllers,OU=Domain Controllers,${BASE_DN}"
        )

        local total_acl_abuse=0

        for dn in "${sensitive_objects[@]}"; do
            local safe_filename
            safe_filename=$(echo "${dn}" | cut -d',' -f1 | sed 's/CN=//;s/ /_/g')
            local outfile="${output_dir}/dacl_${safe_filename}.txt"

            dacledit.py -action read \
                -target-dn "${dn}" \
                -dc-ip "${DC_IP}" \
                "${DOMAIN}/${username}:${password}" \
                > "${outfile}" 2>&1 || true
            sed -i "s/${password}/[REDACTED]/g" "${outfile}" 2>/dev/null || true

            local abuse_count
            abuse_count=$(grep -cE "GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights" \
                "${outfile}" 2>/dev/null || echo "0")
            if ! [[ "${abuse_count}" =~ ^[0-9]+$ ]]; then abuse_count=0; fi

            if [ "${abuse_count}" -gt 0 ]; then
                print_error "🔴 ${abuse_count} ACL dangereuses sur: ${safe_filename}"
                add_finding "CRITICAL" "ACL Dangereuses — ${safe_filename}" \
                    "${abuse_count} permissions critiques (GenericAll/WriteDacl/WriteOwner) sur ${dn}. Risque de prise de contrôle du domaine." \
                    "${outfile}"
                total_acl_abuse=$((total_acl_abuse + abuse_count))
            else
                print_success "Aucune ACL dangereuse sur: ${safe_filename}"
            fi
        done

        if [ "${total_acl_abuse}" -eq 0 ]; then
            print_success "Aucune ACL dangereuse détectée sur les objets sensibles"
        fi

    else
        # dacledit.py non disponible — documenter honnêtement
        print_warning "⚠️  dacledit.py non disponible — analyse ACL approfondie impossible"
        print_info "💡 Installation: pip install impacket  (puis: dacledit.py --help)"
        print_info "   Vérification manuelle:"
        print_info "   dacledit.py -action read -target-dn 'CN=Domain Admins,CN=Users,${BASE_DN}'"
        print_info "               -dc-ip ${DC_IP} ${DOMAIN}/<user>"

        add_finding "INFO" "ACL Non Vérifiées (outil manquant)" \
            "dacledit.py (impacket) non disponible. L'analyse des ACL dangereuses (GenericAll, WriteDacl, etc.) sur les objets privilégiés n'a pas pu être effectuée. Vérification manuelle requise. Référence: CIS AD Benchmark § 2.1 / ISO 27001 A.8.2" ""

        print_warning "⚠️  ACL non vérifiées — installer impacket pour l'analyse complète"
    fi

    #---------------------------------------------------------------------------
    # 4. Analyse BloodHound (rappel)
    #---------------------------------------------------------------------------
    print_info "💡 Analyse ACL graphique complète disponible via BloodHound (section 09_BloodHound)"

    sed -i "s/${password}/[REDACTED]/g" "${output_dir}"/*.txt 2>/dev/null || true

    stop_timer "acl"
}
