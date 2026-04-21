#!/bin/bash
# lib/modules/misc.sh

audit_misc() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/10_Hardening"

    print_section "AUDIT: DURCISSEMENT GÉNÉRAL"
    start_timer "misc"

    local uri
    uri=$(get_ldap_uri)

    # MachineAccountQuota
    print_test "MachineAccountQuota"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=domain)" "ms-DS-MachineAccountQuota" "${output_dir}/maq.txt"
    
    local maq
    maq=$(grep -i "ms-DS-MachineAccountQuota:" "${output_dir}/maq.txt" | awk '{print $2}' || echo "0")

    if [ -n "${maq}" ] && [ "${maq}" -gt 0 ] 2>/dev/null; then
        print_warning "⚠️  MachineAccountQuota = ${maq}"
        add_finding_remediation "MEDIUM" "MachineAccountQuota Élevé" "Valeur: ${maq}. Tout utilisateur authentifié peut joindre ${maq} machines au domaine. Risque d'attaque RBCD (Resource-Based Constrained Delegation)." \
            "${output_dir}/maq.txt" \
            "# Set MachineAccountQuota to 0\nSet-ADDomain -Identity '${DOMAIN}' -Replace @{'ms-DS-MachineAccountQuota'=0}"
    elif [ "${maq:-0}" -eq 0 ] 2>/dev/null; then
        print_success "MachineAccountQuota = 0"
    else
        print_warning "Impossible de lire MachineAccountQuota"
    fi

    # Domain Functional Level
    print_test "Niveau fonctionnel du domaine"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=domain)" "msDS-Behavior-Version" "${output_dir}/func_level.txt"
    
    local func_level
    func_level=$(grep -i "msDS-Behavior-Version:" "${output_dir}/func_level.txt" | awk '{print $2}' || echo "")

    local level_name="Inconnu"
    case "${func_level}" in
        0) level_name="Windows 2000" ;;
        1) level_name="Windows 2003 Interim" ;;
        2) level_name="Windows 2003" ;;
        3) level_name="Windows 2008" ;;
        4) level_name="Windows 2008 R2" ;;
        5) level_name="Windows 2012" ;;
        6) level_name="Windows 2012 R2" ;;
        7) level_name="Windows 2016" ;;
    esac

    if [ -n "${func_level}" ] && [ "${func_level}" -lt 7 ] 2>/dev/null; then
        print_warning "⚠️  Niveau fonctionnel: ${level_name} (${func_level})"
        add_finding "MEDIUM" "Niveau Fonctionnel Ancien" "Niveau fonctionnel du domaine: ${level_name}. Recommandation: Windows 2016 (7) minimum pour bénéficier des dernières protections de sécurité (ex: groupes Protected Users)." "${output_dir}/func_level.txt"
    elif [ "${func_level:-0}" -ge 7 ] 2>/dev/null; then
        print_success "Niveau fonctionnel: ${level_name} (${func_level})"
    else
        print_info "Niveau fonctionnel non déterminé"
    fi

    # AD Recycle Bin
    print_test "Corbeille AD (Recycle Bin)"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=*)" "msDS-EnabledFeatureBL" "${output_dir}/recycle_bin.txt" \
        "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,${BASE_DN}"

    if grep -qi "msDS-EnabledFeatureBL:" "${output_dir}/recycle_bin.txt" 2>/dev/null; then
        print_success "Corbeille AD activée"
    else
        print_warning "⚠️  Corbeille AD non activée"
        add_finding_remediation "LOW" "Corbeille AD Désactivée" "La corbeille AD n'est pas activée. La récupération d'objets supprimés est limitée et complexe." \
            "${output_dir}/recycle_bin.txt" \
            "# Enable AD Recycle Bin\nEnable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target '${DOMAIN}'"
    fi

    # AdminCount orphans
    print_test "Orphelins AdminCount"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(adminCount=1)(!(memberOf=CN=Domain Admins,CN=Users,${BASE_DN})))" \
        "sAMAccountName distinguishedName" "${output_dir}/admincount_orphans.txt"

    local orphan_count
    orphan_count=$(safe_count "sAMAccountName:" "${output_dir}/admincount_orphans.txt")

    if [ "${orphan_count}" -gt 5 ]; then
        print_warning "⚠️  ${orphan_count} comptes avec adminCount=1 orphelin"
        add_finding "LOW" "AdminCount Orphelins" "${orphan_count} comptes ont adminCount=1 mais ne sont plus dans les groupes privilégiés (SDProp stale)." \
            "${output_dir}/admincount_orphans.txt"
    else
        print_success "${orphan_count} orphelins AdminCount (acceptable)"
    fi

    stop_timer "misc"
}
