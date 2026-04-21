#!/bin/bash
# lib/modules/groups.sh

audit_groups() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/04_Groupes_Privileges"

    print_section "AUDIT 4.2: GROUPES PRIVILÉGIÉS"
    start_timer "groups"

    # Bilingual group definitions: "EnglishName|FrenchName|primaryGroupID"
    # French names are used on French-locale DCs
    local priv_groups_def=(
        "Domain Admins|Admins du domaine|512"
        "Enterprise Admins|Administrateurs de l'entreprise|519"
        "Administrators|Administrateurs|544"
        "Schema Admins|Administrateurs du schéma|518"
        "Account Operators|Opérateurs de compte|"
        "Backup Operators|Opérateurs de sauvegarde|"
        "DnsAdmins|DnsAdmins|"
        "Server Operators|Opérateurs de serveur|"
    )

    local total_all_groups=0

    for entry in "${priv_groups_def[@]}"; do
        local name_en="${entry%%|*}"
        local rest="${entry#*|}"
        local name_fr="${rest%%|*}"
        local pgid="${rest##*|}"
        local safe_name="${name_en// /_}"

        # Use OR filter to match either English or French name
        local filter
        if [ "${name_en}" = "${name_fr}" ]; then
            filter="(&(objectClass=group)(cn=${name_en}))"
        else
            filter="(&(objectClass=group)(|(cn=${name_en})(cn=${name_fr})))"
        fi

        ldap_search "${username}" "${pwd_file}" \
            "${filter}" \
            "cn member" "${output_dir}/group_${safe_name}.txt"

        # Detect which name was found
        local found_name="${name_en}"
        if grep -qi "cn: ${name_fr}" "${output_dir}/group_${safe_name}.txt" 2>/dev/null; then
            found_name="${name_fr}"
        fi

        # Count members — match "member:" or "member::" with any formatting
        local member_count=0
        if [ -f "${output_dir}/group_${safe_name}.txt" ]; then
            member_count=$(grep -cE '^\s*member::?' "${output_dir}/group_${safe_name}.txt" 2>/dev/null || true)
            if ! [[ "${member_count}" =~ ^[0-9]+$ ]]; then member_count=0; fi
        fi

        # Fallback: count members via primaryGroupID
        local pgid_count=0
        if [ -n "${pgid}" ] && [ "${member_count}" -eq 0 ]; then
            ldap_search "${username}" "${pwd_file}" \
                "(&(objectCategory=person)(primaryGroupID=${pgid}))" \
                "sAMAccountName" "${output_dir}/group_${safe_name}_pgid.txt"
            pgid_count=$(safe_count "sAMAccountName:" "${output_dir}/group_${safe_name}_pgid.txt")
        fi

        local total_members=$((member_count + pgid_count))
        total_all_groups=$((total_all_groups + total_members))

        if [ "${pgid_count}" -gt 0 ]; then
            print_info "Groupe '${found_name}': ${total_members} membres (${member_count} explicites + ${pgid_count} via primaryGroupID)"
        else
            print_info "Groupe '${found_name}': ${total_members} membres"
        fi

        if [[ "${name_en}" =~ ^(Domain Admins|Enterprise Admins|Schema Admins)$ ]] && [ "${total_members}" -gt 5 ]; then
            add_finding "HIGH" "Groupe ${found_name} Surdimensionné" "${total_members} membres dans ${found_name}. Recommandé: ≤5." "${output_dir}/group_${safe_name}.txt"
        fi
    done

    # Warn if all groups show 0 — likely a permissions issue
    if [ "${total_all_groups}" -eq 0 ]; then
        print_warning "⚠️  Tous les groupes montrent 0 membres — possible manque de permissions de lecture"
        add_finding "LOW" "Lecture Groupes Restreinte" "Aucun membre détecté dans aucun groupe privilégié. L'utilisateur d'audit peut manquer de permissions de lecture." ""
    fi

    print_test "Comptes avec SPN (Kerberoastables)"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
        "sAMAccountName servicePrincipalName" "${output_dir}/users_spn.txt"

    local spn_count
    spn_count=$(safe_count "sAMAccountName:" "${output_dir}/users_spn.txt")

    if [ "${spn_count}" -gt 0 ]; then
        print_warning "⚠️  ${spn_count} comptes avec SPN"
        add_finding "HIGH" "Kerberoasting" "${spn_count} comptes utilisateurs avec SPN — vulnérables au Kerberoasting." "${output_dir}/users_spn.txt"
    else
        print_success "Aucun compte avec SPN"
    fi
    # Pre-Windows 2000 Compatible Access
    print_test "Groupe Pre-Windows 2000 Compatible Access"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))" \
        "member" "${output_dir}/pre_win2000.txt"

    local pre2k_members
    pre2k_members=$(grep -cE '^\s*member::?' "${output_dir}/pre_win2000.txt" 2>/dev/null || true)
    if ! [[ "${pre2k_members}" =~ ^[0-9]+$ ]]; then pre2k_members=0; fi

    if grep -qi "S-1-1-0\|Everyone\|Tout le monde\|S-1-5-11\|Authenticated Users" "${output_dir}/pre_win2000.txt" 2>/dev/null; then
        print_error "🔴 Pre-Windows 2000 contient Everyone ou Authenticated Users!"
        add_finding_remediation "HIGH" "Pre-Windows 2000 Ouvert" "Le groupe Pre-Windows 2000 Compatible Access contient Everyone/Authenticated Users. Accès lecture étendu à tout AD." \
            "${output_dir}/pre_win2000.txt" \
            "# Remove Authenticated Users from Pre-Windows 2000 Compatible Access\nRemove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'S-1-5-11' -Confirm:\$false"
    elif [ "${pre2k_members}" -gt 0 ]; then
        print_warning "⚠️  ${pre2k_members} membres dans Pre-Windows 2000"
    else
        print_success "Pre-Windows 2000 vide ou restreint"
    fi

    # Protected Users group
    print_test "Groupe Protected Users"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectClass=group)(cn=Protected Users))" \
        "member" "${output_dir}/protected_users.txt"

    local protected_count
    protected_count=$(grep -cE '^\s*member::?' "${output_dir}/protected_users.txt" 2>/dev/null || true)
    if ! [[ "${protected_count}" =~ ^[0-9]+$ ]]; then protected_count=0; fi

    if [ "${protected_count}" -eq 0 ]; then
        print_warning "⚠️  Aucun membre dans Protected Users"
        add_finding_remediation "MEDIUM" "Protected Users Vide" "Le groupe Protected Users est vide. Les comptes privilégiés ne bénéficient pas des protections avancées (pas de NTLM, pas de délégation, tickets courts)." \
            "" \
            "# Add privileged accounts to Protected Users\nAdd-ADGroupMember -Identity 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins')"
    else
        print_success "${protected_count} membres dans Protected Users"
    fi

    stop_timer "groups"
}

