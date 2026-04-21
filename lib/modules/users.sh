#!/bin/bash
# lib/modules/users.sh

audit_users() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/03_Comptes_Utilisateurs"

    print_section "AUDIT 4.1: COMPTES UTILISATEURS"
    start_timer "users"

    # Parallel LDAP queries
    {
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
            "sAMAccountName" "${output_dir}/users_pwd_never_expires.txt"
    } &
    local pid_pwd=$!
    BG_PIDS+=("${pid_pwd}")

    {
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
            "sAMAccountName" "${output_dir}/users_asrep.txt"
    } &
    local pid_asrep=$!
    BG_PIDS+=("${pid_asrep}")

    # Disabled accounts
    {
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
            "sAMAccountName" "${output_dir}/users_disabled.txt"
    } &
    local pid_disabled=$!
    BG_PIDS+=("${pid_disabled}")

    wait ${pid_pwd} ${pid_asrep} ${pid_disabled} 2>/dev/null || true

    print_test "Comptes avec mot de passe permanent"
    local never_expires
    never_expires=$(safe_count "sAMAccountName:" "${output_dir}/users_pwd_never_expires.txt")

    if [ "${never_expires}" -gt 0 ]; then
        print_warning "⚠️  ${never_expires} comptes"
        add_finding "MEDIUM" "Mots de Passe Permanents" "${never_expires} comptes ont un mot de passe qui n'expire jamais." "${output_dir}/users_pwd_never_expires.txt"
    else
        print_success "Aucun"
    fi

    print_test "Comptes vulnérables AS-REP Roasting"
    local asrep
    asrep=$(safe_count "sAMAccountName:" "${output_dir}/users_asrep.txt")

    if [ "${asrep}" -gt 0 ]; then
        print_error "🔴 ${asrep} comptes vulnérables"
        add_finding "HIGH" "AS-REP Roasting" "${asrep} comptes vulnérables à l'AS-REP Roasting (pré-auth désactivée)." "${output_dir}/users_asrep.txt"
    else
        print_success "Aucun"
    fi

    print_test "Comptes désactivés"
    local disabled
    disabled=$(safe_count "sAMAccountName:" "${output_dir}/users_disabled.txt")
    print_info "📊 ${disabled} comptes désactivés"
    if [ "${disabled}" -gt 0 ]; then
        print_success "${disabled} comptes désactivés trouvés"
    else
        print_warning "Aucun compte désactivé trouvé"
    fi
    # Passwords in description field
    print_test "Mots de passe dans les descriptions"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*mot de passe*)(info=*pass*)(info=*pwd*)))" \
        "sAMAccountName description info" "${output_dir}/users_pwd_in_desc.txt"

    local pwd_desc_count
    pwd_desc_count=$(safe_count "sAMAccountName:" "${output_dir}/users_pwd_in_desc.txt")

    if [ "${pwd_desc_count}" -gt 0 ]; then
        print_error "🔴 ${pwd_desc_count} comptes avec mot de passe potentiel dans la description!"
        add_finding_remediation "HIGH" "Mots de Passe dans Descriptions" "${pwd_desc_count} comptes ont potentiellement un mot de passe dans le champ description ou info." \
            "${output_dir}/users_pwd_in_desc.txt" \
            "# Remove passwords from description fields\nGet-ADUser -Filter * -Properties Description | Where-Object {\$_.Description -match 'pass|pwd'} | Select-Object SamAccountName, Description"
    else
        print_success "Aucun mot de passe dans les descriptions"
    fi

    # Reversible encryption
    print_test "Chiffrement réversible"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))" \
        "sAMAccountName" "${output_dir}/users_reversible_enc.txt"

    local rev_enc
    rev_enc=$(safe_count "sAMAccountName:" "${output_dir}/users_reversible_enc.txt")

    if [ "${rev_enc}" -gt 0 ]; then
        print_error "🔴 ${rev_enc} comptes avec chiffrement réversible!"
        add_finding_remediation "HIGH" "Chiffrement Réversible" "${rev_enc} comptes stockent le mot de passe en chiffrement réversible (équivalent texte clair)." \
            "${output_dir}/users_reversible_enc.txt" \
            "# Disable reversible encryption\nGet-ADUser -Filter {UserAccountControl -band 128} | Set-ADAccountControl -AllowReversiblePasswordEncryption \$false"
    else
        print_success "Aucun chiffrement réversible"
    fi

    # DES-only Kerberos
    print_test "Kerberos DES uniquement"
    ldap_search "${username}" "${pwd_file}" \
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))" \
        "sAMAccountName" "${output_dir}/users_des_only.txt"

    local des_only
    des_only=$(safe_count "sAMAccountName:" "${output_dir}/users_des_only.txt")

    if [ "${des_only}" -gt 0 ]; then
        print_warning "⚠️  ${des_only} comptes avec Kerberos DES uniquement"
        add_finding "HIGH" "Kerberos DES Uniquement" "${des_only} comptes utilisent le chiffrement DES, considéré comme cassé." \
            "${output_dir}/users_des_only.txt"
    else
        print_success "Aucun compte DES-only"
    fi

    # Recently created accounts (30 days)
    print_test "Comptes créés récemment (30 jours)"
    local thirty_days_ago
    thirty_days_ago=$(date -d "30 days ago" "+%Y%m%d000000.0Z" 2>/dev/null || date -v-30d "+%Y%m%d000000.0Z" 2>/dev/null || echo "")

    if [ -n "${thirty_days_ago}" ]; then
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectCategory=person)(objectClass=user)(whenCreated>=${thirty_days_ago}))" \
            "sAMAccountName whenCreated" "${output_dir}/users_recent.txt"

        local recent_count
        recent_count=$(safe_count "sAMAccountName:" "${output_dir}/users_recent.txt")
        print_info "📊 ${recent_count} comptes créés ces 30 derniers jours"

        if [ "${recent_count}" -gt 0 ]; then
            print_success "${recent_count} comptes récents (vérification manuelle recommandée)"
        fi
    else
        print_info "Calcul de date non supporté — vérification ignorée"
    fi

    stop_timer "users"
}
