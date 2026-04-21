#!/bin/bash
# lib/modules/password_policy.sh

audit_password_policy() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/05_Politique_Mots_de_Passe"

    print_section "AUDIT: POLITIQUE DE MOTS DE PASSE"
    start_timer "password_policy"

    local uri
    uri=$(get_ldap_uri)

    # Default Domain Policy
    print_test "Politique de mot de passe par défaut"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=domain)" \
        "minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold lockoutDuration lockoutObservationWindow pwdProperties" \
        "${output_dir}/default_policy.txt"

    if [ -s "${output_dir}/default_policy.txt" ]; then
        local min_len
        min_len=$(grep -i "minPwdLength:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        local lockout
        lockout=$(grep -i "lockoutThreshold:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        local history
        history=$(grep -i "pwdHistoryLength:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")

        print_info "📊 Longueur min: ${min_len:-N/A} | Verrouillage: ${lockout:-N/A} | Historique: ${history:-N/A}"

        if [ -n "${min_len}" ] && [ "${min_len}" -lt 12 ] 2>/dev/null; then
            print_warning "Longueur minimale < 12 caractères (${min_len})"
            add_finding "HIGH" "Mot de Passe Trop Court" "La longueur minimale est de ${min_len} caractères. Recommandation: ≥12." "${output_dir}/default_policy.txt"
        elif [ -n "${min_len}" ]; then
            print_success "Longueur minimale acceptable: ${min_len}"
        fi

        if [ -n "${lockout}" ] && [ "${lockout}" -eq 0 ] 2>/dev/null; then
            print_warning "Aucun verrouillage de compte configuré!"
            add_finding "HIGH" "Pas de Verrouillage" "Aucun seuil de verrouillage de compte. Brute-force possible." "${output_dir}/default_policy.txt"
        elif [ -n "${lockout}" ]; then
            print_success "Verrouillage après ${lockout} tentatives"
        fi
    else
        print_warning "Impossible de lire la politique"
    fi

    # Fine-Grained Password Policies
    print_test "Politiques de mot de passe granulaires (FGPP)"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=msDS-PasswordSettings)" \
        "cn msDS-MinimumPasswordLength msDS-LockoutThreshold msDS-PasswordSettingsPrecedence" \
        "${output_dir}/fgpp.txt"

    local fgpp_count
    fgpp_count=$(safe_count "cn:" "${output_dir}/fgpp.txt")
    print_info "📊 ${fgpp_count} FGPP trouvées"

    if [ "${fgpp_count}" -gt 0 ]; then
        print_success "${fgpp_count} politiques granulaires"
    else
        print_success "Aucune FGPP — politique par défaut uniquement"
    fi

    stop_timer "password_policy"
}

#===============================================================================
# AUDIT 4.6: GPO  [NEW]
