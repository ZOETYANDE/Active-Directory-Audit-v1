#!/bin/bash
# lib/modules/password_policy.sh

audit_password_policy() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/05_Politique_Mots_de_Passe"

    print_section "AUDIT: POLITIQUE DE MOTS DE PASSE"
    start_timer "password_policy"

    # Default Domain Policy
    print_test "Politique de mot de passe par défaut"
    ldap_search "${username}" "${pwd_file}" \
        "(objectClass=domain)" \
        "minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold lockoutDuration lockoutObservationWindow pwdProperties" \
        "${output_dir}/default_policy.txt"

    if [ -s "${output_dir}/default_policy.txt" ]; then
        local min_len lockout history lockout_dur
        min_len=$(grep -i "minPwdLength:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        lockout=$(grep -i "lockoutThreshold:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        history=$(grep -i "pwdHistoryLength:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")
        lockout_dur=$(grep -i "lockoutDuration:" "${output_dir}/default_policy.txt" 2>/dev/null | awk '{print $2}' || echo "0")

        print_info "📊 Longueur min: ${min_len:-N/A} | Verrouillage: ${lockout:-N/A} tentatives | Historique: ${history:-N/A} | Durée lockout: ${lockout_dur:-N/A}"

        # Longueur minimale (CIS AD Benchmark 1.1.1: >= 14 recommandé)
        if [ -n "${min_len}" ] && [ "${min_len}" -lt 12 ] 2>/dev/null; then
            print_warning "Longueur minimale < 12 caractères (${min_len})"
            add_finding "HIGH" "Mot de Passe Trop Court" \
                "Longueur minimale: ${min_len} caractères. Référence: CIS AD Benchmark 1.1.1 (min 14), ISO 27001 A.9.4.3. Recommandation: ≥14 caractères." \
                "${output_dir}/default_policy.txt"
        elif [ -n "${min_len}" ]; then
            print_success "Longueur minimale acceptable: ${min_len}"
        fi

        # Seuil de verrouillage (CIS AD Benchmark 1.2.1: 1-10 tentatives)
        if [ -n "${lockout}" ] && [ "${lockout}" -eq 0 ] 2>/dev/null; then
            print_error "🔴 Aucun verrouillage de compte configuré!"
            add_finding_remediation "CRITICAL" "Pas de Verrouillage de Compte" \
                "lockoutThreshold=0 : aucun verrouillage. Brute-force et Password Spray illimités. Réf: CIS AD Benchmark 1.2.1 / ISO 27001 A.9.4.3." \
                "${output_dir}/default_policy.txt" \
                "# Set account lockout threshold to 10\nSet-ADDefaultDomainPasswordPolicy -LockoutThreshold 10 -LockoutDuration '00:30:00' -LockoutObservationWindow '00:30:00'"
        elif [ -n "${lockout}" ] && [ "${lockout}" -gt 10 ] 2>/dev/null; then
            print_warning "⚠️  Seuil de verrouillage élevé: ${lockout} tentatives (vulnérable au spray)"
            add_finding "MEDIUM" "Seuil Verrouillage Trop Permissif" \
                "lockoutThreshold=${lockout} est supérieur à 10. Password spray possible avec ${lockout} tentatives par compte. Réf: CIS AD Benchmark 1.2.1." \
                "${output_dir}/default_policy.txt"
        elif [ -n "${lockout}" ]; then
            print_success "Verrouillage après ${lockout} tentatives (correct)"
        fi

        # Durée de verrouillage (CIS: >= 15 min)
        if [ -n "${lockout_dur}" ] && [ "${lockout_dur}" != "0" ] && [ "${lockout_dur}" -lt 900 ] 2>/dev/null; then
            local dur_min=$(( lockout_dur / 60 ))
            print_warning "⚠️  Durée de verrouillage courte: ${dur_min} min"
            add_finding "LOW" "Durée Verrouillage Insuffisante" \
                "Durée de verrouillage: ${dur_min} min. Réf: CIS AD Benchmark 1.2.2 recommande ≥15 min." \
                "${output_dir}/default_policy.txt"
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
