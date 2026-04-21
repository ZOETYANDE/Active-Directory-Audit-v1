#!/bin/bash
# lib/modules/vulns.sh

audit_vulnerabilities() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/08_Vulnerabilites"

    print_section "AUDIT: VULNÉRABILITÉS CONNUES"
    start_timer "vulns"

    local password
    password=$(<"${pwd_file}")

    # Print Spooler (PrintNightmare)
    if [ "${HAS_NXC}" = true ] || [ "${HAS_CME}" = true ]; then
        print_test "Print Spooler / PrintNightmare (CVE-2021-34527)"
        smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M spooler \
            > "${output_dir}/spooler.txt" 2>&1 || true
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/spooler.txt" 2>/dev/null || true

        if grep -qi "Spooler service is running" "${output_dir}/spooler.txt" 2>/dev/null; then
            print_error "🔴 Print Spooler actif sur le DC!"
            add_finding_remediation "CRITICAL" "Print Spooler Actif (PrintNightmare)" "Le service Print Spooler est actif sur ${DC_IP}. Vulnérable à CVE-2021-34527." \
                "${output_dir}/spooler.txt" \
                "# Disable Print Spooler on Domain Controllers\nStop-Service -Name Spooler -Force\nSet-Service -Name Spooler -StartupType Disabled"
        else
            print_success "Print Spooler non actif ou non détecté"
        fi

        # Coercion Attacks (PetitPotam, DFSCoerce, PrinterBug, etc.)
        print_test "Attaques de Coercition NTLM (via coerce_plus)"
        smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M coerce_plus \
            > "${output_dir}/coercion.txt" 2>&1 || true
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/coercion.txt" 2>/dev/null || true

        if grep -qi "VULNERABLE" "${output_dir}/coercion.txt" 2>/dev/null; then
            local vulns_found
            vulns_found=$(grep -i "VULNERABLE" "${output_dir}/coercion.txt" | cut -d',' -f2 | xargs | sed 's/ /, /g')
            print_error "🔴 Vulnérable aux attaques de coercition : ${vulns_found}!"
            add_finding_remediation "HIGH" "Attaques de Coercition NTLM (${vulns_found})" \
                "Le DC est vulnérable à plusieurs vecteurs de coercition NTLM : ${vulns_found}. Un attaquant peut forcer l'authentification NTLM vers une machine qu'il contrôle." \
                "${output_dir}/coercion.txt" \
                "# Remédiations :\n# 1. Désactiver NTLM là où c'est possible\n# 2. Activer Extended Protection for Authentication (EPA)\n# 3. Utiliser des filtres RPC pour bloquer les méthodes vulnérables\n# 4. Appliquer les correctifs (ex: KB5005413)"
        else
            print_success "Aucune vulnérabilité de coercition NTLM détectée"
        fi

        # ZeroLogon (safe check)
        print_test "ZeroLogon (CVE-2020-1472)"
        smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M zerologon \
            > "${output_dir}/zerologon.txt" 2>&1 || true
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/zerologon.txt" 2>/dev/null || true

        if grep -qiE "VULNERABLE|vuln" "${output_dir}/zerologon.txt" 2>/dev/null; then
            print_error "🔴 VULNÉRABLE À ZEROLOGON!"
            add_finding_remediation "CRITICAL" "ZeroLogon (CVE-2020-1472)" "Le DC est vulnérable à ZeroLogon. Compromission du domaine possible sans authentification!" \
                "${output_dir}/zerologon.txt" \
                "# Apply ZeroLogon patches immediately!\n# Ensure FullSecureChannelProtection is enforced\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -Name 'FullSecureChannelProtection' -Value 1"
        else
            print_success "ZeroLogon non vulnérable"
        fi

        # noPac (sAMAccountName spoofing)
        print_test "noPac / sAMAccountName spoofing (CVE-2021-42278)"
        smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M nopac \
            > "${output_dir}/nopac.txt" 2>&1 || true
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/nopac.txt" 2>/dev/null || true

        if grep -qiE "VULNERABLE|vuln" "${output_dir}/nopac.txt" 2>/dev/null; then
            print_error "🔴 Vulnérable à noPac!"
            add_finding_remediation "HIGH" "noPac (CVE-2021-42278/42287)" "Vulnérable à l'usurpation sAMAccountName. Escalade vers Domain Admin possible." \
                "${output_dir}/nopac.txt" \
                "# Apply patches KB5008380 and KB5008602"
        else
            print_success "noPac non vulnérable"
        fi
    else
        print_info "Pas d'outil SMB — vérifications de vulnérabilités limitées"
    fi

    # EternalBlue (MS17-010) via nmap
    print_test "EternalBlue (MS17-010)"
    nmap -T4 -Pn -p 445 --script smb-vuln-ms17-010 "${DC_IP}" \
        -oN "${output_dir}/eternalblue.txt" 2>/dev/null || true

    if grep -qi "VULNERABLE" "${output_dir}/eternalblue.txt" 2>/dev/null; then
        print_error "🔴 VULNÉRABLE À ETERNALBLUE!"
        add_finding_remediation "CRITICAL" "EternalBlue (MS17-010)" "Le DC est vulnérable à EternalBlue. Exécution de code à distance sans authentification!" \
            "${output_dir}/eternalblue.txt" \
            "# Apply MS17-010 patches IMMEDIATELY\n# Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol \$false"
    else
        print_success "EternalBlue non vulnérable"
    fi

    stop_timer "vulns"
}
