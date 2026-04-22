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
            print_error "\U0001f534 Print Spooler actif sur le DC!"
            add_finding_remediation "CRITICAL" "Print Spooler Actif (PrintNightmare)" "Le service Print Spooler est actif sur ${DC_IP}. Vuln\u00e9rable \u00e0 CVE-2021-34527." \
                "${output_dir}/spooler.txt" \
                "# Disable Print Spooler on Domain Controllers\nStop-Service -Name Spooler -Force\nSet-Service -Name Spooler -StartupType Disabled"
        else
            print_success "Print Spooler non actif ou non d\u00e9tect\u00e9"
        fi

        # Modules intrusifs — skipp\u00e9s en SAFE_MODE
        if [ "${SAFE_MODE}" = true ]; then
            print_warning "\u26a0\ufe0f  SAFE_MODE actif: coerce_plus, zerologon et nopac ignor\u00e9s (tests intrusifs)"
            log "INFO" "SAFE_MODE: modules SMB intrusifs ignor\u00e9s"
        else
            # Coercion Attacks
            print_test "Attaques de Coercition NTLM (via coerce_plus)"
            smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M coerce_plus \
                > "${output_dir}/coercion.txt" 2>&1 || true
            sed -i "s/${password}/[REDACTED]/g" "${output_dir}/coercion.txt" 2>/dev/null || true

            if grep -qi "VULNERABLE" "${output_dir}/coercion.txt" 2>/dev/null; then
                local vulns_found
                vulns_found=$(grep -i "VULNERABLE" "${output_dir}/coercion.txt" | cut -d',' -f2 | xargs | sed 's/ /, /g')
                print_error "\U0001f534 Vuln\u00e9rable aux attaques de coercition : ${vulns_found}!"
                add_finding_remediation "HIGH" "Attaques de Coercition NTLM (${vulns_found})" \
                    "Le DC est vuln\u00e9rable \u00e0 plusieurs vecteurs de coercition NTLM : ${vulns_found}. Un attaquant peut forcer l'authentification NTLM vers une machine qu'il contr\u00f4le." \
                    "${output_dir}/coercion.txt" \
                    "# Rem\u00e9diations :\n# 1. D\u00e9sactiver NTLM l\u00e0 o\u00f9 c'est possible\n# 2. Activer Extended Protection for Authentication (EPA)\n# 3. Utiliser des filtres RPC pour bloquer les m\u00e9thodes vuln\u00e9rables\n# 4. Appliquer les correctifs (ex: KB5005413)"
            else
                print_success "Aucune vuln\u00e9rabilit\u00e9 de coercition NTLM d\u00e9tect\u00e9e"
            fi

            # ZeroLogon
            print_test "ZeroLogon (CVE-2020-1472)"
            smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M zerologon \
                > "${output_dir}/zerologon.txt" 2>&1 || true
            sed -i "s/${password}/[REDACTED]/g" "${output_dir}/zerologon.txt" 2>/dev/null || true

            if grep -qiE "VULNERABLE|vuln" "${output_dir}/zerologon.txt" 2>/dev/null; then
                print_error "\U0001f534 VULN\u00c9RABLE \u00c0 ZEROLOGON!"
                add_finding_remediation "CRITICAL" "ZeroLogon (CVE-2020-1472)" "Le DC est vuln\u00e9rable \u00e0 ZeroLogon. Compromission du domaine possible sans authentification!" \
                    "${output_dir}/zerologon.txt" \
                    "# Apply ZeroLogon patches immediately!\n# Ensure FullSecureChannelProtection is enforced\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -Name 'FullSecureChannelProtection' -Value 1"
            else
                print_success "ZeroLogon non vuln\u00e9rable"
            fi

            # noPac
            print_test "noPac / sAMAccountName spoofing (CVE-2021-42278)"
            smb_tool_exec "${DC_IP}" -u "${username}" -p "${password}" -d "${DOMAIN}" -M nopac \
                > "${output_dir}/nopac.txt" 2>&1 || true
            sed -i "s/${password}/[REDACTED]/g" "${output_dir}/nopac.txt" 2>/dev/null || true

            if grep -qiE "VULNERABLE|vuln" "${output_dir}/nopac.txt" 2>/dev/null; then
                print_error "\U0001f534 Vuln\u00e9rable \u00e0 noPac!"
                add_finding_remediation "HIGH" "noPac (CVE-2021-42278/42287)" "Vuln\u00e9rable \u00e0 l'usurpation sAMAccountName. Escalade vers Domain Admin possible." \
                    "${output_dir}/nopac.txt" \
                    "# Apply patches KB5008380 and KB5008602"
            else
                print_success "noPac non vuln\u00e9rable"
            fi
        fi
    else
        print_info "Pas d'outil SMB \u2014 v\u00e9rifications de vuln\u00e9rabilit\u00e9s limit\u00e9es"
    fi

    # EternalBlue (MS17-010) via nmap
    print_test "EternalBlue (MS17-010)"
    if ! command_exists nmap; then
        print_warning "nmap non disponible — EternalBlue ignor\u00e9"
    else
        local NMAP_T="T4"
        [ "${SAFE_MODE}" = true ] && NMAP_T="T2"
        nmap -${NMAP_T} -Pn -p 445 --script smb-vuln-ms17-010 "${DC_IP}" \
            -oN "${output_dir}/eternalblue.txt" 2>/dev/null || true

        if grep -qi "VULNERABLE" "${output_dir}/eternalblue.txt" 2>/dev/null; then
            print_error "\U0001f534 VULN\u00c9RABLE \u00c0 ETERNALBLUE!"
            add_finding_remediation "CRITICAL" "EternalBlue (MS17-010)" "Le DC est vuln\u00e9rable \u00e0 EternalBlue. Ex\u00e9cution de code \u00e0 distance sans authentification!" \
                "${output_dir}/eternalblue.txt" \
                "# Apply MS17-010 patches IMMEDIATELY\n# Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol \$false"
        else
            print_success "EternalBlue non vuln\u00e9rable"
        fi
    fi

    stop_timer "vulns"
}
