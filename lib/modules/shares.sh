#!/bin/bash
# lib/modules/shares.sh

audit_shares() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/07_Partages"

    print_section "AUDIT: PARTAGES SMB"
    start_timer "shares"

    local password
    password=$(<"${pwd_file}")

    # Share enumeration
    print_test "Énumération des partages"
    if [ "${HAS_NXC}" = true ] || [ "${HAS_CME}" = true ]; then
        smb_tool_exec "\"${DC_IP}\" -u \"${username}\" -p \"${password}\" -d \"${DOMAIN}\" --shares" \
            > "${output_dir}/shares.txt" 2>&1 || true
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/shares.txt" 2>/dev/null || true

        local share_count
        share_count=$(grep -cE "READ|WRITE" "${output_dir}/shares.txt" 2>/dev/null || true)
        if ! [[ "${share_count}" =~ ^[0-9]+$ ]]; then share_count=0; fi

        if [ "${share_count}" -gt 0 ]; then
            print_success "${share_count} partages accessibles"
        else
            print_warning "Aucun partage accessible"
        fi

        # Writable shares
        print_test "Partages en écriture"
        local writable
        writable=$(grep -c "WRITE" "${output_dir}/shares.txt" 2>/dev/null || true)
        if ! [[ "${writable}" =~ ^[0-9]+$ ]]; then writable=0; fi

        if [ "${writable}" -gt 0 ]; then
            print_warning "⚠️  ${writable} partages en écriture"
            add_finding_remediation "MEDIUM" "Partages en Écriture" "${writable} partages SMB accessibles en écriture par l'utilisateur d'audit." \
                "${output_dir}/shares.txt" \
                "# Review share permissions\nGet-SmbShare | Get-SmbShareAccess | Where-Object {\$_.AccessRight -eq 'Change' -or \$_.AccessRight -eq 'Full'}"
        else
            print_success "Aucun partage en écriture"
        fi
    else
        print_warning "Pas d'outil SMB pour l'énumération des partages"
    fi

    # SYSVOL content scan
    print_test "Analyse du contenu SYSVOL"
    if [ "${HAS_SMBCLIENT}" = true ]; then
        smbclient "\\\\${DC_IP}\\SYSVOL" -U "${DOMAIN}/${username}%${password}" \
            -c "recurse ON; ls" > "${output_dir}/sysvol_contents.txt" 2>&1 || true
        sed -i "s/${password}/[REDACTED]/g" "${output_dir}/sysvol_contents.txt" 2>/dev/null || true

        # Search for script files with potential credentials
        if grep -qiE "\.bat|\.cmd|\.vbs|\.ps1|\.xml|\.ini" "${output_dir}/sysvol_contents.txt" 2>/dev/null; then
            local script_count
            script_count=$(grep -ciE "\.bat|\.cmd|\.vbs|\.ps1|\.xml|\.ini" "${output_dir}/sysvol_contents.txt" || true)
            print_warning "⚠️  ${script_count} scripts trouvés dans SYSVOL (vérification manuelle recommandée)"
            add_finding "LOW" "Scripts dans SYSVOL" "${script_count} fichiers script dans SYSVOL. Vérifier manuellement pour mots de passe hardcodés." \
                "${output_dir}/sysvol_contents.txt"
        else
            print_success "Pas de scripts suspects dans SYSVOL"
        fi
    else
        print_info "smbclient non disponible — analyse SYSVOL ignorée"
    fi

    stop_timer "shares"
}
