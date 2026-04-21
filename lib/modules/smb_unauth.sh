#!/bin/bash
# lib/modules/smb_unauth.sh

audit_smb_unauth() {
    local output_dir="${OUTPUT_DIR}/08_Vulnerabilites"

    print_section "AUDIT: ÉNUMÉRATION SMB NON AUTHENTIFIÉE"
    start_timer "smb_unauth"

    # Enum4linux-ng (FINALLY ACTIVATED!)
    if [ "${HAS_ENUM4LINUX}" = true ]; then
        print_test "Énumération anonyme (enum4linux-ng)"
        enum4linux-ng -A "${DC_IP}" -oJ "${output_dir}/enum4linux" > /dev/null 2>&1 || true

        if [ -f "${output_dir}/enum4linux.json" ]; then
            print_success "Énumération enum4linux-ng complétée"

            # Check for null session success
            if grep -qi "\"null_session\": true" "${output_dir}/enum4linux.json" 2>/dev/null; then
                print_error "🔴 Session nulle SMB autorisée!"
                add_finding_remediation "CRITICAL" "Session Nulle SMB" "Le serveur autorise les sessions nulles SMB. Énumération anonyme possible." \
                    "${output_dir}/enum4linux.json" \
                    "# Disable null sessions\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RestrictNullSessAccess' -Value 1"
            else
                print_success "Sessions nulles restreintes"
            fi

            # Check for users enumerated anonymously
            if grep -qi "\"users\":" "${output_dir}/enum4linux.json" 2>/dev/null; then
                local anon_users
                anon_users=$(grep -c "\"username\":" "${output_dir}/enum4linux.json" 2>/dev/null || true)
                if [ "${anon_users:-0}" -gt 0 ]; then
                    print_warning "⚠️  ${anon_users} utilisateurs énumérés anonymement"
                    add_finding "HIGH" "Énumération Anonyme d'Utilisateurs" "${anon_users} comptes utilisateurs exposés via énumération RID anonyme." \
                        "${output_dir}/enum4linux.json"
                fi
            fi
        else
            print_warning "enum4linux-ng n'a pas produit de résultats"
        fi
    else
        print_info "enum4linux-ng non disponible — énumération anonyme ignorée"
    fi

    # Null session share test
    if [ "${HAS_SMBCLIENT}" = true ]; then
        print_test "Partages en session nulle"
        smbclient -N -L "\\\\${DC_IP}" > "${output_dir}/null_shares.txt" 2>&1 || true

        if grep -qiE "Disk|IPC|Print" "${output_dir}/null_shares.txt" 2>/dev/null; then
            local null_shares
            null_shares=$(grep -ciE "Disk|IPC" "${output_dir}/null_shares.txt" || true)
            print_warning "⚠️  ${null_shares} partages accessibles en session nulle"
            add_finding "HIGH" "Partages Session Nulle" "${null_shares} partages accessibles sans authentification." \
                "${output_dir}/null_shares.txt"
        else
            print_success "Aucun partage en session nulle"
        fi
    fi

    stop_timer "smb_unauth"
}
