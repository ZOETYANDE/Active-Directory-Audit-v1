#!/bin/bash
# lib/modules/dc_config.sh — DC configuration checks (SMBv1, SMB signing, LDAP signing)

audit_dc_config() {
    print_section "AUDIT 2: CONFIGURATION DC"
    local output_dir="${OUTPUT_DIR}/02_Configuration_DC"
    start_timer "dc_config"

    print_test "Détection SMBv1"
    nmap -T4 -Pn -p 445 --script smb-protocols "${DC_IP}" \
        -oN "${output_dir}/smb_version.txt" 2>/dev/null || true

    if [ -f "${output_dir}/smb_version.txt" ]; then
        if grep -qi "SMBv1" "${output_dir}/smb_version.txt"; then
            print_error "🔴 SMBv1 activé - VULNÉRABILITÉ CRITIQUE"
            add_finding "CRITICAL" "SMBv1 Activé" "Le protocole SMBv1 est activé sur ${DC_IP}. Vulnérable à EternalBlue (MS17-010)." "${output_dir}/smb_version.txt"
        else
            print_success "SMBv1 désactivé"
            add_finding "INFO" "SMBv1 Désactivé" "SMBv1 est correctement désactivé." ""
        fi
    else
        print_warning "Impossible de vérifier SMB"
    fi

    print_test "Signature SMB"
    local smb_signing_confirmed=false

    if [ -f "${OUTPUT_DIR}/cred_test.txt" ]; then
        if grep -qi "signing:True" "${OUTPUT_DIR}/cred_test.txt" 2>/dev/null; then
            print_success "Signature SMB requise (confirmé par NetExec)"
            add_finding "INFO" "Signature SMB Requise" "La signature SMB est correctement requise (confirmé par NetExec)." ""
            smb_signing_confirmed=true
        fi
    fi

    if [ "${smb_signing_confirmed}" = false ]; then
        nmap -T4 -Pn -p 445 --script smb-security-mode "${DC_IP}" \
            -oN "${output_dir}/smb_signing.txt" 2>/dev/null || true

        if [ -f "${output_dir}/smb_signing.txt" ]; then
            if grep -qiE "message_signing:.*required|signing.*required" "${output_dir}/smb_signing.txt"; then
                print_success "Signature SMB requise"
                add_finding "INFO" "Signature SMB Requise" "La signature SMB est correctement requise." ""
            else
                print_warning "Signature SMB non requise - Risque NTLM relay"
                add_finding "HIGH" "Signature SMB Non Requise" "La signature SMB n'est pas requise. Risque d'attaque NTLM relay." "${output_dir}/smb_signing.txt"
            fi
        else
            print_warning "Impossible de vérifier signature"
        fi
    fi

    print_test "Signature LDAP"
    local ldap_result
    ldap_result=$(ldapsearch -x -H "ldap://${DC_IP}" -b "" -s base \
        "(objectClass=*)" 2>&1 || true)

    if echo "${ldap_result}" | grep -qi "result: 0"; then
        print_warning "LDAP non signé accepté — risque d'interception"
        add_finding "MEDIUM" "LDAP Binding Non Signé" "Le serveur accepte les connexions LDAP sans signature. Risque de MITM." ""
    else
        print_success "LDAP sécurisé"
    fi

    stop_timer "dc_config"
}
