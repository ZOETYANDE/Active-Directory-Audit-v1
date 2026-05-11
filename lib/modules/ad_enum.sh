#!/bin/bash
# lib/modules/ad_enum.sh
# Énumération Active Directory via NetExec — compatible compte de LECTURE uniquement

audit_ad_enum() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/09_AD_Enum_NXC"

    print_section "AUDIT: ÉNUMÉRATION ACTIVE DIRECTORY (NXC)"
    start_timer "ad_enum"

    mkdir -p "${output_dir}"

    local password
    password=$(<"${pwd_file}")

    if [ "${HAS_NXC}" != true ]; then
        print_error "NetExec (nxc) n'est pas disponible. Énumération annulée."
        stop_timer "ad_enum"
        return 1
    fi

    print_info "Énumération Active Directory via NetExec (compte lecture)..."

    # ─────────────────────────────────────────────────────────────────
    # 01 — Politique de mot de passe (SMB, fonctionne en lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Politique de mot de passe"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --pass-pol \
        > "${output_dir}/01_password_policy.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/01_password_policy.txt" 2>/dev/null || true
    print_success "Politique de mot de passe exportée"

    # ─────────────────────────────────────────────────────────────────
    # 02 — Liste des utilisateurs (LDAP, fonctionne en lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Énumération des utilisateurs"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --users \
        > "${output_dir}/02_users.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/02_users.txt" 2>/dev/null || true
    print_success "Utilisateurs exportés"

    # ─────────────────────────────────────────────────────────────────
    # 03 — Liste des groupes (LDAP, fonctionne en lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Énumération des groupes"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --groups \
        > "${output_dir}/03_groups.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/03_groups.txt" 2>/dev/null || true
    print_success "Groupes exportés"

    # ─────────────────────────────────────────────────────────────────
    # 04 — Liste des ordinateurs (LDAP, fonctionne en lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Énumération des ordinateurs"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --computers \
        > "${output_dir}/04_computers.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/04_computers.txt" 2>/dev/null || true
    print_success "Ordinateurs exportés"

    # ─────────────────────────────────────────────────────────────────
    # 05 — Partages SMB accessibles (SMB, fonctionne en lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Partages SMB accessibles"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --shares \
        > "${output_dir}/05_shares.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/05_shares.txt" 2>/dev/null || true
    print_success "Partages SMB exportés"

    # ─────────────────────────────────────────────────────────────────
    # 06 — Descriptions utilisateurs (passwords dans descriptions)
    # (LDAP, fonctionne en lecture — très utile pour l'audit)
    # ─────────────────────────────────────────────────────────────────
    print_test "Descriptions utilisateurs (recherche de mots de passe)"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --user-desc \
        > "${output_dir}/06_user_descriptions.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/06_user_descriptions.txt" 2>/dev/null || true
    local desc_count
    desc_count=$(grep -c "Description:" "${output_dir}/06_user_descriptions.txt" 2>/dev/null || echo "0")
    if [ "${desc_count}" -gt 0 ]; then
        print_warning "⚠️  ${desc_count} descriptions trouvées — vérifier si des mots de passe y sont présents"
        add_finding "MEDIUM" "Descriptions Utilisateurs Présentes" "${desc_count} utilisateurs ont une description — risque de mot de passe en clair. Voir 06_user_descriptions.txt" "${output_dir}/06_user_descriptions.txt"
    else
        print_success "Aucune description significative"
    fi

    # ─────────────────────────────────────────────────────────────────
    # 07 — Comptes sans pré-authentification Kerberos (AS-REP Roasting)
    # (LDAP, fonctionne en lecture — trouvaille critique)
    # ─────────────────────────────────────────────────────────────────
    print_test "Comptes vulnérables AS-REP Roasting (nxc)"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --asreproast \
        "${output_dir}/07_asrep_hashes.txt" > "${output_dir}/07_asrep_results.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/07_asrep_results.txt" 2>/dev/null || true

    if [ -s "${output_dir}/07_asrep_hashes.txt" ]; then
        local asrep_count
        asrep_count=$(wc -l < "${output_dir}/07_asrep_hashes.txt")
        print_error "🔴 ${asrep_count} hash(es) AS-REP récupérés — crackables hors-ligne!"
        add_finding_remediation "HIGH" "AS-REP Roasting (NXC)" \
            "${asrep_count} compte(s) sans pré-authentification Kerberos. Les hashes peuvent être craqués hors-ligne (hashcat -m 18200). Voir 07_asrep_hashes.txt" \
            "${output_dir}/07_asrep_hashes.txt" \
            "# Activer la pré-authentification Kerberos sur tous les comptes\nGet-ADUser -Filter {DoesNotRequirePreAuth -eq \$true} | Set-ADAccountControl -DoesNotRequirePreAuth \$false"
    else
        print_success "Aucun compte AS-REP Roastable"
    fi

    # ─────────────────────────────────────────────────────────────────
    # 08 — Comptes Kerberoastables (SPN) (LDAP, fonctionne en lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Comptes Kerberoastables (SPN)"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --kerberoasting \
        "${output_dir}/08_kerberoast_hashes.txt" > "${output_dir}/08_kerberoast_results.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/08_kerberoast_results.txt" 2>/dev/null || true

    if [ -s "${output_dir}/08_kerberoast_hashes.txt" ]; then
        local kerb_count
        kerb_count=$(wc -l < "${output_dir}/08_kerberoast_hashes.txt")
        print_error "🔴 ${kerb_count} hash(es) Kerberoast récupérés — crackables hors-ligne!"
        add_finding_remediation "HIGH" "Kerberoasting (NXC)" \
            "${kerb_count} compte(s) avec SPN utilisateur. Les hashes TGS peuvent être craqués hors-ligne (hashcat -m 13100). Voir 08_kerberoast_hashes.txt" \
            "${output_dir}/08_kerberoast_hashes.txt" \
            "# Remplacer les comptes de service par des gMSA (Group Managed Service Accounts)\nGet-ADUser -Filter {ServicePrincipalName -ne '\$null'} -Properties ServicePrincipalName | Select SamAccountName, ServicePrincipalName"
    else
        print_success "Aucun compte Kerberoastable"
    fi

    # ─────────────────────────────────────────────────────────────────
    # 09 — Comptes sans mot de passe requis (LDAP, lecture)
    # ─────────────────────────────────────────────────────────────────
    print_test "Comptes sans mot de passe requis"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --password-not-required \
        > "${output_dir}/09_no_password_required.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/09_no_password_required.txt" 2>/dev/null || true

    local nopwd_count
    nopwd_count=$(grep -c "Username:" "${output_dir}/09_no_password_required.txt" 2>/dev/null || echo "0")
    if [ "${nopwd_count}" -gt 0 ]; then
        print_error "🔴 ${nopwd_count} compte(s) sans mot de passe requis!"
        add_finding_remediation "HIGH" "Comptes Sans Mot de Passe Requis" \
            "${nopwd_count} compte(s) ont l'attribut PASSWD_NOTREQD. Ces comptes peuvent exister sans mot de passe." \
            "${output_dir}/09_no_password_required.txt" \
            "# Forcer un mot de passe sur tous les comptes\nGet-ADUser -Filter {PasswordNotRequired -eq \$true} | Set-ADUser -PasswordNotRequired \$false"
    else
        print_success "Tous les comptes ont un mot de passe requis"
    fi

    # ─────────────────────────────────────────────────────────────────
    # Rapport d'information global
    # ─────────────────────────────────────────────────────────────────
    add_finding "INFO" "Énumération NXC complète" \
        "Énumération détaillée via NetExec (compte lecture) terminée. Utilisateurs, groupes, ordinateurs, partages, AS-REP et Kerberoast exportés." \
        "Voir dossier: ${output_dir}"

    # ─────────────────────────────────────────────────────────────────
    # Résumé
    # ─────────────────────────────────────────────────────────────────
    cat > "${output_dir}/SUMMARY.txt" << SUMMARY_EOF
===============================================
RÉSUMÉ DE L'ÉNUMÉRATION ACTIVE DIRECTORY (NXC)
===============================================

Date       : $(date)
Cible      : ${DC_IP}
Domaine    : ${DOMAIN}
Utilisateur: ${username}
Mode       : Compte de lecture (Read-Only)

Fichiers générés:
- 01_password_policy.txt       : Politique de mot de passe
- 02_users.txt                 : Liste des utilisateurs
- 03_groups.txt                : Liste des groupes
- 04_computers.txt             : Liste des ordinateurs
- 05_shares.txt                : Partages SMB accessibles
- 06_user_descriptions.txt     : Descriptions (risque mots de passe)
- 07_asrep_hashes.txt          : Hashes AS-REP (si vulnérables)
- 07_asrep_results.txt         : Journal AS-REP Roasting
- 08_kerberoast_hashes.txt     : Hashes Kerberoast (si vulnérables)
- 08_kerberoast_results.txt    : Journal Kerberoasting
- 09_no_password_required.txt  : Comptes sans mot de passe requis

NOTE: Les commandes nécessitant des droits Admin (--sam, --lsa,
--sessions, --loggedon-users) ont été exclues car le compte
d'audit est un compte de lecture uniquement.

===============================================
SUMMARY_EOF

    stop_timer "ad_enum"
}
