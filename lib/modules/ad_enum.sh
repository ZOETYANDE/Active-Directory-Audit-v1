#!/bin/bash
# lib/modules/ad_enum.sh

audit_ad_enum() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/09_AD_Enum_NXC"

    print_section "AUDIT: ÉNUMÉRATION ACTIVE DIRECTORY (NXC)"
    start_timer "ad_enum"

    mkdir -p "${output_dir}"

    # Récupération du mot de passe
    local password
    password=$(<"${pwd_file}")

    if [ "${HAS_NXC}" != true ]; then
        print_error "NetExec (nxc) n'est pas disponible. Énumération annulée."
        stop_timer "ad_enum"
        return 1
    fi

    print_info "Énumération Active Directory commencée via NetExec..."

    # Politique de mot de passe
    print_test "Récupération de la politique de mot de passe"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --pass-pol > "${output_dir}/01_password_policy.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/01_password_policy.txt" 2>/dev/null || true
    print_success "Politique de mot de passe exportée"

    # Utilisateurs
    print_test "Énumération des utilisateurs"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --users > "${output_dir}/02_users.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/02_users.txt" 2>/dev/null || true
    print_success "Utilisateurs exportés"

    # Groupes
    print_test "Énumération des groupes"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --groups > "${output_dir}/03_groups.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/03_groups.txt" 2>/dev/null || true
    print_success "Groupes exportés"

    # Ordinateurs
    print_test "Énumération des ordinateurs"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --computers > "${output_dir}/04_computers.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/04_computers.txt" 2>/dev/null || true
    print_success "Ordinateurs exportés"

    # Partages SMB
    print_test "Énumération des partages SMB"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --shares > "${output_dir}/05_shares.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/05_shares.txt" 2>/dev/null || true
    print_success "Partages SMB exportés"

    # Sessions actives
    print_test "Récupération des sessions actives"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --sessions > "${output_dir}/06_sessions.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/06_sessions.txt" 2>/dev/null || true
    print_success "Sessions exportées"

    # Infos du domaine
    print_test "Récupération des infos du domaine"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" -M whoami > "${output_dir}/07_domain_info.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/07_domain_info.txt" 2>/dev/null || true
    print_success "Infos domaine exportées"

    # Énumération via LDAP avec plus de détails
    print_test "Énumération LDAP détaillée"
    nxc ldap "${DC_IP}" -u "${username}" -p "${password}" --search-filter '(objectClass=user)' > "${output_dir}/08_ldap_users_detailed.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/08_ldap_users_detailed.txt" 2>/dev/null || true
    print_success "Détails LDAP exportés"

    # Vérifier les droits de l'utilisateur actuel
    print_test "Vérification des droits de l'utilisateur"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" -x 'whoami /all' > "${output_dir}/09_user_rights.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/09_user_rights.txt" 2>/dev/null || true
    print_success "Droits de l'utilisateur exportés"

    # Tenter dump SAM (si permissions)
    print_test "Tentative de dump SAM"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --sam > "${output_dir}/10_sam_dump.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/10_sam_dump.txt" 2>/dev/null || true
    if grep -q "Pwn3d!" "${output_dir}/10_sam_dump.txt"; then
        print_success "Dump SAM réussi !"
        add_finding_remediation "CRITICAL" "Extraction base SAM" "La base SAM (hash de mots de passe locaux) du contrôleur de domaine a pu être extraite." "${output_dir}/10_sam_dump.txt" "Restreindre les droits d'administration réseau."
    else
        print_warning "Dump SAM échoué (Droits insuffisants)"
    fi

    # Tenter dump LSA (si permissions)
    print_test "Tentative de dump LSA"
    nxc smb "${DC_IP}" -u "${username}" -p "${password}" --lsa > "${output_dir}/11_lsa_dump.txt" 2>&1
    sed -i "s/${password}/[REDACTED]/g" "${output_dir}/11_lsa_dump.txt" 2>/dev/null || true
    if grep -q "Pwn3d!" "${output_dir}/11_lsa_dump.txt"; then
        print_success "Dump LSA réussi !"
        add_finding_remediation "CRITICAL" "Extraction secrets LSA" "Les secrets LSA (mots de passe en clair) du contrôleur de domaine ont pu être extraits." "${output_dir}/11_lsa_dump.txt" "Restreindre les droits d'administration réseau."
    else
        print_warning "Dump LSA échoué (Droits insuffisants)"
    fi

    # Rapport d'information global
    add_finding "INFO" "Énumération NXC complète" "Une énumération détaillée de l'AD (utilisateurs, groupes, GPO, sessions) a été extraite avec succès par NetExec." "Voir dossier: ${output_dir}"

    # Créer un résumé
    cat > "${output_dir}/SUMMARY.txt" << SUMMARY_EOF
===============================================
RÉSUMÉ DE L'ÉNUMÉRATION ACTIVE DIRECTORY (NXC)
===============================================

Date: $(date)
Cible: ${DC_IP}
Domaine: ${DOMAIN}
Utilisateur: ${username}

Fichiers générés:
- 01_password_policy.txt : Politique de mot de passe
- 02_users.txt : Liste des utilisateurs
- 03_groups.txt : Liste des groupes
- 04_computers.txt : Liste des ordinateurs
- 05_shares.txt : Partages SMB disponibles
- 06_sessions.txt : Sessions actives
- 07_domain_info.txt : Informations du domaine
- 08_ldap_users_detailed.txt : Détails LDAP des utilisateurs
- 09_user_rights.txt : Droits de l'utilisateur
- 10_sam_dump.txt : Dump SAM (si accessible)
- 11_lsa_dump.txt : Dump LSA (si accessible)

===============================================
SUMMARY_EOF

    stop_timer "ad_enum"
}
