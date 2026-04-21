#!/bin/bash
# lib/modules/delegation.sh

audit_delegation() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/12_Delegation"

    print_section "AUDIT: DÉLÉGATION KERBEROS"
    start_timer "delegation"

    # Unconstrained Delegation
    print_test "Délégation non contrainte"
    ldap_search "${username}" "${pwd_file}" \
        "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" \
        "sAMAccountName userAccountControl" "${output_dir}/unconstrained.txt"

    local unc_count
    unc_count=$(safe_count "sAMAccountName:" "${output_dir}/unconstrained.txt")

    if [ "${unc_count}" -gt 0 ]; then
        print_error "🔴 ${unc_count} objets avec délégation non contrainte"
        add_finding "CRITICAL" "Délégation Non Contrainte" "${unc_count} objets (hors DCs) avec délégation non contrainte. Risque de compromission du domaine." "${output_dir}/unconstrained.txt"
    else
        print_success "Aucune délégation non contrainte"
    fi

    # Constrained Delegation
    print_test "Délégation contrainte"
    ldap_search "${username}" "${pwd_file}" \
        "(msDS-AllowedToDelegateTo=*)" \
        "sAMAccountName msDS-AllowedToDelegateTo" "${output_dir}/constrained.txt"

    local con_count
    con_count=$(safe_count "sAMAccountName:" "${output_dir}/constrained.txt")

    if [ "${con_count}" -gt 0 ]; then
        print_warning "⚠️  ${con_count} objets avec délégation contrainte"
        add_finding "MEDIUM" "Délégation Contrainte" "${con_count} objets configurés avec délégation contrainte." "${output_dir}/constrained.txt"
    else
        print_success "Aucune délégation contrainte"
    fi

    # Resource-Based Constrained Delegation (RBCD)
    print_test "Délégation contrainte basée sur les ressources (RBCD)"
    ldap_search "${username}" "${pwd_file}" \
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
        "sAMAccountName" "${output_dir}/rbcd.txt"

    local rbcd_count
    rbcd_count=$(safe_count "sAMAccountName:" "${output_dir}/rbcd.txt")

    if [ "${rbcd_count}" -gt 0 ]; then
        print_warning "⚠️  ${rbcd_count} objets avec RBCD"
        add_finding "HIGH" "RBCD Configurée" "${rbcd_count} objets avec délégation RBCD. Vérifier si légitime." "${output_dir}/rbcd.txt"
    else
        print_success "Aucune RBCD"
    fi

    stop_timer "delegation"
}

#===============================================================================
# AUDIT 4.8: ACL ABUSE  [NEW]
#===============================================================================

audit_acl_abuse() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/13_AclAbuse"
    [ -d "${output_dir}" ] || mkdir -p "${output_dir}"

    print_section "AUDIT: ABUS DES ACL"
    start_timer "acl_abuse"

    # Check for genericWrite/GenericAll on sensitive objects
    print_test "Recherche d'abus de permissions (GenericWrite/GenericAll)"
    ldap_search "${username}" "${pwd_file}" "(objectClass=*)" "distinguishedName" "${output_dir}/acls.txt"

    # Parse ACLs for abuse patterns
    local abuse_found=0
    while IFS= read -r line; do
        if [[ "${line}" == *"GenericWrite"* || "${line}" == *"GenericAll"* ]]; then
            abuse_found=1
            print_error "🔴 Abus de permissions détecté: ${line}"
            add_finding "HIGH" "Abus de Permissions" "Objet avec permissions GenericWrite/GenericAll. Risque de prise de contrôle." "${output_dir}/acls.txt"
        fi
    done < "${output_dir}/acls.txt"

    if [ "${abuse_found}" -eq 0 ]; then
        print_success "Aucun abus de permissions détecté"
    fi

    stop_timer "acl_abuse"
}
