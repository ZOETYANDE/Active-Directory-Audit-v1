#!/bin/bash
# lib/modules/laps.sh

audit_laps() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/15_LAPS"

    print_section "AUDIT: LAPS (LOCAL ADMIN PASSWORD SOLUTION)"
    start_timer "laps"

    # Check if LAPS schema is present
    print_test "Présence du schéma LAPS"
    ldap_search "${username}" "${pwd_file}" \
        "(attributeID=1.2.840.113556.1.4.2311)" \
        "cn" "${output_dir}/laps_schema_legacy.txt"

    # Also check for Windows LAPS (new)
    ldap_search "${username}" "${pwd_file}" \
        "(attributeID=1.2.840.113556.1.4.2340)" \
        "cn" "${output_dir}/laps_schema_new.txt"

    local has_legacy_laps=false
    local has_new_laps=false

    if grep -q "cn:" "${output_dir}/laps_schema_legacy.txt" 2>/dev/null; then
        has_legacy_laps=true
    fi
    if grep -q "cn:" "${output_dir}/laps_schema_new.txt" 2>/dev/null; then
        has_new_laps=true
    fi

    if [ "${has_legacy_laps}" = true ] || [ "${has_new_laps}" = true ]; then
        print_success "LAPS déployé"

        # Count computers WITH LAPS password
        print_test "Couverture LAPS"
        ldap_search "${username}" "${pwd_file}" \
            "(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))" \
            "sAMAccountName" "${output_dir}/laps_covered.txt"

        local covered
        covered=$(safe_count "sAMAccountName:" "${output_dir}/laps_covered.txt")
        local total_computers
        total_computers=$(safe_count "sAMAccountName:" "${OUTPUT_DIR}/11_Ordinateurs/all_computers.txt")

        print_info "📊 LAPS: ${covered}/${total_computers} ordinateurs couverts"

        if [ "${total_computers}" -gt 0 ] && [ "${covered}" -lt "${total_computers}" ]; then
            local uncovered=$((total_computers - covered))
            print_warning "⚠️  ${uncovered} ordinateurs sans LAPS"
            add_finding "MEDIUM" "Couverture LAPS Partielle" "${covered}/${total_computers} ordinateurs couverts par LAPS. ${uncovered} manquants." "${output_dir}/laps_covered.txt"
        else
            print_success "Couverture LAPS complète"
        fi
    else
        print_error "🔴 LAPS non déployé!"
        add_finding "HIGH" "LAPS Non Déployé" "LAPS n'est pas déployé. Les mots de passe administrateur local sont probablement identiques." ""
    fi

    stop_timer "laps"
}
