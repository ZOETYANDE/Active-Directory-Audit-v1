#!/bin/bash
# lib/modules/bloodhound.sh — BloodHound collection with FQDN auto-resolution

audit_bloodhound() {
    local username="$1"
    local pwd_file="$2"
    local output_dir="${OUTPUT_DIR}/09_BloodHound"

    print_section "AUDIT 5: BLOODHOUND (ANALYSE GRAPHIQUE AD)"
    start_timer "bloodhound"

    mkdir -p "${output_dir}"

    # Check bloodhound-python
    print_test "Vérification bloodhound-python"
    if [ "${HAS_BLOODHOUND}" != true ]; then
        print_error "bloodhound-python non installé"
        print_info "💡 Installation: pip install bloodhound --break-system-packages"
        stop_timer "bloodhound"
        return 0
    fi

    local bh_version
    bh_version=$(bloodhound-python --version 2>&1 | head -1)
    print_success "BloodHound disponible: ${bh_version}"

    # Check impacket
    print_test "Vérification impacket"
    if ! python3 -c "import impacket" 2>/dev/null; then
        print_error "Impacket manquant"
        stop_timer "bloodhound"
        return 0
    fi
    print_success "Impacket installé"

    # Resolve DC FQDN
    print_info "🔍 Résolution du FQDN du DC..."
    local dc_fqdn=""
    local domain_lower
    domain_lower=$(echo "${DOMAIN}" | tr '[:upper:]' '[:lower:]')

    if [ -n "${DC_HOSTNAME}" ]; then
        # Strip any existing domain suffix to avoid double-domain (e.g. HOST.domain.domain)
        local hostname_base="${DC_HOSTNAME%%.*}"
        dc_fqdn="${hostname_base}.${domain_lower}"
        print_info "✓ FQDN configuré: ${dc_fqdn}"
    else
        # Try reverse DNS
        local ptr_result
        ptr_result=$(host "${DC_IP}" 2>/dev/null | grep -i "pointer" | awk '{print $NF}' | sed 's/\.$//')
        if [ -n "${ptr_result}" ]; then
            dc_fqdn="${ptr_result}"
            print_info "✓ FQDN via DNS inverse: ${dc_fqdn}"
        else
            # Try LDAP
            ldap_search "${username}" "${pwd_file}" \
                "(objectClass=computer)" "dNSHostName" "${output_dir}/dc_fqdn_ldap.txt"
            local ldap_hostname
            ldap_hostname=$(grep -i "dNSHostName:" "${output_dir}/dc_fqdn_ldap.txt" | head -1 | awk '{print $2}')

            if [ -n "${ldap_hostname}" ]; then
                dc_fqdn="${ldap_hostname}"
                print_info "✓ FQDN via LDAP: ${dc_fqdn}"
            else
                # Try SRV
                local srv_result
                srv_result=$(host -t SRV "_ldap._tcp.${domain_lower}" "${DC_IP}" 2>/dev/null | \
                    grep -i "SRV" | head -1 | awk '{print $NF}' | sed 's/\.$//')
                if [ -n "${srv_result}" ]; then
                    dc_fqdn="${srv_result}"
                    print_info "✓ FQDN via SRV: ${dc_fqdn}"
                fi
            fi
        fi
    fi

    print_test "FQDN du contrôleur de domaine"
    if [ -z "${dc_fqdn}" ]; then
        print_error "❌ Impossible de déterminer le FQDN du DC"
        print_info "🛠️  Éditez DC_HOSTNAME dans le fichier de config ou utilisez --dc-hostname"
        stop_timer "bloodhound"
        return 0
    fi
    print_success "FQDN résolu: ${dc_fqdn}"

    # Validate password
    print_test "Validation du mot de passe"
    local password
    password=$(<"${pwd_file}")
    if [ -z "${password}" ]; then
        print_error "Mot de passe vide"
        stop_timer "bloodhound"
        return 1
    fi
    print_success "Mot de passe chargé (${#password} caractères)"

    # Execute BloodHound
    print_info "🚀 Lancement de la collecte BloodHound..."
    print_info "   Domaine: ${domain_lower} | DC: ${dc_fqdn} | DNS: ${DC_IP}"

    local original_dir
    original_dir=$(pwd)
    cd "${output_dir}" || { print_error "Erreur de répertoire"; stop_timer "bloodhound"; return 1; }

    print_test "Collecte BloodHound"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ EXÉCUTION BLOODHOUND — bloodhound-python -c All            │${NC}"
    echo -e "${YELLOW}│ DC: ${dc_fqdn}${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    bloodhound-python \
        -c All \
        -d "${domain_lower}" \
        -u "${username}" \
        -p "${password}" \
        -dc "${dc_fqdn}" \
        -ns "${DC_IP}" \
        --zip 2>&1 | tee bloodhound_output.log

    local exit_code=${PIPESTATUS[0]}

    local json_count zip_count
    json_count=$(find . -maxdepth 1 -name "*.json" -type f 2>/dev/null | wc -l)
    zip_count=$(find . -maxdepth 1 -name "*.zip" -type f 2>/dev/null | wc -l)

    # Retry without --zip if needed
    if [ ${zip_count} -eq 0 ] && [ ${json_count} -eq 0 ] && [ ${exit_code} -ne 0 ]; then
        print_warning "Retry sans --zip..."
        bloodhound-python -c All -d "${domain_lower}" -u "${username}" \
            -p "${password}" -dc "${dc_fqdn}" -ns "${DC_IP}" 2>&1 | tee -a bloodhound_output.log
        json_count=$(find . -maxdepth 1 -name "*.json" -type f 2>/dev/null | wc -l)
        zip_count=$(find . -maxdepth 1 -name "*.zip" -type f 2>/dev/null | wc -l)
    fi

    cd "${original_dir}" || true

    if [ ${json_count} -gt 0 ] || [ ${zip_count} -gt 0 ]; then
        print_success "✅ ${json_count} JSON + ${zip_count} ZIP créés"
        add_finding "INFO" "BloodHound Collecté" "${json_count} fichiers JSON et ${zip_count} archives ZIP générés." "${output_dir}"

        print_info "📁 Fichiers générés:"
        find "${output_dir}" -maxdepth 1 \( -name "*.json" -o -name "*.zip" \) -type f 2>/dev/null | while read -r file; do
            local size_kb=$(( $(stat -c%s "${file}" 2>/dev/null || echo "0") / 1024 ))
            print_info "   - $(basename "${file}") (${size_kb} KB)"
        done

        echo ""
        print_info "📊 Importer dans BloodHound GUI: sudo neo4j start && bloodhound"
    else
        print_error "❌ Aucun fichier généré"
        add_finding "MEDIUM" "BloodHound Échoué" "La collecte BloodHound n'a pas produit de résultats." "${output_dir}/bloodhound_output.log"
        if [ -f "${output_dir}/bloodhound_output.log" ]; then
            print_info "📋 Dernières lignes:"
            tail -10 "${output_dir}/bloodhound_output.log" | while IFS= read -r line; do echo "   ${line}"; done
        fi
    fi

    stop_timer "bloodhound"
}
