#!/bin/bash
# lib/modules/inventory.sh — Network inventory via parallel nmap scans

audit_inventory() {
    print_section "AUDIT 1: INVENTAIRE (MODE PARALLÈLE)"
    local output_dir="${OUTPUT_DIR}/01_Inventaire"
    start_timer "inventory"

    print_info "Lancement de 4 scans nmap en parallèle..."

    nmap -T4 -sn "${NETWORK}" \
        -oN "${output_dir}/hosts_alive.txt" \
        -oX "${output_dir}/hosts_alive.xml" \
        >/dev/null 2>&1 &
    local pid1=$!
    BG_PIDS+=("${pid1}")
    log_parallel "${pid1}" "discovery" "LANCÉ"

    nmap -T4 -Pn -p 88,389,445,636,3268 "${NETWORK}" --open \
        -oN "${output_dir}/ad_services.txt" \
        -oX "${output_dir}/ad_services.xml" \
        >/dev/null 2>&1 &
    local pid2=$!
    BG_PIDS+=("${pid2}")
    log_parallel "${pid2}" "services AD" "LANCÉ"

    nmap -T4 -Pn -sV -sC -p 53,88,135,139,389,445,464,636,3268,3269,3389 "${DC_IP}" \
        -oN "${output_dir}/dc_full_scan.txt" \
        -oX "${output_dir}/dc_full_scan.xml" \
        >/dev/null 2>&1 &
    local pid3=$!
    BG_PIDS+=("${pid3}")
    log_parallel "${pid3}" "DC complet" "LANCÉ"

    nmap -T4 -Pn -p 445 --script smb-protocols,smb2-protocols "${DC_IP}" \
        -oN "${output_dir}/smb_version.txt" \
        >/dev/null 2>&1 &
    local pid4=$!
    BG_PIDS+=("${pid4}")
    log_parallel "${pid4}" "SMB" "LANCÉ"

    sleep 2.5
    local running=0
    for p in ${pid1} ${pid2} ${pid3} ${pid4}; do
        ps -p ${p} >/dev/null 2>&1 && ((running++)) || true
    done
    print_info "✅ État: ${running}/4 scans actifs"

    wait ${pid1} ${pid2} ${pid3} ${pid4} 2>/dev/null || true

    print_test "Découverte réseau"
    if [ -f "${output_dir}/hosts_alive.txt" ] && [ -s "${output_dir}/hosts_alive.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    print_test "Services AD"
    if [ -f "${output_dir}/ad_services.txt" ] && [ -s "${output_dir}/ad_services.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    print_test "Scan DC"
    if [ -f "${output_dir}/dc_full_scan.txt" ] && [ -s "${output_dir}/dc_full_scan.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    print_test "Versions SMB"
    if [ -f "${output_dir}/smb_version.txt" ] && [ -s "${output_dir}/smb_version.txt" ]; then
        print_success "Fichier créé"
    else
        print_warning "Aucun résultat"
    fi

    local hosts_count
    hosts_count=$(safe_count "Host is up" "${output_dir}/hosts_alive.txt")
    print_info "📊 Hôtes découverts: ${hosts_count}"

    local dc_count
    dc_count=$(safe_count "88/tcp" "${output_dir}/ad_services.txt")
    print_info "📊 Contrôleurs potentiels: ${dc_count}"

    stop_timer "inventory"
}
