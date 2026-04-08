#!/bin/bash
# lib/reporting/text_reports.sh

generate_security_summary() {
    print_section "GÉNÉRATION DU RÉSUMÉ"

    local total_results=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))
    [ ${TESTS_TOTAL} -ne ${total_results} ] && TESTS_TOTAL=${total_results}

    local risk_score=$((TESTS_FAILED * 3 + TESTS_WARNING))
    local risk_level
    if [ "$risk_score" -lt 5 ]; then risk_level="✅ FAIBLE"
    elif [ "$risk_score" -lt 10 ]; then risk_level="⚠️  MODÉRÉ"
    elif [ "$risk_score" -lt 20 ]; then risk_level="🔴 ÉLEVÉ"
    else risk_level="🔴 CRITIQUE"; fi

    cat > "${SUMMARY_FILE}" <<EOF
════════════════════════════════════════════════════════════════
                📊 RÉSUMÉ DE SÉCURITÉ
                 Audit Active Directory
════════════════════════════════════════════════════════════════

📅 Date: $(date '+%Y-%m-%d %H:%M:%S')
🏢 Domaine: ${DOMAIN}
🖥️  DC: ${DC_IP}
📦 Version: ${SCRIPT_VERSION}

┌─ 📈 STATISTIQUES
│  Tests exécutés: ${TESTS_TOTAL}
│  ✅ Réussis: ${TESTS_PASSED}
│  ⚠️  Avertissements: ${TESTS_WARNING}
│  🔴 Échecs: ${TESTS_FAILED}
└─

Score de risque: ${risk_score}
Niveau: ${risk_level}

════════════════════════════════════════════════════════════════
EOF

    print_success "Résumé: ${SUMMARY_FILE}"
    cat "${SUMMARY_FILE}"
}

generate_log_summary() {
    print_section "RÉSUMÉ DES LOGS"

    cat > "${LOG_SUMMARY_FILE}" <<EOF
════════════════════════════════════════════════════════════════
            📋 RÉSUMÉ DES LOGS D'AUDIT
════════════════════════════════════════════════════════════════
Date: $(date '+%Y-%m-%d %H:%M:%S')
Fichier log: ${LOG_FILE}

STATISTIQUES DES ÉVÉNEMENTS
────────────────────────────
EOF

    local levels=("INFO" "TEST" "SUCCESS" "WARNING" "ERROR" "CMD" "PERF" "PARALLEL" "FINDING")
    for level in "${levels[@]}"; do
        local count
        count=$(grep -c "\[${level}\]" "${LOG_FILE}" 2>/dev/null || echo "0")
        printf "%-15s : %d\n" "${level}" "${count}" >> "${LOG_SUMMARY_FILE}"
    done

    echo "" >> "${LOG_SUMMARY_FILE}"
    echo "ERREURS" >> "${LOG_SUMMARY_FILE}"
    echo "───────" >> "${LOG_SUMMARY_FILE}"
    grep "\[ERROR\]" "${LOG_FILE}" >> "${LOG_SUMMARY_FILE}" 2>/dev/null || echo "Aucune" >> "${LOG_SUMMARY_FILE}"

    echo "" >> "${LOG_SUMMARY_FILE}"
    echo "PERFORMANCE" >> "${LOG_SUMMARY_FILE}"
    echo "───────────" >> "${LOG_SUMMARY_FILE}"
    grep "\[PERF\].*arrêté" "${LOG_FILE}" >> "${LOG_SUMMARY_FILE}" 2>/dev/null || echo "N/A" >> "${LOG_SUMMARY_FILE}"

    print_success "Résumé logs: ${LOG_SUMMARY_FILE}"
}

generate_report() {
    print_section "GÉNÉRATION DU RAPPORT TEXTE"
    start_timer "report"

    cat > "${REPORT_FILE}" <<EOF
================================================================================
               📋 RAPPORT D'AUDIT AD v${SCRIPT_VERSION}
================================================================================

Référence: ${AUDIT_REF}
Date: $(date '+%Y-%m-%d %H:%M:%S')
Domaine: ${DOMAIN}
DC: ${DC_IP}
Réseau: ${NETWORK}
LDAPS: ${LDAPS_MODE}
Règlement: CIMA N°010-2024 — Article 7

STATISTIQUES
────────────
Tests: ${TESTS_TOTAL}
✅ Réussis: ${TESTS_PASSED}
⚠️  Avertissements: ${TESTS_WARNING}
🔴 Échecs: ${TESTS_FAILED}

PERFORMANCE
───────────
EOF

    for key in "${!PERF_TIMERS[@]}"; do
        if [[ "$key" == *"_duration" ]]; then
            local name="${key%_duration}"
            local dur="${PERF_TIMERS[$key]}"
            printf "%-25s : %ds\n" "$name" "$dur" >> "${REPORT_FILE}"
        fi
    done

    cat >> "${REPORT_FILE}" <<EOF

FINDINGS (${#FINDINGS_SEVERITY[@]})
────────
EOF

    local i
    for ((i=0; i<${#FINDINGS_SEVERITY[@]}; i++)); do
        echo "[${FINDINGS_SEVERITY[$i]}] ${FINDINGS_TITLE[$i]}: ${FINDINGS_DESC[$i]}" >> "${REPORT_FILE}"
    done

    echo "" >> "${REPORT_FILE}"
    echo "================================================================================" >> "${REPORT_FILE}"
    echo "FIN DU RAPPORT" >> "${REPORT_FILE}"
    echo "================================================================================" >> "${REPORT_FILE}"

    print_success "Rapport texte: ${REPORT_FILE}"
    stop_timer "report"
}

#===============================================================================
# ARCHIVE & INTEGRITY
#===============================================================================

generate_checksums() {
    print_info "🔒 Génération des checksums SHA256..."
    find "${OUTPUT_DIR}" -type f ! -name "checksums.sha256" | sort | while read -r f; do
        sha256sum "${f}" >> "${OUTPUT_DIR}/checksums.sha256" 2>/dev/null || true
    done
    log "INFO" "Checksums generated: ${OUTPUT_DIR}/checksums.sha256"
    print_success "Checksums: ${OUTPUT_DIR}/checksums.sha256"
}

create_archive() {
    local archive="${OUTPUT_DIR}.tar.gz"
    print_info "📦 Création de l'archive: ${archive}"
    tar -czf "${archive}" "${OUTPUT_DIR}" 2>/dev/null || true
    chmod 600 "${archive}" 2>/dev/null || true

    if [ -f "${archive}" ]; then
        local size_mb=$(( $(stat -c%s "${archive}" 2>/dev/null || echo "0") / 1048576 ))
        print_success "Archive créée: ${archive} (${size_mb} MB)"

        if [ "${ENCRYPT_OUTPUT}" = true ] && command_exists gpg; then
            print_info "🔐 Chiffrement GPG..."
            gpg --symmetric --cipher-algo AES256 "${archive}" 2>/dev/null && \
                rm -f "${archive}" && \
                print_success "Archive chiffrée: ${archive}.gpg" || \
                print_warning "Chiffrement GPG échoué"
        fi
    fi
}

#===============================================================================
# MAIN
#===============================================================================

show_help() {
    cat <<EOF
╔═══════════════════════════════════════════════════════════════╗
║  AD AUDIT FRAMEWORK v${SCRIPT_VERSION}                               ║
╚═══════════════════════════════════════════════════════════════╝

