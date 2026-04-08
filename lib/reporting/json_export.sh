#!/bin/bash
# lib/reporting/json_export.sh

generate_json_report() {
    print_section "GÉNÉRATION DU RAPPORT JSON"

    {
        echo "{"
        echo "  \"audit_metadata\": {"
        echo "    \"version\": \"${SCRIPT_VERSION}\","
        echo "    \"domain\": \"${DOMAIN}\","
        echo "    \"dc_ip\": \"${DC_IP}\","
        echo "    \"timestamp\": \"$(date -Iseconds)\","
        echo "    \"total_tests\": ${TESTS_TOTAL},"
        echo "    \"passed\": ${TESTS_PASSED},"
        echo "    \"warnings\": ${TESTS_WARNING},"
        echo "    \"failures\": ${TESTS_FAILED}"
        echo "  },"
        echo "  \"findings\": ["

        local i
        local total=${#FINDINGS_SEVERITY[@]}
        for ((i=0; i<total; i++)); do
            local sev="${FINDINGS_SEVERITY[$i]}"
            # Escape double quotes in title and desc
            local title="${FINDINGS_TITLE[$i]//\"/\\\"}"
            local desc="${FINDINGS_DESC[$i]//\"/\\\"}"
            local evidence="${FINDINGS_EVIDENCE[$i]//\"/\\\"}"
            local comma=","
            [ $((i+1)) -eq ${total} ] && comma=""

            echo "    {"
            echo "      \"id\": \"FIND-$(printf '%03d' $((i+1)))\","
            echo "      \"severity\": \"${sev}\","
            echo "      \"title\": \"${title}\","
            echo "      \"description\": \"${desc}\","
            echo "      \"evidence_file\": \"${evidence}\""
            echo "    }${comma}"
        done

        echo "  ]"
        echo "}"
    } > "${JSON_REPORT}"

    print_success "Rapport JSON: ${JSON_REPORT}"
    log "INFO" "JSON report generated: ${JSON_REPORT}"
}

#===============================================================================
# POWERSHELL REMEDIATION SCRIPT  [NEW v2.0]
#===============================================================================

