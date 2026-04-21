#!/bin/bash
# lib/reporting/remediation.sh

generate_remediation_script() {
    print_section "GÉNÉRATION DU SCRIPT DE REMÉDIATION"

    {
        echo "# ============================================================================"
        echo "# SCRIPT DE REMÉDIATION ACTIVE DIRECTORY"
        echo "# Généré automatiquement par AD Audit Framework v${SCRIPT_VERSION}"
        echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Domaine: ${DOMAIN} | DC: ${DC_IP}"
        echo "# ============================================================================"
        echo "#"
        echo "# IMPORTANT: Revoyez chaque commande avant exécution!"
        echo "# Testez d'abord dans un environnement de test."
        echo "# ============================================================================"
        echo ""
        echo "# Requires: ActiveDirectory PowerShell module"
        echo "# Import-Module ActiveDirectory"
        echo ""

        if [ ${#REMEDIATION_CMDS[@]} -gt 0 ]; then
            local i
            for ((i=0; i<${#REMEDIATION_CMDS[@]}; i++)); do
                echo "# ---------------------------------------------------------------"
                echo "# ${REMEDIATION_LABELS[$i]}"
                echo "# ---------------------------------------------------------------"
                # Output each line of the remediation command
                echo "${REMEDIATION_CMDS[$i]}" | while IFS= read -r line; do
                    echo "${line}"
                done
                echo ""
            done
        else
            echo "# Aucune remédiation automatique générée."
            echo "# Consultez le rapport HTML pour les recommandations manuelles."
        fi

        echo "# ============================================================================"
        echo "# FIN DU SCRIPT DE REMÉDIATION"
        echo "# ============================================================================"
    } > "${REMEDIATION_FILE}"

    print_success "Script remédiation: ${REMEDIATION_FILE}"
    log "INFO" "Remediation script generated: ${REMEDIATION_FILE}"
}

#===============================================================================
# TEXT SUMMARY & REPORT GENERATION
#===============================================================================
