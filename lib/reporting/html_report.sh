#!/bin/bash
# lib/reporting/html_report.sh

generate_html_report() {
    print_section "GÉNÉRATION DU RAPPORT HTML"

    local risk_score=$((TESTS_FAILED * 3 + TESTS_WARNING))
    local risk_level risk_color
    if [ "$risk_score" -lt 5 ]; then
        risk_level="FAIBLE"; risk_color="#22c55e"
    elif [ "$risk_score" -lt 10 ]; then
        risk_level="MODÉRÉ"; risk_color="#f59e0b"
    elif [ "$risk_score" -lt 20 ]; then
        risk_level="ÉLEVÉ"; risk_color="#ef4444"
    else
        risk_level="CRITIQUE"; risk_color="#dc2626"
    fi

    local total_duration="${PERF_TIMERS[total_duration]:-0}"

    # Count findings by severity
    local crit=0 high=0 med=0 low=0 info=0
    local j
    for ((j=0; j<${#FINDINGS_SEVERITY[@]}; j++)); do
        case "${FINDINGS_SEVERITY[$j]}" in
            CRITICAL) ((crit++)) || true ;;
            HIGH) ((high++)) || true ;;
            MEDIUM) ((med++)) || true ;;
            LOW) ((low++)) || true ;;
            INFO) ((info++)) || true ;;
        esac
    done

    cat > "${HTML_REPORT}" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport d'Audit Active Directory</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
.container{max-width:1100px;margin:0 auto}
h1{font-size:1.8rem;margin-bottom:.5rem}
h2{font-size:1.3rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.header{text-align:center;padding:2rem;background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--border);border-radius:12px;margin-bottom:2rem}
.header .subtitle{color:var(--muted);font-size:.95rem}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1.5rem 0}
.meta-item{background:var(--card);padding:1rem;border-radius:8px;border:1px solid var(--border)}
.meta-item .label{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.meta-item .value{font-size:1.1rem;font-weight:600;margin-top:.25rem}
.risk-badge{display:inline-block;font-size:1.5rem;font-weight:700;padding:.5rem 1.5rem;border-radius:8px;margin-top:.5rem}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}
.stat{text-align:center;padding:1.2rem;background:var(--card);border-radius:8px;border:1px solid var(--border)}
.stat .num{font-size:2rem;font-weight:700}
.stat .lbl{font-size:.8rem;color:var(--muted)}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.75rem 1rem;text-align:left;border-bottom:1px solid var(--border)}
th{background:var(--card);font-size:.85rem;text-transform:uppercase;color:var(--muted);letter-spacing:.03em}
tr:hover{background:rgba(59,130,246,.05)}
.sev{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:600;text-transform:uppercase}
.sev-critical{background:#dc2626;color:#fff}
.sev-high{background:#ef4444;color:#fff}
.sev-medium{background:#f59e0b;color:#000}
.sev-low{background:#3b82f6;color:#fff}
.sev-info{background:#64748b;color:#fff}
.perf{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.75rem}
.perf-item{background:var(--card);padding:.75rem;border-radius:6px;border:1px solid var(--border);font-size:.9rem}
.footer{text-align:center;margin-top:3rem;padding:1.5rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--border)}
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    # Header section
    cat >> "${HTML_REPORT}" <<EOF
<div class="header">
<h1>🛡️ Rapport d'Audit Active Directory</h1>
<p class="subtitle">${AUDIT_REF} — ${DOMAIN}</p>
<div class="risk-badge" style="background:${risk_color};color:#fff">Risque: ${risk_level} (score: ${risk_score})</div>
</div>

<div class="meta">
<div class="meta-item"><div class="label">Domaine</div><div class="value">${DOMAIN}</div></div>
<div class="meta-item"><div class="label">Contrôleur DC</div><div class="value">${DC_IP}</div></div>
<div class="meta-item"><div class="label">Date</div><div class="value">$(date '+%Y-%m-%d %H:%M')</div></div>
<div class="meta-item"><div class="label">Version</div><div class="value">${SCRIPT_VERSION}</div></div>
</div>

<h2>📈 Statistiques</h2>
<div class="stats">
<div class="stat"><div class="num">${TESTS_TOTAL}</div><div class="lbl">Tests</div></div>
<div class="stat"><div class="num" style="color:#22c55e">${TESTS_PASSED}</div><div class="lbl">Réussis</div></div>
<div class="stat"><div class="num" style="color:#f59e0b">${TESTS_WARNING}</div><div class="lbl">Avertissements</div></div>
<div class="stat"><div class="num" style="color:#ef4444">${TESTS_FAILED}</div><div class="lbl">Échecs</div></div>
</div>

<h2>📊 Résumé des Findings (${crit} Critique, ${high} Élevé, ${med} Moyen)</h2>
<table>
<thead><tr><th>Sévérité</th><th>Finding</th><th>Description</th></tr></thead>
<tbody>
EOF

    # Add findings rows
    local i
    for ((i=0; i<${#FINDINGS_SEVERITY[@]}; i++)); do
        local sev="${FINDINGS_SEVERITY[$i]}"
        local sev_class
        case "${sev}" in
            CRITICAL) sev_class="sev-critical" ;;
            HIGH)     sev_class="sev-high" ;;
            MEDIUM)   sev_class="sev-medium" ;;
            LOW)      sev_class="sev-low" ;;
            *)        sev_class="sev-info" ;;
        esac

        # Escape HTML
        local title="${FINDINGS_TITLE[$i]//</&lt;}"
        local desc="${FINDINGS_DESC[$i]//</&lt;}"

        cat >> "${HTML_REPORT}" <<EOF
<tr><td><span class="sev ${sev_class}">${sev}</span></td><td><strong>${title}</strong></td><td>${desc}</td></tr>
EOF
    done

    cat >> "${HTML_REPORT}" <<EOF
</tbody></table>

<h2>⏱️ Performance</h2>
<div class="perf">
EOF

    # Performance metrics
    for key in "${!PERF_TIMERS[@]}"; do
        if [[ "$key" == *"_duration" ]]; then
            local name="${key%_duration}"
            local dur="${PERF_TIMERS[$key]}"
            local m=$((dur / 60))
            local s=$((dur % 60))
            echo "<div class=\"perf-item\"><strong>${name}</strong>: ${m}m ${s}s</div>" >> "${HTML_REPORT}"
        fi
    done

    cat >> "${HTML_REPORT}" <<EOF
</div>

<div class="footer">
<p>Généré par AD Audit Framework v${SCRIPT_VERSION} — $(date '+%Y-%m-%d %H:%M:%S')</p>
<p>Réf: ${AUDIT_REF} | Règlement CIMA N°010-2024 — Article 7</p>
</div>
</div>
</body>
</html>
EOF

    print_success "Rapport HTML: ${HTML_REPORT}"
    log "INFO" "HTML report generated: ${HTML_REPORT}"
}
#===============================================================================
# JSON FINDINGS EXPORT  [NEW v2.0]
#===============================================================================

