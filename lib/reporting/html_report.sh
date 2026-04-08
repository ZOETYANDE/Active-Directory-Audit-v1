#!/bin/bash
# lib/reporting/html_report.sh — Premium HTML report with executive summary, charts, and remediation

generate_html_report() {
    print_section "GÉNÉRATION DU RAPPORT HTML"

    local risk_score=$((TESTS_FAILED * 3 + TESTS_WARNING))
    local risk_level risk_color risk_emoji
    if [ "$risk_score" -lt 5 ]; then
        risk_level="FAIBLE"; risk_color="#22c55e"; risk_emoji="🟢"
    elif [ "$risk_score" -lt 10 ]; then
        risk_level="MODÉRÉ"; risk_color="#f59e0b"; risk_emoji="🟡"
    elif [ "$risk_score" -lt 20 ]; then
        risk_level="ÉLEVÉ"; risk_color="#ef4444"; risk_emoji="🟠"
    else
        risk_level="CRITIQUE"; risk_color="#dc2626"; risk_emoji="🔴"
    fi

    local total_duration="${PERF_TIMERS[total_duration]:-0}"
    local total_min=$((total_duration / 60))
    local total_sec=$((total_duration % 60))

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

    local actionable=$((crit + high + med + low))

    # Compute percentages for donut chart (avoid division by zero)
    local total_findings=${#FINDINGS_SEVERITY[@]}
    local pct_crit=0 pct_high=0 pct_med=0 pct_low=0 pct_info=0
    if [ "${total_findings}" -gt 0 ]; then
        pct_crit=$((crit * 100 / total_findings))
        pct_high=$((high * 100 / total_findings))
        pct_med=$((med * 100 / total_findings))
        pct_low=$((low * 100 / total_findings))
        pct_info=$((100 - pct_crit - pct_high - pct_med - pct_low))
    fi

    # Conic gradient stops for CSS donut chart
    local stop1=${pct_crit}
    local stop2=$((stop1 + pct_high))
    local stop3=$((stop2 + pct_med))
    local stop4=$((stop3 + pct_low))

    # Pass rate for gauge
    local pass_rate=0
    if [ "${TESTS_TOTAL}" -gt 0 ]; then
        pass_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    fi

    cat > "${HTML_REPORT}" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport d'Audit Active Directory</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
:root{--bg:#0a0e1a;--surface:#111827;--card:#1a2332;--card-hover:#1e293b;--border:#2a3444;--border-light:#374151;--text:#e2e8f0;--text-muted:#8b9cb8;--text-dim:#64748b;--accent:#6366f1;--accent-glow:rgba(99,102,241,.15);--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#3b82f6;--info:#64748b;--pass:#22c55e;--gradient-1:linear-gradient(135deg,#6366f1,#8b5cf6);--gradient-2:linear-gradient(135deg,#0ea5e9,#6366f1);--shadow:0 4px 24px rgba(0,0,0,.4);--shadow-lg:0 8px 40px rgba(0,0,0,.5)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}
.page{max-width:1200px;margin:0 auto;padding:2rem 2rem 4rem}

/* Navigation */
.toc{position:fixed;right:1.5rem;top:50%;transform:translateY(-50%);z-index:100;display:flex;flex-direction:column;gap:.5rem}
.toc a{display:block;width:10px;height:10px;border-radius:50%;background:var(--border);transition:all .3s;text-decoration:none}
.toc a:hover{background:var(--accent);transform:scale(1.4);box-shadow:0 0 12px var(--accent)}
@media(max-width:900px){.toc{display:none}}

/* Header */
.hero{text-align:center;padding:3rem 2rem;background:linear-gradient(135deg,#111827 0%,#1a1a3e 50%,#111827 100%);border:1px solid var(--border);border-radius:16px;margin-bottom:2.5rem;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:60%;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.hero h1{font-size:2rem;font-weight:800;letter-spacing:-.02em;background:var(--gradient-1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero .sub{color:var(--text-muted);font-size:.95rem;margin-top:.5rem}
.risk-pill{display:inline-flex;align-items:center;gap:.5rem;font-size:1.3rem;font-weight:700;padding:.6rem 2rem;border-radius:50px;margin-top:1.2rem;letter-spacing:.02em}

/* Executive Summary */
.exec{display:grid;grid-template-columns:1fr 1fr;gap:2rem;margin-bottom:2.5rem}
@media(max-width:768px){.exec{grid-template-columns:1fr}}
.exec-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.8rem;box-shadow:var(--shadow)}
.exec-card h3{font-size:.85rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-bottom:1.2rem}

/* Donut chart (pure CSS) */
.donut-wrap{display:flex;align-items:center;gap:2rem}
.donut{width:140px;height:140px;border-radius:50%;position:relative;flex-shrink:0}
.donut-hole{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:80px;height:80px;border-radius:50%;background:var(--card);display:flex;align-items:center;justify-content:center;flex-direction:column}
.donut-hole .big{font-size:1.6rem;font-weight:800;line-height:1}
.donut-hole .small{font-size:.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.03em}
.legend{display:flex;flex-direction:column;gap:.55rem}
.legend-item{display:flex;align-items:center;gap:.5rem;font-size:.85rem}
.legend-dot{width:10px;height:10px;border-radius:3px;flex-shrink:0}

/* Meta cards */
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin-bottom:2.5rem}
.meta-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.3rem;transition:border-color .2s}
.meta-card:hover{border-color:var(--accent)}
.meta-card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);margin-bottom:.25rem}
.meta-card .val{font-size:1rem;font-weight:600}

/* Stats bar */
.stats-bar{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2.5rem}
@media(max-width:600px){.stats-bar{grid-template-columns:repeat(2,1fr)}}
.stat-box{text-align:center;padding:1.2rem .8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;transition:transform .2s}
.stat-box:hover{transform:translateY(-2px)}
.stat-box .num{font-size:1.8rem;font-weight:800;line-height:1.1}
.stat-box .label{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-top:.3rem}

/* Section headers */
.section{margin:2.5rem 0 1rem;display:flex;align-items:center;gap:.75rem}
.section h2{font-size:1.2rem;font-weight:700}
.section::after{content:'';flex:1;height:1px;background:var(--border)}
.section-id{display:inline-block;background:var(--accent-glow);border:1px solid rgba(99,102,241,.3);color:var(--accent);font-size:.65rem;padding:.15rem .5rem;border-radius:4px;font-weight:600;letter-spacing:.04em}

/* Findings table */
.findings-table{width:100%;border-collapse:separate;border-spacing:0;margin:1rem 0;background:var(--card);border-radius:12px;overflow:hidden;border:1px solid var(--border)}
.findings-table th{background:var(--surface);padding:.85rem 1rem;text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);border-bottom:1px solid var(--border)}
.findings-table td{padding:.75rem 1rem;border-bottom:1px solid var(--border);font-size:.88rem;vertical-align:top}
.findings-table tr:last-child td{border-bottom:none}
.findings-table tr:hover td{background:rgba(99,102,241,.04)}
.sev{display:inline-block;padding:.2rem .55rem;border-radius:5px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.sev-critical{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.sev-high{background:rgba(249,115,22,.15);color:#fb923c;border:1px solid rgba(249,115,22,.3)}
.sev-medium{background:rgba(234,179,8,.12);color:#facc15;border:1px solid rgba(234,179,8,.25)}
.sev-low{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.25)}
.sev-info{background:rgba(100,116,139,.12);color:#94a3b8;border:1px solid rgba(100,116,139,.25)}
.finding-title{font-weight:600;color:var(--text)}
.finding-desc{color:var(--text-muted);font-size:.82rem;margin-top:.2rem}
.finding-idx{color:var(--text-dim);font-family:monospace;font-size:.75rem}

/* Performance grid */
.perf-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.8rem;margin:1rem 0}
.perf-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.8rem 1rem;display:flex;justify-content:space-between;align-items:center;font-size:.88rem}
.perf-card .name{color:var(--text-muted);text-transform:capitalize}
.perf-card .dur{font-weight:600;font-variant-numeric:tabular-nums}

/* Footer */
.foot{text-align:center;margin-top:3rem;padding:2rem 1rem;border-top:1px solid var(--border);color:var(--text-dim);font-size:.8rem;line-height:1.8}
.foot .brand{font-weight:700;background:var(--gradient-1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}

/* Print styles */
@media print{
  body{background:#fff;color:#111;font-size:10pt}
  .page{padding:0}
  .hero{background:#f1f5f9!important;border-color:#ccc;page-break-after:avoid}
  .hero h1{-webkit-text-fill-color:#111;color:#111}
  .toc{display:none}
  .findings-table,.exec-card,.stat-box,.meta-card,.perf-card{background:#fff;border-color:#ddd;box-shadow:none}
  .findings-table th{background:#f1f5f9}
  .section::after{background:#ccc}
  .foot{border-color:#ccc}
  tr{page-break-inside:avoid}
}
</style>
</head>
<body>
<div class="page">

<!-- Dot navigation -->
<nav class="toc">
<a href="#top" title="Haut"></a>
<a href="#summary" title="Résumé"></a>
<a href="#findings" title="Findings"></a>
<a href="#perf" title="Performance"></a>
</nav>
HTMLHEAD

    # ── HERO SECTION ──
    cat >> "${HTML_REPORT}" <<EOF
<div class="hero" id="top">
<h1>🛡️ Rapport d'Audit Sécurité Active Directory</h1>
<p class="sub">${AUDIT_REF} — Domaine <strong>${DOMAIN}</strong></p>
<div class="risk-pill" style="background:${risk_color}20;color:${risk_color};border:1px solid ${risk_color}50">${risk_emoji} Risque ${risk_level} — Score ${risk_score}</div>
</div>

<!-- Meta cards -->
<div class="meta-grid">
<div class="meta-card"><div class="lbl">Domaine</div><div class="val">${DOMAIN}</div></div>
<div class="meta-card"><div class="lbl">Contrôleur DC</div><div class="val">${DC_IP}</div></div>
<div class="meta-card"><div class="lbl">Date d'Audit</div><div class="val">$(date '+%d/%m/%Y %H:%M')</div></div>
<div class="meta-card"><div class="lbl">Durée Totale</div><div class="val">${total_min}m ${total_sec}s</div></div>
<div class="meta-card"><div class="lbl">Framework</div><div class="val">v${SCRIPT_VERSION}</div></div>
<div class="meta-card"><div class="lbl">Réseau</div><div class="val">${NETWORK}</div></div>
</div>

<!-- Executive Summary -->
<div class="section" id="summary"><span class="section-id">01</span><h2>Résumé Exécutif</h2></div>
<div class="exec">
<div class="exec-card">
<h3>Répartition des Findings</h3>
<div class="donut-wrap">
<div class="donut" style="background:conic-gradient(var(--crit) 0% ${stop1}%,var(--high) ${stop1}% ${stop2}%,var(--med) ${stop2}% ${stop3}%,var(--low) ${stop3}% ${stop4}%,var(--info) ${stop4}% 100%)">
<div class="donut-hole"><span class="big">${total_findings}</span><span class="small">findings</span></div>
</div>
<div class="legend">
<div class="legend-item"><span class="legend-dot" style="background:var(--crit)"></span>Critique: ${crit}</div>
<div class="legend-item"><span class="legend-dot" style="background:var(--high)"></span>Élevé: ${high}</div>
<div class="legend-item"><span class="legend-dot" style="background:var(--med)"></span>Moyen: ${med}</div>
<div class="legend-item"><span class="legend-dot" style="background:var(--low)"></span>Faible: ${low}</div>
<div class="legend-item"><span class="legend-dot" style="background:var(--info)"></span>Info: ${info}</div>
</div>
</div>
</div>
<div class="exec-card">
<h3>Posture de Sécurité</h3>
<div style="margin-top:.5rem">
<div style="display:flex;justify-content:space-between;font-size:.82rem;color:var(--text-muted);margin-bottom:.4rem"><span>Taux de conformité</span><span style="font-weight:700;color:var(--text)">${pass_rate}%</span></div>
<div style="background:var(--border);border-radius:6px;height:10px;overflow:hidden"><div style="background:var(--pass);height:100%;width:${pass_rate}%;border-radius:6px;transition:width 1s"></div></div>
</div>
<div style="margin-top:1.2rem;display:grid;grid-template-columns:1fr 1fr;gap:.8rem">
<div><div style="font-size:1.5rem;font-weight:800;color:var(--pass)">${TESTS_PASSED}</div><div style="font-size:.72rem;color:var(--text-dim);text-transform:uppercase">Réussis</div></div>
<div><div style="font-size:1.5rem;font-weight:800;color:var(--crit)">${actionable}</div><div style="font-size:.72rem;color:var(--text-dim);text-transform:uppercase">À Corriger</div></div>
<div><div style="font-size:1.5rem;font-weight:800;color:var(--med)">${TESTS_WARNING}</div><div style="font-size:.72rem;color:var(--text-dim);text-transform:uppercase">Warnings</div></div>
<div><div style="font-size:1.5rem;font-weight:800;color:var(--text)">${TESTS_TOTAL}</div><div style="font-size:.72rem;color:var(--text-dim);text-transform:uppercase">Total Tests</div></div>
</div>
</div>
</div>

<!-- Stats -->
<div class="stats-bar">
<div class="stat-box"><div class="num" style="color:var(--crit)">${crit}</div><div class="label">Critique</div></div>
<div class="stat-box"><div class="num" style="color:var(--high)">${high}</div><div class="label">Élevé</div></div>
<div class="stat-box"><div class="num" style="color:var(--med)">${med}</div><div class="label">Moyen</div></div>
<div class="stat-box"><div class="num" style="color:var(--low)">${low}</div><div class="label">Faible</div></div>
<div class="stat-box"><div class="num" style="color:var(--info)">${info}</div><div class="label">Info</div></div>
</div>

<!-- Findings table -->
<div class="section" id="findings"><span class="section-id">02</span><h2>Findings Détaillés (${total_findings})</h2></div>
<table class="findings-table">
<thead><tr><th style="width:40px">#</th><th style="width:90px">Sévérité</th><th>Finding</th><th>Description</th></tr></thead>
<tbody>
EOF

    # ── FINDINGS ROWS ──
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

        local title="${FINDINGS_TITLE[$i]//</<}"
        local desc="${FINDINGS_DESC[$i]//</<}"
        local idx=$(printf '%02d' $((i+1)))

        cat >> "${HTML_REPORT}" <<EOF
<tr><td class="finding-idx">${idx}</td><td><span class="sev ${sev_class}">${sev}</span></td><td class="finding-title">${title}</td><td class="finding-desc">${desc}</td></tr>
EOF
    done

    # ── PERFORMANCE SECTION ──
    cat >> "${HTML_REPORT}" <<EOF
</tbody></table>

<div class="section" id="perf"><span class="section-id">03</span><h2>Performance par Module</h2></div>
<div class="perf-grid">
EOF

    for key in "${!PERF_TIMERS[@]}"; do
        if [[ "$key" == *"_duration" ]]; then
            local name="${key%_duration}"
            local dur="${PERF_TIMERS[$key]}"
            local m=$((dur / 60))
            local s=$((dur % 60))
            echo "<div class=\"perf-card\"><span class=\"name\">${name}</span><span class=\"dur\">${m}m ${s}s</span></div>" >> "${HTML_REPORT}"
        fi
    done

    # ── FOOTER ──
    cat >> "${HTML_REPORT}" <<EOF
</div>

<div class="foot">
<p>Généré par <span class="brand">AD Audit Framework v${SCRIPT_VERSION}</span> — $(date '+%Y-%m-%d %H:%M:%S')</p>
<p>${AUDIT_REF} | Domaine: ${DOMAIN} | DC: ${DC_IP}</p>
<p style="margin-top:.5rem;font-size:.72rem">Ce rapport est confidentiel. Distribution restreinte aux parties autorisées.</p>
</div>
</div>
</body>
</html>
EOF

    print_success "Rapport HTML: ${HTML_REPORT}"
    log "INFO" "HTML report generated: ${HTML_REPORT}"
}
