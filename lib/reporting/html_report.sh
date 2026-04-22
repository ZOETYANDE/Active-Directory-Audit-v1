#!/bin/bash
# lib/reporting/html_report.sh — Rapport HTML avec dashboard, filtres, remédiation inline, ISO/CIS

generate_html_report() {
    print_section "GÉNÉRATION DU RAPPORT HTML"

    local risk_score=$((TESTS_FAILED * 3 + TESTS_WARNING))
    local risk_level risk_color risk_emoji
    if   [ "$risk_score" -lt 5  ]; then risk_level="FAIBLE";   risk_color="#22c55e"; risk_emoji="🟢"
    elif [ "$risk_score" -lt 10 ]; then risk_level="MODÉRÉ";   risk_color="#f59e0b"; risk_emoji="🟡"
    elif [ "$risk_score" -lt 20 ]; then risk_level="ÉLEVÉ";    risk_color="#ef4444"; risk_emoji="🟠"
    else                                risk_level="CRITIQUE";  risk_color="#dc2626"; risk_emoji="🔴"; fi

    local total_duration="${PERF_TIMERS[total_duration]:-0}"
    local total_min=$((total_duration / 60))
    local total_sec=$((total_duration % 60))

    local crit=0 high=0 med=0 low=0 info=0
    local j
    for ((j=0; j<${#FINDINGS_SEVERITY[@]}; j++)); do
        case "${FINDINGS_SEVERITY[$j]}" in
            CRITICAL) ((crit++)) || true ;;
            HIGH)     ((high++)) || true ;;
            MEDIUM)   ((med++)) || true ;;
            LOW)      ((low++)) || true ;;
            INFO)     ((info++)) || true ;;
        esac
    done

    local actionable=$((crit + high + med + low))
    local total_findings=${#FINDINGS_SEVERITY[@]}
    local pass_rate=0
    [ "${TESTS_TOTAL}" -gt 0 ] && pass_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))

    local pct_crit=0 pct_high=0 pct_med=0 pct_low=0
    if [ "${total_findings}" -gt 0 ]; then
        pct_crit=$((crit * 100 / total_findings))
        pct_high=$((high * 100 / total_findings))
        pct_med=$((med  * 100 / total_findings))
        pct_low=$((low  * 100 / total_findings))
    fi
    local stop1=${pct_crit}
    local stop2=$((stop1 + pct_high))
    local stop3=$((stop2 + pct_med))
    local stop4=$((stop3 + pct_low))

    # Trier les findings par sévérité (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    # On construit des indices ordonnés
    local -a sorted_idx=()
    for sev_order in CRITICAL HIGH MEDIUM LOW INFO; do
        for ((j=0; j<${#FINDINGS_SEVERITY[@]}; j++)); do
            [ "${FINDINGS_SEVERITY[$j]}" = "${sev_order}" ] && sorted_idx+=("$j")
        done
    done

    # Construire le HTML des lignes de findings (triées)
    local findings_rows=""
    local row_num=0
    for idx in "${sorted_idx[@]}"; do
        ((row_num++)) || true
        local sev="${FINDINGS_SEVERITY[$idx]}"
        local sev_class sev_order_num
        case "${sev}" in
            CRITICAL) sev_class="sev-critical"; sev_order_num=1 ;;
            HIGH)     sev_class="sev-high";     sev_order_num=2 ;;
            MEDIUM)   sev_class="sev-medium";   sev_order_num=3 ;;
            LOW)      sev_class="sev-low";      sev_order_num=4 ;;
            *)        sev_class="sev-info";     sev_order_num=5 ;;
        esac
        local title="${FINDINGS_TITLE[$idx]//</&lt;}"
        local desc="${FINDINGS_DESC[$idx]//</&lt;}"
        local row_idx=$(printf '%02d' "$row_num")

        # Chercher une remédiation associée à ce titre
        local remed_html=""
        local r
        for ((r=0; r<${#REMEDIATION_LABELS[@]}; r++)); do
            if [[ "${REMEDIATION_LABELS[$r]}" == *"${FINDINGS_TITLE[$idx]}"* ]]; then
                local remed_code="${REMEDIATION_CMDS[$r]//</&lt;}"
                remed_html="<details class=\"remed\"><summary>🔧 Remédiation PowerShell</summary><pre class=\"remed-code\">${remed_code}</pre></details>"
                break
            fi
        done

        findings_rows+="<tr data-sev=\"${sev_order_num}\" class=\"finding-row\">"
        findings_rows+="<td class=\"finding-idx\">${row_idx}</td>"
        findings_rows+="<td><span class=\"sev ${sev_class}\">${sev}</span></td>"
        findings_rows+="<td><div class=\"finding-title\">${title}</div>${remed_html}</td>"
        findings_rows+="<td class=\"finding-desc\">${desc}</td>"
        findings_rows+="</tr>"$'\n'
    done

    # Construire les barres de performance
    local perf_bars=""
    local max_dur=1
    for key in "${!PERF_TIMERS[@]}"; do
        [[ "$key" == *"_duration" ]] || continue
        local d="${PERF_TIMERS[$key]}"
        [ "${d}" -gt "${max_dur}" ] && max_dur="${d}"
    done
    for key in "${!PERF_TIMERS[@]}"; do
        [[ "$key" == *"_duration" ]] || continue
        local name="${key%_duration}"
        local dur="${PERF_TIMERS[$key]}"
        local m=$((dur / 60)); local s=$((dur % 60))
        local pct_bar=$(( dur * 100 / max_dur ))
        perf_bars+="<div class=\"perf-row\"><div class=\"perf-name\">${name}</div>"
        perf_bars+="<div class=\"perf-bar-wrap\"><div class=\"perf-bar\" style=\"width:${pct_bar}%\"></div></div>"
        perf_bars+="<div class=\"perf-dur\">${m}m ${s}s</div></div>"$'\n'
    done

    cat > "${HTML_REPORT}" <<HTMLEOF
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Rapport Audit AD — ${DOMAIN}</title>
<meta name="description" content="Rapport d'audit sécurité Active Directory — ${DOMAIN} — ${AUDIT_REF}">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
:root{--bg:#0a0e1a;--surface:#111827;--card:#1a2332;--border:#2a3444;--text:#e2e8f0;--muted:#8b9cb8;--dim:#64748b;--accent:#6366f1;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#3b82f6;--info:#64748b;--pass:#22c55e;--g1:linear-gradient(135deg,#6366f1,#8b5cf6);--shadow:0 4px 24px rgba(0,0,0,.4)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65}
.page{max-width:1200px;margin:0 auto;padding:2rem 2rem 5rem}
/* Hero */
.hero{text-align:center;padding:3rem 2rem;background:linear-gradient(135deg,#111827,#1a1a3e 50%,#111827);border:1px solid var(--border);border-radius:16px;margin-bottom:2rem;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:60%;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.hero h1{font-size:1.9rem;font-weight:800;background:var(--g1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero .sub{color:var(--muted);font-size:.95rem;margin-top:.5rem}
.risk-pill{display:inline-flex;align-items:center;gap:.5rem;font-size:1.2rem;font-weight:700;padding:.6rem 2rem;border-radius:50px;margin-top:1.2rem}
/* Meta */
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.meta-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem;transition:border-color .2s}
.meta-card:hover{border-color:var(--accent)}
.meta-card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.2rem}
.meta-card .val{font-size:.95rem;font-weight:600}
/* Exec */
.exec{display:grid;grid-template-columns:1fr 1fr;gap:2rem;margin-bottom:2rem}
@media(max-width:768px){.exec{grid-template-columns:1fr}}
.exec-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.8rem}
.exec-card h3{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:1.2rem}
.donut-wrap{display:flex;align-items:center;gap:2rem}
.donut{width:130px;height:130px;border-radius:50%;flex-shrink:0;position:relative}
.donut-hole{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:78px;height:78px;border-radius:50%;background:var(--card);display:flex;flex-direction:column;align-items:center;justify-content:center}
.donut-hole .big{font-size:1.5rem;font-weight:800;line-height:1}
.donut-hole .small{font-size:.6rem;color:var(--muted);text-transform:uppercase}
.legend{display:flex;flex-direction:column;gap:.5rem}
.legend-item{display:flex;align-items:center;gap:.5rem;font-size:.82rem}
.legend-dot{width:9px;height:9px;border-radius:3px;flex-shrink:0}
/* Stats */
.stats-bar{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}
@media(max-width:600px){.stats-bar{grid-template-columns:repeat(2,1fr)}}
.stat-box{text-align:center;padding:1.2rem .8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;transition:transform .2s}
.stat-box:hover{transform:translateY(-2px)}
.stat-box .num{font-size:1.8rem;font-weight:800;line-height:1.1}
.stat-box .lbl{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:.3rem}
/* Section */
.section{margin:2.5rem 0 1rem;display:flex;align-items:center;gap:.75rem}
.section h2{font-size:1.1rem;font-weight:700}
.section::after{content:'';flex:1;height:1px;background:var(--border)}
.section-id{background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.3);color:var(--accent);font-size:.65rem;padding:.15rem .5rem;border-radius:4px;font-weight:600}
/* Filter toolbar */
.filter-bar{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin-bottom:1rem}
.filter-bar label{font-size:.75rem;color:var(--muted)}
.filter-btn{padding:.3rem .85rem;border-radius:20px;border:1px solid var(--border);background:var(--card);color:var(--muted);font-size:.75rem;font-weight:600;cursor:pointer;transition:all .2s;font-family:inherit}
.filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(99,102,241,.1)}
.filter-btn.active{font-weight:700}
/* Findings table */
.findings-table{width:100%;border-collapse:separate;border-spacing:0;margin:0;background:var(--card);border-radius:12px;overflow:hidden;border:1px solid var(--border)}
.findings-table th{background:var(--surface);padding:.8rem 1rem;text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--border)}
.findings-table td{padding:.75rem 1rem;border-bottom:1px solid var(--border);font-size:.87rem;vertical-align:top}
.findings-table tr:last-child td{border-bottom:none}
.findings-table tr:hover td{background:rgba(99,102,241,.04)}
.finding-row.hidden{display:none}
.sev{display:inline-block;padding:.2rem .55rem;border-radius:5px;font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.sev-critical{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.sev-high{background:rgba(249,115,22,.15);color:#fb923c;border:1px solid rgba(249,115,22,.3)}
.sev-medium{background:rgba(234,179,8,.12);color:#facc15;border:1px solid rgba(234,179,8,.25)}
.sev-low{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.25)}
.sev-info{background:rgba(100,116,139,.12);color:#94a3b8;border:1px solid rgba(100,116,139,.25)}
.finding-title{font-weight:600}
.finding-desc{color:var(--muted);font-size:.82rem}
.finding-idx{color:var(--dim);font-family:monospace;font-size:.75rem;width:40px}
/* Remédiation inline */
.remed{margin-top:.5rem}
.remed summary{font-size:.75rem;color:var(--accent);cursor:pointer;font-weight:600;padding:.2rem 0;user-select:none}
.remed summary:hover{text-decoration:underline}
.remed-code{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.75rem 1rem;font-size:.75rem;font-family:'Courier New',monospace;color:#7ee787;overflow-x:auto;white-space:pre;margin-top:.4rem;line-height:1.5}
/* Performance bars */
.perf-row{display:grid;grid-template-columns:140px 1fr 60px;align-items:center;gap:.75rem;padding:.45rem 0;border-bottom:1px solid var(--border)}
.perf-row:last-child{border-bottom:none}
.perf-name{font-size:.83rem;color:var(--muted);text-transform:capitalize}
.perf-bar-wrap{background:var(--border);border-radius:4px;height:8px;overflow:hidden}
.perf-bar{background:var(--g1);height:100%;border-radius:4px;transition:width .8s}
.perf-dur{font-size:.8rem;font-weight:600;text-align:right;font-variant-numeric:tabular-nums}
.perf-wrap{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem 1.5rem}
/* Progress gauge */
.gauge-wrap{margin-top:.5rem}
.gauge-label{display:flex;justify-content:space-between;font-size:.8rem;color:var(--muted);margin-bottom:.35rem}
.gauge-track{background:var(--border);border-radius:6px;height:10px;overflow:hidden}
.gauge-fill{background:var(--pass);height:100%;border-radius:6px}
/* Footer */
.foot{text-align:center;margin-top:3rem;padding:2rem 1rem;border-top:1px solid var(--border);color:var(--dim);font-size:.78rem;line-height:2}
.brand{font-weight:700;background:var(--g1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.ref-badge{display:inline-block;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);color:var(--accent);font-size:.65rem;padding:.1rem .45rem;border-radius:4px;margin:0 .2rem;font-weight:600}
@media print{body{background:#fff;color:#111}.hero{background:#f1f5f9!important}.toc,.filter-bar{display:none}.findings-table,.exec-card,.stat-box{background:#fff;border-color:#ddd}tr{page-break-inside:avoid}}
</style>
</head>
<body>
<div class="page">

<!-- HERO -->
<div class="hero" id="top">
  <h1>🛡️ Rapport d'Audit Sécurité Active Directory</h1>
  <p class="sub">${AUDIT_REF} — Domaine <strong>${DOMAIN}</strong></p>
  <div class="risk-pill" style="background:${risk_color}20;color:${risk_color};border:1px solid ${risk_color}50">${risk_emoji} Risque ${risk_level} — Score ${risk_score}</div>
  <div style="margin-top:1rem;font-size:.82rem;color:var(--muted)">
    <span class="ref-badge">ISO 27001:2022</span>
    <span class="ref-badge">CIS AD Benchmark</span>
    <span class="ref-badge">MITRE ATT&amp;CK</span>
  </div>
</div>

<!-- META CARDS -->
<div class="meta-grid">
  <div class="meta-card"><div class="lbl">Domaine</div><div class="val">${DOMAIN}</div></div>
  <div class="meta-card"><div class="lbl">Contrôleur DC</div><div class="val">${DC_IP}</div></div>
  <div class="meta-card"><div class="lbl">Date d'Audit</div><div class="val">$(date '+%d/%m/%Y %H:%M')</div></div>
  <div class="meta-card"><div class="lbl">Durée Totale</div><div class="val">${total_min}m ${total_sec}s</div></div>
  <div class="meta-card"><div class="lbl">Framework</div><div class="val">v${SCRIPT_VERSION}</div></div>
  <div class="meta-card"><div class="lbl">Réseau Audité</div><div class="val">${NETWORK}</div></div>
  <div class="meta-card"><div class="lbl">Mode LDAPS</div><div class="val">${LDAPS_MODE}</div></div>
  <div class="meta-card"><div class="lbl">Mode Safe</div><div class="val">${SAFE_MODE}</div></div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section" id="summary"><span class="section-id">01</span><h2>Résumé Exécutif</h2></div>
<div class="exec">
  <div class="exec-card">
    <h3>Répartition des Findings</h3>
    <div class="donut-wrap">
      <div class="donut" style="background:conic-gradient(var(--crit) 0% ${stop1}%,var(--high) ${stop1}% ${stop2}%,var(--med) ${stop2}% ${stop3}%,var(--low) ${stop3}% ${stop4}%,var(--info) ${stop4}% 100%)">
        <div class="donut-hole"><span class="big">${total_findings}</span><span class="small">findings</span></div>
      </div>
      <div class="legend">
        <div class="legend-item"><span class="legend-dot" style="background:var(--crit)"></span>Critique: <strong>${crit}</strong></div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--high)"></span>Élevé: <strong>${high}</strong></div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--med)"></span>Moyen: <strong>${med}</strong></div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--low)"></span>Faible: <strong>${low}</strong></div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--info)"></span>Info: <strong>${info}</strong></div>
      </div>
    </div>
  </div>
  <div class="exec-card">
    <h3>Posture de Sécurité</h3>
    <div class="gauge-wrap">
      <div class="gauge-label"><span>Taux de conformité</span><span style="font-weight:700;color:var(--text)">${pass_rate}%</span></div>
      <div class="gauge-track"><div class="gauge-fill" style="width:${pass_rate}%"></div></div>
    </div>
    <div style="margin-top:1.2rem;display:grid;grid-template-columns:1fr 1fr;gap:.8rem">
      <div><div style="font-size:1.5rem;font-weight:800;color:var(--pass)">${TESTS_PASSED}</div><div style="font-size:.7rem;color:var(--dim);text-transform:uppercase">Réussis</div></div>
      <div><div style="font-size:1.5rem;font-weight:800;color:var(--crit)">${actionable}</div><div style="font-size:.7rem;color:var(--dim);text-transform:uppercase">À Corriger</div></div>
      <div><div style="font-size:1.5rem;font-weight:800;color:var(--med)">${TESTS_WARNING}</div><div style="font-size:.7rem;color:var(--dim);text-transform:uppercase">Warnings</div></div>
      <div><div style="font-size:1.5rem;font-weight:800;color:var(--text)">${TESTS_TOTAL}</div><div style="font-size:.7rem;color:var(--dim);text-transform:uppercase">Total Tests</div></div>
    </div>
  </div>
</div>

<!-- STATS BAR -->
<div class="stats-bar">
  <div class="stat-box"><div class="num" style="color:var(--crit)">${crit}</div><div class="lbl">Critique</div></div>
  <div class="stat-box"><div class="num" style="color:var(--high)">${high}</div><div class="lbl">Élevé</div></div>
  <div class="stat-box"><div class="num" style="color:var(--med)">${med}</div><div class="lbl">Moyen</div></div>
  <div class="stat-box"><div class="num" style="color:var(--low)">${low}</div><div class="lbl">Faible</div></div>
  <div class="stat-box"><div class="num" style="color:var(--info)">${info}</div><div class="lbl">Info</div></div>
</div>

<!-- FINDINGS -->
<div class="section" id="findings"><span class="section-id">02</span><h2>Findings Détaillés (${total_findings} — triés par sévérité)</h2></div>

<div class="filter-bar">
  <label>Filtrer :</label>
  <button class="filter-btn active" onclick="filterFindings(0)">Tous (${total_findings})</button>
  <button class="filter-btn" onclick="filterFindings(1)">🔴 Critique (${crit})</button>
  <button class="filter-btn" onclick="filterFindings(2)">🟠 Élevé (${high})</button>
  <button class="filter-btn" onclick="filterFindings(3)">🟡 Moyen (${med})</button>
  <button class="filter-btn" onclick="filterFindings(4)">🔵 Faible (${low})</button>
  <button class="filter-btn" onclick="filterFindings(5)">⚪ Info (${info})</button>
</div>

<table class="findings-table" id="findings-table">
<thead><tr><th style="width:40px">#</th><th style="width:90px">Sévérité</th><th style="width:35%">Finding</th><th>Description &amp; Référence</th></tr></thead>
<tbody>
HTMLEOF

    # Écrire les lignes de findings triées
    printf '%s' "${findings_rows}" >> "${HTML_REPORT}"

    cat >> "${HTML_REPORT}" <<PERFEOF
</tbody>
</table>

<!-- PERFORMANCE -->
<div class="section" id="perf"><span class="section-id">03</span><h2>Performance par Module</h2></div>
<div class="perf-wrap">
PERFEOF

    printf '%s' "${perf_bars}" >> "${HTML_REPORT}"

    cat >> "${HTML_REPORT}" <<FOOTEOF
</div>

<!-- FOOTER -->
<div class="foot">
  <p>Généré par <span class="brand">AD Audit Framework v${SCRIPT_VERSION}</span> — $(date '+%Y-%m-%d %H:%M:%S')</p>
  <p>${AUDIT_REF} | Domaine: ${DOMAIN} | DC: ${DC_IP}</p>
  <p>Références: <span class="ref-badge">ISO 27001:2022</span> <span class="ref-badge">CIS AD Benchmark v2</span> <span class="ref-badge">MITRE ATT&amp;CK for Enterprise</span></p>
  <p style="margin-top:.5rem;font-size:.7rem;color:var(--dim)">Ce rapport est confidentiel. Distribution restreinte aux parties autorisées.</p>
</div>

</div><!-- .page -->

<script>
function filterFindings(sev) {
  const rows = document.querySelectorAll('.finding-row');
  const btns = document.querySelectorAll('.filter-btn');
  btns.forEach(function(b) { b.classList.remove('active'); });
  btns[sev].classList.add('active');
  rows.forEach(function(r) {
    if (sev === 0 || parseInt(r.dataset.sev) === sev) {
      r.classList.remove('hidden');
    } else {
      r.classList.add('hidden');
    }
  });
}
</script>
</body>
</html>
FOOTEOF

    print_success "Rapport HTML: ${HTML_REPORT}"
    log "INFO" "HTML report generated: ${HTML_REPORT}"
}
