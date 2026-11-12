/* dashboard/static/dashboard.js
   NetGuard IDS Professional SOC Dashboard & Forensics Suite
   Full client-side controller supporting all 10 workspaces.
*/

"use strict";

// ── State variables ──
let activityChart = null;
let _sseSource = null;
let _activeTab = "live";          // "live" | "history"
let _historyDays = 1;
let _alertsCache = [];
let _rulesMetadataCache = [];
let _currentTrafficPage = 1;
let _totalTrafficPages = 1;
let _currentModalAlert = null;
let _calYear = new Date().getFullYear();
let _calMonth = new Date().getMonth() + 1;
let _calSelectedDay = null;
let _calDayData = {};
let _currentCaseId = null;
let _csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || "";

async function initCsrf() {
  if (_csrfToken) return;
  try {
    const res = await fetch("/api/csrf-token");
    const data = await res.json();
    _csrfToken = data.csrf_token || "";
  } catch (e) {
    console.warn("Could not load CSRF token:", e);
  }
}

function getAuthHeaders(extra = {}) {
  const h = { ...extra };
  if (_csrfToken) {
    h["X-CSRFToken"] = _csrfToken;
  }
  return h;
}

const CAL_MONTHS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
];

// ── Utility: Escape HTML ──
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Toast Notifications ──
function showToast(message, type = "success") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${type === 'success' ? '✓' : '⚠'}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ── Workspace Switching (Phase 3) ──
function switchWorkspace(name) {
  document.querySelectorAll(".nav-tab").forEach(t => {
    t.classList.toggle("active", t.getAttribute("data-workspace") === name);
  });
  document.querySelectorAll(".workspace-pane").forEach(p => {
    p.classList.toggle("hidden", p.id !== `ws-${name}`);
  });

  if (name === "traffic") {
    loadTraffic(1);
  } else if (name === "pcap") {
    loadPcapJobs();
  } else if (name === "cases") {
    loadCases();
  } else if (name === "devices") {
    loadDevices();
  } else if (name === "health") {
    loadRuleHealth();
  } else if (name === "settings") {
    loadSettings();
    loadNotificationConfig();
  } else if (name === "overview") {
    loadRecentAlerts();
  }
}

// ── Rule Metadata Inventory & Dynamic Dropdown (Phase 3) ──
async function loadRuleMetadata() {
  try {
    const rules = await fetch("/api/rules").then(r => r.json());
    if (Array.isArray(rules)) {
      _rulesMetadataCache = rules;
      const select = document.getElementById("alert-rule-filter");
      if (select) {
        const cur = select.value;
        select.innerHTML = `<option value="ALL">All Rules (${rules.length})</option>` +
          rules.map(r => `<option value="${r.rule_name}">${r.rule_name}</option>`).join("");
        if (cur) select.value = cur;
      }
      const label = document.getElementById("rules-active-label");
      if (label) {
        label.textContent = `${rules.length} Rules Active`;
      }
    }
  } catch (e) {
    console.warn("Failed to load /api/rules:", e);
  }
}

// ── Initialise Activity Chart ──
function initChart() {
  const canvas = document.getElementById("activityChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  activityChart = new Chart(ctx, {
    type: "bar",
    data: { labels: [], datasets: [] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#94a3b8",
            font: { family: "'Inter', sans-serif", size: 10 },
            boxWidth: 10,
            padding: 10,
          },
        },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          borderColor: "rgba(99, 130, 255, 0.2)",
          borderWidth: 1,
          titleColor: "#e2e8f0",
          bodyColor: "#94a3b8",
          cornerRadius: 6,
        },
      },
      scales: {
        x: {
          stacked: true,
          ticks: { color: "#475569", font: { size: 10, family: "'JetBrains Mono', monospace" }, maxTicksLimit: 12 },
          grid: { color: "rgba(99, 130, 255, 0.05)" },
        },
        y: {
          stacked: true,
          beginAtZero: true,
          ticks: { color: "#475569", font: { size: 10 }, stepSize: 1 },
          grid: { color: "rgba(99, 130, 255, 0.07)" },
        },
      },
    },
  });
}

// ── Refresh Activity Chart ──
async function loadChart() {
  try {
    const data = await fetch("/api/chart").then(r => r.json());
    if (activityChart && data.labels && data.datasets) {
      activityChart.data.labels = data.labels;
      activityChart.data.datasets = data.datasets;
      activityChart.update();
    }
  } catch (e) {
    console.warn("Chart load failed:", e);
  }
}

// ── Fetch & render status KPIs ──
async function loadStatus() {
  try {
    const data = await fetch("/api/status").then(r => r.json());
    const level = data.threat_level || "clear";
    const label = level.charAt(0).toUpperCase() + level.slice(1);
    const dot   = document.getElementById("status-dot");
    const badge = document.getElementById("status-label");
    if (dot) dot.className = "status-dot " + level;
    if (badge) badge.textContent = label + " Threat";
    const tv = document.getElementById("threat-level");
    if (tv) {
      tv.textContent = label;
      tv.className = "stat-value " + level;
    }
    const ac = document.getElementById("alert-count");
    if (ac) ac.textContent = data.alert_count_1h ?? 0;
    const scans = (data.rule_breakdown || {})["PORT_SCAN"] ?? 0;
    const sc = document.getElementById("scan-count");
    if (sc) sc.textContent = scans;
    const st = document.getElementById("server-time");
    if (st) st.textContent = data.server_time || "";
    if (data.active_rules_count) {
      const activeEl = document.getElementById("rules-active-label");
      if (activeEl) activeEl.textContent = `${data.active_rules_count} Rules Active`;
    }
  } catch (e) {
    console.error("Status fetch failed:", e);
  }
}

// ── Plain language observations ──
async function loadObservations() {
  try {
    const data = await fetch("/api/observations").then(r => r.json());
    const list = document.getElementById("observations-list");
    const count = document.getElementById("obs-count");
    if (count) count.textContent = data.length;
    if (!list) return;
    if (!data.length) {
      list.innerHTML = '<div class="loading-state">No observations yet — network quiet.</div>';
      return;
    }
    list.innerHTML = data.map(obs => `
      <div class="observation-item">
        ${escapeHtml(obs.message)}
        <div class="obs-time">${obs.time_str || ""}</div>
      </div>
    `).join("");
  } catch (e) {
    console.error("Observations fetch failed:", e);
  }
}

// ── Calendar Heatmap (Overview) ──
async function renderCalendar(year, month) {
  const label = document.getElementById("cal-month-label");
  if (label) label.textContent = CAL_MONTHS[month - 1] + "  " + year;
  const container = document.getElementById("cal-days-container");
  if (container) container.innerHTML = '<div class="cal-loading">Loading…</div>';
  try {
    const data = await fetch(`/api/alerts/calendar?year=${year}&month=${month}`).then(r => r.json());
    _calDayData = {};
    (data.days || []).forEach(d => { _calDayData[d.date_str] = d; });
    paintCalendarGrid(year, month);
  } catch (e) {
    console.error("Calendar fetch failed:", e);
  }
}

function paintCalendarGrid(year, month) {
  const container = document.getElementById("cal-days-container");
  if (!container) return;
  const today = new Date();
  const todayStr = `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2,"0")}-${String(today.getDate()).padStart(2,"0")}`;
  const firstDate = new Date(year, month - 1, 1);
  const daysInMonth = new Date(year, month, 0).getDate();
  const startOffset = (firstDate.getDay() + 6) % 7;

  let html = "";
  for (let i = 0; i < startOffset; i++) {
    html += `<div class="cal-day cal-empty"></div>`;
  }
  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${String(month).padStart(2,"0")}-${String(d).padStart(2,"0")}`;
    const info = _calDayData[dateStr] || { count: 0, has_high: 0 };
    const count = info.count || 0;
    const isHigh = info.has_high === 1;
    const isToday = dateStr === todayStr;
    const isSel = dateStr === _calSelectedDay;

    let heatClass = "heat-none";
    if (count > 0) {
      if (isHigh || count >= 15) heatClass = "heat-high";
      else if (count >= 5) heatClass = "heat-mid";
      else heatClass = "heat-low";
    }
    const todayMark = isToday ? " cal-today" : "";
    const selMark = isSel ? " cal-selected" : "";

    html += `
      <div class="cal-day ${heatClass}${todayMark}${selMark}"
           onclick="calSelectDay('${dateStr}')"
           title="${dateStr}${count ? " — " + count + " alert" + (count > 1 ? "s" : "") : ""}">
        <span class="cal-day-num">${d}</span>
        ${count ? `<span class="cal-dot-ind"></span>` : ""}
      </div>`;
  }
  container.innerHTML = html;
}

async function calSelectDay(dateStr) {
  _calSelectedDay = dateStr;
  paintCalendarGrid(_calYear, _calMonth);
  const sumEl = document.getElementById("cal-summary");
  if (sumEl) sumEl.style.display = "none";
  const panel = document.getElementById("cal-day-view");
  if (panel) panel.classList.remove("hidden");

  const tbody = document.getElementById("cal-day-tbody");
  const title = document.getElementById("cal-day-title");
  const badge = document.getElementById("cal-day-badge");
  if (title) title.textContent = dateStr;
  if (badge) badge.textContent = "…";
  if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Loading…</td></tr>';

  try {
    const data = await fetch(`/api/alerts/by-date?date=${dateStr}`).then(r => r.json());
    const alerts = data.alerts || [];
    if (badge) badge.textContent = data.total ?? alerts.length;
    if (!tbody) return;
    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No alerts on ${dateStr}.</td></tr>`;
      return;
    }
    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td><span class="mac">${escapeHtml(a.time_str || "—")}</span></td>
        <td><span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span></td>
        <td><span class="ip-cell">${escapeHtml(a.src_ip || "—")}</span></td>
        <td><span class="mono-val">${a.dst_port || "—"}</span></td>
        <td><span class="severity-badge sev-${a.severity}">${escapeHtml(a.severity || "?")}</span></td>
        <td class="alert-detail-cell">${escapeHtml(a.detail || "")}</td>
        <td><button class="btn-secondary" style="padding:2px 6px;" onclick="openInvestigation(${a.id})">🔍</button></td>
      </tr>
    `).join("");
  } catch (e) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Failed to load.</td></tr>';
  }
}

function calCloseDayView() {
  _calSelectedDay = null;
  const view = document.getElementById("cal-day-view");
  if (view) view.classList.add("hidden");
  const sum = document.getElementById("cal-summary");
  if (sum) sum.style.display = "flex";
  paintCalendarGrid(_calYear, _calMonth);
  calLoadTodaySummary();
}

function calPrevMonth() {
  _calMonth--;
  if (_calMonth < 1) { _calMonth = 12; _calYear--; }
  calCloseDayView();
  renderCalendar(_calYear, _calMonth);
}

function calNextMonth() {
  _calMonth++;
  if (_calMonth > 12) { _calMonth = 1; _calYear++; }
  calCloseDayView();
  renderCalendar(_calYear, _calMonth);
}

async function calLoadTodaySummary() {
  const today = new Date();
  const ds = `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2,'0')}-${String(today.getDate()).padStart(2,'0')}`;
  try {
    const dayData = await fetch(`/api/alerts/by-date?date=${ds}`).then(r => r.json());
    const alerts = dayData.alerts || [];
    const high = alerts.filter(a => a.severity === "high").length;
    const totEl = document.getElementById("cal-stat-total");
    const hiEl = document.getElementById("cal-stat-high");
    const ruleEl = document.getElementById("cal-stat-rule");
    if (totEl) totEl.textContent = alerts.length;
    if (hiEl) hiEl.textContent = high;
    const ruleCounts = {};
    alerts.forEach(a => { ruleCounts[a.rule_name] = (ruleCounts[a.rule_name] || 0) + 1; });
    const topRule = Object.entries(ruleCounts).sort((a,b) => b[1]-a[1])[0]?.[0] || "—";
    if (ruleEl) ruleEl.textContent = topRule.replace(/_/g, " ");
  } catch (e) {
    console.warn("Today summary load failed:", e);
  }
}

// ── Alerts Feed & Filtering (Live + History) ──
function switchAlertsTab(tab) {
  _activeTab = tab;
  document.getElementById("tab-live")?.classList.toggle("active", tab === "live");
  document.getElementById("tab-history")?.classList.toggle("active", tab === "history");
  const rangeGroup = document.getElementById("history-range");
  if (rangeGroup) rangeGroup.style.display = tab === "history" ? "flex" : "none";
  if (tab === "live") loadLiveAlerts();
  else loadHistory(_historyDays);
}

async function loadLiveAlerts() {
  try {
    const alerts = await fetch("/api/alerts?hours=1").then(r => r.json());
    _alertsCache = Array.isArray(alerts) ? alerts : [];
    const badge = document.getElementById("alerts-badge");
    if (badge) badge.textContent = _alertsCache.length;
    const navBadge = document.getElementById("nav-alerts-badge");
    if (navBadge) navBadge.textContent = _alertsCache.length;
    renderFilteredAlerts();
  } catch (e) {
    console.error("Live alerts load failed:", e);
  }
}

async function loadHistory(days) {
  _historyDays = days;
  document.querySelectorAll(".range-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`range-${days}`)?.classList.add("active");
  try {
    const data = await fetch(`/api/alerts/history?days=${days}`).then(r => r.json());
    _alertsCache = Array.isArray(data.alerts) ? data.alerts : [];
    const badge = document.getElementById("alerts-badge");
    if (badge) badge.textContent = _alertsCache.length;
    renderFilteredAlerts();
  } catch (e) {
    console.error("History load failed:", e);
  }
}

function matchesFilter(a, query, ruleFilter, sevFilter) {
  if (ruleFilter !== "ALL" && a.rule_name !== ruleFilter) return false;
  if (sevFilter !== "ALL" && (a.severity || "medium").toLowerCase() !== sevFilter.toLowerCase()) return false;
  if (query) {
    const q = query.toLowerCase();
    const str = [
      a.rule_name, a.src_ip, a.dst_ip, a.dst_port,
      a.country, a.city, a.detail, a.time_str, a.evidence_json
    ].filter(Boolean).join(" ").toLowerCase();
    if (!str.includes(q)) return false;
  }
  return true;
}

function onFilterChange() {
  renderFilteredAlerts();
}

function renderFilteredAlerts() {
  const query = (document.getElementById("alert-search-input")?.value || "").trim();
  const ruleFilter = document.getElementById("alert-rule-filter")?.value || "ALL";
  const sevFilter = document.getElementById("alert-sev-filter")?.value || "ALL";
  const filtered = _alertsCache.filter(a => matchesFilter(a, query, ruleFilter, sevFilter));

  const tbody = document.getElementById("alerts-tbody");
  if (!tbody) return;
  const metaText = document.getElementById("filter-meta-text");
  if (metaText) {
    metaText.textContent = `Showing ${filtered.length} of ${_alertsCache.length} alerts`;
  }

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No alerts match filter criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(a => `
    <tr>
      <td><span class="mono-val">${escapeHtml(a.time_str || a.datetime_str || "—")}</span></td>
      <td><span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span></td>
      <td><span class="ip-cell">${escapeHtml(a.src_ip || "—")}</span></td>
      <td><span class="ip-cell">${escapeHtml(a.dst_ip || "—")}</span></td>
      <td><span class="mono-val">${a.dst_port || "—"}</span></td>
      <td>${a.flag || "🌐"} <span style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(a.country_code || a.country || "")}</span></td>
      <td><span class="severity-badge sev-${a.severity}">${escapeHtml(a.severity || "?")}</span></td>
      <td class="alert-detail-cell">${escapeHtml(a.detail || "")}</td>
      <td>
        <button class="btn-secondary" style="padding:3px 8px;font-size:0.72rem;" onclick="openInvestigation(${a.id})">🔍 Investigate</button>
      </td>
    </tr>
  `).join("");
}

// ── Alert Investigation Modal & Correlated Flow Pivot ──
async function openInvestigation(alertId) {
  try {
    const alert = await fetch(`/api/alerts/${alertId}`).then(r => r.json());
    _currentModalAlert = alert;

    const overlay = document.getElementById("modal-overlay");
    const modal = document.getElementById("investigation-modal");
    if (overlay) overlay.classList.add("active");
    if (modal) modal.classList.add("open");

    const meta = document.getElementById("modal-meta");
    if (meta) {
      meta.innerHTML = `
        <div class="modal-meta-item"><span class="modal-meta-label">Time:</span> <span class="mono-val">${escapeHtml(alert.time_str || "")}</span></div>
        <div class="modal-meta-item"><span class="modal-meta-label">Rule:</span> <span class="rule-badge rule-${alert.rule_name}">${escapeHtml(alert.rule_name)}</span></div>
        <div class="modal-meta-item"><span class="modal-meta-label">Severity:</span> <span class="severity-badge sev-${alert.severity}">${escapeHtml(alert.severity)}</span></div>
        <div class="modal-meta-item"><span class="modal-meta-label">Src IP:</span> <span class="ip-cell">${escapeHtml(alert.src_ip)}</span></div>
        <div class="modal-meta-item"><span class="modal-meta-label">Dst IP:</span> <span class="ip-cell">${escapeHtml(alert.dst_ip)}:${alert.dst_port || ""}</span></div>
      `;
    }

    const exp = document.getElementById("modal-explanation");
    if (exp) exp.textContent = alert.explanation || "No explanation recorded.";
    const det = document.getElementById("modal-detail");
    if (det) det.textContent = alert.detail || "No raw detail.";

    const evSec = document.getElementById("modal-evidence-section");
    const evBox = document.getElementById("modal-evidence");
    if (evSec && evBox) {
      if (alert.evidence) {
        evBox.textContent = JSON.stringify(alert.evidence, null, 2);
        evSec.style.display = "block";
      } else {
        evSec.style.display = "none";
      }
    }

    const flowSec = document.getElementById("modal-flow-pivot-section");
    const flowIdEl = document.getElementById("modal-flow-id");
    if (flowSec && flowIdEl) {
      if (alert.flow_id) {
        flowIdEl.textContent = alert.flow_id;
        flowSec.style.display = "block";
      } else {
        flowSec.style.display = "none";
      }
    }

    const fbSec = document.getElementById("existing-feedback-section");
    const fbBox = document.getElementById("existing-feedback");
    if (fbSec && fbBox) {
      if (alert.feedback) {
        fbBox.innerHTML = `Classified as <strong>${escapeHtml(alert.feedback.classification)}</strong>: "${escapeHtml(alert.feedback.analyst_note || "No note")}"`;
        fbSec.style.display = "block";
      } else {
        fbSec.style.display = "none";
      }
    }

    const res = document.getElementById("modal-feedback-result");
    if (res) res.textContent = "";
  } catch (e) {
    showToast("Failed to load alert details", "error");
  }
}

function closeModal() {
  document.getElementById("modal-overlay")?.classList.remove("active");
  document.getElementById("investigation-modal")?.classList.remove("open");
  _currentModalAlert = null;
}

function pivotToFlowFromModal() {
  if (_currentModalAlert && _currentModalAlert.flow_id) {
    const flowId = _currentModalAlert.flow_id;
    closeModal();
    switchWorkspace("traffic");
    openFlowDrawer(flowId);
  }
}

async function submitFeedback(classification) {
  if (!_currentModalAlert) return;
  const note = document.getElementById("analyst-note")?.value || "";
  try {
    const res = await fetch("/api/feedback/reclassify", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        alert_id: _currentModalAlert.id,
        new_classification: classification,
        analyst_note: note,
      }),
    }).then(r => r.json());
    if (res.status === "ok") {
      showToast(`Alert #${_currentModalAlert.id} marked as ${classification}`, "success");
      closeModal();
      loadRuleHealth();
    } else {
      showToast(res.error || "Feedback failed", "error");
    }
  } catch (e) {
    showToast("Feedback error", "error");
  }
}

function openCaseFromAlert() {
  if (!_currentModalAlert) return;
  const aid = _currentModalAlert.id;
  const rule = _currentModalAlert.rule_name;
  closeModal();
  openNewCaseModal();
  const titleInput = document.getElementById("case-title-input");
  if (titleInput) titleInput.value = `Incident: ${rule} on ${_currentModalAlert.dst_ip}`;
  window._pendingCaseAlertIds = [aid];
}

function openCaseFromAlertId(alertId, ruleName, dstIp) {
  openNewCaseModal();
  const titleInput = document.getElementById("case-title-input");
  if (titleInput) titleInput.value = `Incident: ${ruleName} on ${dstIp}`;
  window._pendingCaseAlertIds = [alertId];
}

// ── Overview Live Alerts Feed (Phase 3) ──
async function loadRecentAlerts() {
  const tbody = document.getElementById("recent-alerts-tbody");
  if (!tbody) return;
  try {
    const alerts = await fetch("/api/alerts?hours=24").then(r => r.json());
    if (!Array.isArray(alerts)) return;

    let crit = 0, high = 0, med = 0, low = 0;
    alerts.forEach(a => {
      const s = (a.severity || "").toLowerCase();
      if (s === "critical") crit++;
      else if (s === "high") high++;
      else if (s === "medium") med++;
      else if (s === "low") low++;
    });
    const cCrit = document.getElementById("chip-crit");
    const cHigh = document.getElementById("chip-high");
    const cMed = document.getElementById("chip-med");
    const cLow = document.getElementById("chip-low");
    if (cCrit) cCrit.textContent = `Crit: ${crit}`;
    if (cHigh) cHigh.textContent = `High: ${high}`;
    if (cMed) cMed.textContent = `Med: ${med}`;
    if (cLow) cLow.textContent = `Low: ${low}`;

    const recent = alerts.slice(0, 15);
    if (!recent.length) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No security alerts recorded in the past 24 hours.</td></tr>`;
      return;
    }

    tbody.innerHTML = recent.map(renderRecentAlertRow).join("");
  } catch (e) {
    console.warn("Failed to load recent alerts:", e);
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state">Failed to load recent alerts feed.</td></tr>`;
  }
}

function renderRecentAlertRow(a) {
  const sev = (a.severity || "medium").toLowerCase();
  const rule = escapeHtml(a.rule_name || "Unknown");
  const timeStr = escapeHtml(a.time_str || "—");
  const src = escapeHtml(a.src_ip || "—");
  const dst = escapeHtml(a.dst_ip || "—");
  const proto = escapeHtml(a.protocol || "—");
  const port = a.dst_port ?? a.src_port ?? "—";
  const detail = escapeHtml(a.detail || "No details provided");
  return `
    <tr id="recent-alert-${a.id}">
      <td><span class="mono-val" style="font-size:0.75rem;">${timeStr}</span></td>
      <td><span class="severity-badge sev-${sev}">${sev.toUpperCase()}</span></td>
      <td><span class="rule-badge rule-${a.rule_name}">${rule}</span></td>
      <td><span class="ip-cell">${src}</span></td>
      <td><span class="ip-cell">${dst}</span></td>
      <td><span class="rule-badge" style="background:rgba(99,102,241,0.15);color:#818cf8;font-size:0.7rem;">${proto}</span></td>
      <td><span class="mono-val">${port}</span></td>
      <td class="alert-detail-cell" title="${detail}" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${detail}</td>
      <td style="white-space:nowrap;">
        <button class="btn-secondary" style="padding:2px 8px;font-size:0.72rem;" onclick="openInvestigation(${a.id})" title="Investigate in modal">🔍 View</button>
        <button class="btn-secondary" style="padding:2px 8px;font-size:0.72rem;margin-left:4px;" onclick="openCaseFromAlertId(${a.id}, '${rule}', '${dst}')" title="Create incident case">📁 Case</button>
      </td>
    </tr>
  `;
}

function prependRecentAlert(a) {
  const tbody = document.getElementById("recent-alerts-tbody");
  if (!tbody) return;
  const emptyRow = tbody.querySelector(".empty-state");
  if (emptyRow) tbody.innerHTML = "";

  const s = (a.severity || "").toLowerCase();
  if (s === "critical") {
    const el = document.getElementById("chip-crit");
    if (el) el.textContent = `Crit: ${parseInt(el.textContent.replace(/\D/g, '') || 0) + 1}`;
  } else if (s === "high") {
    const el = document.getElementById("chip-high");
    if (el) el.textContent = `High: ${parseInt(el.textContent.replace(/\D/g, '') || 0) + 1}`;
  } else if (s === "medium") {
    const el = document.getElementById("chip-med");
    if (el) el.textContent = `Med: ${parseInt(el.textContent.replace(/\D/g, '') || 0) + 1}`;
  } else if (s === "low") {
    const el = document.getElementById("chip-low");
    if (el) el.textContent = `Low: ${parseInt(el.textContent.replace(/\D/g, '') || 0) + 1}`;
  }

  const temp = document.createElement("tbody");
  temp.innerHTML = renderRecentAlertRow(a);
  const newRow = temp.firstElementChild;
  tbody.insertBefore(newRow, tbody.firstChild);

  while (tbody.children.length > 20) {
    tbody.removeChild(tbody.lastChild);
  }
}

// ── Traffic Explorer with KQL & Reverse DNS (Phase 1 & Phase 7) ──
let _currentTrafficKql = "";
let _dnsCache = {};

function setKqlQuery(kql) {
  const input = document.getElementById("traffic-kql-input");
  if (input) input.value = kql;
  executeKqlSearch(1);
}

function setKqlQuickFilter(kql) {
  setKqlQuery(kql);
}

function executeKqlSearch(page = 1) {
  const input = document.getElementById("traffic-kql-input");
  _currentTrafficKql = input ? input.value.trim() : "";
  loadTraffic(page);
}

function clearKqlSearch() {
  const input = document.getElementById("traffic-kql-input");
  if (input) input.value = "";
  _currentTrafficKql = "";
  loadTraffic(1);
}

function resetTrafficFilters() {
  clearKqlSearch();
  const sInput = document.getElementById("traffic-search-input");
  if (sInput) sInput.value = "";
  const portF = document.getElementById("traffic-port-filter");
  if (portF) portF.value = "";
  const protoF = document.getElementById("traffic-proto-filter");
  if (protoF) protoF.value = "";
  const dirF = document.getElementById("traffic-dir-filter");
  if (dirF) dirF.value = "";
  const alertF = document.getElementById("traffic-alert-filter");
  if (alertF) alertF.value = "all";
  loadTraffic(1);
}

async function loadTraffic(page = 1) {
  _currentTrafficPage = page;
  const kql = document.getElementById("traffic-kql-input")?.value?.trim() || _currentTrafficKql || "";
  const search = document.getElementById("traffic-search-input")?.value || "";
  const port = document.getElementById("traffic-port-filter")?.value || "";
  const proto = document.getElementById("traffic-proto-filter")?.value || "";
  const dir = document.getElementById("traffic-dir-filter")?.value || "";
  const hasAlerts = document.getElementById("traffic-alert-filter")?.value || "all";

  const params = new URLSearchParams({
    page: page,
    page_size: 25,
  });

  if (kql) {
    params.set("kql", kql);
  } else {
    if (search) params.set("search", search);
    if (port) params.set("port", port);
    if (proto) params.set("protocol", proto);
    if (dir) params.set("direction", dir);
    if (hasAlerts && hasAlerts !== "all") params.set("has_alerts", hasAlerts);
  }

  const tbody = document.getElementById("traffic-tbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="10" class="empty-state">Loading network flow records…</td></tr>`;

  try {
    const data = await fetch(`/api/traffic?${params.toString()}`).then(r => r.json());
    if (data.error) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="10" class="empty-state" style="color:#f87171;">Query error: ${escapeHtml(data.error)}</td></tr>`;
      showToast(`Traffic query error: ${data.error}`, "error");
      return;
    }
    const flows = data.flows || [];
    _totalTrafficPages = data.total_pages || 1;

    const meta = document.getElementById("traffic-meta-text");
    const durStr = data.duration_ms ? ` (${data.duration_ms}ms)` : "";
    if (meta) meta.textContent = `Showing ${flows.length} of ${data.total} recorded flows${durStr}`;
    const pagInfo = document.getElementById("traffic-pagination-info");
    if (pagInfo) pagInfo.textContent = `Page ${data.page} of ${_totalTrafficPages} (${data.total} flows)`;

    if (!tbody) return;
    if (!flows.length) {
      tbody.innerHTML = `<tr><td colspan="10" class="empty-state">No network flows match filter criteria.</td></tr>`;
      return;
    }

    renderFlowRows(tbody, flows);

    // Asynchronously resolve DNS in background without blocking rendering
    const unknownIps = new Set();
    flows.forEach(f => {
      if (f.src_ip && !_dnsCache[f.src_ip]) unknownIps.add(f.src_ip);
      if (f.dst_ip && !_dnsCache[f.dst_ip]) unknownIps.add(f.dst_ip);
    });

    if (unknownIps.size > 0) {
      fetch("/api/dns/reverse", {
        method: "POST",
        headers: getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ips: Array.from(unknownIps) }),
      }).then(r => r.json()).then(res => {
        if (res.results) {
          Object.assign(_dnsCache, res.results);
          updateFlowDnsLabels();
        }
      }).catch(e => console.warn("DNS resolution error:", e));
    }
  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="10" class="empty-state" style="color:#f87171;">Failed to query flows: ${escapeHtml(e.message)}</td></tr>`;
  }
}

function renderFlowRows(tbody, flows) {
  tbody.innerHTML = flows.map(f => {
    const alertBadge = f.alert_count > 0
      ? `<span class="severity-badge sev-high">${f.alert_count} Alerts</span>`
      : `<span style="font-size:0.7rem;color:var(--text-muted);">Clean</span>`;

    const srcEntry = _dnsCache[f.src_ip];
    const dstEntry = _dnsCache[f.dst_ip];
    const srcDns = typeof srcEntry === "object" ? srcEntry?.hostname : srcEntry;
    const dstDns = typeof dstEntry === "object" ? dstEntry?.hostname : dstEntry;
    const srcHost = srcDns && typeof srcDns === "string" && !srcDns.startsWith("[") ? `<div class="dns-host" style="font-size:0.68rem;color:#818cf8;">${escapeHtml(srcDns)}</div>` : "";
    const dstHost = dstDns && typeof dstDns === "string" && !dstDns.startsWith("[") ? `<div class="dns-host" style="font-size:0.68rem;color:#818cf8;">${escapeHtml(dstDns)}</div>` : "";

    return `
      <tr style="cursor:pointer;" onclick="openFlowDrawer('${f.flow_id}')">
        <td><span class="mono-val">${escapeHtml(f.last_time_str || "—")}</span></td>
        <td><span class="rule-badge" style="background:rgba(99,102,241,0.15);color:#818cf8;">${escapeHtml(f.protocol || "")}</span></td>
        <td>
          <span class="ip-cell" data-ip="${escapeHtml(f.src_ip)}">${escapeHtml(f.src_ip)}:${f.src_port || ""}</span>
          ${srcHost}
        </td>
        <td>
          <span class="ip-cell" data-ip="${escapeHtml(f.dst_ip)}">${escapeHtml(f.dst_ip)}:${f.dst_port || ""}</span>
          ${dstHost}
        </td>
        <td><span style="font-size:0.75rem;text-transform:capitalize;color:#cbd5e1;">${escapeHtml(f.direction || "")}</span></td>
        <td><span class="mono-val">${f.packets ?? f.packet_count ?? 0}</span></td>
        <td><span class="mono-val">${formatBytes(f.bytes ?? f.byte_count ?? 0)}</span></td>
        <td><span class="mono-val">${f.duration_str || "0.00s"}</span></td>
        <td>${alertBadge}</td>
        <td>
          <button class="btn-secondary" style="padding:2px 6px;font-size:0.72rem;" onclick="event.stopPropagation();openFlowDrawer('${f.flow_id}')">Inspect</button>
        </td>
      </tr>
    `;
  }).join("");
}

function updateFlowDnsLabels() {
  document.querySelectorAll("#traffic-tbody .ip-cell[data-ip]").forEach(el => {
    const ip = el.getAttribute("data-ip");
    const entry = _dnsCache[ip];
    const host = typeof entry === "object" ? entry?.hostname : entry;
    if (host && typeof host === "string" && !host.startsWith("[")) {
      let hostEl = el.parentElement.querySelector(".dns-host");
      if (!hostEl) {
        hostEl = document.createElement("div");
        hostEl.className = "dns-host";
        hostEl.style.cssText = "font-size:0.68rem;color:#818cf8;";
        el.parentElement.appendChild(hostEl);
      }
      hostEl.textContent = host;
    }
  });
}

function trafficPrevPage() {
  if (_currentTrafficPage > 1) loadTraffic(_currentTrafficPage - 1);
}
function trafficNextPage() {
  if (_currentTrafficPage < _totalTrafficPages) loadTraffic(_currentTrafficPage + 1);
}

function exportTrafficCsv() {
  const kql = document.getElementById("traffic-kql-input")?.value?.trim() || "";
  const search = document.getElementById("traffic-search-input")?.value || "";
  const proto = document.getElementById("traffic-proto-filter")?.value || "";
  const dir = document.getElementById("traffic-dir-filter")?.value || "";
  window.location.href = `/api/traffic/export?kql=${encodeURIComponent(kql)}&search=${encodeURIComponent(search)}&protocol=${encodeURIComponent(proto)}&direction=${encodeURIComponent(dir)}`;
}

// ── Visual Query Builder (Phase 1.3) ──
function openQueryBuilderModal() {
  const overlay = document.getElementById("query-builder-overlay");
  const modal = document.getElementById("query-builder-modal");
  if (overlay) overlay.classList.add("active");
  if (modal) modal.style.display = "block";
  updateQueryBuilderPreview();
}

function closeQueryBuilderModal() {
  document.getElementById("query-builder-overlay")?.classList.remove("active");
  const modal = document.getElementById("query-builder-modal");
  if (modal) modal.style.display = "none";
}

function addQueryBuilderRow(conj = "and") {
  const container = document.getElementById("qb-rows-container");
  if (!container) return;
  const row = document.createElement("div");
  row.className = "qb-row";
  row.style.cssText = "display:flex;gap:8px;align-items:center;margin-bottom:8px;";
  row.innerHTML = `
    <select class="filter-select qb-conj" style="width:70px;" onchange="updateQueryBuilderPreview()">
      <option value="and" ${conj === 'and' ? 'selected' : ''}>AND</option>
      <option value="or" ${conj === 'or' ? 'selected' : ''}>OR</option>
    </select>
    <select class="filter-select qb-field" style="width:130px;" onchange="updateQueryBuilderPreview()">
      <option value="src_ip">Source IP</option>
      <option value="dst_ip">Destination IP</option>
      <option value="dst_port">Dest Port</option>
      <option value="src_port">Source Port</option>
      <option value="protocol">Protocol</option>
      <option value="direction">Direction</option>
      <option value="is_alerted">Alerted</option>
      <option value="packet_count">Packet Count</option>
      <option value="byte_count">Byte Count</option>
      <option value="dns_query">DNS Query</option>
    </select>
    <select class="filter-select qb-op" style="width:110px;" onchange="updateQueryBuilderPreview()">
      <option value=":" selected>Equals (:)</option>
      <option value="!=">Not Equals (!=)</option>
      <option value=">">Greater Than (&gt;)</option>
      <option value="<">Less Than (&lt;)</option>
      <option value="contains">Contains</option>
      <option value="startswith">Starts With</option>
    </select>
    <input type="text" class="form-input qb-val" style="flex:1;" placeholder="Value" oninput="updateQueryBuilderPreview()" />
    <button class="btn-secondary" style="padding:4px 8px;font-size:0.75rem;color:#f87171;" onclick="removeQueryBuilderRow(this)">✕</button>
  `;
  container.appendChild(row);
  updateQueryBuilderPreview();
}

function removeQueryBuilderRow(btn) {
  const row = btn.closest(".qb-row");
  if (row) {
    row.remove();
    updateQueryBuilderPreview();
  }
}

function updateQueryBuilderPreview() {
  const container = document.getElementById("qb-rows-container");
  const preview = document.getElementById("qb-preview-box");
  if (!container || !preview) return;

  const rows = container.querySelectorAll(".qb-row");
  const parts = [];

  rows.forEach((r, idx) => {
    const conj = r.querySelector(".qb-conj")?.value || "and";
    const field = r.querySelector(".qb-field")?.value;
    const op = r.querySelector(".qb-op")?.value || ":";
    let val = r.querySelector(".qb-val")?.value?.trim();

    if (!field || val === undefined || val === "") return;

    if (["dst_port", "src_port", "packet_count", "byte_count"].includes(field)) {
      const num = parseInt(val, 10);
      val = isNaN(num) ? "0" : String(num);
    } else if (field === "is_alerted") {
      val = (val === "true" || val === "1") ? "true" : "false";
    } else {
      val = `"${val.replace(/"/g, '')}"`;
    }

    const expr = `${field} ${op} ${val}`;
    if (idx === 0) {
      parts.push(expr);
    } else {
      parts.push(`${conj} ${expr}`);
    }
  });

  preview.value = parts.join(" ");
}

function applyQueryBuilderToTraffic() {
  const preview = document.getElementById("qb-preview-box");
  const kql = preview ? preview.value.trim() : "";
  const input = document.getElementById("traffic-kql-input");
  if (input) input.value = kql;
  closeQueryBuilderModal();
  executeKqlSearch(1);
}

// ── Query Generation Assistant (Phase 1.4) ──
function openQueryAssistantModal() {
  const overlay = document.getElementById("query-assistant-overlay");
  const modal = document.getElementById("query-assistant-modal");
  if (overlay) overlay.classList.add("active");
  if (modal) modal.style.display = "block";
  document.getElementById("qa-intent-input")?.focus();
}

function closeQueryAssistantModal() {
  document.getElementById("query-assistant-overlay")?.classList.remove("active");
  const modal = document.getElementById("query-assistant-modal");
  if (modal) modal.style.display = "none";
}

function setAssistantExample(text) {
  const input = document.getElementById("qa-intent-input");
  if (input) {
    input.value = text;
    generateAssistantKql();
  }
}

async function generateAssistantKql() {
  const intent = document.getElementById("qa-intent-input")?.value?.trim();
  if (!intent) {
    showToast("Please enter a search description", "warning");
    return;
  }
  const resSec = document.getElementById("qa-result-section");
  const outBox = document.getElementById("qa-kql-output");

  try {
    const res = await fetch("/api/traffic/assistant", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ intent }),
    }).then(r => r.json());

    if (res.kql) {
      if (outBox) outBox.textContent = res.kql;
      if (resSec) resSec.style.display = "block";
    } else {
      showToast(res.error || "Failed to generate KQL", "error");
    }
  } catch (e) {
    showToast(`Assistant error: ${e.message}`, "error");
  }
}

function copyAssistantKql() {
  const outBox = document.getElementById("qa-kql-output");
  if (outBox && outBox.textContent) {
    navigator.clipboard.writeText(outBox.textContent).then(() => {
      showToast("KQL copied to clipboard", "success");
    });
  }
}

function applyAssistantKql() {
  const outBox = document.getElementById("qa-kql-output");
  const kql = outBox ? outBox.textContent.trim() : "";
  if (kql) {
    const input = document.getElementById("traffic-kql-input");
    if (input) input.value = kql;
    closeQueryAssistantModal();
    executeKqlSearch(1);
  }
}

// ── Flow Detail Drawer (Phase 2) ──
async function openFlowDrawer(flowId) {
  const overlay = document.getElementById("flow-drawer-overlay");
  const drawer = document.getElementById("flow-drawer");
  const body = document.getElementById("flow-drawer-body");
  if (overlay) overlay.classList.add("active");
  if (drawer) drawer.classList.add("open");
  if (body) body.innerHTML = '<div class="loading-state">Loading session details…</div>';

  try {
    const data = await fetch(`/api/traffic/${flowId}`).then(r => r.json());
    if (data.error) throw new Error(data.error);
    const f = data.flow || {};
    const alerts = data.alerts || [];
    const pkts = data.packet_events || [];

    body.innerHTML = `
      <div style="background:rgba(30,41,59,0.5);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;">
        <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:4px;">FLOW IDENTIFIER</div>
        <div class="mono-val" style="color:#818cf8;word-break:break-all;margin-bottom:12px;">${escapeHtml(f.flow_id)}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:0.78rem;">
          <div><span style="color:var(--text-muted)">Protocol:</span> <strong>${escapeHtml(f.protocol)}</strong></div>
          <div><span style="color:var(--text-muted)">Direction:</span> <strong>${escapeHtml(f.direction)}</strong></div>
          <div><span style="color:var(--text-muted)">Source:</span> <span class="mono-val">${escapeHtml(f.src_ip)}:${f.src_port || ""}</span></div>
          <div><span style="color:var(--text-muted)">Destination:</span> <span class="mono-val">${escapeHtml(f.dst_ip)}:${f.dst_port || ""}</span></div>
          <div><span style="color:var(--text-muted)">Packets:</span> <span class="mono-val">${f.packet_count ?? f.packets ?? 0}</span></div>
          <div><span style="color:var(--text-muted)">Volume:</span> <span class="mono-val">${formatBytes(f.byte_count ?? f.bytes ?? 0)}</span></div>
          <div><span style="color:var(--text-muted)">Start:</span> <span class="mono-val">${f.start_time_str}</span></div>
          <div><span style="color:var(--text-muted)">Last Seen:</span> <span class="mono-val">${f.last_seen_str}</span></div>
        </div>
        <div style="margin-top:14px;display:flex;gap:8px;">
          <a class="btn-primary" href="/api/traffic/${f.flow_id}/pcap" download="flow_${f.flow_id.slice(0,12)}.pcap" style="text-decoration:none;">
            Download PCAP Slice
          </a>
        </div>
      </div>

      <div>
        <h4 style="font-size:0.85rem;font-weight:600;color:#f1f5f9;margin-bottom:8px;">Associated Security Alerts (${alerts.length})</h4>
        ${alerts.length === 0 ? '<div style="font-size:0.75rem;color:var(--text-muted);">No detection alerts associated with this flow session.</div>' :
          alerts.map(a => `
            <div style="background:rgba(30,41,59,0.4);border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span>
                <span class="severity-badge sev-${a.severity}">${escapeHtml(a.severity)}</span>
              </div>
              <div style="font-size:0.75rem;color:#cbd5e1;">${escapeHtml(a.detail)}</div>
            </div>
          `).join('')}
      </div>

      <div>
        <h4 style="font-size:0.85rem;font-weight:600;color:#f1f5f9;margin-bottom:8px;">Recorded Packet Events (${pkts.length})</h4>
        <div class="table-wrapper" style="max-height:220px;overflow-y:auto;">
          <table class="alerts-table" style="font-size:0.72rem;">
            <thead><tr><th>#</th><th>Time</th><th>Len</th><th>Flags</th><th>Payload Sample</th></tr></thead>
            <tbody>
              ${pkts.map(p => `
                <tr>
                  <td>${p.packet_index}</td>
                  <td>${p.time_str || "—"}</td>
                  <td>${p.packet_len}B</td>
                  <td>${p.tcp_flags || "—"}</td>
                  <td class="mono-val" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(p.payload_sample || "—")}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (e) {
    if (body) body.innerHTML = `<div class="empty-state">Failed to load session details: ${escapeHtml(e.message)}</div>`;
  }
}

function closeFlowDrawer() {
  document.getElementById("flow-drawer-overlay")?.classList.remove("active");
  document.getElementById("flow-drawer")?.classList.remove("open");
}

function openSaveSearchModal() {
  const name = prompt("Enter a name for this saved search query:");
  if (!name) return;
  const search = document.getElementById("traffic-search-input")?.value || "";
  const port = document.getElementById("traffic-port-filter")?.value || "";
  const proto = document.getElementById("traffic-proto-filter")?.value || "";
  fetch("/api/saved-searches", {
    method: "POST",
    headers: getAuthHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name: name, query: { search, port, protocol: proto } }),
  }).then(r => r.json()).then(res => {
    if (res.status === "ok") showToast(`Saved search "${name}" created`, "success");
  });
}

// ── Threat Hunting Multi-Source Telemetry (Phase 2) ──
function applyHuntingPreset(preset) {
  const typeSelect = document.getElementById("hunting-search-type");
  const queryInput = document.getElementById("hunting-query-input");

  let type = "rule";
  let query = "";

  if (preset === "high_entropy_dns") {
    type = "rule";
    query = "DNS_ANOMALY";
  } else if (preset === "stealth_scan") {
    type = "rule";
    query = "TCP_STEALTH_SCAN";
  } else if (preset === "icmp_tunnel") {
    type = "rule";
    query = "ICMP_TUNNEL";
  } else if (preset === "fragment_anomaly") {
    type = "rule";
    query = "IP_FRAGMENT_ANOMALY";
  } else if (preset === "cleartext_on_443") {
    type = "rule";
    query = "CLEAR_HTTP_ON_TLS_PORT";
  } else if (preset === "irc_beaconing") {
    type = "rule";
    query = "IRC_C2_BEACONING";
  }

  if (typeSelect) typeSelect.value = type;
  if (queryInput) queryInput.value = query;

  executeCustomHunt();
}

async function executeCustomHunt() {
  const type = document.getElementById("hunting-search-type")?.value || "rule";
  const query = document.getElementById("hunting-query-input")?.value?.trim() || "";
  const hours = document.getElementById("hunting-time-window")?.value || "24";
  const tbody = document.getElementById("hunting-results-tbody");

  if (!query) {
    showToast("Please enter an indicator, pattern, or rule name", "warning");
    return;
  }

  if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Searching alerts, packet events, flows, and anomalies for [${escapeHtml(query)}]…</td></tr>`;

  try {
    const params = new URLSearchParams({ type, q: query, hours });
    const data = await fetch(`/api/hunting/search?${params.toString()}`).then(r => r.json());

    if (data.error) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="color:#f87171;">Hunt search error: ${escapeHtml(data.error)}</td></tr>`;
      showToast(`Search error: ${data.error}`, "error");
      return;
    }

    const results = data.results || [];
    if (!tbody) return;

    if (!results.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No telemetry matching [${escapeHtml(query)}] across alerts, flows, or anomalies in the past ${hours}h.</td></tr>`;
      return;
    }

    tbody.innerHTML = results.map(r => {
      let classBadge = `<span class="severity-badge sev-low">${escapeHtml(r.classification)}</span>`;
      if (r.classification === "Existing IDS alert") {
        classBadge = `<span class="severity-badge sev-high">Existing IDS Alert</span>`;
      } else if (r.classification === "Suspicious traffic indicator") {
        classBadge = `<span class="severity-badge sev-medium">Suspicious Traffic</span>`;
      } else if (r.classification === "Statistical anomaly") {
        classBadge = `<span class="severity-badge" style="background:rgba(245,158,11,0.2);color:#fbbf24;border:1px solid rgba(245,158,11,0.3);">Statistical Anomaly</span>`;
      }

      const actionBtn = r.flow_id
        ? `<button class="btn-secondary" style="padding:2px 6px;font-size:0.72rem;" onclick="openFlowDrawer('${r.flow_id}')">Inspect Flow</button>`
        : (r.alert_id
            ? `<button class="btn-secondary" style="padding:2px 6px;font-size:0.72rem;" onclick="openInvestigation(${r.alert_id})">🔍 Alert</button>`
            : `—`);

      return `
        <tr>
          <td><span class="mono-val" style="font-size:0.75rem;">${escapeHtml(r.time_str || "—")}</span></td>
          <td>${classBadge}</td>
          <td><span class="ip-cell">${escapeHtml(r.indicator || "—")}</span></td>
          <td><span class="rule-badge rule-${r.context}">${escapeHtml(r.context || "—")}</span></td>
          <td><span class="mono-val">${escapeHtml(r.proto_port || "—")}</span></td>
          <td class="alert-detail-cell" title="${escapeHtml(r.details || '')}">${escapeHtml(r.details || "—")}</td>
          <td>${actionBtn}</td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="color:#f87171;">Threat hunt failed: ${escapeHtml(e.message)}</td></tr>`;
  }
}

// ── PCAP File Upload & Background Analysis (Phase 4) ──
let _pcapPollInterval = null;

function handlePcapFileUpload(file) {
  if (!file) return;

  const MAX_SIZE = 100 * 1024 * 1024; // 100 MB
  if (file.size > MAX_SIZE) {
    showToast(`File exceeds maximum size limit (100 MB). Size: ${formatBytes(file.size)}`, "error");
    return;
  }

  const validExts = [".pcap", ".pcapng", ".cap"];
  const nameLower = file.name.toLowerCase();
  const hasValidExt = validExts.some(ext => nameLower.endsWith(ext));
  if (!hasValidExt) {
    showToast("Invalid file type. Please upload a .pcap, .pcapng, or .cap capture.", "error");
    return;
  }

  const progContainer = document.getElementById("upload-progress-container");
  const progBar = document.getElementById("upload-progress-bar");
  const fnLabel = document.getElementById("upload-filename");
  const pctLabel = document.getElementById("upload-percentage");

  if (progContainer) progContainer.style.display = "block";
  if (fnLabel) fnLabel.textContent = `Uploading ${file.name} (${formatBytes(file.size)})…`;
  if (progBar) progBar.style.width = "0%";
  if (pctLabel) pctLabel.textContent = "0%";

  const formData = new FormData();
  formData.append("file", file);
  if (_csrfToken) formData.append("csrf_token", _csrfToken);

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/pcap/upload", true);
  if (_csrfToken) xhr.setRequestHeader("X-CSRFToken", _csrfToken);

  xhr.upload.onprogress = function(e) {
    if (e.lengthComputable) {
      const pct = Math.round((e.loaded / e.total) * 100);
      if (progBar) progBar.style.width = `${pct}%`;
      if (pctLabel) pctLabel.textContent = `${pct}%`;
    }
  };

  xhr.onload = function() {
    if (xhr.status >= 200 && xhr.status < 300) {
      try {
        const res = JSON.parse(xhr.responseText);
        if (res.job_id) {
          if (progBar) progBar.style.width = "100%";
          if (pctLabel) pctLabel.textContent = "Queued";
          showToast(`Capture queued for isolated replay (Job: ${res.job_id})`, "success");
          loadPcapJobs();
          startPcapJobPolling(res.job_id);
          setTimeout(() => {
            if (progContainer) progContainer.style.display = "none";
          }, 800);
          return;
        }
      } catch (e) {}
    }

    let errMsg = "Upload failed";
    try {
      const errRes = JSON.parse(xhr.responseText);
      if (errRes.error) errMsg = errRes.error;
    } catch (e) {
      errMsg = `Upload failed (HTTP ${xhr.status})`;
    }
    showToast(errMsg, "error");
    if (progContainer) progContainer.style.display = "none";
  };

  xhr.onerror = function() {
    showToast("Network error during PCAP upload", "error");
    if (progContainer) progContainer.style.display = "none";
  };

  xhr.send(formData);
}

function startPcapJobPolling(jobId) {
  if (_pcapPollInterval) clearInterval(_pcapPollInterval);
  let pollCount = 0;
  const maxPolls = 150; // 5 minutes max at 2s interval

  _pcapPollInterval = setInterval(async () => {
    pollCount++;
    if (pollCount > maxPolls) {
      clearInterval(_pcapPollInterval);
      return;
    }

    try {
      const res = await fetch(`/api/pcap/jobs/${jobId}`).then(r => r.json());
      const job = res.job || res;
      if (job && job.status) {
        loadPcapJobs();
        if (job.status === "completed") {
          clearInterval(_pcapPollInterval);
          showToast(`PCAP Job ${jobId} completed! Found ${job.alert_count || 0} alerts across ${job.processed_packets || 0} packets.`, "success");
        } else if (job.status === "failed") {
          clearInterval(_pcapPollInterval);
          showToast(`PCAP Job ${jobId} failed: ${job.error_message || "Replay error"}`, "error");
        }
      }
    } catch (e) {
      console.warn("Polling error:", e);
    }
  }, 2000);
}

async function loadPcapJobs() {
  try {
    const jobs = await fetch("/api/pcap/jobs").then(r => r.json());
    const tbody = document.getElementById("pcap-jobs-tbody");
    if (!tbody) return;
    if (!jobs.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No PCAP analysis jobs recorded yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = jobs.map(j => {
      const statusColor = j.status === "completed" ? "var(--success)" : (j.status === "failed" ? "var(--danger)" : "var(--accent)");
      return `
        <tr>
          <td><span class="mono-val" style="color:#818cf8;">${escapeHtml(j.job_id)}</span></td>
          <td>${escapeHtml(j.filename)}</td>
          <td><span class="mono-val">${formatBytes(j.file_size)}</span></td>
          <td><strong style="color:${statusColor};text-transform:capitalize;">${escapeHtml(j.status)}</strong></td>
          <td><span class="mono-val">${j.processed_packets || 0}</span></td>
          <td><span class="mono-val" style="color:#f87171;font-weight:600;">${j.alert_count || 0}</span></td>
          <td><span class="mono-val">${(j.duration_s || 0).toFixed(2)}s</span></td>
          <td>
            <a class="btn-secondary" href="/api/pcap/jobs/${j.job_id}/export?format=json" download="${j.job_id}_alerts.json" style="padding:2px 6px;text-decoration:none;">Export JSON</a>
            <a class="btn-secondary" href="/api/pcap/jobs/${j.job_id}/export?format=csv" download="${j.job_id}_alerts.csv" style="padding:2px 6px;text-decoration:none;">Export CSV</a>
          </td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    console.warn("Failed to load pcap jobs:", e);
  }
}

// ── Cases & Incident Management (Phase 7) ──
function openNewCaseModal() {
  const overlay = document.getElementById("case-modal-overlay");
  const modal = document.getElementById("case-modal");
  if (overlay) overlay.classList.add("active");
  if (modal) modal.style.display = "block";
}

function closeNewCaseModal() {
  document.getElementById("case-modal-overlay")?.classList.remove("active");
  const modal = document.getElementById("case-modal");
  if (modal) modal.style.display = "none";
}

async function submitNewCase() {
  const title = document.getElementById("case-title-input")?.value || "";
  const sev = document.getElementById("case-sev-input")?.value || "medium";
  const assignee = document.getElementById("case-assignee-input")?.value || "SOC Analyst";
  const desc = document.getElementById("case-desc-input")?.value || "";

  if (!title) {
    showToast("Title is required", "error");
    return;
  }

  const alertIds = window._pendingCaseAlertIds || [];
  window._pendingCaseAlertIds = [];

  try {
    const res = await fetch("/api/cases", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        title: title,
        severity: sev,
        assigned_to: assignee,
        description: desc,
        alert_ids: alertIds,
      }),
    }).then(r => r.json());

    if (res.status === "ok") {
      showToast(`Created case ${res.case_id}`, "success");
      closeNewCaseModal();
      loadCases();
    } else {
      showToast(res.error || "Case creation failed", "error");
    }
  } catch (e) {
    showToast("Case error", "error");
  }
}

async function loadCases() {
  try {
    const cases = await fetch("/api/cases").then(r => r.json());
    const cols = { open: [], investigating: [], resolved: [], closed: [] };
    cases.forEach(c => {
      const st = (c.status || "open").toLowerCase();
      if (cols[st]) cols[st].push(c);
      else cols.open.push(c);
    });

    ["open", "investigating", "resolved", "closed"].forEach(st => {
      const badge = document.getElementById(`badge-${st}`);
      if (badge) badge.textContent = cols[st].length;
      const container = document.getElementById(`items-${st}`);
      if (!container) return;
      if (!cols[st].length) {
        container.innerHTML = `<div style="font-size:0.72rem;color:var(--text-muted);text-align:center;padding:12px 0;">No cases</div>`;
        return;
      }
      container.innerHTML = cols[st].map(c => `
        <div class="case-card" onclick="viewCaseDetail('${c.case_id}')">
          <div class="case-card-header">
            <span class="case-id">${escapeHtml(c.case_id)}</span>
            <span class="severity-badge sev-${c.severity}">${escapeHtml(c.severity)}</span>
          </div>
          <div class="case-card-title">${escapeHtml(c.title)}</div>
          <div class="case-card-meta">
            <span>👤 ${escapeHtml(c.assigned_to || c.assignee || "Unassigned")}</span>
            <span>🚨 ${c.alert_count || 0} Alerts</span>
          </div>
        </div>
      `).join("");
    });
  } catch (e) {
    console.warn("Failed to load cases:", e);
  }
}

function viewCaseDetail(caseId) {
  _currentCaseId = caseId;
  const overlay = document.getElementById("case-detail-overlay");
  const modal = document.getElementById("case-detail-modal");
  if (overlay) overlay.classList.add("active");
  if (modal) modal.style.display = "block";

  const idEl = document.getElementById("cd-id");
  const titleEl = document.getElementById("cd-title");
  const descEl = document.getElementById("cd-desc");
  const statusSel = document.getElementById("cd-status-select");
  const sevSel = document.getElementById("cd-sev-select");
  const assigneeInput = document.getElementById("cd-assignee-input");
  const sevBadge = document.getElementById("cd-sev-badge");
  const statusBadge = document.getElementById("cd-status-badge");
  const alertCountEl = document.getElementById("cd-alert-count");
  const alertsTbody = document.getElementById("cd-alerts-tbody");
  const notesList = document.getElementById("cd-notes-list");

  if (idEl) idEl.textContent = caseId;
  if (alertsTbody) alertsTbody.innerHTML = `<tr><td colspan="6" class="empty-state">Loading linked alerts…</td></tr>`;
  if (notesList) notesList.innerHTML = `<div style="font-size:0.75rem;color:var(--text-muted);padding:8px 0;">Loading activity notes…</div>`;

  fetch(`/api/cases/${caseId}`).then(r => r.json()).then(data => {
    if (data.error) {
      showToast(data.error, "error");
      closeCaseDetailModal();
      return;
    }
    const c = data.case || {};
    const alerts = data.alerts || [];
    const notes = data.notes || [];

    if (titleEl) titleEl.textContent = c.title || caseId;
    if (descEl) descEl.textContent = c.description || "No description provided.";
    if (statusSel) statusSel.value = (c.status || "open").toLowerCase();
    if (sevSel) sevSel.value = (c.severity || "medium").toLowerCase();
    if (assigneeInput) assigneeInput.value = c.assigned_to || c.assignee || "SOC Analyst";

    if (sevBadge) {
      sevBadge.textContent = (c.severity || "medium").toUpperCase();
      sevBadge.className = `severity-badge sev-${c.severity || "medium"}`;
    }
    if (statusBadge) {
      statusBadge.textContent = (c.status || "open").toUpperCase();
    }
    if (alertCountEl) alertCountEl.textContent = alerts.length;

    if (alertsTbody) {
      if (!alerts.length) {
        alertsTbody.innerHTML = `<tr><td colspan="6" class="empty-state">No detection alerts linked to this case.</td></tr>`;
      } else {
        alertsTbody.innerHTML = alerts.map(a => `
          <tr>
            <td><span class="mono-val">#${a.id}</span></td>
            <td><span class="mono-val">${escapeHtml(a.time_str || '')}</span></td>
            <td><span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span></td>
            <td><span class="ip-cell">${escapeHtml(a.src_ip)}</span></td>
            <td><span class="ip-cell">${escapeHtml(a.dst_ip)}:${a.dst_port || ''}</span></td>
            <td>
              <button class="btn-secondary" style="padding:2px 6px;font-size:0.7rem;" onclick="openInvestigation(${a.id})">🔍 Inspect</button>
            </td>
          </tr>
        `).join("");
      }
    }

    renderCaseNotes(notesList, notes);
  }).catch(e => {
    showToast(`Failed to load case details: ${e.message}`, "error");
  });
}

function renderCaseNotes(container, notes) {
  if (!container) return;
  if (!notes.length) {
    container.innerHTML = `<div style="font-size:0.72rem;color:var(--text-muted);padding:8px 0;">No notes recorded yet.</div>`;
    return;
  }
  container.innerHTML = notes.map(n => `
    <div style="background:rgba(15,23,42,0.6);border-left:3px solid #818cf8;border-radius:4px;padding:6px 10px;">
      <div style="display:flex;justify-content:space-between;font-size:0.68rem;color:var(--text-muted);margin-bottom:2px;">
        <span style="font-weight:600;color:#cbd5e1;">${escapeHtml(n.author || 'Analyst')}</span>
        <span>${escapeHtml(n.time_str || '')}</span>
      </div>
      <div style="font-size:0.75rem;color:#f1f5f9;white-space:pre-wrap;">${escapeHtml(n.note)}</div>
    </div>
  `).join("");
}

function closeCaseDetailModal() {
  document.getElementById("case-detail-overlay")?.classList.remove("active");
  const modal = document.getElementById("case-detail-modal");
  if (modal) modal.style.display = "none";
  loadCases();
}

async function updateCaseAssignee() {
  if (!_currentCaseId) return;
  const assignee = document.getElementById("cd-assignee-input")?.value?.trim() || "";
  try {
    const res = await fetch(`/api/cases/${_currentCaseId}`, {
      method: "PATCH",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ assigned_to: assignee }),
    }).then(r => r.json());
    if (res.status === "ok" || res.status === "no changes") {
      showToast("Assignee updated", "success");
      loadCases();
    } else {
      showToast(res.error || "Update failed", "error");
    }
  } catch (e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

async function updateCaseStatus(newStatus) {
  if (!_currentCaseId || !newStatus) return;
  try {
    const res = await fetch(`/api/cases/${_currentCaseId}`, {
      method: "PATCH",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ status: newStatus }),
    }).then(r => r.json());
    if (res.status === "ok" || res.status === "no changes") {
      showToast(`Case status moved to ${newStatus}`, "success");
      const statusBadge = document.getElementById("cd-status-badge");
      if (statusBadge) statusBadge.textContent = newStatus.toUpperCase();
      loadCases();
    } else {
      showToast(res.error || "Status update failed", "error");
    }
  } catch (e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

async function updateCaseSeverity(newSev) {
  if (!_currentCaseId || !newSev) return;
  try {
    const res = await fetch(`/api/cases/${_currentCaseId}`, {
      method: "PATCH",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ severity: newSev }),
    }).then(r => r.json());
    if (res.status === "ok" || res.status === "no changes") {
      showToast(`Case severity updated to ${newSev}`, "success");
      const sevBadge = document.getElementById("cd-sev-badge");
      if (sevBadge) {
        sevBadge.textContent = newSev.toUpperCase();
        sevBadge.className = `severity-badge sev-${newSev}`;
      }
      loadCases();
    } else {
      showToast(res.error || "Severity update failed", "error");
    }
  } catch (e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

async function submitCaseNote() {
  if (!_currentCaseId) return;
  const input = document.getElementById("cd-new-note");
  const note = input ? input.value.trim() : "";
  if (!note) {
    showToast("Please enter an investigation note", "warning");
    return;
  }

  try {
    const res = await fetch(`/api/cases/${_currentCaseId}/notes`, {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ note, author: "SOC Analyst" }),
    }).then(r => r.json());

    if (res.status === "ok") {
      showToast("Note added to incident log", "success");
      if (input) input.value = "";
      const data = await fetch(`/api/cases/${_currentCaseId}`).then(r => r.json());
      const notesList = document.getElementById("cd-notes-list");
      renderCaseNotes(notesList, data.notes || []);
    } else {
      showToast(res.error || "Failed to add note", "error");
    }
  } catch (e) {
    showToast(`Failed to add note: ${e.message}`, "error");
  }
}

function exportCurrentCaseReport() {
  if (!_currentCaseId) return;
  fetch(`/api/cases/${_currentCaseId}`).then(r => r.json()).then(data => {
    const c = data.case || {};
    const alerts = data.alerts || [];
    const notes = data.notes || [];

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Incident Report: ${escapeHtml(c.title || c.case_id)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; color: #1e293b; line-height: 1.5; }
    h1 { color: #0f172a; margin-bottom: 4px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    .meta-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 16px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px 10px; font-size: 13px; text-align: left; }
    th { background: #f1f5f9; }
    .note-item { border-left: 3px solid #6366f1; padding: 8px 12px; margin-bottom: 8px; background: #f8fafc; }
  </style>
</head>
<body>
  <h1>NetGuard IDS — Incident Investigation Report</h1>
  <div style="font-size:14px;color:#64748b;margin-bottom:16px;">Case Reference: <strong>${escapeHtml(c.case_id)}</strong> | Generated: ${new Date().toISOString()}</div>

  <div class="meta-box">
    <div><strong>Incident Title:</strong> ${escapeHtml(c.title)}</div>
    <div><strong>Status:</strong> ${escapeHtml(c.status)} | <strong>Severity:</strong> ${escapeHtml(c.severity)} | <strong>Assigned:</strong> ${escapeHtml(c.assigned_to || c.assignee || 'Unassigned')}</div>
    <div><strong>Created:</strong> ${escapeHtml(c.created_str || '—')} | <strong>Last Updated:</strong> ${escapeHtml(c.updated_str || '—')}</div>
    <div style="margin-top:10px;"><strong>Summary / Scope:</strong><br>${escapeHtml(c.description || 'No description.')}</div>
  </div>

  <h2>Associated Security Alerts (${alerts.length})</h2>
  <table>
    <thead><tr><th>ID</th><th>Timestamp</th><th>Rule</th><th>Severity</th><th>Source</th><th>Destination</th><th>Details</th></tr></thead>
    <tbody>
      ${alerts.map(a => `<tr><td>#${a.id}</td><td>${escapeHtml(a.time_str || '')}</td><td>${escapeHtml(a.rule_name)}</td><td>${escapeHtml(a.severity)}</td><td>${escapeHtml(a.src_ip)}</td><td>${escapeHtml(a.dst_ip)}:${a.dst_port||''}</td><td>${escapeHtml(a.detail||'')}</td></tr>`).join('')}
    </tbody>
  </table>

  <h2 style="margin-top:24px;">Analyst Notes &amp; Findings (${notes.length})</h2>
  ${notes.length === 0 ? '<p>No investigative notes recorded.</p>' : notes.map(n => `
    <div class="note-item">
      <div style="font-size:12px;color:#64748b;"><strong>${escapeHtml(n.author || 'Analyst')}</strong> — ${escapeHtml(n.time_str || '')}</div>
      <div style="margin-top:4px;">${escapeHtml(n.note)}</div>
    </div>
  `).join('')}
</body>
</html>`;

    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `case_${c.case_id}_report.html`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Incident report downloaded", "success");
  });
}

function closeCurrentCase() {
  updateCaseStatus('closed');
  const sel = document.getElementById("cd-status-select");
  if (sel) sel.value = "closed";
}

// ── Reports Generation (Phase 8) ──
function triggerReportDownload() {
  const type = document.getElementById("report-type-select")?.value || "daily";
  const fmt = document.getElementById("report-fmt-select")?.value || "html";
  const hours = document.getElementById("report-hours-select")?.value || "24";
  showToast(`Generating ${type} report (${fmt.toUpperCase()})…`, "success");
  window.location.href = `/api/reports/generate?type=${encodeURIComponent(type)}&format=${encodeURIComponent(fmt)}&hours=${encodeURIComponent(hours)}`;
}

// ── Network Devices (Phase 3) ──
async function loadDevices() {
  try {
    const devices = await fetch("/api/devices").then(r => r.json());
    const tbody = document.getElementById("devices-tbody");
    const badge = document.getElementById("devices-badge");
    const dc = document.getElementById("device-count");
    if (badge) badge.textContent = devices.length;
    if (dc) dc.textContent = devices.length;
    if (!tbody) return;
    if (!devices.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No network devices recorded.</td></tr>`;
      return;
    }
    tbody.innerHTML = devices.map(d => {
      const isRandomized = d.vendor === "Randomized / Private MAC";
      const vendorBadge = isRandomized
        ? `<span class="rule-badge" style="background:rgba(168,85,247,0.15);color:#c084fc;">Randomized / Private MAC</span>`
        : escapeHtml(d.vendor || "Unknown");
      return `
        <tr>
          <td><span class="mac">${escapeHtml(d.mac)}</span></td>
          <td><span class="ip-cell">${escapeHtml(d.ip || "—")}</span></td>
          <td>${vendorBadge}</td>
          <td><span class="mono-val">${escapeHtml(d.first_seen_str || "—")}</span></td>
          <td><span class="mono-val">${escapeHtml(d.last_seen_str || "—")}</span></td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    console.warn("Devices load failed:", e);
  }
}

// ── Rule Health & Tuning Precision (Phase 6) ──
async function loadRuleHealth() {
  try {
    const [statsRes, rulesRes] = await Promise.all([
      fetch("/api/feedback/stats").then(r => r.json()),
      fetch("/api/rules").then(r => r.json()),
    ]);
    const stats = statsRes.stats || {};
    const rules = Array.isArray(rulesRes) ? rulesRes : [];
    const tbody = document.getElementById("rule-health-tbody");
    if (!tbody) return;
    if (!rules.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No rules registered.</td></tr>`;
      return;
    }

    tbody.innerHTML = rules.map(r => {
      const s = stats[r.rule_name] || { true_positive: 0, false_positive: 0 };
      const tp = s.true_positive;
      const fp = s.false_positive;
      const total = tp + fp;
      const prec = total > 0 ? ((tp / total) * 100).toFixed(1) + "%" : "N/A (No reviews yet)";
      let rec = "Awaiting Analyst Reviews (Sample N=0)";
      if (total > 0) {
        rec = "Optimal Threshold";
        if (fp > 5 && fp > tp) rec = "Consider Raising Threshold or Port Scope";
        else if (tp > 10 && fp === 0) rec = "High-Fidelity Deterministic Signature";
      }

      return `
        <tr>
          <td><span class="rule-badge rule-${r.rule_name}">${escapeHtml(r.rule_name)}</span></td>
          <td><span style="font-size:0.75rem;color:var(--text-muted);text-transform:capitalize;">${escapeHtml(r.category || "Network")}</span></td>
          <td><span class="mono-val" style="color:#34d399;font-weight:600;">${tp}</span></td>
          <td><span class="mono-val" style="color:#f87171;font-weight:600;">${fp}</span></td>
          <td><span class="mono-val">${prec}</span></td>
          <td style="font-size:0.74rem;color:#94a3b8;">${rec}</td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    console.warn("Rule health load failed:", e);
  }
}

// ── Settings & Notification Wizard (Phase 6 & 10) ──
function showNotifTab(name) {
  ["email", "telegram", "webhook", "sms"].forEach(t => {
    const btn = document.getElementById(`tab-btn-${t}`);
    const pane = document.getElementById(`notif-tab-${t}`);
    if (btn) {
      if (t === name) {
        btn.classList.add("btn-primary");
        btn.classList.remove("btn-secondary");
      } else {
        btn.classList.remove("btn-primary");
        btn.classList.add("btn-secondary");
      }
    }
    if (pane) {
      pane.style.display = (t === name) ? "block" : "none";
    }
  });
}

function applySmtpPreset(preset) {
  const host = document.getElementById("cfg-smtp-host");
  const port = document.getElementById("cfg-smtp-port");
  const from = document.getElementById("cfg-smtp-from");

  if (preset === "gmail") {
    if (host) host.value = "smtp.gmail.com";
    if (port) port.value = "587";
    if (from && !from.value) from.value = "netguard-alerts@example.com";
  } else if (preset === "office365") {
    if (host) host.value = "smtp.office365.com";
    if (port) port.value = "587";
    if (from && !from.value) from.value = "netguard-alerts@example.com";
  } else if (preset === "local") {
    if (host) host.value = "localhost";
    if (port) port.value = "25";
    if (from && !from.value) from.value = "ids@localhost";
  }
}

async function loadNotificationConfig() {
  try {
    const configs = await fetch("/api/notifications/config").then(r => r.json());
    if (configs.email) {
      const e = configs.email;
      if (e.host && document.getElementById("cfg-smtp-host")) document.getElementById("cfg-smtp-host").value = e.host;
      if (e.port && document.getElementById("cfg-smtp-port")) document.getElementById("cfg-smtp-port").value = e.port;
      if (e.user && document.getElementById("cfg-smtp-user")) document.getElementById("cfg-smtp-user").value = e.user;
      if (e.from_addr && document.getElementById("cfg-smtp-from")) document.getElementById("cfg-smtp-from").value = e.from_addr;
      if (e.to_addr && document.getElementById("cfg-smtp-to")) document.getElementById("cfg-smtp-to").value = e.to_addr;
    }
    if (configs.telegram) {
      const t = configs.telegram;
      if (t.chat_id && document.getElementById("cfg-tg-chat")) document.getElementById("cfg-tg-chat").value = t.chat_id;
    }
    if (configs.webhook) {
      const w = configs.webhook;
      if (w.url && document.getElementById("cfg-wh-url")) document.getElementById("cfg-wh-url").value = w.url;
    }
    if (configs.sms) {
      const sm = configs.sms;
      if (sm.account_sid && document.getElementById("cfg-sms-sid")) document.getElementById("cfg-sms-sid").value = sm.account_sid;
      if (sm.from_number && document.getElementById("cfg-sms-from")) document.getElementById("cfg-sms-from").value = sm.from_number;
      if (sm.to_number && document.getElementById("cfg-sms-to")) document.getElementById("cfg-sms-to").value = sm.to_number;
    }
  } catch (e) {
    console.warn("Failed to load notification settings:", e);
  }
}

async function saveNotificationProvider(provider) {
  let cfg = {};
  if (provider === "email" || provider === "smtp") {
    provider = "email";
    cfg = {
      host: document.getElementById("cfg-smtp-host")?.value?.trim() || "",
      port: parseInt(document.getElementById("cfg-smtp-port")?.value || 587, 10),
      user: document.getElementById("cfg-smtp-user")?.value?.trim() || "",
      from_addr: document.getElementById("cfg-smtp-from")?.value?.trim() || "",
      to_addr: document.getElementById("cfg-smtp-to")?.value?.trim() || "",
      use_tls: true,
    };
    const pass = document.getElementById("cfg-smtp-pass")?.value?.trim();
    if (pass) cfg.password = pass;
  } else if (provider === "telegram") {
    cfg = {
      chat_id: document.getElementById("cfg-tg-chat")?.value?.trim() || "",
    };
    const token = document.getElementById("cfg-tg-token")?.value?.trim();
    if (token) cfg.bot_token = token;
  } else if (provider === "webhook") {
    cfg = {
      url: document.getElementById("cfg-wh-url")?.value?.trim() || "",
    };
    const secret = document.getElementById("cfg-wh-secret")?.value?.trim();
    if (secret) cfg.secret = secret;
  } else if (provider === "sms") {
    cfg = {
      account_sid: document.getElementById("cfg-sms-sid")?.value?.trim() || "",
      from_number: document.getElementById("cfg-sms-from")?.value?.trim() || "",
      to_number: document.getElementById("cfg-sms-to")?.value?.trim() || "",
    };
    const token = document.getElementById("cfg-sms-token")?.value?.trim();
    if (token) cfg.auth_token = token;
  }

  try {
    const res = await fetch("/api/notifications/config", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ provider, config: cfg }),
    }).then(r => r.json());

    if (res.status === "ok") {
      showToast(`${provider.toUpperCase()} provider settings saved`, "success");
      loadSettings();
    } else {
      showToast(res.error || "Save failed", "error");
    }
  } catch (e) {
    showToast(`Error saving configuration: ${e.message}`, "error");
  }
}

async function testNotificationProvider(provider) {
  let customCfg = {};
  let recipient = null;

  if (provider === "email" || provider === "smtp") {
    provider = "email";
    recipient = document.getElementById("cfg-smtp-to")?.value?.trim() || undefined;
    customCfg = {
      host: document.getElementById("cfg-smtp-host")?.value?.trim() || "",
      port: parseInt(document.getElementById("cfg-smtp-port")?.value || 587, 10),
      user: document.getElementById("cfg-smtp-user")?.value?.trim() || "",
      from_addr: document.getElementById("cfg-smtp-from")?.value?.trim() || "",
      to_addr: recipient,
      use_tls: true,
    };
    const pass = document.getElementById("cfg-smtp-pass")?.value?.trim();
    if (pass) customCfg.password = pass;
  } else if (provider === "telegram") {
    recipient = document.getElementById("cfg-tg-chat")?.value?.trim() || undefined;
    const token = document.getElementById("cfg-tg-token")?.value?.trim();
    if (token) customCfg.bot_token = token;
    if (recipient) customCfg.chat_id = recipient;
  } else if (provider === "webhook") {
    recipient = document.getElementById("cfg-wh-url")?.value?.trim() || undefined;
    if (recipient) customCfg.url = recipient;
    const secret = document.getElementById("cfg-wh-secret")?.value?.trim();
    if (secret) customCfg.secret = secret;
  } else if (provider === "sms") {
    recipient = document.getElementById("cfg-sms-to")?.value?.trim() || undefined;
    customCfg = {
      account_sid: document.getElementById("cfg-sms-sid")?.value?.trim() || "",
      from_number: document.getElementById("cfg-sms-from")?.value?.trim() || "",
      to_number: recipient,
    };
    const token = document.getElementById("cfg-sms-token")?.value?.trim();
    if (token) customCfg.auth_token = token;
  }

  showToast(`Dispatching diagnostic test for ${provider.toUpperCase()}…`, "info");

  try {
    const res = await fetch("/api/notifications/test", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ provider, custom_cfg: customCfg, recipient }),
    }).then(r => r.json());

    if (res.success || res.status === "ok") {
      showToast(res.message || `Test notification sent via ${provider}`, "success");
    } else {
      showToast(res.error || res.message || "Test dispatch failed", "error");
    }
  } catch (e) {
    showToast(`Test error: ${e.message}`, "error");
  }
}

async function loadSettings() {
  // 1. Providers
  try {
    const provs = await fetch("/api/notifications/providers").then(r => r.json());
    const grid = document.getElementById("providers-status-grid");
    if (grid) {
      grid.innerHTML = Object.entries(provs).map(([name, p]) => `
        <div style="background:rgba(30,41,59,0.5);border:1px solid var(--border);border-radius:6px;padding:10px 14px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <strong style="text-transform:capitalize;font-size:0.82rem;">${escapeHtml(name)}</strong>
            <span style="color:${p.configured ? 'var(--success)' : 'var(--text-muted)'};font-size:0.72rem;">${p.configured ? 'Active' : 'Unconfigured'}</span>
          </div>
          <div style="font-size:0.7rem;color:var(--text-muted);">${escapeHtml(p.adapter || "")}</div>
        </div>
      `).join("");
    }
  } catch (e) {}

  // 2. Telemetry
  try {
    const sys = await fetch("/api/system/metrics").then(r => r.json());
    const box = document.getElementById("system-telemetry-box");
    if (box) {
      box.innerHTML = `
        Uptime: <strong>${sys.uptime_str || "—"}</strong> · Storage: <strong>${sys.storage.db_size_mb} MB (${sys.storage.db_backend})</strong><br/>
        Hardware Cores: <strong>${sys.capabilities.physical_cores ?? "—"} Physical (${sys.capabilities.effective_cpu_quota ?? "—"} Effective Quota)</strong><br/>
        Available RAM: <strong>${(sys.capabilities.available_ram_mb ?? 0).toFixed(0)} MB</strong> · 1m Load Avg: <strong>${(sys.capabilities.load_1m ?? 0).toFixed(2)}</strong><br/>
        Parallel Engine Profile: <strong style="color:#818cf8;">${sys.performance_profile.name || "auto"} (${sys.performance_profile.workers || 1} workers)</strong>
      `;
    }
  } catch (e) {}

  // 3. Audit trail
  try {
    const logs = await fetch("/api/audit-log?limit=20").then(r => r.json());
    const tbody = document.getElementById("audit-log-tbody");
    if (tbody) {
      if (!logs.length) tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No audit entries.</td></tr>`;
      else {
        tbody.innerHTML = logs.map(l => `
          <tr>
            <td><span class="mono-val">${escapeHtml(l.time_str)}</span></td>
            <td><span class="mono-val">${escapeHtml(l.user_identity)}</span></td>
            <td><span class="rule-badge" style="background:rgba(99,102,241,0.15);color:#818cf8;">${escapeHtml(l.action)}</span></td>
            <td>${escapeHtml(l.resource_type)} ${l.resource_id ? '#' + escapeHtml(l.resource_id) : ''}</td>
            <td class="alert-detail-cell">${escapeHtml(JSON.stringify(l.details || {}))}</td>
          </tr>
        `).join("");
      }
    }
  } catch (e) {}
}

async function sendTestNotification() {
  try {
    const res = await fetch("/api/notifications/test", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ provider: "webhook" }),
    }).then(r => r.json());
    showToast(res.message || "Test dispatched", "success");
    loadSettings();
  } catch (e) {
    showToast("Test notification failed", "error");
  }
}

async function toggleBaselineQuarantine() {
  try {
    const status = await fetch("/api/baselines").then(r => r.json());
    const target = !(status.quarantine_active ?? false);
    const res = await fetch("/api/baselines/quarantine", {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ quarantine: target }),
    }).then(r => r.json());
    showToast(`Quarantine mode: ${res.quarantined ? 'ENABLED (Frozen)' : 'DISABLED (Active)'}`, "success");
    const btn = document.getElementById("quarantine-toggle-btn");
    if (btn) btn.textContent = res.quarantined ? "Disable Quarantine" : "Enable Quarantine";
  } catch (e) {
    showToast("Quarantine toggle failed", "error");
  }
}

// ── SSE Live Streaming ──
function initSse() {
  if (typeof EventSource === "undefined") {
    console.warn("EventSource not supported; falling back to 30s polling.");
    return;
  }
  _sseSource = new EventSource("/api/stream");
  _sseSource.onmessage = function (event) {
    try {
      const alert = JSON.parse(event.data);
      if (!alert || !alert.id) return;
      _alertsCache.unshift(alert);
      if (_alertsCache.length > 500) _alertsCache.pop();

      if (_activeTab === "live") {
        renderFilteredAlerts();
        const badge = document.getElementById("alerts-badge");
        if (badge) badge.textContent = _alertsCache.length;
        const navBadge = document.getElementById("nav-alerts-badge");
        if (navBadge) navBadge.textContent = _alertsCache.length;
      }
      prependRecentAlert(alert);
    } catch (e) {
      console.error("SSE parse error:", e);
    }
  };
  _sseSource.onerror = function () {
    console.warn("SSE connection error; reconnecting in 5s...");
  };
}

// ── Helper: Format Bytes ──
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

// ── Full Refresh ──
function refreshAll() {
  loadRuleMetadata();
  loadStatus();
  loadObservations();
  loadChart();
  if (_activeTab === "live") loadLiveAlerts();
  else loadHistory(_historyDays);
  calLoadTodaySummary();
}

// ── App Startup ──
document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  initChart();
  loadRuleMetadata();
  loadStatus();
  loadObservations();
  loadChart();
  loadLiveAlerts();
  loadRecentAlerts();
  renderCalendar(_calYear, _calMonth);
  calLoadTodaySummary();
  initSse();

  // Attach Drag-and-Drop to PCAP Drop Zone
  const dropZone = document.getElementById("pcap-drop-zone");
  if (dropZone) {
    ["dragenter", "dragover"].forEach(evt => {
      dropZone.addEventListener(evt, e => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = "var(--accent)";
      });
    });
    ["dragleave", "drop"].forEach(evt => {
      dropZone.addEventListener(evt, e => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = "var(--border)";
      });
    });
    dropZone.addEventListener("drop", e => {
      const dt = e.dataTransfer;
      const files = dt ? dt.files : null;
      if (files && files.length > 0) {
        handlePcapFileUpload(files[0]);
      }
    });
  }

  // Periodic polling for non-SSE panels
  setInterval(() => {
    loadStatus();
    loadObservations();
    loadChart();
  }, 30000);
});
