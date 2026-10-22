/* dashboard/static/dashboard.js
   All dashboard data fetching, rendering, and Chart.js setup.
   Live alerts via SSE (Server-Sent Events). Other panels refresh every 30s.
*/

"use strict";

// ── Chart instance (global so we can update it) ──
let activityChart = null;

// ── SSE connection (global) ──
let _sseSource = null;

// ── Initialise chart with empty data ──
function initChart() {
  const ctx = document.getElementById("activityChart").getContext("2d");
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
            font: { family: "'Inter', sans-serif", size: 11 },
            boxWidth: 12,
            padding: 16,
          },
        },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          borderColor: "rgba(99, 130, 255, 0.2)",
          borderWidth: 1,
          titleColor: "#e2e8f0",
          bodyColor: "#94a3b8",
          cornerRadius: 8,
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

// ── Client-side alerts cache & filter state ──
let _alertsCache = [];

function matchesFilter(a, query, ruleFilter, sevFilter) {
  if (ruleFilter !== "ALL" && a.rule_name !== ruleFilter) return false;
  if (sevFilter !== "ALL" && (a.severity || "medium").toLowerCase() !== sevFilter.toLowerCase()) return false;
  if (query) {
    const q = query.toLowerCase();
    const str = [
      a.rule_name, a.src_ip, a.dst_ip, a.dst_port,
      a.country, a.city, a.detail, a.time_str, a.datetime_str
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

  const isHistory = _activeTab === "history";
  const metaText = document.getElementById("filter-meta-text");
  if (metaText) {
    if (query || ruleFilter !== "ALL" || sevFilter !== "ALL") {
      metaText.textContent = `Showing ${filtered.length} of ${_alertsCache.length} alerts`;
    } else {
      metaText.textContent = `Showing all ${_alertsCache.length} alerts`;
    }
  }

  if (!filtered.length) {
    const emptyMsg = _alertsCache.length === 0
      ? (isHistory ? `No alerts in the last ${_historyDays} day(s).` : "No alerts in the last hour.")
      : "No alerts match your filter criteria.";
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state">${emptyMsg}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(isHistory ? buildHistoryRow : buildAlertRow).join("");
}

// ── Fetch & render status ──
async function loadStatus() {
  try {
    const data = await fetch("/api/status").then(r => r.json());
    const level = data.threat_level || "clear";
    const label = level.charAt(0).toUpperCase() + level.slice(1);
    const dot   = document.getElementById("status-dot");
    const badge = document.getElementById("status-label");
    dot.className = "status-dot " + level;
    badge.textContent = label + " Threat";
    const tv = document.getElementById("threat-level");
    tv.textContent = label;
    tv.className = "stat-value " + level;
    document.getElementById("alert-count").textContent = data.alert_count_1h ?? 0;
    const scans = (data.rule_breakdown || {})["PORT_SCAN"] ?? 0;
    document.getElementById("scan-count").textContent = scans;
    document.getElementById("server-time").textContent = data.server_time || "";
    if (data.active_rules_count) {
      const activeEl = document.getElementById("rules-active-label");
      if (activeEl) activeEl.textContent = `${data.active_rules_count} Rules Active`;
    }
  } catch (e) {
    console.error("Status fetch failed:", e);
  }
}

// ── Fetch & render observations ──
async function loadObservations() {
  try {
    const data = await fetch("/api/observations").then(r => r.json());
    const list = document.getElementById("observations-list");
    document.getElementById("obs-count").textContent = data.length;
    if (!data.length) {
      list.innerHTML = '<div class="loading-state">No observations yet.</div>';
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

// ── Build one alert <tr> from an alert object ──
function buildAlertRow(a) {
  const flag    = escapeHtml(a.flag || "🌐");
  const country = escapeHtml(a.country || "");
  const city    = escapeHtml(a.city || "");
  const geo     = country ? flag + " " + country + (city ? ", " + city : "") : flag;

  return `
    <tr id="alert-row-${a.id}">
      <td><span class="mac">${escapeHtml(a.time_str || "")}</span></td>
      <td><span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span></td>
      <td><span class="ip">${escapeHtml(a.src_ip || "—")}</span></td>
      <td><span class="ip">${escapeHtml(a.dst_ip || "—")}</span></td>
      <td><span class="mac">${a.dst_port || "—"}</span></td>
      <td><span class="geo-cell" title="${escapeHtml(a.country || "Unknown")}">${geo}</span></td>
      <td><span class="severity-badge sev-${a.severity}">${escapeHtml(a.severity || "medium")}</span></td>
      <td class="detail-cell" title="${escapeHtml(a.detail || "")}">${escapeHtml(a.detail || "")}</td>
      <td><button class="btn-investigate" onclick="openInvestigation(${a.id})">🔍 Investigate</button></td>
    </tr>
  `;
}

// ── Fetch & render full alerts table ──
async function loadAlerts() {
  try {
    const data = await fetch("/api/alerts").then(r => r.json());
    _alertsCache = Array.isArray(data) ? data : [];
    document.getElementById("alerts-badge").textContent = _alertsCache.length;
    renderFilteredAlerts();
  } catch (e) {
    console.error("Alerts fetch failed:", e);
  }
}

// ── SSE: live alert injection ──
function initSSE() {
  if (_sseSource) _sseSource.close();
  _sseSource = new EventSource("/api/stream");

  _sseSource.onmessage = (e) => {
    try {
      const alert = JSON.parse(e.data);
      // Prepend to memory cache (keep max 5000 items)
      _alertsCache.unshift(alert);
      if (_alertsCache.length > 5000) _alertsCache.pop();

      // Render respecting current active filter
      renderFilteredAlerts();
      showToast(alert);
      const badge = document.getElementById("alerts-badge");
      if (badge) badge.textContent = _alertsCache.length.toString();
      loadStatus();
    } catch (err) {
      console.warn("SSE parse error:", err);
    }
  };

  _sseSource.onerror = () => {
    console.warn("SSE lost — reconnecting in 5s");
    _sseSource.close();
    setTimeout(initSSE, 5000);
  };
}

// ── Toast notification ──
let _toastTimeout = null;
function showToast(alert) {
  let toast = document.getElementById("live-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "live-toast";
    toast.className = "live-toast";
    document.body.appendChild(toast);
  }
  const sev = alert.severity === "high" ? "🔴" : "⚠️";
  toast.innerHTML = sev + " <strong>" + escapeHtml(alert.rule_name) + "</strong> — " + escapeHtml(alert.src_ip || "unknown");
  toast.classList.add("toast-show");
  clearTimeout(_toastTimeout);
  _toastTimeout = setTimeout(() => toast.classList.remove("toast-show"), 4000);
}

// ── Investigation Modal ──
let _currentAlertId = null;

async function openInvestigation(alertId) {
  _currentAlertId = alertId;
  document.getElementById("modal-feedback-result").textContent = "";
  document.getElementById("analyst-note").value = "";
  try {
    const alert = await fetch("/api/alerts/" + alertId).then(r => r.json());
    document.getElementById("modal-title").textContent =
      "Investigating Alert #" + alertId + " — " + (alert.rule_name || "");

    const flag    = alert.flag || "🌐";
    const country = alert.country || "";
    const city    = alert.city || "";
    const geoStr  = country ? flag + " " + country + (city ? ", " + city : "") : flag;

    const meta = [
      { label: "Time",        value: alert.time_str || "—" },
      { label: "Rule",        value: alert.rule_name || "—" },
      { label: "Source IP",   value: alert.src_ip || "—" },
      { label: "Destination", value: alert.dst_ip || "—" },
      { label: "Port",        value: alert.dst_port != null ? alert.dst_port : "—" },
      { label: "Severity",    value: alert.severity || "—" },
      { label: "Origin",      value: geoStr },
    ];
    document.getElementById("modal-meta").innerHTML = meta.map(m => `
      <div class="meta-item">
        <div class="meta-label">${escapeHtml(m.label)}</div>
        <div class="meta-value">${escapeHtml(String(m.value))}</div>
      </div>
    `).join("");

    document.getElementById("modal-explanation").textContent = alert.explanation || "";
    document.getElementById("modal-detail").textContent = alert.detail || "No detail available.";

    const evBox = document.getElementById("modal-evidence");
    const evSec = document.getElementById("modal-evidence-section");
    if (evBox && evSec) {
      if (alert.evidence) {
        evBox.textContent = typeof alert.evidence === "object"
          ? JSON.stringify(alert.evidence, null, 2)
          : String(alert.evidence);
        evSec.style.display = "block";
      } else {
        evSec.style.display = "none";
      }
    }

    if (alert.feedback) {
      const fb = alert.feedback;
      const cls = fb.classification === "true_positive" ? "✅ True Positive" : "❌ False Positive";
      document.getElementById("existing-feedback").innerHTML =
        "<strong>" + escapeHtml(cls) + "</strong>" + (fb.analyst_note ? " — " + escapeHtml(fb.analyst_note) : "");
      document.getElementById("existing-feedback-section").style.display = "block";
    } else {
      document.getElementById("existing-feedback-section").style.display = "none";
    }

    document.getElementById("modal-overlay").classList.add("open");
    document.getElementById("investigation-modal").classList.add("open");
  } catch(e) {
    console.error("Investigation fetch failed:", e);
  }
}

function closeModal() {
  document.getElementById("modal-overlay").classList.remove("open");
  document.getElementById("investigation-modal").classList.remove("open");
  _currentAlertId = null;
}

async function submitFeedback(classification) {
  if (!_currentAlertId) return;
  const note = document.getElementById("analyst-note").value.trim();
  const resultEl = document.getElementById("modal-feedback-result");
  try {
    const res = await fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: _currentAlertId, classification, analyst_note: note }),
    });
    const data = await res.json();
    if (data.status === "ok") {
      const label = classification === "true_positive" ? "✅ Marked as True Positive" : "❌ Marked as False Positive";
      resultEl.style.color = classification === "true_positive" ? "#34d399" : "#f87171";
      resultEl.textContent = label + " — saved to feedback log.";
      document.getElementById("existing-feedback").textContent = label + (note ? " — " + note : "");
      document.getElementById("existing-feedback-section").style.display = "block";
    } else {
      resultEl.style.color = "#f87171";
      resultEl.textContent = "Error: " + (data.error || "Unknown error");
    }
  } catch(e) {
    resultEl.style.color = "#f87171";
    resultEl.textContent = "Network error — feedback not saved.";
  }
}

document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

// ── Chart ──
async function loadChart() {
  try {
    const data = await fetch("/api/chart").then(r => r.json());
    if (!activityChart) return;
    activityChart.data.labels   = data.labels   || [];
    activityChart.data.datasets = data.datasets || [];
    activityChart.update("active");
  } catch (e) {
    console.error("Chart fetch failed:", e);
  }
}

// ── Devices (with vendor) ──
async function loadDevices() {
  try {
    const data = await fetch("/api/devices").then(r => r.json());
    const tbody = document.getElementById("devices-tbody");
    document.getElementById("devices-badge").textContent = data.length;
    document.getElementById("device-count").textContent  = data.length;
    if (!data.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No devices detected yet.</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(d => `
      <tr>
        <td><span class="mac">${escapeHtml(d.mac || "—")}</span></td>
        <td><span class="ip">${escapeHtml(d.ip  || "—")}</span></td>
        <td><span class="vendor-badge">${escapeHtml(d.vendor || "Unknown")}</span></td>
        <td><span class="mac">${escapeHtml(d.first_seen_str || "—")}</span></td>
        <td><span class="mac">${escapeHtml(d.last_seen_str  || "—")}</span></td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Devices fetch failed:", e);
  }
}

// ── Refresh everything ──
async function refreshAll() {
  const btn = document.getElementById("refresh-btn");
  btn.classList.add("spinning");
  await Promise.all([
    loadStatus(),
    loadObservations(),
    loadAlerts(),
    loadChart(),
    loadDevices(),
  ]);
  btn.classList.remove("spinning");
}

// ── XSS guard ──
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── History tab state ──
let _activeTab      = "live";   // "live" | "history"
let _historyDays    = 7;

// ── Switch between Live and History tabs ──
function switchAlertsTab(tab) {
  _activeTab = tab;
  document.getElementById("tab-live").classList.toggle("active", tab === "live");
  document.getElementById("tab-history").classList.toggle("active", tab === "history");
  const rangeEl = document.getElementById("history-range");
  rangeEl.style.display = tab === "history" ? "flex" : "none";

  const thead = document.getElementById("alerts-thead");
  if (tab === "history") {
    thead.innerHTML = `<tr>
      <th>Date &amp; Time</th><th>Rule</th><th>Source IP</th>
      <th>Destination IP</th><th>Port</th><th>Origin</th>
      <th>Severity</th><th>Details</th><th>Classify</th>
    </tr>`;
    loadHistory(_historyDays);
  } else {
    thead.innerHTML = `<tr>
      <th>Time</th><th>Rule</th><th>Source IP</th>
      <th>Destination IP</th><th>Port</th><th>Origin</th>
      <th>Severity</th><th>Details</th><th>Classify</th>
    </tr>`;
    loadAlerts();
  }
}

// ── Build a history alert row (shows full datetime) ──
function buildHistoryRow(a) {
  const flag    = escapeHtml(a.flag || "🌐");
  const country = escapeHtml(a.country || "");
  const city    = escapeHtml(a.city || "");
  const geo     = country ? flag + " " + country + (city ? ", " + city : "") : flag;
  const dt      = escapeHtml(a.datetime_str || a.date_str || a.time_str || "");
  return `
    <tr id="alert-row-${a.id}">
      <td><span class="mac">${dt}</span></td>
      <td><span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span></td>
      <td><span class="ip">${escapeHtml(a.src_ip || "—")}</span></td>
      <td><span class="ip">${escapeHtml(a.dst_ip || "—")}</span></td>
      <td><span class="mac">${a.dst_port || "—"}</span></td>
      <td><span class="geo-cell" title="${escapeHtml(a.country || "Unknown")}">${geo}</span></td>
      <td><span class="severity-badge sev-${a.severity}">${escapeHtml(a.severity || "medium")}</span></td>
      <td class="detail-cell" title="${escapeHtml(a.detail || "")}">${escapeHtml(a.detail || "")}</td>
      <td><button class="btn-investigate" onclick="openInvestigation(${a.id})">🔍 Investigate</button></td>
    </tr>
  `;
}

// ── Load history for N days ──
async function loadHistory(days) {
  _historyDays = days;
  // Update active range button
  [1, 3, 7].forEach(d => {
    const btn = document.getElementById("range-" + d);
    if (btn) btn.classList.toggle("active", d === days);
  });
  const tbody = document.getElementById("alerts-tbody");
  tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Loading history…</td></tr>';
  try {
    const data = await fetch("/api/alerts/history?days=" + days).then(r => r.json());
    _alertsCache = data.alerts || [];
    document.getElementById("alerts-badge").textContent = data.total ?? _alertsCache.length;
    renderFilteredAlerts();
  } catch (e) {
    console.error("History fetch failed:", e);
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Failed to load history.</td></tr>';
  }
}

// ── Boot ──
document.addEventListener("DOMContentLoaded", () => {
  initChart();
  refreshAll();
  initSSE();                         // start live push stream
  setInterval(refreshAll, 30_000);   // keep status/chart/obs in sync
  calInit();                         // boot calendar with current month
});

// =============================================================================
// ═══════════════════════ CALENDAR LOG VIEWER ══════════════════════════════════
// =============================================================================

const CAL_MONTHS = [
  "January","February","March","April","May","June",
  "July","August","September","October","November","December"
];

// State
let _calYear  = new Date().getFullYear();
let _calMonth = new Date().getMonth() + 1;   // 1-based
let _calDayData = {};   // date_str → {count, has_high}
let _calSelectedDay = null;

// Initialise calendar on page load
function calInit() {
  renderCalendar(_calYear, _calMonth);
  calLoadTodaySummary();
}

// Load today's stats + plain-language observations into the right panel
async function calLoadTodaySummary(dateStr) {
  const today = new Date();
  const ds = dateStr || `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2,'0')}-${String(today.getDate()).padStart(2,'0')}`;
  const label = dateStr ? `Summary: ${ds}` : "Today's Summary";
  document.getElementById("cal-summary-label").textContent = label;

  try {
    const [dayData, obsData] = await Promise.all([
      fetch(`/api/alerts/by-date?date=${ds}`).then(r => r.json()),
      fetch('/api/observations').then(r => r.json())
    ]);

    const alerts = dayData.alerts || [];
    const total  = alerts.length;
    const high   = alerts.filter(a => a.severity === 'high').length;

    // Top rule by count
    const ruleCounts = {};
    alerts.forEach(a => { ruleCounts[a.rule_name] = (ruleCounts[a.rule_name] || 0) + 1; });
    const topRule = Object.entries(ruleCounts).sort((a,b) => b[1]-a[1])[0]?.[0] || '—';

    document.getElementById('cal-stat-total').textContent = total || '0';
    document.getElementById('cal-stat-high').textContent  = high  || '0';
    document.getElementById('cal-stat-rule').textContent  = topRule.replace(/_/g,' ');

    // Plain-language observations
    const obsList = document.getElementById('cal-obs-list');
    const obs = (obsData.observations || []).slice(0, 8);
    if (!obs.length) {
      obsList.innerHTML = '<div class="cal-obs-item cal-obs-empty">No observations yet — network looks quiet.</div>';
    } else {
      obsList.innerHTML = obs.map(o => {
        const sev = o.rule_name ? (o.rule_name.includes('HIGH') || o.rule_name.includes('FLOOD') ? 'sev-high' :
                     o.rule_name.includes('SCAN') ? 'sev-medium' : 'sev-low') : 'sev-low';
        const ts = o.timestamp ? new Date(o.timestamp*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}) : '';
        return `<div class="cal-obs-item ${sev}">
          <span class="cal-obs-time">${ts}</span>
          <span>${escapeHtml(o.message || '')}</span>
        </div>`;
      }).join('');
    }
  } catch(e) {
    console.warn('Summary load failed:', e);
  }
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

// Fetch heatmap data then paint the grid
async function renderCalendar(year, month) {
  document.getElementById("cal-month-label").textContent =
    CAL_MONTHS[month - 1] + "  " + year;
  document.getElementById("cal-days-container").innerHTML =
    '<div class="cal-loading">Loading…</div>';
  try {
    const data = await fetch(`/api/alerts/calendar?year=${year}&month=${month}`).then(r => r.json());
    _calDayData = {};
    (data.days || []).forEach(d => { _calDayData[d.date_str] = d; });
    paintCalendarGrid(year, month);
  } catch(e) {
    console.error("Calendar fetch failed:", e);
  }
}

// Build the CSS grid of day cells
function paintCalendarGrid(year, month) {
  const today = new Date();
  const todayStr = `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2,"0")}-${String(today.getDate()).padStart(2,"0")}`;

  // JS Date: getDay() returns 0=Sun … 6=Sat. We want 0=Mon … 6=Sun.
  const firstDate   = new Date(year, month - 1, 1);
  const daysInMonth = new Date(year, month, 0).getDate();
  // Monday-based offset: Sun(0)->6, Mon(1)->0 … Sat(6)->5
  const startOffset = (firstDate.getDay() + 6) % 7;

  let html = "";

  // Empty cells before the 1st
  for (let i = 0; i < startOffset; i++) {
    html += `<div class="cal-day cal-empty"></div>`;
  }

  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${String(month).padStart(2,"0")}-${String(d).padStart(2,"0")}`;
    const info    = _calDayData[dateStr] || { count: 0, has_high: 0 };
    const count   = info.count || 0;
    const isHigh  = info.has_high === 1;
    const isToday = dateStr === todayStr;
    const isSel   = dateStr === _calSelectedDay;

    let heatClass = "heat-none";
    if (count > 0) {
      if (isHigh || count >= 15)  heatClass = "heat-high";
      else if (count >= 5)        heatClass = "heat-mid";
      else                        heatClass = "heat-low";
    }

    const todayMark = isToday ? " cal-today"    : "";
    const selMark   = isSel   ? " cal-selected" : "";

    // Compact: number + tiny dot indicator only (no count badge)
    html += `
      <div class="cal-day ${heatClass}${todayMark}${selMark}"
           onclick="calSelectDay('${dateStr}')"
           title="${dateStr}${count ? " — " + count + " alert" + (count > 1 ? "s" : "") : ""}">
        <span class="cal-day-num">${d}</span>
        ${count ? `<span class="cal-dot-ind"></span>` : ""}
      </div>`;
  }

  document.getElementById("cal-days-container").innerHTML = html;
}

// Click a day → swap summary for day-log in right panel
async function calSelectDay(dateStr) {
  _calSelectedDay = dateStr;
  paintCalendarGrid(_calYear, _calMonth);

  // Swap panels
  document.getElementById('cal-summary').style.display = 'none';
  const panel = document.getElementById('cal-day-view');
  panel.classList.remove('hidden');

  const tbody = document.getElementById('cal-day-tbody');
  document.getElementById('cal-day-title').textContent = dateStr;
  document.getElementById('cal-day-badge').textContent = '…';
  tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Loading…</td></tr>';

  try {
    const data   = await fetch(`/api/alerts/by-date?date=${dateStr}`).then(r => r.json());
    const alerts = data.alerts || [];
    document.getElementById("cal-day-badge").textContent = data.total ?? alerts.length;

    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No alerts on ${dateStr}.</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const ts = escapeHtml(a.time_str || "—");
      const detail = (a.detail || "").substring(0, 50);
      const detailFull = escapeHtml(a.detail || "");
      return `
        <tr>
          <td><span class="mac">${ts}</span></td>
          <td><span class="rule-badge rule-${a.rule_name}">${escapeHtml(a.rule_name)}</span></td>
          <td><span class="ip">${escapeHtml(a.src_ip || "—")}</span></td>
          <td><span class="mac">${a.dst_port || "—"}</span></td>
          <td><span class="severity-badge sev-${a.severity}">${escapeHtml(a.severity || "?")}</span></td>
          <td class="detail-cell" title="${detailFull}">${escapeHtml(detail)}${a.detail && a.detail.length > 50 ? "…" : ""}</td>
          <td><button class="btn-investigate" onclick="openInvestigation(${a.id})" title="Investigate">🔍</button></td>
        </tr>`;
    }).join("");
  } catch(e) {
    console.error("Day fetch failed:", e);
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Failed to load.</td></tr>';
  }
}

function calCloseDayView() {
  _calSelectedDay = null;
  document.getElementById('cal-day-view').classList.add('hidden');
  document.getElementById('cal-summary').style.display = 'flex';
  paintCalendarGrid(_calYear, _calMonth);
  calLoadTodaySummary();   // refresh to today
}
