const COLORS = { ok: "#4fd1a5", warn: "#f5b14c", bad: "#f2596d", accent: "#3cc4f0", grid: "#25354f", text: "#8fa3c2" };
Chart.defaults.color = COLORS.text;
Chart.defaults.borderColor = COLORS.grid;
Chart.defaults.maintainAspectRatio = false;

const charts = {};
function draw(id, config) {
  if (charts[id]) { charts[id].data = config.data; charts[id].update(); return; }
  charts[id] = new Chart(document.getElementById(id), config);
}

async function loadStats() {
  const s = await api("/api/dashboard/stats");
  const set = (id, v) => (document.getElementById(id).textContent = v);
  set("sTotal", s.total); set("sNormal", s.normal); set("sThreats", s.threats);
  set("sHigh", s.high); set("sMedium", s.medium); set("sLow", s.low);

  draw("chartSplit", { type: "doughnut",
    data: { labels: ["Normal", "Attack"], datasets: [{ data: [s.normal, s.threats], backgroundColor: [COLORS.ok, COLORS.bad], borderWidth: 0 }] },
    options: { plugins: { legend: { position: "bottom" } } } });

  draw("chartRisk", { type: "bar",
    data: { labels: ["Low", "Medium", "High"], datasets: [{ data: [s.low, s.medium, s.high], backgroundColor: [COLORS.ok, COLORS.warn, COLORS.bad] }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });

  const names = Object.keys(s.threat_types);
  draw("chartThreats", { type: "bar",
    data: { labels: names, datasets: [{ data: names.map(n => s.threat_types[n]), backgroundColor: COLORS.accent }] },
    options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } } });

  draw("chartTime", { type: "line",
    data: { labels: s.timeline.map(t => new Date(t.end).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })),
      datasets: [
        { label: "All activity", data: s.timeline.map(t => t.total), borderColor: COLORS.accent, tension: .3 },
        { label: "Attacks", data: s.timeline.map(t => t.attacks), borderColor: COLORS.bad, tension: .3 }] },
    options: { plugins: { legend: { position: "bottom" } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });

  document.getElementById("recentAlerts").innerHTML =
    s.recent_alerts.map(alertHtml).join("") || '<p class="empty-msg">No alerts yet. Analyze some activity on the Threat detection page.</p>';
  document.getElementById("recentRows").innerHTML =
    s.recent_predictions.map(p => predRow(p, false)).join("") || '<tr><td class="empty" colspan="5">No detections yet.</td></tr>';
}

loadStats().catch(e => console.error(e));
setInterval(() => loadStats().catch(() => {}), 10000);   // live refresh
