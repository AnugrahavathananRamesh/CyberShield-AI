// Used by both the Alerts page and the Detection history page.
const alertList = document.getElementById("alertList");
const historyRows = document.getElementById("historyRows");

async function loadAlerts() {
  const level = document.getElementById("levelFilter").value;
  const data = await api("/api/alerts?limit=200" + (level ? "&level=" + encodeURIComponent(level) : ""));
  alertList.innerHTML = data.alerts.map(alertHtml).join("") ||
    '<p class="empty-msg">No alerts match this filter.</p>';
}

async function loadHistory() {
  const filter = document.getElementById("predFilter").value;
  const data = await api("/api/predictions?limit=200");
  const rows = data.predictions.filter(p => !filter || p.prediction === filter);
  historyRows.innerHTML = rows.map(p => predRow(p, true)).join("") ||
    '<tr><td class="empty" colspan="6">No detections to show yet.</td></tr>';
}

if (alertList) {
  document.getElementById("levelFilter").addEventListener("change", loadAlerts);
  loadAlerts();
}
if (historyRows) {
  document.getElementById("predFilter").addEventListener("change", loadHistory);
  loadHistory();
}
