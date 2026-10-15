const PRESETS = {
  normal: { failed_logins: 0, connection_count: 6, packet_count: 40, duration: 2.5, protocol: "tcp", service: "http",
            src_bytes: 1500, dst_bytes: 8000, error_rate: 0.01, logged_in: "1", source_ip: "192.168.1.20", destination_ip: "10.0.0.5" },
  brute:  { failed_logins: 25, connection_count: 40, packet_count: 180, duration: 45, protocol: "tcp", service: "ssh",
            src_bytes: 900, dst_bytes: 600, error_rate: 0.25, logged_in: "0", source_ip: "203.0.113.45", destination_ip: "10.0.0.5" },
  dos:    { failed_logins: 0, connection_count: 1500, packet_count: 30000, duration: 3, protocol: "tcp", service: "http",
            src_bytes: 5000000, dst_bytes: 20, error_rate: 0.6, logged_in: "0", source_ip: "198.51.100.77", destination_ip: "10.0.0.8" },
  scan:   { failed_logins: 0, connection_count: 300, packet_count: 400, duration: 0.4, protocol: "tcp", service: "ftp",
            src_bytes: 60, dst_bytes: 20, error_rate: 0.8, logged_in: "0", source_ip: "203.0.113.90", destination_ip: "10.0.0.0" },
  exfil:  { failed_logins: 0, connection_count: 2, packet_count: 40000, duration: 500, protocol: "tcp", service: "ftp",
            src_bytes: 30000000, dst_bytes: 400, error_rate: 0.03, logged_in: "1", source_ip: "192.168.1.35", destination_ip: "198.51.100.200" },
};

const form = document.getElementById("predictForm");
const errorBox = document.getElementById("formError");

document.querySelectorAll("[data-preset]").forEach(btn => btn.addEventListener("click", () => {
  const values = PRESETS[btn.dataset.preset];
  Object.entries(values).forEach(([k, v]) => { form.elements[k].value = v; });
  errorBox.hidden = true;
}));

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorBox.hidden = true;
  const payload = Object.fromEntries(new FormData(form).entries());
  const button = document.getElementById("analyzeBtn");
  button.disabled = true; button.textContent = "Analyzing...";
  try {
    const data = await api("/api/predict", { method: "POST", body: JSON.stringify(payload) });
    show(data.result, data.alert);
  } catch (err) {
    const details = err.details ? Object.values(err.details).join(". ") : "";
    errorBox.textContent = details ? `${err.message}: ${details}` : err.message;
    errorBox.hidden = false;
  } finally {
    button.disabled = false; button.textContent = "Analyze activity";
  }
});

function show(r, alert) {
  document.getElementById("resultEmpty").hidden = true;
  document.getElementById("resultBody").hidden = false;
  const banner = document.getElementById("banner");
  banner.className = "banner " + r.risk_level;
  banner.textContent = r.prediction === "Attack"
    ? `${r.risk_level.toUpperCase()} RISK ALERT: ${r.threat} detected.`
    : "No threat detected. Activity looks normal.";
  const set = (id, v) => (document.getElementById(id).textContent = v);
  set("rPrediction", r.prediction); set("rThreat", r.threat);
  set("rConfidence", r.confidence + "%"); set("rScore", r.risk_score + "%"); set("rLevel", r.risk_level);
  const fill = document.getElementById("meterFill");
  fill.className = r.risk_level; fill.style.width = r.risk_score + "%";
  document.getElementById("rProbs").innerHTML = Object.entries(r.probabilities)
    .sort((a, b) => b[1] - a[1]).map(([k, v]) => `<li><span>${esc(k)}</span><span>${esc(v)}%</span></li>`).join("");
  set("rAlert", alert ? "An alert was created and saved. See the Alerts page." : "Result saved to detection history. No alert needed.");
}
