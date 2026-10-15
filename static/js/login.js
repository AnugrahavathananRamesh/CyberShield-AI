// Shared helpers used by every page.
async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (res.status === 401 && !url.includes("/api/login")) {
    window.location.href = "/login";
    throw new Error("Session expired");
  }
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const err = new Error(data.error || "Request failed");
    err.details = data.details;
    throw err;
  }
  return data;
}

// Escape text before putting it into innerHTML (prevents XSS)
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtTime(iso) { return new Date(iso).toLocaleString(); }
function tag(text) { return `<span class="tag ${esc(text)}">${esc(text)}</span>`; }

function alertHtml(a) {
  const act = a.activity || {};
  return `<div class="alert ${esc(a.risk_level)}">
    <strong>${esc(a.message)}</strong>
    Risk score: ${esc(a.risk_score)}% &middot; Confidence: ${esc(a.confidence)}% &middot; ${tag(a.risk_level)}
    <small>${esc(fmtTime(a.timestamp))} &middot; ${esc(act.source_ip || "unknown")} to ${esc(act.destination_ip || "unknown")}
    &middot; ${esc(act.service || "")}/${esc(act.protocol || "")}, failed logins: ${esc(act.failed_logins ?? 0)}</small>
  </div>`;
}

function predRow(p, withUser) {
  return `<tr><td>${esc(fmtTime(p.timestamp))}</td><td>${tag(p.prediction)}</td>
    <td>${esc(p.threat)}</td><td>${esc(p.risk_score)}% ${tag(p.risk_level)}</td>
    <td>${esc(p.confidence)}%</td>${withUser ? `<td>${esc(p.username)}</td>` : ""}</tr>`;
}


document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorBox = document.getElementById("loginError");
  errorBox.hidden = true;
  try {
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      }),
    });
    window.location.href = "/dashboard";
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.hidden = false;
  }
});
