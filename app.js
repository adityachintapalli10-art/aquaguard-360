/* AquaGuard 360 admin dashboard - vanilla JS, no external dependencies.
   All dynamic text is inserted with textContent (never innerHTML) to avoid XSS. */
"use strict";
let CSRF = "";
const $view = document.getElementById("view");

// ---------- helpers ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : String(kid));
  return el;
}
async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) {
    o.headers["Content-Type"] = "application/json";
    o.body = JSON.stringify(opts.body);
  }
  if (o.method !== "GET") o.headers["X-CSRF-Token"] = CSRF;
  const r = await fetch(path, o);
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const fmtL = (v) => (v >= 10000 ? (v / 1000).toFixed(1) + " kL" : Math.round(v) + " L");
const fmtT = (s) => (s ? s.replace("T", " ").replace("Z", " UTC") : "never");
const badge = (txt, cls) => h("span", { class: "badge " + cls }, txt);
const table = (head, rows) =>
  h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, head.map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
const errBox = (e) => h("p", { class: "error", role: "alert" }, e.message);

function lineChart(canvas, series, labels) {
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth, H = canvas.clientHeight;
  canvas.width = W * dpr; canvas.height = H * dpr;
  const c = canvas.getContext("2d");
  c.scale(dpr, dpr);
  const css = getComputedStyle(document.body);
  const ink = css.getPropertyValue("--muted"), line = css.getPropertyValue("--line");
  const pad = { l: 46, r: 10, t: 10, b: 24 };
  const max = Math.max(1, ...series.flatMap((s) => s.values)) * 1.1;
  const n = Math.max(2, labels.length);
  const x = (i) => pad.l + ((W - pad.l - pad.r) * i) / (n - 1);
  const y = (v) => H - pad.b - ((H - pad.t - pad.b) * v) / max;
  c.font = "11px system-ui"; c.fillStyle = ink; c.strokeStyle = line;
  for (let g = 0; g <= 4; g++) {
    const v = (max * g) / 4;
    c.beginPath(); c.moveTo(pad.l, y(v)); c.lineTo(W - pad.r, y(v)); c.stroke();
    c.fillText(v.toFixed(v < 10 ? 1 : 0), 4, y(v) + 4);
  }
  const step = Math.ceil(labels.length / 6);
  labels.forEach((l, i) => { if (i % step === 0) c.fillText(l, x(i) - 12, H - 6); });
  for (const s of series) {
    c.strokeStyle = s.color; c.lineWidth = 2; c.beginPath();
    s.values.forEach((v, i) => (i ? c.lineTo(x(i), y(v)) : c.moveTo(x(i), y(v))));
    c.stroke();
  }
}
const legend = (items) =>
  h("p", { class: "legend small" }, items.map(([n, col]) => {
    const i = h("i"); i.style.background = col; return h("span", {}, i, n);
  }));

// ---------- views ----------
const views = {};

views.dashboard = async () => {
  const [s, alerts, cons] = await Promise.all([api("/api/summary"), api("/api/alerts?status=active"), api("/api/consumption?hours=24")]);
  const open = Object.values(s.open_alerts).reduce((a, b) => a + b, 0);
  const card = (label, val, sub) => h("div", { class: "card" }, h("div", { class: "muted small" }, label), h("div", { class: "num" }, val), h("div", { class: "small muted" }, sub || ""));
  return h("div", {},
    h("h2", {}, "Dashboard"),
    h("div", { class: "cards" },
      card("Open alerts", open, `high ${s.open_alerts.high || 0} / medium ${s.open_alerts.medium || 0} / low ${s.open_alerts.low || 0}`),
      card("Devices online", `${s.devices_online} / ${s.devices_total}`, `${s.hardware_devices} hardware, ${s.demo_devices} simulated demo`),
      card("Supplied (24 h)", fmtL(s.inlet_24h_l), "measured at inlet meters"),
      card("Consumed (24 h)", fmtL(s.downstream_24h_l), "measured at downstream meters"),
      card("Unaccounted-for", fmtL(s.unaccounted_24h_l), `${s.unaccounted_pct}% of supplied (not proof of a leak)`)),
    s.demo_devices ? h("p", { class: "notice" }, "Some devices are in DEMO mode: their readings are simulated, not real sensor measurements.") : null,
    h("div", { class: "panel" }, h("h3", {}, "Active alerts"), alertTable(alerts.slice(0, 8))),
    h("div", { class: "panel" }, h("h3", {}, "Water balance by street (24 h)"), consumptionTable(cons.streets)));
};

function consumptionTable(streets) {
  return table(["Locality", "Street", "Supplied", "Consumed", "Gap"],
    streets.map((r) => [r.locality, r.street, fmtL(r.inlet_l), fmtL(r.downstream_l),
      r.gap_pct == null ? "n/a" : r.gap_pct + "%"]));
}

function alertTable(list) {
  if (!list.length) return h("p", { class: "muted" }, "No alerts.");
  return table(["#", "Time", "Severity", "Type", "Where", "Status", ""],
    list.map((a) => [a.id, fmtT(a.created_at), badge(a.severity, a.severity), a.type.replace("_", " "),
      a.device || a.street || "-", a.status,
      h("button", { class: "btn small", onclick: () => { location.hash = "#alert/" + a.id; } }, "Open")]));
}

views.areas = async () => {
  const [locs, streets] = await Promise.all([api("/api/localities"), api("/api/streets")]);
  const msg = h("div");
  const submit = (path, fn) => async (e) => {
    e.preventDefault();
    try { await api(path, { method: "POST", body: fn(new FormData(e.target)) }); render(); }
    catch (err) { msg.replaceChildren(errBox(err)); }
  };
  return h("div", {}, h("h2", {}, "Areas & Streets"), msg,
    h("div", { class: "panel" }, h("h3", {}, "Add locality"),
      h("form", { class: "inline", onsubmit: submit("/api/localities", (f) => ({ name: f.get("name") })) },
        h("label", {}, "Name", h("input", { name: "name", required: true })), h("button", { class: "btn primary" }, "Add"))),
    h("div", { class: "panel" }, h("h3", {}, "Add street"),
      h("form", { class: "inline", onsubmit: submit("/api/streets", (f) => ({ locality_id: +f.get("locality_id"), name: f.get("name") })) },
        h("label", {}, "Locality", h("select", { name: "locality_id", required: true }, locs.map((l) => h("option", { value: l.id }, l.name)))),
        h("label", {}, "Street", h("input", { name: "name", required: true })), h("button", { class: "btn primary" }, "Add"))),
    h("div", { class: "panel" }, table(["Locality", "Street", "Meters"], streets.map((s) => [s.locality, s.name, s.device_count]))));
};

views.flow = async () => {
  const streets = await api("/api/streets");
  const out = h("div");
  const sel = h("select", { onchange: () => load() }, streets.map((s) => h("option", { value: s.id }, `${s.locality} / ${s.name}`)));
  const hoursSel = h("select", { onchange: () => load() }, [["6", "6 h"], ["24", "24 h"], ["168", "7 days"]].map(([v, t]) => h("option", { value: v, selected: v === "24" }, t)));
  async function load() {
    if (!sel.value) return;
    try {
      const [ser, cons] = await Promise.all([api(`/api/streets/${sel.value}/series?hours=${hoursSel.value}`), api(`/api/consumption?hours=${hoursSel.value}`)]);
      const buckets = [...new Set(ser.points.map((p) => p.b))].sort((a, b) => a - b);
      const val = (kind) => buckets.map((b) => { const p = ser.points.find((q) => q.b === b && q.kind === kind); return p ? p.vol / (ser.bucket_s / 60) : 0; });
      const labels = buckets.map((b) => new Date(b * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
      const canvas = h("canvas");
      out.replaceChildren(
        h("div", { class: "panel" }, h("h3", {}, "Average flow (L/min)"), legend([["Inlet", "#0b6fa4"], ["Downstream", "#e67e22"]]), canvas),
        h("div", { class: "panel" }, h("h3", {}, `Volumes, last ${hoursSel.selectedOptions[0].text}`), consumptionTable(cons.streets)));
      lineChart(canvas, [{ values: val("inlet"), color: "#0b6fa4" }, { values: val("downstream"), color: "#e67e22" }], labels);
    } catch (e) { out.replaceChildren(errBox(e)); }
  }
  setTimeout(load, 0);
  return h("div", {}, h("h2", {}, "Flow & Consumption"),
    h("form", { class: "inline panel", onsubmit: (e) => e.preventDefault() }, h("label", {}, "Street", sel), h("label", {}, "Period", hoursSel)), out);
};

views.alerts = async () => {
  const list = await api("/api/alerts");
  return h("div", {}, h("h2", {}, "Leakage Alerts"), h("div", { class: "panel" }, alertTable(list)));
};

async function alertView(id) {
  const { alert: a, maintenance: m } = await api("/api/alerts/" + id);
  const msg = h("div");
  const setStatus = (status) => async () => {
    try { await api(`/api/alerts/${id}/status`, { method: "POST", body: { status } }); render(); }
    catch (e) { msg.replaceChildren(errBox(e)); }
  };
  const addM = async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    try { await api(`/api/alerts/${id}/maintenance`, { method: "POST", body: { action: f.get("action"), notes: f.get("notes") } }); render(); }
    catch (err) { msg.replaceChildren(errBox(err)); }
  };
  return h("div", {}, h("h2", {}, `Alert #${a.id}`), msg,
    h("div", { class: "panel" },
      h("p", {}, badge(a.severity, a.severity), " ", a.type.replace("_", " "), " - status: ", h("strong", {}, a.status)),
      h("p", {}, a.message),
      h("p", { class: "muted small" }, `Created ${fmtT(a.created_at)}` + (a.est_loss_l ? ` | est. volume ${Math.round(a.est_loss_l)} L` : "")),
      a.status !== "resolved" ? h("p", {},
        h("button", { class: "btn", onclick: setStatus("acknowledged") }, "Acknowledge"), " ",
        h("button", { class: "btn", onclick: setStatus("investigating") }, "Investigating"), " ",
        h("button", { class: "btn primary", onclick: setStatus("resolved") }, "Resolve")) : null),
    h("div", { class: "panel" }, h("h3", {}, "Maintenance log"),
      m.length ? table(["Time", "Action", "Notes", "Admin"], m.map((r) => [fmtT(r.created_at), r.action, r.notes, r.admin])) : h("p", { class: "muted" }, "No records yet."),
      h("form", { class: "inline", onsubmit: addM },
        h("label", {}, "Action", h("select", { name: "action" }, ["inspection", "repair", "verification", "note"].map((x) => h("option", {}, x)))),
        h("label", {}, "Notes", h("input", { name: "notes", maxlength: 1000 })), h("button", { class: "btn primary" }, "Add record"))),
    h("p", {}, h("a", { href: "#alerts" }, "Back to alerts")));
}

views.devices = async () => {
  const [devs, streets] = await Promise.all([api("/api/devices"), api("/api/streets")]);
  const msg = h("div");
  const add = async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    try {
      const r = await api("/api/devices", { method: "POST", body: { name: f.get("name"), street_id: +f.get("street_id"), kind: f.get("kind"), mode: f.get("mode"), calibration_factor: +f.get("cal") } });
      msg.replaceChildren(h("p", { class: "notice" }, `Device created. API key (shown once): ${r.api_key}`));
      e.target.reset();
    } catch (err) { msg.replaceChildren(errBox(err)); }
  };
  return h("div", {}, h("h2", {}, "IoT Devices"), msg,
    h("div", { class: "panel" }, h("h3", {}, "Register device"),
      h("form", { class: "inline", onsubmit: add },
        h("label", {}, "Name", h("input", { name: "name", required: true })),
        h("label", {}, "Street", h("select", { name: "street_id" }, streets.map((s) => h("option", { value: s.id }, `${s.locality} / ${s.name}`)))),
        h("label", {}, "Role", h("select", { name: "kind" }, [h("option", { value: "inlet" }, "inlet"), h("option", { value: "downstream" }, "downstream")])),
        h("label", {}, "Mode", h("select", { name: "mode" }, [h("option", { value: "hardware" }, "hardware"), h("option", { value: "demo" }, "demo (simulated)")])),
        h("label", {}, "Calibration x", h("input", { name: "cal", type: "number", step: "0.001", value: "1", min: "0.1", max: "10" })),
        h("button", { class: "btn primary" }, "Register"))),
    h("div", { class: "panel" }, table(["Device", "Street", "Role", "Data source", "Status", "Last update"],
      devs.map((d) => [d.name, d.street, d.kind, badge(d.mode === "demo" ? "demo (simulated)" : "hardware", d.mode),
        badge(d.online ? "online" : "offline", d.online ? "ok" : "off"), fmtT(d.last_seen)]))));
};

views.reports = async () => h("div", {}, h("h2", {}, "Reports"),
  h("div", { class: "panel" }, h("p", {}, "Download CSV exports (opens in Excel/Sheets) or use your browser's Print > Save as PDF."),
    h("p", {}, [["24", "Consumption 24 h"], ["168", "Consumption 7 days"], ["720", "Consumption 30 days"]].map(([hrs, t]) =>
      h("a", { class: "btn", href: `/api/reports/consumption.csv?hours=${hrs}` }, t)), " ",
      h("a", { class: "btn", href: "/api/reports/alerts.csv" }, "All alerts"), " ",
      h("button", { class: "btn", onclick: () => window.print() }, "Print / PDF"))));

views.admin = async () => {
  const [audit, settings] = await Promise.all([api("/api/audit"), api("/api/settings")]);
  const msg = h("div");
  const save = async (e) => {
    e.preventDefault(); const body = {};
    for (const [k, v] of new FormData(e.target)) body[k] = +v;
    try { await api("/api/settings", { method: "POST", body }); msg.replaceChildren(h("p", { class: "notice" }, "Settings saved.")); }
    catch (err) { msg.replaceChildren(errBox(err)); }
  };
  return h("div", {}, h("h2", {}, "Audit Logs & Settings"), msg,
    h("div", { class: "panel" }, h("h3", {}, "Detection thresholds"),
      h("form", { class: "inline", onsubmit: save },
        Object.entries(settings).map(([k, v]) => h("label", {}, k, h("input", { name: k, type: "number", step: "any", min: "0", value: v }))),
        h("button", { class: "btn primary" }, "Save"))),
    h("div", { class: "panel" }, h("h3", {}, "Recent admin actions"),
      table(["Time", "Admin", "Action", "Detail", "IP"], audit.map((r) => [fmtT(r.ts), r.admin || "-", r.action, r.detail, r.ip]))));
};

// ---------- router ----------
const NAV = [["dashboard", "Dashboard"], ["areas", "Areas & Streets"], ["flow", "Flow & Consumption"], ["alerts", "Alerts"], ["devices", "Devices"], ["reports", "Reports"], ["admin", "Audit & Settings"]];
let timer = null;
async function render() {
  clearTimeout(timer);
  const hash = location.hash.slice(1) || "dashboard";
  const [name, arg] = hash.split("/");
  document.getElementById("nav").replaceChildren(...NAV.map(([k, t]) => h("a", { href: "#" + k, class: k === name || (name === "alert" && k === "alerts") ? "active" : "" }, t)));
  try {
    $view.replaceChildren(name === "alert" ? await alertView(+arg) : await (views[name] || views.dashboard)());
    if (name === "dashboard") timer = setTimeout(render, 30000);
  } catch (e) { $view.replaceChildren(errBox(e)); }
}
window.addEventListener("hashchange", render);
document.getElementById("logout").addEventListener("click", async () => { await api("/logout", { method: "POST" }); location.href = "/login"; });
api("/api/me").then((m) => { CSRF = m.csrf; render(); });
