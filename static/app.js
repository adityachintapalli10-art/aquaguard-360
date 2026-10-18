const state = { csrf: "", admin: null, view: "dashboard" };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
const number = (value, digits = 0) => Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: digits });
const date = (value) => value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC" : "No readings yet";
const human = (value) => String(value || "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());

async function api(path, options = {}) {
  const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) };
  if (state.csrf && ["POST", "PATCH", "DELETE"].includes(options.method)) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  if (response.status === 401 && path !== "/api/login") showLogin();
  if (!response.ok) {
    const message = (await response.json().catch(() => ({}))).error || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return response.headers.get("Content-Type")?.includes("application/json") ? response.json() : response;
}

function showLogin() {
  $("#app").hidden = true;
  $("#login-view").hidden = false;
  state.csrf = "";
  state.admin = null;
}
function showApp() {
  $("#login-view").hidden = true;
  $("#app").hidden = false;
  $("#admin-name").textContent = state.admin?.username || "Administrator";
}
function toast(message, error = false) {
  const node = document.createElement("div");
  node.className = `toast${error ? " error" : ""}`;
  node.textContent = message;
  $("#toast-region").append(node);
  setTimeout(() => node.remove(), 3800);
}
function pageHead(title, subtitle, action = "") {
  return `<div class="page-head"><div><p class="eyebrow">AQUAGUARD 360 / OPERATIONS</p><h1>${title}</h1><p>${subtitle}</p></div><div class="head-actions">${action}</div></div>`;
}
function metric(label, value, sub, icon, tone = "") {
  return `<article class="metric"><div class="metric-top">${label}<span class="metric-icon ${tone}">${icon}</span></div><div class="metric-number">${value}</div><div class="metric-sub">${sub}</div></article>`;
}
function sourceTag(source) {
  return `<span class="tag ${source === "hardware" ? "hardware" : "simulated"}">${source === "hardware" ? "Hardware" : "Simulated"}</span>`;
}
function severityTag(severity) { return `<span class="tag ${esc(severity)}">${esc(severity)}</span>`; }
function empty(title, detail) { return `<div class="empty"><b>${title}</b>${detail}</div>`; }

function render(view) {
  state.view = view;
  $$(".nav-link[data-view]").forEach(link => link.classList.toggle("active", link.dataset.view === view));
  const labels = { dashboard: "Overview", areas: "Areas & streets", devices: "Meters & sensors", readings: "Flow monitoring", alerts: "Alerts", maintenance: "Maintenance", reports: "Reports", audit: "Audit log", settings: "System settings" };
  $("#crumb").textContent = labels[view] || "Overview";
  const handlers = { dashboard: dashboard, areas: areas, devices: devices, readings: readings, alerts: alerts, maintenance: maintenance, reports: reports, audit: audit, settings: settings };
  (handlers[view] || dashboard)().catch(error => {
    $("#page").innerHTML = `${pageHead(labels[view] || "Overview", "Unable to load this view.")}<div class="panel">${empty("Couldn't load data", esc(error.message))}</div>`;
  });
  $("#sidebar").classList.remove("open");
}

async function dashboard() {
  const data = await api("/api/dashboard");
  const countNode = $("#nav-alert-count");
  countNode.hidden = !data.activeAlerts;
  countNode.textContent = data.activeAlerts;
  const latest = (data.recentAlerts || []).slice(0, 4);
  const alertsPanel = `<section class="panel"><div class="panel-head"><div><div class="panel-title">Recent alerts</div><div class="panel-subtitle">Suspected issues · not confirmed leaks</div></div><button class="panel-link" data-go="alerts">View all →</button></div>${latest.length ? latest.map(alert => `<div class="alert-row"><span class="severity-mark ${esc(alert.severity)}"></span><div class="alert-copy"><div class="alert-title">${esc(alert.device_name)} · ${esc(alert.area_name || "Unassigned area")}</div><div class="alert-detail">${number(alert.observed_flow_lpm, 1)} L/min vs ${number(alert.threshold_lpm, 1)} threshold · ${date(alert.created_at)}</div></div>${severityTag(alert.severity)}</div>`).join("") : empty("All quiet for now", "No open threshold alerts are recorded.")}<div class="coverage"><span class="coverage-label">Critical alerts</span><b class="coverage-value">${data.criticalAlerts}</b></div></section>`;
  const hours = data.series.slice(-12);
  window.__aquaSeries = hours;
  $("#page").innerHTML = `${pageHead("Water at a glance", "Network status and measured readings across your monitored areas.", `<button class="button" id="refresh-dashboard">↻ &nbsp;Refresh</button><button class="button" id="run-alert-simulation">⚑ &nbsp;Test alert</button><button class="button primary" id="run-simulation">▶ &nbsp;Run simulation</button>`)}
    <div class="callout amber" style="margin-bottom:14px"><b>Demo mode · simulated readings are not live sensor measurements</b>This workspace contains clearly labeled sample and simulated telemetry. Historical and stale readings are never presented as live.</div>
    <div class="metrics">${metric("Registered localities", number(data.localities), "Configured monitoring areas", "⌖")}${metric("Monitored streets", number(data.streets), "Within registered localities", "≋")}${metric("Connected meters", `${number(data.onlineSensors)} <span style="font-size:12px;color:#96a2a9">/ ${number(data.meters)}</span>`, `${data.offlineSensors} without a reading in 10 min`, "◉", data.offlineSensors ? "amber" : "")}${metric("Open alerts", number(data.activeAlerts), `${number(data.criticalAlerts)} critical · suspected only`, "⚑", data.activeAlerts ? "red" : "")}</div>
    <div class="grid-main"><div class="panel"><div class="panel-head"><div><div class="panel-title">Recent flow readings</div><div class="panel-subtitle">Average flow per hour · UTC · latest 24 hours</div></div><button class="panel-link" data-go="readings">View readings →</button></div><div class="chart-area"><canvas id="flow-chart" aria-label="Average flow rate by hour" role="img"></canvas></div><div class="chart-legend"><span><i class="legend-dot"></i>Avg. flow (L/min)</span><span class="chart-note">Last updated ${date(data.lastUpdated)}</span></div></div><div class="side-stack">${alertsPanel}<section class="panel"><div class="panel-head"><div><div class="panel-title">Today · recorded data</div><div class="panel-subtitle">Measurement coverage, not a supply total</div></div></div><div class="coverage"><span class="coverage-label">Valid readings</span><b class="coverage-value">${number(data.todayReadingCount)}</b></div><div class="coverage"><span class="coverage-label">Sum of meter totalizers*</span><b class="coverage-value">${number(data.sumOfTotalizersLiters, 1)} L</b></div><div class="chart-legend">*Not aggregated as network consumption; meters may overlap.</div></section></div></div>`;
  drawChart(hours);
  $("#refresh-dashboard").onclick = () => render("dashboard");
  const runSimulation = async scenario => {
    try {
      const result = await api("/api/simulate", { method: "POST", body: JSON.stringify({ scenario }) });
      toast(`${result.created} ${scenario === "normal" ? "normal" : "high-flow"} simulated readings generated.`);
      render("dashboard");
    } catch (error) { toast(error.message, true); }
  };
  $("#run-simulation").onclick = () => runSimulation("normal");
  $("#run-alert-simulation").onclick = () => runSimulation("high-flow");
  $$("[data-go]").forEach(button => button.onclick = () => render(button.dataset.go));
}
function drawChart(series) {
  const canvas = $("#flow-chart"); if (!canvas) return;
  const bounds = canvas.getBoundingClientRect(); const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(300, bounds.width) * dpr; canvas.height = Math.max(150, bounds.height) * dpr;
  const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
  const w = canvas.width / dpr, h = canvas.height / dpr, pad = { l: 35, r: 8, t: 12, b: 25 };
  const values = series.map(x => Number(x.flow || 0)); const max = Math.max(10, ...values) * 1.2;
  ctx.font = "9px DM Sans, Arial"; ctx.strokeStyle = "#edf1f2"; ctx.fillStyle = "#91a0a9"; ctx.lineWidth = 1;
  for (let i=0;i<4;i++) { const y=pad.t+(h-pad.t-pad.b)*i/3;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();ctx.fillText(number(max*(1-i/3),0),3,y+3); }
  if (!series.length) { ctx.fillStyle="#8b98a2";ctx.textAlign="center";ctx.fillText("No readings recorded yet",w/2,h/2);return; }
  const points=series.map((item,i)=>({x:pad.l+(w-pad.l-pad.r)*(series.length===1?.5:i/(series.length-1)),y:pad.t+(h-pad.t-pad.b)*(1-Number(item.flow||0)/max)}));
  const gradient=ctx.createLinearGradient(0,pad.t,0,h-pad.b);gradient.addColorStop(0,"rgba(34,199,173,.22)");gradient.addColorStop(1,"rgba(34,199,173,0)");
  ctx.beginPath();points.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.lineTo(points.at(-1).x,h-pad.b);ctx.lineTo(points[0].x,h-pad.b);ctx.closePath();ctx.fillStyle=gradient;ctx.fill();
  ctx.beginPath();points.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.strokeStyle="#19a995";ctx.lineWidth=2;ctx.stroke();
  points.forEach((p,i)=>{if(i===points.length-1||i%3===0){ctx.beginPath();ctx.arc(p.x,p.y,3,0,Math.PI*2);ctx.fillStyle="#fff";ctx.fill();ctx.strokeStyle="#19a995";ctx.lineWidth=2;ctx.stroke();}});
  ctx.fillStyle="#91a0a9";ctx.textAlign="center";series.forEach((x,i)=>{if(i%Math.max(1,Math.ceil(series.length/5))===0){const label=String(x.hour||"").slice(11,13)+":00";ctx.fillText(label,points[i].x,h-7);}});
}

async function areas() {
  const data = await api("/api/areas");
  const options = data.items.map(area=>`<option value="${area.id}">${esc(area.name)}</option>`).join("");
  $("#page").innerHTML = `${pageHead("Areas & streets", "Organize monitoring zones and street-level records.", `<button class="button" data-refresh>↻ &nbsp;Refresh</button>`)}
    <div class="two-col"><section class="panel"><div class="panel-head"><div><div class="panel-title">Registered localities</div><div class="panel-subtitle">${data.items.length} configured monitoring area${data.items.length===1?"":"s"}</div></div></div>${data.items.length?`<div class="table-wrap"><table><thead><tr><th>LOCALITY</th><th>CITY / TOWN</th><th>STREETS</th><th>METERS</th><th>CREATED</th></tr></thead><tbody>${data.items.map(area=>`<tr><td><div class="cell-main">${esc(area.name)}</div><div class="cell-sub">${esc(area.description||"Monitoring zone")}</div></td><td>${esc(area.city||"Not configured")}</td><td>${number(area.street_count)}</td><td>${number(area.meter_count)}</td><td>${date(area.created_at)}</td></tr>${area.streets.map(street=>`<tr><td style="padding-left:30px;color:#788891">↳ ${esc(street.name)}</td><td colspan="4" class="cell-sub">Street in ${esc(area.name)}</td></tr>`).join("")}`).join("")}</tbody></table></div>`:empty("No localities yet","Create your first locality and optionally add streets.")}</section>
    <form id="area-form" class="panel form-panel"><h3>Add a locality</h3><p>Geographic details are only recorded when you provide them. No coordinates or addresses are invented.</p><div class="form-grid"><div class="field"><label for="area-name">Locality name *</label><input id="area-name" name="name" maxlength="100" required placeholder="e.g. North ward"></div><div class="field"><label for="area-city">City / town</label><input id="area-city" name="city" maxlength="100" placeholder="Optional"></div><div class="field span-two"><label for="area-streets">Streets</label><textarea id="area-streets" name="streets" placeholder="One street per line"></textarea></div><div class="field span-two"><label for="area-description">Description</label><input id="area-description" name="description" maxlength="500" placeholder="Optional notes"></div></div><div class="form-actions"><button class="button primary" type="submit">Create locality</button></div></form></div>`;
  $("#area-form").onsubmit=async event=>{event.preventDefault();const form=new FormData(event.currentTarget);try{await api("/api/areas",{method:"POST",body:JSON.stringify({name:form.get("name"),city:form.get("city"),description:form.get("description"),streets:form.get("streets").split("\n").map(x=>x.trim()).filter(Boolean)})});toast("Locality created.");areas();}catch(error){toast(error.message,true);}};
  $("[data-refresh]").onclick=()=>render("areas");
}

async function devices() {
  const [data, areaData] = await Promise.all([api("/api/devices"),api("/api/areas")]);
  const localityOptions=areaData.items.map(area=>`<option value="${area.id}">${esc(area.name)}</option>`).join("");
  $("#page").innerHTML=`${pageHead("Meters & sensors","Register monitored devices, define alert thresholds, and check the latest communication.",`<button class="button" data-refresh>↻ &nbsp;Refresh</button>`)}
    <div class="two-col"><section class="panel"><div class="panel-head"><div><div class="panel-title">Registered devices</div><div class="panel-subtitle">Connectivity is inferred from the last recorded timestamp, not a live connection.</div></div></div>${data.items.length?`<div class="table-wrap"><table><thead><tr><th>DEVICE</th><th>LOCATION</th><th>SOURCE</th><th>THRESHOLD</th><th>LAST READING</th><th>FLOW</th><th>STATUS</th></tr></thead><tbody>${data.items.map(d=>`<tr><td><div class="cell-main">${esc(d.name)}</div><div class="cell-sub">${esc(d.device_id)}</div></td><td>${esc(d.area_name||"Unassigned")}<div class="cell-sub">${esc(d.street_name||"")}</div></td><td>${sourceTag(d.source)}</td><td>${number(d.threshold_lpm,1)} L/min</td><td>${date(d.last_seen)}</td><td>${d.last_flow==null?"—":`${number(d.last_flow,1)} L/min`}</td><td><button class="button small" data-device-active="${d.id}" data-next-active="${!d.active}">${d.active?"Disable":"Enable"}</button></td></tr>`).join("")}</tbody></table></div>`:empty("No devices registered","Add a simulated meter to start a demo, or register a hardware device.")}</section>
    <form class="panel form-panel" id="device-form"><h3>Register a meter</h3><p>Hardware credentials are shown once after creation. Store them securely on the device.</p><div class="form-grid"><div class="field"><label for="device-id">Device ID *</label><input id="device-id" name="deviceId" required pattern="[A-Za-z0-9_-]{3,64}" placeholder="FLOW-003"></div><div class="field"><label for="device-name">Display name *</label><input id="device-name" name="name" required maxlength="100" placeholder="Street inlet"></div><div class="field"><label for="device-area">Locality</label><select id="device-area" name="areaId"><option value="">Unassigned</option>${localityOptions}</select></div><div class="field"><label for="device-street">Street ID (optional)</label><input id="device-street" name="streetId" type="number" min="1" placeholder="See Areas & streets"></div><div class="field"><label for="device-source">Data source</label><select id="device-source" name="source"><option value="simulated">Simulated demo device</option><option value="hardware">Hardware (credentialed)</option></select></div><div class="field"><label for="device-threshold">High-flow threshold (L/min)</label><input id="device-threshold" name="thresholdLpm" type="number" min="0.1" max="100000" step="0.1" value="30"></div></div><div class="form-actions"><button class="button primary" type="submit">Register device</button></div></form></div>`;
  $("#device-form").onsubmit=async event=>{event.preventDefault();const form=new FormData(event.currentTarget);try{const result=await api("/api/devices",{method:"POST",body:JSON.stringify({deviceId:form.get("deviceId"),name:form.get("name"),areaId:form.get("areaId")?Number(form.get("areaId")):null,streetId:form.get("streetId")?Number(form.get("streetId")):null,source:form.get("source"),thresholdLpm:Number(form.get("thresholdLpm"))})});if(result.deviceKey){toast(`Device created. Copy device credential: ${result.deviceKey}`);alert(`Copy this device key now. It cannot be retrieved again:\n\n${result.deviceKey}`);}else toast("Device registered.");devices();}catch(error){toast(error.message,true);}};
  $$("[data-device-active]").forEach(button=>button.onclick=async()=>{try{await api(`/api/devices/${button.dataset.deviceActive}`,{method:"PATCH",body:JSON.stringify({active:button.dataset.nextActive==="true"})});toast(button.dataset.nextActive==="true"?"Device enabled.":"Device disabled.");devices();}catch(error){toast(error.message,true);}});
  $("[data-refresh]").onclick=()=>render("devices");
}

async function readings() {
  const data=await api("/api/readings");
  $("#page").innerHTML=`${pageHead("Flow monitoring","Historical telemetry with source, data quality, and UTC timestamps.",`<button class="button" data-refresh>↻ &nbsp;Refresh</button>`)}
    <div class="callout amber" style="margin-bottom:14px"><b>Not a live feed</b>Readings update when a registered device submits telemetry or an administrator runs the simulator. Stale values remain timestamped.</div>
    <section class="panel"><div class="panel-head"><div><div class="panel-title">Latest readings</div><div class="panel-subtitle">Most recent 200 records · volumes are per-device totalizers and are not summed as network consumption.</div></div><span class="tag">${data.items.length} records</span></div>${data.items.length?`<div class="table-wrap"><table><thead><tr><th>RECORDED (UTC)</th><th>DEVICE</th><th>LOCALITY / STREET</th><th>FLOW</th><th>TOTALIZER</th><th>PRESSURE</th><th>QUALITY</th><th>SOURCE</th></tr></thead><tbody>${data.items.map(r=>`<tr><td>${date(r.measured_at)}</td><td><div class="cell-main">${esc(r.device_name)}</div><div class="cell-sub">${esc(r.device_id)}</div></td><td>${esc(r.area_name||"Unassigned")}<div class="cell-sub">${esc(r.street_name||"")}</div></td><td>${number(r.flow_lpm,1)} L/min</td><td>${r.total_liters==null?"—":`${number(r.total_liters,1)} L`}</td><td>${r.pressure_kpa==null?"—":`${number(r.pressure_kpa,1)} kPa`}</td><td><span class="tag ${esc(r.quality)}">${esc(r.quality)}</span></td><td>${sourceTag(r.source)}</td></tr>`).join("")}</tbody></table></div>`:empty("No readings yet","Run a simulated reading or configure a hardware integration.")}</section>`;
  $("[data-refresh]").onclick=()=>render("readings");
}

async function alerts() {
  const data=await api("/api/alerts");
  $("#page").innerHTML=`${pageHead("Alerts & investigation","Review threshold events, acknowledge investigation, and preserve the audit trail.",`<button class="button" data-refresh>↻ &nbsp;Refresh</button>`)}
    <div class="callout amber" style="margin-bottom:14px"><b>Suspected anomaly ≠ confirmed leak</b>Alerts are generated when a valid flow reading exceeds a configured device threshold. Investigate and verify before treating an alert as a physical leak.</div>
    <section class="panel"><div class="panel-head"><div><div class="panel-title">Alert history</div><div class="panel-subtitle">${data.items.filter(a=>a.status==="open").length} open · all severity levels</div></div></div>${data.items.length?`<div class="table-wrap"><table><thead><tr><th>SEVERITY</th><th>DEVICE / LOCATION</th><th>REASON</th><th>OBSERVED</th><th>EST. EXCESS*</th><th>SOURCE</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody>${data.items.map(a=>`<tr><td>${severityTag(a.severity)}</td><td><div class="cell-main">${esc(a.device_name)}</div><div class="cell-sub">${esc(a.area_name||"Unassigned")} · ${date(a.created_at)}</div></td><td style="white-space:normal;min-width:200px;max-width:280px">${esc(a.reason)}</td><td>${number(a.observed_flow_lpm,1)} / ${number(a.threshold_lpm,1)} L/min</td><td>${a.estimated_loss_liters==null?"—":`~${number(a.estimated_loss_liters,1)} L / 10 min`}</td><td>${sourceTag(a.source)}</td><td><span class="tag ${esc(a.status)}">${esc(a.status)}</span></td><td>${a.status==="open"?`<button class="button small" data-ack="${a.id}">Acknowledge</button>`:"—"}</td></tr>`).join("")}</tbody></table></div>`:empty("No alerts recorded","An alert is created when a reading exceeds a device's configured threshold.")}<div class="chart-legend">*Simple threshold-excess estimate; not confirmed physical water loss.</div></section>`;
  $$("[data-ack]").forEach(button=>button.onclick=async()=>{try{await api(`/api/alerts/${button.dataset.ack}/acknowledge`,{method:"POST",body:"{}"});toast("Alert acknowledged; investigation task created.");alerts();}catch(error){toast(error.message,true);}});
  $("[data-refresh]").onclick=()=>render("alerts");
}

async function maintenance() {
  const data=await api("/api/maintenance");
  $("#page").innerHTML=`${pageHead("Maintenance","Investigation tasks created when an administrator acknowledges an alert.","")}
    <section class="panel"><div class="panel-head"><div><div class="panel-title">Investigation queue</div><div class="panel-subtitle">Record repairs and verification outside this demo workflow; physical repair verification is not automatic.</div></div></div>${data.items.length?`<div class="table-wrap"><table><thead><tr><th>TASK</th><th>DEVICE</th><th>ALERT SEVERITY</th><th>STATUS</th><th>CREATED</th></tr></thead><tbody>${data.items.map(t=>`<tr><td><div class="cell-main">${esc(t.description)}</div><div class="cell-sub">Task #${t.id}</div></td><td>${esc(t.external_device_id)}</td><td>${t.severity?severityTag(t.severity):"—"}</td><td><span class="tag open">${esc(t.status)}</span></td><td>${date(t.created_at)}</td></tr>`).join("")}</tbody></table></div>`:empty("No maintenance tasks","A task is created when an alert is acknowledged.")}</section>`;
}

async function reports() {
  const data=await api("/api/readings");
  const sources=[...new Set(data.items.map(r=>r.source))];
  $("#page").innerHTML=`${pageHead("Reports & exports","Download recorded telemetry with measurement sources, units, and UTC timestamps.",`<a class="button primary" href="/api/reports.csv" id="csv-export" download>↓ &nbsp;Export readings CSV</a>`)}
    <div class="metrics">${metric("Exportable recent readings",number(data.items.length),"Up to 200 shown here · CSV includes up to 10,000","▤")}${metric("Data sources",sources.length? sources.map(sourceTag).join(" "):"—","Each CSV row labels simulated or hardware source","◉")}${metric("Reporting timezone","UTC","Timestamps in ISO-8601 format","◷")}${metric("Report format","CSV","No PDF rendering service configured","↓")}</div>
    <div class="two-col"><section class="panel"><div class="panel-head"><div><div class="panel-title">Report contents</div><div class="panel-subtitle">CSV export includes actual recorded measurements only</div></div></div><div class="alert-row"><span class="severity-mark info"></span><div class="alert-copy"><div class="alert-title">Measurement details</div><div class="alert-detail">Source, timestamp, device, locality, street, flow, meter totalizer, pressure (when present), data quality.</div></div></div><div class="alert-row"><span class="severity-mark info"></span><div class="alert-copy"><div class="alert-title">Honest aggregation</div><div class="alert-detail">Overlapping meter totalizers are not presented as network totals. Export is raw telemetry, not a water-balance report.</div></div></div></section><div class="callout"><b>Data coverage</b>CSV export provides historical measurements, not PDF reports or verified savings. External notification delivery is not configured.</div></div>`;
}

async function audit() {
  const data=await api("/api/audit");
  $("#page").innerHTML=`${pageHead("Audit log","Recent administrative actions and authentication events.")}
    <section class="panel">${data.items.length?`<div class="table-wrap"><table><thead><tr><th>TIME (UTC)</th><th>ADMIN</th><th>ACTION</th><th>DETAIL</th></tr></thead><tbody>${data.items.map(row=>`<tr><td>${date(row.created_at)}</td><td>${esc(row.username||"System")}</td><td>${esc(human(row.action))}</td><td>${esc(row.detail)}</td></tr>`).join("")}</tbody></table></div>`:empty("No activity recorded","Administrative actions will appear here.")}</section>`;
}

async function settings() {
  const data=await api("/api/settings");
  $("#page").innerHTML=`${pageHead("System settings","Runtime configuration and integration status.")}
    <div class="two-col"><section class="panel"><div class="panel-head"><div><div class="panel-title">Environment</div><div class="panel-subtitle">Demo-grade local configuration</div></div></div><div class="coverage"><span class="coverage-label">Database</span><b class="coverage-value">${esc(data.database)}</b></div><div class="coverage"><span class="coverage-label">Display timezone</span><b class="coverage-value">${esc(data.timezone)}</b></div><div class="coverage"><span class="coverage-label">Session duration</span><b class="coverage-value">${number(data.sessionHours)} hours</b></div><div class="coverage"><span class="coverage-label">External notifications</span><b class="coverage-value" style="font-size:10px">${esc(data.externalNotifications)}</b></div></section>
    <div class="callout amber"><b>Before connecting physical sensors</b>Deploy behind HTTPS, set COOKIE_SECURE=true, provision a unique device key, and securely store X-Device-Key. Hardware ingestion is authenticated, but this standalone demo is not a substitute for a production TLS reverse proxy, secrets manager, operational backups, or security review.<br><br><b>Telemetry endpoint</b><span class="inline-code">${esc(data.telemetry)}</span><br><br><b>IoT credential handling</b>Generated once at device registration; stored as a SHA-256 hash and never retrievable from the server.</div></div>`;
}

async function boot() {
  $("#clock").textContent = `${new Date().toISOString().slice(11,16)} UTC`;
  try {
    const session=await api("/api/session");
    state.csrf=session.csrfToken;state.admin=session.admin;showApp();render("dashboard");
  } catch (_) { showLogin(); }
}

$("#login-form").addEventListener("submit",async event=>{
  event.preventDefault();const button=$("#login-submit");button.disabled=true;$("#login-error").textContent="";
  try{const result=await api("/api/login",{method:"POST",body:JSON.stringify({username:$("#username").value,password:$("#password").value})});state.csrf=result.csrfToken;state.admin=result.admin;showApp();render("dashboard");}
  catch(error){$("#login-error").textContent=error.message;}
  finally{button.disabled=false;}
});
$("#toggle-password").onclick=()=>{const input=$("#password");input.type=input.type==="password"?"text":"password";$("#toggle-password").textContent=input.type==="password"?"Show":"Hide";};
$("#navigation").addEventListener("click",event=>{const link=event.target.closest("[data-view]");if(link)render(link.dataset.view);});
$("#logout").onclick=async()=>{try{await api("/api/logout",{method:"POST",body:"{}"});}catch(error){toast(error.message,true);}showLogin();};
$("#menu-toggle").onclick=()=>$("#sidebar").classList.toggle("open");
window.addEventListener("resize",()=>{if(state.view==="dashboard")drawChart(window.__aquaSeries||[]);});
boot();
