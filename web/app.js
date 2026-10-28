"use strict";
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const api = {
  async get(u) { return (await fetch(u)).json(); },
  async post(u, b) {
    return (await fetch(u, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: b ? JSON.stringify(b) : null,
    })).json();
  },
};
const state = { selFlow: null, flowCount: 0, findingCount: 0, intRows: 0, checks: [] };

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2200);
}

/* ---------- tabs ---------- */
$$("nav a").forEach((a) => a.addEventListener("click", () => {
  $$("nav a").forEach((x) => x.classList.remove("active"));
  $$(".tab").forEach((x) => x.classList.remove("active"));
  a.classList.add("active");
  $("#tab-" + a.dataset.tab).classList.add("active");
  if (a.dataset.tab === "scanner") loadFindings();
  if (a.dataset.tab === "extensions") loadExtensions();
  if (a.dataset.tab === "logs") loadLogs();
  if (a.dataset.tab === "target") loadTargets();
}));

/* ---------- raw message helpers ---------- */
function reqToRaw(req) {
  let out = `${req.method} ${req.path} ${req.http_version || "HTTP/1.1"}\n`;
  for (const [k, v] of req.headers) out += `${k}: ${v}\n`;
  out += "\n" + (req.body_is_base64 ? "[binary body]" : req.body || "");
  return out;
}
function respToRaw(resp) {
  if (!resp) return "(no response)";
  let out = `${resp.http_version || "HTTP/1.1"} ${resp.status_code} ${resp.reason || ""}\n`;
  for (const [k, v] of resp.headers) out += `${k}: ${v}\n`;
  out += "\n" + (resp.body_is_base64 ? "[binary body, base64 omitted]" : resp.body || "");
  return out;
}
function statusClass(s) { return s ? "status-" + String(s)[0] : ""; }

/* ---------- history ---------- */
async function loadHistory() {
  const search = $("#histSearch").value;
  const scope = $("#histScope").checked;
  const rows = await api.get(`/api/history?search=${encodeURIComponent(search)}&scope_only=${scope}`);
  const tb = $("#histTable tbody"); tb.innerHTML = "";
  for (const f of rows) tb.appendChild(histRow(f));
}
function histRow(f) {
  const tr = document.createElement("tr");
  if (!f.in_scope) tr.className = "out-scope";
  tr.dataset.id = f.id;
  tr.innerHTML = `<td>${f.seq ?? ""}</td><td>${f.host}</td><td>${f.method}</td>
    <td>${f.path}</td><td class="${statusClass(f.status_code)}">${f.status_code ?? ""}</td>
    <td>${f.mime_type || ""}</td><td>${f.length ?? ""}</td>`;
  tr.addEventListener("click", () => selectFlow(f.id, tr));
  return tr;
}
async function selectFlow(id, tr) {
  $$("#histTable tbody tr").forEach((x) => x.classList.remove("sel"));
  if (tr) tr.classList.add("sel");
  const f = await api.get("/api/flow/" + id);
  if (f.error) return;
  state.selFlow = f;
  $("#histReq").textContent = reqToRaw(f.request);
  $("#histResp").textContent = respToRaw(f.response);
  $("#histSel").textContent = `${f.request.method} ${f.request.url}`;
  ["#toRepeater", "#toIntruder", "#auditFlow"].forEach((s) => $(s).disabled = false);
}
$("#histRefresh").addEventListener("click", loadHistory);
$("#histSearch").addEventListener("input", debounce(loadHistory, 300));
$("#histScope").addEventListener("change", loadHistory);
$("#histClear").addEventListener("click", async () => {
  await api.post("/api/history/clear"); loadHistory(); toast("history cleared");
});

/* ---------- send-to + audit ---------- */
$("#toRepeater").addEventListener("click", () => {
  const f = state.selFlow; if (!f) return;
  $("#repMethod").value = f.request.method;
  $("#repUrl").value = f.request.url;
  $("#repHeaders").value = f.request.headers.map(([k, v]) => `${k}: ${v}`).join("\n");
  $("#repBody").value = f.request.body_is_base64 ? "" : f.request.body || "";
  gotoTab("repeater"); toast("sent to Repeater");
});
$("#toIntruder").addEventListener("click", () => {
  const f = state.selFlow; if (!f) return;
  $("#intTemplate").value = reqToRawForIntruder(f.request);
  $("#intScheme").value = f.request.scheme;
  $("#intHost").value = f.request.host;
  $("#intPort").value = f.request.port;
  gotoTab("intruder"); toast("sent to Intruder");
});
function reqToRawForIntruder(req) {
  let out = `${req.method} ${req.path} ${req.http_version || "HTTP/1.1"}\r\n`;
  for (const [k, v] of req.headers) out += `${k}: ${v}\r\n`;
  out += "\r\n" + (req.body_is_base64 ? "" : req.body || "");
  return out;
}
$("#auditFlow").addEventListener("click", async () => {
  const f = state.selFlow; if (!f) return;
  const ids = selectedCheckIds();
  $("#auditFlow").disabled = true; $("#auditFlow").textContent = "auditing…";
  const r = await api.post("/api/scanner/audit", { flow_id: f.id, check_ids: ids });
  $("#auditFlow").disabled = false; $("#auditFlow").textContent = "Active audit this request";
  if (r.error) return toast(r.error);
  toast(`audit: ${r.points} points, ${r.requests} reqs, ${r.findings} findings${r.note ? " — " + r.note : ""}`);
});

/* ---------- intercept ---------- */
$("#interceptToggle").addEventListener("click", async () => {
  const r = await api.post("/api/intercept/toggle");
  setInterceptUI(r.enabled);
});
function setInterceptUI(on) {
  $("#interceptToggle").classList.toggle("on", on);
  $("#interceptState").textContent = on ? "on" : "off";
}
async function loadPending() {
  const held = await api.get("/api/intercept/pending");
  const tb = $("#heldTable tbody"); tb.innerHTML = "";
  for (const h of held) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${h.host}</td><td>${h.request.method}</td><td>${h.request.path}</td>`;
    tr.addEventListener("click", () => selectHeld(h));
    tb.appendChild(tr);
  }
  const n = held.length;
  const b = $("#interceptBadge");
  b.style.display = n ? "" : "none"; b.textContent = n;
}
let curHeld = null;
function selectHeld(h) {
  curHeld = h;
  $("#interceptEditor").value = reqToRaw(h.request);
  $("#forwardBtn").disabled = false; $("#dropBtn").disabled = false;
}
$("#forwardBtn").addEventListener("click", async () => {
  if (!curHeld) return;
  const parsed = parseRaw($("#interceptEditor").value);
  await api.post(`/api/intercept/${curHeld.id}/forward`, {
    method: parsed.method, path: parsed.path, headers: parsed.headers, body: parsed.body,
  });
  clearHeldEditor();
});
$("#dropBtn").addEventListener("click", async () => {
  if (!curHeld) return;
  await api.post(`/api/intercept/${curHeld.id}/forward`, { drop: true });
  clearHeldEditor();
});
function clearHeldEditor() {
  curHeld = null; $("#interceptEditor").value = "";
  $("#forwardBtn").disabled = true; $("#dropBtn").disabled = true;
  loadPending();
}

/* ---------- scope + targets ---------- */
async function loadScope() {
  const s = await api.get("/api/scope");
  $("#scopeInclude").value = s.include.join("\n");
  $("#scopeExclude").value = s.exclude.join("\n");
}
$("#saveScope").addEventListener("click", async () => {
  await api.post("/api/scope", {
    include: $("#scopeInclude").value.split("\n").filter(Boolean),
    exclude: $("#scopeExclude").value.split("\n").filter(Boolean),
  });
  toast("scope saved");
});
$("#addTargets").addEventListener("click", async () => {
  const urls = $("#targetInput").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const r = await api.post("/api/targets/add", { urls });
  toast(`added ${r.added} (total ${r.total})`); loadTargets();
});
$("#seedTargets").addEventListener("click", async () => {
  toast("fetching targets…");
  const r = await api.post("/api/targets/seed", { crawl: $("#crawlToggle").checked });
  toast(`fetched ${r.fetched}, ${r.targets} in list`); loadTargets();
});
$("#auditTargets").addEventListener("click", async () => {
  toast("auditing all targets…");
  const r = await api.post("/api/targets/audit", { flow_id: "", check_ids: selectedCheckIds() });
  toast(`audited ${r.targets} targets: ${r.findings} findings from ${r.requests} reqs`);
});
async function loadTargets() {
  const ts = await api.get("/api/targets");
  const tb = $("#targetTable tbody"); tb.innerHTML = "";
  for (const t of ts) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${t.url}</td><td class="${statusClass(t.status)}">${t.status ?? "—"}</td>`;
    tb.appendChild(tr);
  }
}

/* ---------- repeater ---------- */
$("#repSend").addEventListener("click", async () => {
  const headers = $("#repHeaders").value.split("\n").filter((l) => l.includes(":"))
    .map((l) => { const i = l.indexOf(":"); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; });
  $("#repResp").textContent = "sending…";
  const r = await api.post("/api/repeater/send", {
    method: $("#repMethod").value, url: $("#repUrl").value, headers,
    body: $("#repBody").value, follow_redirects: $("#repFollow").checked,
  });
  if (r.error) { $("#repResp").textContent = "ERROR: " + r.error; $("#repMeta").textContent = ""; return; }
  $("#repResp").textContent = respToRaw(r);
  $("#repMeta").textContent = `· ${r.status_code} · ${r.length} bytes · ${r.elapsed_ms} ms`;
});

/* ---------- intruder ---------- */
$("#addMarker").addEventListener("click", () => {
  const ta = $("#intTemplate");
  const s = ta.selectionStart, e = ta.selectionEnd;
  const v = ta.value;
  ta.value = v.slice(0, s) + "§" + v.slice(s, e) + "§" + v.slice(e);
});
$("#intStart").addEventListener("click", async () => {
  const blocks = $("#intPayloads").value.split(/\n\s*\n/).map((b) => b.split("\n").filter(Boolean));
  $("#intTable tbody").innerHTML = ""; state.intRows = 0;
  $("#intMeta").textContent = "starting…";
  await api.post("/api/intruder/start", {
    template: $("#intTemplate").value, scheme: $("#intScheme").value,
    host: $("#intHost").value, port: parseInt($("#intPort").value) || 443,
    attack: $("#intAttack").value, payload_sets: blocks,
    sniper_original: "",
  });
});

/* ---------- scanner ---------- */
async function loadChecks() {
  const r = await api.get("/api/scanner/checks");
  state.checks = r.active;
  const el = $("#checkList"); el.innerHTML = "";
  for (const c of r.active) {
    const id = "chk_" + c.id.replace(/\W/g, "");
    const lbl = document.createElement("label");
    lbl.innerHTML = `<input type="checkbox" id="${id}" value="${c.id}" checked>
      <span class="sev ${c.severity}">${c.severity}</span> ${c.name}`;
    el.appendChild(lbl);
  }
}
function selectedCheckIds() {
  return [...$$("#checkList input:checked")].map((i) => i.value);
}
async function loadFindings() {
  const rows = await api.get("/api/findings");
  const tb = $("#findTable tbody"); tb.innerHTML = "";
  for (const f of rows) tb.appendChild(findRow(f));
  state.findingCount = rows.length; $("#findingCount").textContent = rows.length;
  const b = $("#scanBadge"); b.style.display = rows.length ? "" : "none"; b.textContent = rows.length;
}
function findRow(f) {
  const tr = document.createElement("tr");
  tr.innerHTML = `<td><span class="sev ${f.severity}">${f.severity}</span></td>
    <td>${f.name}</td><td>${f.host}</td><td title="${esc(f.detail)}">${esc(f.detail)}</td>`;
  return tr;
}
$("#clearFind").addEventListener("click", async () => {
  await api.post("/api/findings/clear"); loadFindings(); toast("findings cleared");
});

/* ---------- decoder ---------- */
async function loadDecoderModes() {
  const modes = await api.get("/api/decoder/modes");
  const sel = $("#decMode"); sel.innerHTML = "";
  for (const m of modes) { const o = document.createElement("option"); o.value = o.textContent = m; sel.appendChild(o); }
}
async function decode(op) {
  const r = await api.post("/api/decoder", { mode: $("#decMode").value, op, text: $("#decIn").value });
  $("#decOut").textContent = r.result;
}
$("#decEncode").addEventListener("click", () => decode("encode"));
$("#decDecode").addEventListener("click", () => decode("decode"));

/* ---------- extensions / logs ---------- */
async function loadExtensions() {
  const rows = await api.get("/api/extensions");
  const tb = $("#extTable tbody"); tb.innerHTML = "";
  for (const e of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><input type="checkbox" ${e.enabled ? "checked" : ""} ${e.error ? "disabled" : ""}></td>
      <td>${esc(e.name)}</td><td>${esc(e.description || e.error || "")}</td><td class="mono">${e.filename}</td>`;
    tr.querySelector("input").addEventListener("change", (ev) =>
      api.post(`/api/extensions/${e.id}/toggle?enabled=${ev.target.checked}`));
    tb.appendChild(tr);
  }
}
async function loadLogs() {
  const rows = await api.get("/api/logs");
  $("#logOut").textContent = rows.map((l) =>
    `[${new Date(l.ts * 1000).toLocaleTimeString()}] ${l.source}: ${l.msg}`).join("\n");
}

/* ---------- built-in browser ---------- */
let browserRunning = false;
async function refreshBrowser() {
  const s = await api.get("/api/browser");
  const btn = $("#browserBtn");
  if (!s.any) {
    btn.disabled = true;
    btn.title = "No Chromium found. Install Chrome or run: playwright install chromium";
    return;
  }
  browserRunning = s.running;
  btn.textContent = s.running ? "⬛ Close browser" : "🌐 Open browser";
  btn.title = `Engine: ${s.system ? "system Chrome" : "Playwright Chromium"} — routes through the proxy`;
}
$("#browserBtn").addEventListener("click", async () => {
  const btn = $("#browserBtn");
  btn.disabled = true;
  if (browserRunning) {
    await api.post("/api/browser/close");
    toast("browser closed");
  } else {
    const r = await api.post("/api/browser/launch", { engine: "auto" });
    toast(r.ok ? `browser launched (${r.engine})` : "launch failed: " + r.error);
  }
  btn.disabled = false;
  refreshBrowser();
});

/* ---------- websocket ---------- */
function connectWS() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => $("#wsState").textContent = "live";
  ws.onclose = () => { $("#wsState").textContent = "off"; setTimeout(connectWS, 2000); };
  ws.onmessage = (ev) => {
    const { type, data } = JSON.parse(ev.data);
    if (type === "flow") {
      state.flowCount++; $("#flowCount").textContent = state.flowCount;
      const tb = $("#histTable tbody");
      if ($("#tab-proxy").classList.contains("active")) tb.prepend(histRow(data));
    } else if (type === "finding") {
      state.findingCount++; $("#findingCount").textContent = state.findingCount;
      const b = $("#scanBadge"); b.style.display = ""; b.textContent = state.findingCount;
      if ($("#tab-scanner").classList.contains("active")) $("#findTable tbody").prepend(findRow(data));
    } else if (type === "intercept") {
      loadPending();
    } else if (type === "intercept_resolved") {
      loadPending();
    } else if (type === "intercept_state") {
      setInterceptUI(data.enabled);
    } else if (type === "intruder_result") {
      state.intRows++;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${data.index}</td><td class="mono">${esc((data.payloads || []).join(" | "))}</td>
        <td class="${statusClass(data.status)}">${data.error ? "ERR" : data.status}</td>
        <td>${data.length}</td><td>${data.elapsed_ms ?? ""}</td>`;
      $("#intTable tbody").appendChild(tr);
    } else if (type === "intruder_start") {
      $("#intMeta").textContent = `· running ${data.total} requests…`;
    } else if (type === "intruder_done") {
      $("#intMeta").textContent = `· done (${data.count} requests)`;
    } else if (type === "targets") {
      if ($("#tab-target").classList.contains("active")) loadTargets();
    } else if (type === "log") {
      if ($("#tab-logs").classList.contains("active")) loadLogs();
    }
  };
}

/* ---------- utils ---------- */
function parseRaw(raw) {
  const [head, ...rest] = raw.split("\n\n");
  const lines = head.split("\n");
  const [method, path] = lines[0].split(" ");
  const headers = lines.slice(1).filter((l) => l.includes(":"))
    .map((l) => { const i = l.indexOf(":"); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; });
  return { method, path, headers, body: rest.join("\n\n") };
}
function gotoTab(name) { document.querySelector(`nav a[data-tab="${name}"]`).click(); }
function esc(s) { return (s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

/* ---------- init ---------- */
(async function init() {
  const st = await api.get("/api/status");
  setInterceptUI(st.intercept);
  await Promise.all([loadHistory(), loadScope(), loadChecks(), loadDecoderModes(), loadPending(), refreshBrowser()]);
  connectWS();
})();
