"use strict";
const $ = (s) => document.querySelector(s);
const DOMAINS = ["endpoint", "identity", "email", "network", "cloud", "data", "agent"];
const TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hhmmss = (ts) => new Date(ts * 1000).toLocaleTimeString("th-TH", { hour12: false });
const store = { get: (k) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } },
                set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };

const state = { paused: false, filter: new Set(DOMAINS), incidents: [], selected: null,
  buckets: [], lastStats: null, ctrl: null };
const BUCKET_SEC = 5, BUCKETS = 60;

function headers() { const k = store.get("apiKey"); return k ? { "X-API-Key": k } : {}; }

// ---------- connection (SSE over fetch so the API key header can be sent) ----------
async function connect() {
  state.ctrl?.abort();
  const ctrl = state.ctrl = new AbortController();
  try {
    const res = await fetch("/api/soc/stream", { headers: headers(), signal: ctrl.signal });
    if (res.status === 401) { setLive(false, "ต้องใช้ API key"); showKeyBar("API key ไม่ถูกต้องหรือยังไม่ได้ใส่"); return; }
    if (!res.ok || !res.body) throw new Error("HTTP " + res.status);
    $("#keyBar").hidden = true;
    setLive(true);
    loadCti(); loadQueries();
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += value;
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) { handle(buf.slice(0, i)); buf = buf.slice(i + 2); }
    }
  } catch (e) {
    if (ctrl.signal.aborted) return;
  }
  setLive(false);
  setTimeout(connect, 3000);
}

function handle(chunk) {
  let ev = "message", data = "";
  for (const line of chunk.split("\n")) {
    if (line.startsWith("event:")) ev = line.slice(6).trim();
    else if (line.startsWith("data:")) data += line.slice(5).trim();
  }
  if (!data) return;
  const msg = JSON.parse(data);
  if (ev === "snapshot") {
    $("#stream").innerHTML = "";
    msg.events.forEach((e) => addEvent(e, false));
    state.buckets = []; pushBucket(msg.events);
    renderIncidents(msg.incidents); renderEndpoints(msg.endpoints); renderStats(msg.stats);
    $("#agentLog").innerHTML = ""; msg.agent_records.forEach((r) => addAgentRecord(r, false));
    renderAgents(msg.agents); renderRules(msg.rules);
    $("#offaiLive").innerHTML = ""; msg.events.filter((e) => e.detector === "offensive-ai").forEach((e) => addOffai(e, false));
    renderOffai(msg.offai);
  } else if (ev === "tick") {
    msg.events.forEach((e) => addEvent(e, true));
    pushBucket(msg.events);
    if (msg.incidents) renderIncidents(msg.incidents);
    if (msg.endpoints) renderEndpoints(msg.endpoints);
    renderStats(msg.stats);
    msg.agent_records.forEach((r) => addAgentRecord(r, true));
    renderAgents(msg.agents); renderRules(msg.rules);
    msg.events.filter((e) => e.detector === "offensive-ai").forEach((e) => addOffai(e, true));
    renderOffai(msg.offai);
    if (state.session && msg.agent_records.some((r) => r.session === state.session)) openSession(state.session, false);
  }
}

function setLive(on, text) {
  const el = $("#live");
  el.className = "pill " + (on ? "on" : "off");
  el.querySelector("span").textContent = text || (on ? "LIVE" : "กำลังเชื่อมต่อใหม่…");
}
function showKeyBar(msg) { $("#keyBar").hidden = false; $("#keyMsg").textContent = msg || ""; $("#apiKey").value = store.get("apiKey"); }

// ---------- KPIs ----------
const sparkHist = [];
function setKpi(id, v) {
  const el = $(id); const s = String(v);
  if (el.textContent !== s) { el.textContent = s; el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); }
}
function renderStats(s) {
  state.lastStats = s;
  setKpi("#k-epm", s.events_per_min);
  $("#nb-inc").textContent = s.open_incidents;
  $("#nb-ep").textContent = s.endpoints.healthy + s.endpoints.at_risk + s.endpoints.compromised;
  setKpi("#k-open", s.open_incidents);
  setKpi("#k-coord", s.coordinated);
  setKpi("#k-cti", s.cti_hits);
  const ep = s.endpoints, total = ep.healthy + ep.at_risk + ep.compromised;
  setKpi("#k-ep", `${ep.healthy}/${total}`);
  $("#k-ep-s").innerHTML = `<span style="color:var(--high)">${ep.at_risk} at risk</span> · <span style="color:var(--critical)">${ep.compromised} compromised</span>`;
  setKpi("#k-crit", `${s.severity.critical} / ${s.severity.high}`);
  $("#k-crit-s").textContent = `medium ${s.severity.medium} · low ${s.severity.low}`;
  $("#k-open-s").textContent = `${s.open_incidents - s.coordinated} single-domain`;
  if (s.mode) {
    const m = s.mode, el = $("#modePill");
    el.textContent = m.simulation ? (m.ingested ? `Telemetry: SIMULATED + ${m.ingested} real` : "Telemetry: SIMULATED")
      : `Telemetry: LIVE · ${m.ingested.toLocaleString()} records ใหม่${m.restored ? ` · ${m.restored} alerts จากฐานข้อมูล` : ""}`;
    el.className = "pill " + (m.simulation ? "warn" : "ok");
  }
  sparkHist.push(s.events_per_min); if (sparkHist.length > 60) sparkHist.shift();
  drawSpark();
  renderTactics(s.tactics);
  DOMAINS.forEach((d) => { const b = document.getElementById("lg-" + d); if (b) b.textContent = s.totals[d]; });
}

function drawSpark() {
  const c = $("#spark"), ctx = fit(c);
  const w = c.clientWidth, h = c.clientHeight, max = Math.max(...sparkHist, 1);
  ctx.clearRect(0, 0, w, h);
  ctx.beginPath();
  sparkHist.forEach((v, i) => { const x = (i / 59) * w, y = h - (v / max) * (h - 3) - 1; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = css("--accent"); ctx.lineWidth = 1.5; ctx.stroke();
}

function fit(c) {
  const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  if (c.width !== w * dpr || c.height !== h * dpr) { c.width = w * dpr; c.height = h * dpr; }
  const ctx = c.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); return ctx;
}

// ---------- throughput chart ----------
function pushBucket(events, nowSec = Date.now() / 1000) {
  // keep a continuous window of BUCKETS slots ending "now" (empty slots = 0 events)
  const now = Math.floor(nowSec / BUCKET_SEC);
  const byT = new Map(state.buckets.map((b) => [b.t, b]));
  state.buckets = [];
  for (let t = now - BUCKETS + 1; t <= now; t++)
    state.buckets.push(byT.get(t) || { t, ...Object.fromEntries(DOMAINS.map((d) => [d, 0])) });
  const first = state.buckets[0].t;
  events.forEach((e) => { const b = state.buckets[Math.floor(e.ts / BUCKET_SEC) - first]; if (b) b[e.domain]++; });
  drawFlow();
}
function drawFlow() {
  const c = $("#flow"), ctx = fit(c), w = c.clientWidth, h = c.clientHeight, pad = 22;
  ctx.clearRect(0, 0, w, h);
  const data = state.buckets, max = Math.max(4, ...data.map((b) => Math.max(...DOMAINS.map((d) => b[d]))));
  ctx.strokeStyle = css("--grid"); ctx.fillStyle = css("--muted"); ctx.font = "10px system-ui"; ctx.lineWidth = 1;
  for (let g = 0; g <= 2; g++) {
    const y = pad / 2 + (h - pad) * (g / 2);
    ctx.beginPath(); ctx.moveTo(28, y); ctx.lineTo(w, y); ctx.stroke();
    ctx.fillText(String(Math.round(max * (1 - g / 2))), 4, y + 3);
  }
  const xs = (i) => 28 + i * ((w - 30) / (BUCKETS - 1));
  const ys = (v) => pad / 2 + (h - pad) * (1 - v / max);
  for (const d of DOMAINS) {
    const col = css("--" + d);
    ctx.beginPath();
    data.forEach((b, i) => (i ? ctx.lineTo(xs(i), ys(b[d])) : ctx.moveTo(xs(i), ys(b[d]))));
    ctx.strokeStyle = col; ctx.lineWidth = 1.8; ctx.lineJoin = "round"; ctx.stroke();
    if (data.length) { const l = data.length - 1; ctx.fillStyle = col; ctx.beginPath(); ctx.arc(xs(l), ys(data[l][d]), 2.5, 0, 7); ctx.fill(); }
  }
  ctx.fillStyle = css("--muted"); ctx.fillText("−5 นาที", 30, h - 2); ctx.fillText("ตอนนี้", w - 34, h - 2);
}

// ---------- MITRE ----------
function renderTactics(t) {
  const max = Math.max(1, ...Object.values(t));
  $("#tactics").innerHTML = TACTICS.map((k) => `<div class="tac"><span>${esc(k)}</span>
    <div class="bar"><i style="width:${((t[k] || 0) / max) * 100}%"></i></div><b>${t[k] || 0}</b></div>`).join("");
}

// ---------- stream ----------
function addEvent(e, animate) {
  if (state.paused || !state.filter.has(e.domain)) return;
  const li = document.createElement("li");
  li.style.setProperty("--c", css("--" + e.domain));
  if (!animate) li.style.animation = "none";
  const extra = [e.remote_ip && `→ ${e.remote_ip}`, e.cve].filter(Boolean).map(esc).join(" ");
  li.innerHTML = `<span class="mono muted">${hhmmss(e.ts)}</span><i class="d"></i>
    <div>${e.simulated === false ? '<span class="real">REAL</span>' : ""}<span class="sev" style="--sevc:var(--${esc(e.severity)})">${esc(e.severity)}</span> ${esc(e.title)}
    <div class="x">${esc(e.domain)} · ${esc(e.host)} · ${esc(e.user)} · ${esc(e.technique)} ${extra}
    ${e.cti_match ? `<span class="cti">⚑ CTI: ${esc(e.cti_match)}</span>` : ""}</div></div>`;
  const ul = $("#stream"); ul.prepend(li);
  while (ul.children.length > 60) ul.lastChild.remove();
}

// ---------- endpoints ----------
function renderEndpoints(eps) {
  const order = { compromised: 0, at_risk: 1, healthy: 2 };
  eps = [...eps].sort((a, b) => order[a.status] - order[b.status] || b.alerts - a.alerts);
  $("#endpoints tbody").innerHTML = eps.map((p) => `<tr><td>${esc(p.host)}<div class="sub">${esc(p.os)}</div></td>
    <td><span class="st ${esc(p.status)}">${esc(p.status.replace("_", " "))}</span></td>
    <td style="color:var(${p.realtime_protection ? "--cti" : "--critical"})">${p.realtime_protection ? "On" : "OFF"}</td>
    <td>${p.alerts}</td></tr>`).join("");
}

// ---------- incidents ----------
function renderIncidents(list) {
  state.incidents = list;
  $("#incidents").innerHTML = list.length ? list.map((i) => `<div class="inc ${i.coordinated ? "coord" : ""} ${i.status}"
      data-id="${i.id}" style="--sevc:var(--${esc(i.severity)})">
      <div class="t"><span>${i.real ? '<span class="real">REAL</span>' : ""}#${i.id} ${esc(i.title)}</span><span class="sev">${esc(i.severity)}</span></div>
      <div class="m">${i.domains.map((d) => `<span class="chip" style="color:var(--${esc(d)})">${esc(d)}</span>`).join("")}
        <span>${i.alerts.length} alerts</span><span>${esc(i.hosts.join(", "))}</span><span>${hhmmss(i.last_ts)}</span>
        ${i.status !== "open" ? `<span class="ist ${esc(i.status)}">${esc(i.status.replace("_", " "))}</span>` : ""}${i.assignee ? `<span>👤 ${esc(i.assignee)}</span>` : ""}</div></div>`).join("")
    : `<p class="muted">ยังไม่มี incident — รอ telemetry…</p>`;
  if (state.selected) { const cur = list.find((i) => i.id === state.selected); if (cur) renderDetail(cur); }
}
$("#incidents").addEventListener("click", (ev) => {
  const el = ev.target.closest(".inc"); if (!el) return;
  state.selected = Number(el.dataset.id);
  const inc = state.incidents.find((i) => i.id === state.selected);
  if (inc) { renderDetail(inc); $("#detailCard").scrollIntoView({ behavior: "smooth", block: "nearest" }); }
});
$("#d-close").onclick = () => { state.selected = null; $("#detailCard").hidden = true; };

function renderDetail(inc) {
  $("#detailCard").hidden = false;
  renderWorkflow(inc);
  $("#d-title").innerHTML = `#${inc.id} · ${esc(inc.title)} · <span class="sev" style="--sevc:var(--${esc(inc.severity)})">${esc(inc.severity)}</span>
    <small class="muted">users: ${esc(inc.users.join(", "))} · tactics: ${esc(inc.tactics.join(" → "))}</small>`;
  // graph: domain nodes (left) → incident hub (center) → affected hosts (right)
  const W = 720, H = 300, doms = inc.domains, hosts = inc.hosts;
  const y = (i, n) => (H / (n + 1)) * (i + 1);
  let svg = "";
  doms.forEach((d, i) => {
    const yy = y(i, doms.length), col = css("--" + d), n = inc.alerts.filter((a) => a.domain === d).length;
    svg += `<path class="flow" d="M170 ${yy} C 260 ${yy}, 280 ${H / 2}, 330 ${H / 2}" stroke="${col}" fill="none" stroke-width="2"/>
      <rect x="20" y="${yy - 20}" width="150" height="40" rx="8" fill="${css("--node-bg")}" stroke="${col}"/>
      <text x="34" y="${yy - 3}" style="fill:${col};font-weight:700;text-transform:uppercase">${esc(d)}</text>
      <text x="34" y="${yy + 13}" style="fill:${css("--muted")};font-size:11px">${n} alert(s)</text>`;
  });
  hosts.forEach((h, i) => {
    const yy = y(i, hosts.length);
    svg += `<path d="M450 ${H / 2} C 500 ${H / 2}, 510 ${yy}, 560 ${yy}" stroke="${css("--node-line")}" fill="none" stroke-width="1.5"/>
      <rect x="560" y="${yy - 14}" width="145" height="28" rx="6" fill="${css("--node-bg")}" stroke="${css("--node-line")}"/>
      <text x="572" y="${yy + 4}" style="font-family:var(--mono);font-size:11px">${esc(h)}</text>`;
  });
  const sc = css("--" + inc.severity);
  svg += `<rect x="330" y="${H / 2 - 32}" width="120" height="64" rx="10" fill="${css("--hub-bg")}" stroke="${sc}" stroke-width="2"/>
    <text x="390" y="${H / 2 - 8}" text-anchor="middle" style="fill:${sc};font-weight:700;font-size:11px">${inc.coordinated ? "COORDINATED" : "INCIDENT"}</text>
    <text x="390" y="${H / 2 + 10}" text-anchor="middle" style="font-weight:700">#${inc.id}</text>
    <text x="390" y="${H / 2 + 24}" text-anchor="middle" style="fill:${css("--muted")};font-size:10px">${inc.alerts.length} correlated</text>`;
  $("#graph").innerHTML = svg;
  $("#timeline").innerHTML = inc.alerts.map((a) => `<li style="--c:var(--${esc(a.domain)})">
    <span class="mono muted">${hhmmss(a.ts)}</span> <span class="sev" style="--sevc:var(--${esc(a.severity)})">${esc(a.severity)}</span>
    ${esc(a.title)}<div class="muted">${esc(a.domain)} · ${esc(a.host)} · ${esc(a.technique)}${a.session ? ` · <a href="#" class="slink" data-s="${esc(a.session)}">${esc(a.agent)} / ${esc(a.session)}</a>` : ""}${a.cti_match ? ` · <span style="color:var(--cti)">CTI: ${esc(a.cti_match)}</span>` : ""}</div></li>`).join("");
}

// ---------- incident workflow ----------
function analystName() {
  let a = store.get("analyst");
  if (!a) { a = prompt("ชื่อผู้ปฏิบัติงาน (analyst)") || ""; if (a.length >= 2) store.set("analyst", a); }
  return a.length >= 2 ? a : "";
}
function renderWorkflow(inc) {
  if (state.wfFor !== inc.id) {  // only reset the form when switching incidents, never while typing
    state.wfFor = inc.id;
    $("#wfStatus").value = inc.status; $("#wfAssignee").value = inc.assignee || ""; $("#wfNote").value = ""; $("#wfMsg").textContent = "";
  }
  const items = [...(inc.notes || []).map((n) => ({ ...n, kind: "note" })), ...(inc.history || []).map((h) => ({ ...h, kind: "sys" }))]
    .sort((a, b) => b.ts - a.ts);
  $("#wfNotes").innerHTML = items.map((x) => x.kind === "note"
    ? `<li><span class="mono muted">${new Date(x.ts * 1000).toLocaleString("th-TH", { hour12: false })}</span> <b>${esc(x.analyst)}</b>: ${esc(x.text)}</li>`
    : `<li class="sys"><span class="mono">${new Date(x.ts * 1000).toLocaleString("th-TH", { hour12: false })}</span> ${esc(x.analyst)} · ${esc(x.change)}</li>`).join("")
    || '<li class="muted">ยังไม่มีบันทึก</li>';
}
$("#wfSave").onclick = async () => {
  const id = state.selected, analyst = analystName(); if (!id || !analyst) return;
  const body = { analyst, status: $("#wfStatus").value, assignee: $("#wfAssignee").value.trim() };
  const note = $("#wfNote").value.trim(); if (note) body.note = note;
  try {
    const inc = await api(`/api/soc/incidents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const i = state.incidents.findIndex((x) => x.id === id); if (i >= 0) state.incidents[i] = inc;
    $("#wfNote").value = ""; $("#wfMsg").textContent = inc.real ? "บันทึกแล้ว (เก็บถาวร + audit log)" : "บันทึกแล้ว (incident จำลอง: ไม่เก็บถาวร)";
    renderIncidents(state.incidents);
  } catch (e) { $("#wfMsg").textContent = "ไม่สำเร็จ: " + e.message; }
};
async function download(path, filename, open) {
  const r = await fetch(path, { headers: headers() });
  if (!r.ok) throw new Error("HTTP " + r.status);
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a"); a.href = url;
  if (open) a.target = "_blank"; else a.download = filename;
  a.rel = "noopener"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 60000);
}
$("#wfReport").onclick = () => { if (state.selected) download(`/api/soc/incidents/${state.selected}/report?analyst=${encodeURIComponent(store.get("analyst"))}`, "", true).catch((e) => { $("#wfMsg").textContent = e.message; }); };
$("#incCsv").onclick = () => download("/api/soc/incidents.csv", "soc-incidents.csv", false).catch((e) => alert(e.message));

// ---------- Agentic AI ----------
const RULE_SEV = {};
function renderAgents(list) {
  state.agents = list;
  $("#nb-agent").textContent = list.length;
  $("#agents tbody").innerHTML = list.map((a) => `<tr><td class="mono">${esc(a.id)}<div class="muted" style="font-family:inherit">owner ${esc(a.owner)}</div></td>
    <td class="mono">${esc(a.host)}</td><td title="${esc((a.scopes || []).join(", "))}">${a.scopes ? a.scopes.length : "?"}${a.shell ? ' <span class="muted">+shell</span>' : ""}</td>
    <td>${a.calls}</td><td style="color:var(${a.denied ? "--high" : "--muted"})">${a.denied}</td>
    <td><span class="risk"><i style="width:${a.risk}%"></i></span>${a.risk}</td>
    <td><span class="st ${esc(a.status)}">${esc(a.status)}</span>${a.registered === false ? ' <span class="st unregistered" title="seen in logs but not in the agent inventory">unregistered</span>' : ""}</td>
    <td><button title="บันทึกสถานะ contained และ audit log — ยังไม่มี connector สั่ง revoke token จริง" class="mini ${a.contained ? "release" : ""}" data-agent="${esc(a.id)}" data-on="${a.contained ? 0 : 1}">${a.contained ? "Release" : "Contain"}</button></td></tr>`).join("");
}
function renderRules(rules) {
  rules.forEach((r) => { RULE_SEV[r.id] = r.severity; });
  $("#rules").innerHTML = rules.map((r) => `<li class="${r.hits ? "hit" : ""}"><span class="mono">${esc(r.id)}</span>
    <span>${esc(r.title)} <span class="sev" style="--sevc:var(--${esc(r.severity)})">${esc(r.severity)}</span>
    <span class="muted">· ${esc(r.technique)} · ${esc(r.tactic)}</span></span><b>${r.hits}</b></li>`).join("");
}
function agentRow(r) {
  const chips = (r.rules || []).map((id) => `<span class="rchip" style="--sevc:var(--${esc(RULE_SEV[id] || "medium")})">${esc(id)}</span>`).join("");
  return `<span class="mono muted">${hhmmss(r.ts)}</span><span class="mono">${esc(r.agent)}</span>
    <span class="sum"><span class="kind">${esc(r.kind)}</span>${esc(r.summary)} <span class="muted">${esc(r.session)}</span>${chips}</span>
    <span class="dec ${esc(r.decision)}">${esc(r.decision)}</span>`;
}
function addAgentRecord(r, animate) {
  if (state.paused) return;
  const li = document.createElement("li");
  li.dataset.s = r.session; li.innerHTML = agentRow(r);
  if (animate) li.style.animation = "slide .35s ease-out";
  const ul = $("#agentLog"); ul.prepend(li);
  while (ul.children.length > 80) ul.lastChild.remove();
}
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { ...headers(), ...(opts.headers || {}) } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || "HTTP " + r.status);
  return r.json();
}
function buildTree(procs) {
  const kids = {}; procs.forEach((p) => { (kids[p.ppid] ||= []).push(p); });
  const shells = ["bash", "sh", "zsh", "cmd.exe", "powershell.exe", "pwsh", "curl.exe"];
  const node = (p) => `<li><span class="img ${p.rules?.length || (p.ppid && shells.includes(p.image) && !state.sessionShell) ? "bad" : ""}">${esc(p.image)}</span>
    <span class="muted">pid ${p.pid}</span>${(p.rules || []).map((id) => `<span class="rchip" style="--sevc:var(--${esc(RULE_SEV[id] || "medium")})">${esc(id)}</span>`).join("")}
    <span class="cmd">${esc(p.cmdline)}</span>${kids[p.pid] ? `<ul>${kids[p.pid].map(node).join("")}</ul>` : ""}</li>`;
  const pids = new Set(procs.map((p) => p.pid));
  const roots = procs.filter((p) => p.ppid == null || !pids.has(p.ppid));
  return roots.length ? `<ul>${roots.map(node).join("")}</ul>` : '<p class="muted">ไม่มี process ใน session นี้</p>';
}
async function openSession(sid, scroll = true) {
  try {
    const d = await api("/api/soc/agents/sessions/" + encodeURIComponent(sid));
    state.session = sid; state.sessionShell = d.agent.shell;
    $("#sessionBox").hidden = false;
    $("#s-title").innerHTML = `${esc(sid)} · <span class="mono">${esc(d.agent.id)}</span> @ ${esc(d.agent.host)}
      <small class="muted">scopes: ${esc(d.agent.scopes ? d.agent.scopes.join(", ") : "unknown (unregistered)")} · egress: ${esc(d.agent.egress ? d.agent.egress.join(", ") : "unknown")}</small>`;
    $("#s-tree").innerHTML = buildTree(d.processes);
    $("#s-net").innerHTML = d.network.map((n) => `<li><span class="mono muted">${hhmmss(n.ts)}</span><span class="mono">${esc(n.ip)}:${n.port}</span>
      <span class="sum">${esc(n.dest)} · ${(n.bytes_out / 1e6).toFixed(2)} MB out ${(n.rules || []).map((id) => `<span class="rchip" style="--sevc:var(--${esc(RULE_SEV[id])})">${esc(id)}</span>`).join("")}</span>
      ${d.agent.egress ? `<span class="dec ${d.agent.egress.includes(n.dest) ? "allowed" : "denied"}">${d.agent.egress.includes(n.dest) ? "allowlisted" : "unapproved"}</span>` : '<span class="dec allowed">unknown</span>'}</li>`).join("")
      || '<li class="muted">ไม่มี</li>';
    $("#s-log").innerHTML = d.records.filter((r) => r.kind !== "network" && r.kind !== "process").map((r) => `<li style="--c:var(--${r.rules.length ? "critical" : "agent"})">
      <span class="mono muted">${hhmmss(r.ts)}</span> <span class="kind">${esc(r.kind)}</span> ${esc(r.summary)}
      <span class="dec ${esc(r.decision)}">${esc(r.decision)}</span>${r.rules.map((id) => `<span class="rchip" style="--sevc:var(--${esc(RULE_SEV[id])})">${esc(id)}</span>`).join("")}
      ${r.snippet ? `<div class="muted mono">${esc(r.snippet)}</div>` : ""}${r.on_behalf_of ? `<div class="muted">on behalf of ${esc(r.on_behalf_of)}</div>` : ""}</li>`).join("");
    if (scroll) $("#sessionBox").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) { /* session aged out of the buffer */ }
}
$("#s-close").onclick = () => { state.session = null; $("#sessionBox").hidden = true; };
for (const sel of ["#agentLog", "#huntRes"]) $(sel).addEventListener("click", (ev) => { const li = ev.target.closest("li[data-s]"); if (li) openSession(li.dataset.s); });
document.addEventListener("click", (ev) => { const a = ev.target.closest("a.slink"); if (a) { ev.preventDefault(); openSession(a.dataset.s); } });
$("#agents").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-agent]"); if (!b) return;
  const on = b.dataset.on === "1";
  const analyst = store.get("analyst") || prompt("ชื่อผู้ปฏิบัติงาน (analyst)") || "";
  if (analyst.length < 2) return;
  store.set("analyst", analyst);
  const reason = prompt(on ? `เหตุผลในการ contain ${b.dataset.agent} (revoke token / suspend)` : `เหตุผลในการ release ${b.dataset.agent}`);
  if (!reason || reason.length < 5) return;
  try { await api(`/api/soc/agents/${encodeURIComponent(b.dataset.agent)}/contain`, { method: "POST",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contain: on, analyst, reason }) }); }
  catch (e) { alert("ไม่สำเร็จ: " + e.message); }
});
const PRESETS = { "denied / blocked": "-decision:allowed", "shell from agents": "kind:process", "secrets": ".env",
  "egress": "kind:network rule:*", "prompt injection": "kind:prompt", "any detection": "rule:*" };
$("#presets").innerHTML = Object.keys(PRESETS).map((k) => `<button type="button" data-q="${esc(PRESETS[k])}">${esc(k)}</button>`).join("");
$("#presets").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) { $("#huntQ").value = b.dataset.q; hunt(); } });
$("#huntForm").addEventListener("submit", (ev) => { ev.preventDefault(); hunt(); });
async function hunt() {
  try {
    const d = await api("/api/soc/hunt?limit=100&q=" + encodeURIComponent($("#huntQ").value));
    $("#huntRes").innerHTML = d.results.map((r) => `<li data-s="${esc(r.session)}">${agentRow(r)}</li>`).join("") || '<li class="muted">ไม่พบ</li>';
  } catch (e) { $("#huntRes").innerHTML = `<li class="err">${esc(e.message)}</li>`; }
}

// ---------- Offensive AI agents ----------
const OFF_SEV = {};
function renderOffai(o) {
  if (!o) return;
  $("#frameworks").innerHTML = o.frameworks.map((f) => `<div class="fw ${f.hits ? "hot" : ""}">
    <div class="n"><span>${esc(f.name)}</span><b title="detections">${f.hits}</b></div><div class="d">${esc(f.desc)}</div>
    <div class="t">${f.indicators ? `${f.indicators} indicators · ${Object.entries(f.by_type).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}` : "indicator feed ยังไม่โหลด"}</div></div>`).join("");
  o.rules.forEach((r) => { OFF_SEV[r.id] = r.severity; });
  $("#nb-off").textContent = o.rules.reduce((n, r) => n + r.hits, 0);
  $("#offaiRules").innerHTML = o.rules.map((r) => `<li class="${r.hits ? "hit" : ""}"><span class="mono">${esc(r.id)}</span>
    <span>${esc(r.title)} <span class="sev" style="--sevc:var(--${esc(r.severity)})">${esc(r.severity)}</span>
    <span class="muted">· ${esc(r.technique)} · ${esc(r.tactic)}</span></span><b>${r.hits}</b></li>`).join("");
}
function addOffai(e, animate) {
  if (state.paused) return;
  const li = document.createElement("li");
  li.style.setProperty("--c", css("--off"));
  if (!animate) li.style.animation = "none";
  const extra = [e.provider && `${e.provider} (${e.region})`, e.indicator && `IOC: ${e.indicator}`, e.tools && e.tools.join(", "),
    e.stages && e.stages.join(" → "), e.distinct_ips && `${e.distinct_ips} IPs / ${e.requests} req`, e.agent_cmdline].filter(Boolean).map(esc).join(" · ");
  li.innerHTML = `<span class="mono muted">${hhmmss(e.ts)}</span><i class="d"></i>
    <div>${e.simulated === false ? '<span class="real">REAL</span>' : ""}<span class="sev" style="--sevc:var(--${esc(e.severity)})">${esc(e.severity)}</span> ${esc(e.title)}
    <div class="x">${esc(e.host)} · ${esc(e.user)} · ${esc(e.technique)}${extra ? " · " + extra : ""}
    ${/^https:\/\//.test(e.source_url || "") ? ` · <a class="link" target="_blank" rel="noopener" href="${esc(e.source_url)}">source</a>` : ""}</div></div>`;
  const ul = $("#offaiLive"); ul.prepend(li);
  while (ul.children.length > 40) ul.lastChild.remove();
}
const Q = { all: [], lang: "ทั้งหมด", sel: null };
async function loadQueries() {
  try { const d = await api("/api/soc/offensive-ai"); Q.all = d.queries; renderOffai(d); renderQueries(); } catch (e) { /* retried on reconnect */ }
}
function renderQueries() {
  const langs = ["ทั้งหมด", ...new Set(Q.all.map((q) => q.lang))];
  $("#qTabs").innerHTML = langs.map((l) => `<button type="button" class="${l === Q.lang ? "on" : ""}" data-l="${esc(l)}">${esc(l)}</button>`).join("");
  const list = Q.all.filter((q) => Q.lang === "ทั้งหมด" || q.lang === Q.lang);
  $("#qList").innerHTML = list.map((q) => `<li data-f="${esc(q.file)}" class="${q.file === Q.sel ? "sel" : ""}"><span class="lang">${esc(q.lang)}</span><span>${esc(q.title)}</span></li>`).join("");
}
$("#qTabs").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) { Q.lang = b.dataset.l; renderQueries(); } });
$("#qList").addEventListener("click", (ev) => {
  const li = ev.target.closest("li"); if (!li) return;
  const q = Q.all.find((x) => x.file === li.dataset.f); Q.sel = q.file; renderQueries();
  $("#qBox").hidden = false; $("#qTitle").textContent = `${q.file}`; $("#qCode").textContent = q.query;
});
$("#qCopy").onclick = async () => { try { await navigator.clipboard.writeText($("#qCode").textContent); $("#qCopy").textContent = "คัดลอกแล้ว"; setTimeout(() => { $("#qCopy").textContent = "คัดลอก"; }, 1500); } catch {} };
$("#qDl").onclick = () => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([$("#qCode").textContent], { type: "text/plain" }));
  a.download = Q.sel || "query.txt"; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};

// ---------- CTI ----------
async function loadCti(force) {
  $("#ctiStatus").textContent = "CTI: กำลังดึง…";
  try {
    const r = await fetch("/api/soc/cti" + (force ? "?refresh=true" : ""), { headers: headers() });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const f = await r.json();
    const ok = Object.values(f).filter((x) => x.ok).length;
    const el = $("#ctiStatus");
    const n = Object.keys(f).length;
    el.textContent = `CTI: ${ok}/${n} feeds live`;
    el.className = "pill " + (ok === n ? "ok" : ok ? "warn" : "bad");
    const ag = f.agentic;
    $("#offaiFeed").textContent = ag?.data ? `indicators: ${ag.data.total} (หมดอายุตัดออก ${ag.data.expired}) · ${ag.stale ? "STALE · " : ""}อัปเดต ${hhmmss(ag.fetched_at)}`
      : `indicator feed ดึงไม่สำเร็จ — ใช้ seed ในตัว (${ag?.error || ""})`;
    renderFeed("kev", f.kev, (d) => `${d.total.toLocaleString()} CVE · ransomware ${d.ransomware_linked}`,
      (v) => `<span class="k">${esc(v.cve)}</span>${v.ransomware ? '<span class="tag">ransomware</span>' : ""}
        <div>${esc(v.vendor)} ${esc(v.product)} — ${esc(v.name)}</div><div class="muted">added ${esc(v.date_added)} · due ${esc(v.due)}</div>`);
    renderFeed("feodo", f.feodo, (d) => `${d.total} C2 · online ${d.online}`,
      (v) => `<span class="k">${esc(v.ip)}:${esc(v.port)}</span> <b>${esc(v.malware)}</b> <span class="muted">${esc(v.country || "")} · ${esc(v.status)}</span>
        <div class="muted">${esc(v.as_name || "")} · last online ${esc(v.last_online || "-")}</div>`);
    renderFeed("tf", f.threatfox, (d) => `${d.total} IOCs`,
      (v) => `<span class="k">${esc(v.ioc)}</span> <span class="muted">${esc(v.type)}</span>
        <div><b>${esc(v.malware)}</b> · ${esc(v.threat)} · conf ${esc(v.confidence)}%</div><div class="muted">${esc(v.first_seen)}</div>`);
  } catch (e) {
    $("#ctiStatus").textContent = "CTI: error"; $("#ctiStatus").className = "pill bad";
  }
}
function renderFeed(id, feed, meta, row) {
  const ul = $("#" + id), m = $("#" + id + "-meta");
  if (!feed?.data) { ul.innerHTML = `<li class="err">ดึงข้อมูลไม่สำเร็จ: ${esc(feed?.error || "unknown")}</li>`; m.textContent = ""; return; }
  m.textContent = `${meta(feed.data)} · ${feed.stale ? "STALE · " : ""}${hhmmss(feed.fetched_at)}`;
  ul.innerHTML = feed.data.items.map((v) => `<li>${row(v)}</li>`).join("") || `<li class="muted">ไม่มีรายการ</li>`;
}

// ---------- controls ----------
$("#legend").innerHTML = DOMAINS.map((d) => `<span><i style="background:var(--${d})"></i>${d} <b id="lg-${d}">0</b></span>`).join("");
$("#filters").innerHTML = DOMAINS.map((d) => `<button class="on" data-d="${d}" style="--c:var(--${d})">${d}</button>`).join("");
$("#filters").addEventListener("click", (ev) => {
  const b = ev.target.closest("button"); if (!b) return;
  const d = b.dataset.d; state.filter.has(d) ? state.filter.delete(d) : state.filter.add(d);
  b.classList.toggle("on");
});
$("#pause").onclick = (ev) => { state.paused = !state.paused; ev.target.textContent = state.paused ? "เล่นต่อ" : "หยุดชั่วคราว"; };
$("#ctiRefresh").onclick = () => loadCti(true);
$("#connectBtn").onclick = () => { store.set("apiKey", $("#apiKey").value); connect(); };
setInterval(() => { $("#clock").textContent = new Date().toLocaleString("th-TH", { hour12: false }); }, 1000);
setInterval(() => loadCti(false), 5 * 60 * 1000);
window.addEventListener("resize", () => { drawFlow(); drawSpark(); });
// ---------- theme + navigation ----------
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#themeBtn span").textContent = t === "dark" ? "Light Mode" : "Dark Mode";
  drawFlow(); drawSpark();
  if (state.selected) { const cur = state.incidents.find((i) => i.id === state.selected); if (cur) renderDetail(cur); }
}
$("#themeBtn").onclick = () => {
  const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  try { localStorage.setItem("theme", t); } catch {}
  applyTheme(t);
};
$("#themeBtn span").textContent = document.documentElement.dataset.theme === "dark" ? "Light Mode" : "Dark Mode";
(() => {  // highlight the sidebar item of the section in view
  const links = [...document.querySelectorAll("#nav a[href^='#']")];
  const targets = links.map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
  if (!("IntersectionObserver" in window)) return;
  const seen = new Map();
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => seen.set(e.target, e.isIntersecting ? e.intersectionRatio : 0));
    let best = null, ratio = 0;
    for (const t of targets) if ((seen.get(t) || 0) > ratio && t.id !== "top") { best = t; ratio = seen.get(t); }
    if (window.scrollY < 120) best = document.getElementById("top");
    if (!best) return;
    links.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + best.id));
  }, { threshold: [0, .15, .4, .7] });
  targets.forEach((t) => io.observe(t));
  window.addEventListener("scroll", () => { if (window.scrollY < 120) links.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#top")); }, { passive: true });
})();

renderTactics({});
connect();
