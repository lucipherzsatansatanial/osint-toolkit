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

function headers() {
  const h = {}, k = store.get("apiKey"), t = store.get("tenant");
  if (k) h["X-API-Key"] = k;
  if (t) h["X-Tenant"] = t;  // honoured only for platform staff; others are pinned to their tenant
  return h;
}

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
    loadMe().then(loadWorkspace);
    loadCti(); loadQueries(); loadNotify(); loadAiStatus(); loadChains(); loadRisk(); loadRules();
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
    openIncidentFromHash();
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
  renderCopilot(inc);
  renderCase(inc);
  loadResponse(inc.id);
  $("#d-title").innerHTML = `#${inc.id} · ${esc(inc.title)} · <span class="sev" style="--sevc:var(--${esc(inc.severity)})">${esc(inc.severity)}</span>
    <small class="muted">${[inc.users.length ? "users: " + esc(inc.users.join(", ")) : "", inc.tactics.length ? "tactics: " + esc(inc.tactics.join(" → ")) : ""].filter(Boolean).join(" · ")}</small>`;
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

// ---------- identity / RBAC ----------
const can = (p) => !state.me || state.me.permissions.includes(p);
async function loadMe() {
  try {
    state.me = await api("/api/me");
    $("#meBox").hidden = false;
    $("#meName").textContent = state.me.name;
    $("#meRole").textContent = `${state.me.role_th}${state.me.named ? "" : " · shared key"} · tenant: ${state.me.tenant}`;
    document.querySelectorAll("[data-plat]").forEach((el) => { el.hidden = !state.me.platform; });
    if (state.me.platform) loadTenants();
    if (can("users.manage")) loadGov();
    document.querySelectorAll("[data-perm]").forEach((el) => { el.hidden = !can(el.dataset.perm); });
    if (can("users.manage")) loadUsers();
    if (state.agents) renderAgents(state.agents);
  } catch { /* older server */ }
}
$("#logoutBtn").onclick = () => { store.set("apiKey", ""); state.ctrl?.abort(); state.me = null; $("#meBox").hidden = true; showKeyBar("ใส่ token ของผู้ใช้"); setLive(false, "ออกจากระบบแล้ว"); };
const ROLE_TH = {};
async function loadUsers() {
  try {
    const d = await api("/api/users");
    d.roles.forEach((r) => { ROLE_TH[r.id] = r.th; });
    if (!$("#newRole").options.length)
      $("#newRole").innerHTML = d.roles.map((r) => `<option value="${esc(r.id)}" ${r.id === "analyst" ? "selected" : ""}>${esc(r.th)} (${esc(r.id)})</option>`).join("");
    $("#rolesList").innerHTML = d.roles.map((r) => `<li><b>${esc(r.th)} (${esc(r.id)})</b>: ${esc(r.permissions.join(", "))}</li>`).join("");
    const t = (x) => x ? new Date(x * 1000).toLocaleString("th-TH", { hour12: false }) : "-";
    $("#usersTbl tbody").innerHTML = d.users.map((u) => `<tr><td>${esc(u.username)}${state.me?.platform && u.tenant ? `<div class="sub">${esc(u.tenant === "*" ? "platform" : u.tenant)}</div>` : ""}</td>
      <td><select data-u="${esc(u.username)}" class="roleSel">${d.roles.map((r) => `<option value="${esc(r.id)}" ${r.id === u.role ? "selected" : ""}>${esc(r.th)}</option>`).join("")}</select></td>
      <td><span class="st ${u.disabled ? "contained" : "healthy"}">${u.disabled ? "ปิดใช้งาน" : "ใช้งาน"}</span></td>
      <td class="muted">${t(u.last_seen)}</td><td class="muted">${esc(u.created_by || "")}</td>
      <td><button class="mini release" data-act="rotate" data-u="${esc(u.username)}">ออก token ใหม่</button>
          <button class="mini release" data-act="${u.disabled ? "enable" : "disable"}" data-u="${esc(u.username)}">${u.disabled ? "เปิดใช้งาน" : "ปิดใช้งาน"}</button></td></tr>`).join("")
      || '<tr><td colspan="6" class="muted">ยังไม่มีผู้ใช้ — สร้างผู้ใช้แรกด้านบน</td></tr>';
  } catch (e) { $("#usersTbl tbody").innerHTML = `<tr><td colspan="6" class="err">${esc(e.message)}</td></tr>`; }
}
function showToken(user, token) {
  $("#tokenBox").hidden = false; $("#tokenUser").textContent = user; $("#tokenVal").textContent = token;
}
$("#tokenCopy").onclick = async () => { try { await navigator.clipboard.writeText($("#tokenVal").textContent); $("#tokenCopy").textContent = "คัดลอกแล้ว"; } catch {} };
$("#userForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("#newUser").value.trim().toLowerCase(), role: $("#newRole").value }) });
    showToken(r.username, r.token); $("#newUser").value = ""; loadUsers();
  } catch (e) { alert("สร้างไม่สำเร็จ: " + e.message); }
});
$("#usersTbl").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-act]"); if (!b) return;
  const u = b.dataset.u;
  try {
    if (b.dataset.act === "rotate") {
      if (!confirm(`ออก token ใหม่ให้ ${u}? token เดิมจะใช้ไม่ได้ทันที`)) return;
      const r = await api(`/api/users/${encodeURIComponent(u)}/rotate`, { method: "POST" }); showToken(u, r.token);
    } else {
      await api(`/api/users/${encodeURIComponent(u)}`, { method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ disabled: b.dataset.act === "disable" }) });
    }
    loadUsers();
  } catch (e) { alert("ไม่สำเร็จ: " + e.message); }
});
$("#usersTbl").addEventListener("change", async (ev) => {
  const sel = ev.target.closest(".roleSel"); if (!sel) return;
  try {
    await api(`/api/users/${encodeURIComponent(sel.dataset.u)}`, { method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: sel.value }) });
  } catch (e) { alert("ไม่สำเร็จ: " + e.message); }
  loadUsers();
});

// ---------- AI SOC Copilot ----------
const ASSESS_TH = { likely_malicious: "น่าจะเป็นการโจมตีจริง", suspicious: "น่าสงสัย", likely_benign: "น่าจะไม่เป็นอันตราย", insufficient_data: "ข้อมูลไม่พอ" };
const PRIO_TH = { now: "ทันที", today: "วันนี้", follow_up: "ติดตาม" };
state.chats = {};
async function loadAiStatus() {
  try {
    const s = await api("/api/soc/ai/status");
    $("#aiStatus").textContent = s.enabled ? `Claude · ${s.model} · ${s.redact ? "ปิดบังชื่อผู้ใช้/IP ภายในก่อนส่ง" : "ไม่ปิดบังข้อมูล"}`
      : "ยังไม่ตั้งค่า ANTHROPIC_API_KEY — สรุปแบบกฎ (ไม่ใช้ AI)";
  } catch { $("#aiStatus").textContent = ""; }
}
function renderCopilot(inc) {
  if (state.cpFor !== inc.id) {
    state.cpFor = inc.id;
    $("#chatQ").value = "";
    renderChat();
    if (inc.ai) renderAi(inc.ai);
    else $("#aiOut").innerHTML = '<p class="muted">กด "สรุปด้วย AI" เพื่อสรุปเหตุการณ์ ไทม์ไลน์ และขั้นตอนรับมือ</p>';
    $("#aiRefresh").hidden = !inc.ai || !can("ai.use");
  }
}
function renderAi(a) { renderAiInto($("#aiOut"), a); }
function renderAiInto(el, a) {
  const t = (x) => esc(x || "");
  const fbRef = el.id === "chAi" ? `chain:${state.chainSel}` : `inc:${state.selected}`;
  const fbFeat = el.id === "chAi" ? "chain" : "summary";
  const ground = a.checks && !a.checks.grounded ? `<div class="ground">⚠ AI กล่าวถึงข้อมูลที่ไม่พบในเหตุการณ์ ควรตรวจสอบ: ${a.checks.unverified.map((u) => t(u.value)).join(", ")}</div>` : "";
  el.innerHTML = `
    <div class="ai-head">${t(a.headline)}${a.source === "claude" ? fbButtons(fbFeat, fbRef) : ""}</div>${ground}
    <div class="ai-badges"><span class="${t(a.assessment)}">${t(ASSESS_TH[a.assessment] || a.assessment)}</span>
      <span>ความมั่นใจ: ${t(a.confidence)}</span>${(a.attack_stages || []).map((x) => `<span>${t(x)}</span>`).join("")}</div>
    <p>${t(a.summary)}</p>
    <div class="ai-grid">
      <div><h4>AI Incident Timeline</h4><ol class="timeline">${(a.timeline || []).map((e) => `<li style="--c:var(--accent)">
        <span class="mono muted">${t(e.time)}</span> ${t(e.event)}<div class="muted">${t(e.significance)}</div></li>`).join("") || '<li class="muted">-</li>'}</ol></div>
      <div><h4>ขั้นตอนรับมือที่แนะนำ</h4><ul class="ai-actions">${(a.recommended_actions || []).map((x) => `<li>
        <span class="p ${t(x.priority)}">${t(PRIO_TH[x.priority] || x.priority)}</span><span>${t(x.action)}<small>${t(x.owner)}</small></span></li>`).join("")}</ul>
        ${(a.open_questions || []).length ? `<h4>คำถามที่ควรหาคำตอบต่อ</h4><ul>${a.open_questions.map((q) => `<li>${t(q)}</li>`).join("")}</ul>` : ""}</div>
    </div>
    <div class="ai-foot">${a.source === "claude"
      ? `สร้างโดย ${t(a.model)}${a.redacted ? ` · ปิดบังข้อมูลบุคคล ${a.pseudonyms || 0} รายการก่อนส่ง` : ""}`
      : `สรุปแบบกฎ (ไม่ใช้ AI) — ${t(a.note)}`}${a.generated_by ? ` · ขอโดย ${t(a.generated_by)}` : ""}${a.generated_at ? ` · ${new Date(a.generated_at * 1000).toLocaleString("th-TH", { hour12: false })}` : ""}
      · ผลจาก AI ต้องตรวจสอบก่อนนำไปตัดสินใจ</div>`;
}
async function runSummary(refresh) {
  const id = state.selected; if (!id) return;
  $("#aiOut").innerHTML = '<p class="muted"><span class="spin"></span> กำลังวิเคราะห์ incident…</p>';
  try {
    const a = await api(`/api/soc/incidents/${id}/ai/summary`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh }) });
    const inc = state.incidents.find((i) => i.id === id); if (inc) inc.ai = a;
    if (state.selected === id) { renderAi(a); $("#aiRefresh").hidden = false; }
  } catch (e) { $("#aiOut").innerHTML = `<p class="err">ไม่สำเร็จ: ${esc(e.message)}</p>`; }
}
$("#aiSummBtn").onclick = () => runSummary(false);
$("#aiRefresh").onclick = () => runSummary(true);
function renderChat() {
  const log = state.chats[state.cpFor] || [];
  $("#chatLog").innerHTML = log.map((m) => `<li class="${m.role}">${esc(m.content)}${m.meta ? `<small>${esc(m.meta)}</small>` : ""}</li>`).join("");
  $("#chatLog").scrollTop = 1e9;
}
async function askCopilot(q) {
  const id = state.selected; if (!id || !q.trim()) return;
  const log = (state.chats[id] ||= []);
  const history = log.map(({ role, content }) => ({ role, content }));
  log.push({ role: "user", content: q }); log.push({ role: "assistant", content: "…" }); renderChat();
  try {
    const r = await api(`/api/soc/incidents/${id}/ai/ask`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: q, history }) });
    log[log.length - 1] = { role: "assistant", content: r.answer, meta: (r.source === "claude" ? r.model : r.source)
      + (r.checks && !r.checks.grounded ? ` · ⚠ ไม่พบในข้อมูล: ${r.checks.unverified.map((u) => u.value).join(", ")}` : "") };
  } catch (e) { log[log.length - 1] = { role: "assistant", content: "ไม่สำเร็จ: " + e.message }; }
  if (state.cpFor === id) renderChat();
}
$("#chatForm").addEventListener("submit", (ev) => { ev.preventDefault(); const q = $("#chatQ").value; $("#chatQ").value = ""; askCopilot(q); });
const CHAT_PRESETS = ["ควร isolate เครื่องไหนก่อน เพราะอะไร", "มีหลักฐานการส่งข้อมูลออก (exfiltration) ไหม", "เขียนสรุปสำหรับผู้บริหาร 3 บรรทัด", "ต้องแจ้ง สคส. ตาม PDPA หรือไม่"];
$("#chatPresets").innerHTML = CHAT_PRESETS.map((q) => `<button type="button">${esc(q)}</button>`).join("");
$("#chatPresets").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) askCopilot(b.textContent); });

// ---------- phase 3: NL hunting, enrichment, attack chains ----------
const NL_PRESETS = ["หาเซิร์ฟเวอร์ที่ติดต่อ AI API ของจีนในชั่วโมงที่ผ่านมา", "alert ระดับ critical ที่มาจาก log จริง",
  "AI agent ที่ถูกปฏิเสธการเรียก tool", "การเคลื่อนที่ข้ามเครื่อง (lateral movement) วันนี้", "incident ที่ยังไม่มีผู้รับผิดชอบ"];
$("#nlPresets").innerHTML = NL_PRESETS.map((q) => `<button type="button">${esc(q)}</button>`).join("");
$("#nlPresets").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) { $("#nlQ").value = b.textContent; nlHunt(); } });
$("#nlForm").addEventListener("submit", (ev) => { ev.preventDefault(); nlHunt(); });
const t2 = (ts) => ts ? new Date(ts * 1000).toLocaleString("th-TH", { hour12: false }) : "-";
const NL_COLS = {
  alerts: [["ts", "เวลา", (r) => t2(r.ts)], ["severity", "ระดับ", (r) => `<span class="sev" style="--sevc:var(--${esc(r.severity)})">${esc(r.severity)}</span>`],
           ["title", "เหตุการณ์", (r) => `${r.simulated === false ? '<span class="real">REAL</span>' : ""}${esc(r.title)}`],
           ["host", "เครื่อง", (r) => esc(r.host)], ["user", "บัญชี", (r) => esc(r.user)]],
  agent_audit: [["ts", "เวลา", (r) => t2(r.ts)], ["agent", "Agent", (r) => esc(r.agent)], ["kind", "ชนิด", (r) => esc(r.kind)],
                ["summary", "รายละเอียด", (r) => esc(r.summary)], ["decision", "ผล", (r) => esc(r.decision)], ["rules", "Rules", (r) => esc((r.rules || []).join(", "))]],
  incidents: [["id", "#", (r) => r.id], ["severity", "ระดับ", (r) => `<span class="sev" style="--sevc:var(--${esc(r.severity)})">${esc(r.severity)}</span>`],
              ["title", "Incident", (r) => esc(r.title)], ["status", "สถานะ", (r) => esc(r.status)], ["hosts", "เครื่อง", (r) => esc((r.hosts || []).join(", "))]],
};
async function nlHunt() {
  const q = $("#nlQ").value.trim(); if (!q) return;
  $("#nlPlan").innerHTML = '<p class="muted"><span class="spin"></span> กำลังแปลงคำถามเป็นเงื่อนไขค้นหา…</p>';
  try {
    const r = await api("/api/soc/hunt/nl", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: q }) });
    const p = r.plan;
    $("#nlPlan").innerHTML = `<div><span class="mode ${r.mode === "ai" ? "ai" : ""}">${r.mode === "ai" ? "AI" : "keyword"}</span>${esc(p.explanation)}</div>
      <div class="chips"><span>source=${esc(r.source)}</span>${p.since_minutes ? `<span>ย้อนหลัง ${p.since_minutes} นาที</span>` : ""}
        ${p.filters.map((f) => `<span>${esc(f.field)} ${esc(f.op)} ${esc(f.value)}</span>`).join("")}</div>
      <div class="muted">พบ ${r.total} รายการ${r.ignored_fields?.length ? ` · ข้ามฟิลด์ที่ไม่รู้จัก: ${esc(r.ignored_fields.join(", "))}` : ""}${r.note ? " · " + esc(r.note) : ""}</div>
      ${p.kql ? `<div class="qhead" style="margin-top:8px"><b>KQL สำหรับ Defender/Sentinel (ข้อเสนอ ตรวจก่อนรัน)</b><button class="mini" type="button" id="kqlCopy">คัดลอก</button></div><pre class="code" id="kqlCode">${esc(p.kql)}</pre>` : ""}`;
    const kc = $("#kqlCopy"); if (kc) kc.onclick = () => navigator.clipboard.writeText($("#kqlCode").textContent).catch(() => {});
    const cols = NL_COLS[r.source];
    $("#nlRes thead").innerHTML = `<tr>${cols.map((c) => `<th>${c[1]}</th>`).join("")}</tr>`;
    $("#nlRes tbody").innerHTML = r.results.map((x) => `<tr data-inc="${esc(x.incident_id || (r.source === "incidents" ? x.id : "") || "")}">${cols.map((c) => `<td>${c[2](x)}</td>`).join("")}</tr>`).join("")
      || `<tr><td colspan="${cols.length}" class="muted">ไม่พบ</td></tr>`;
  } catch (e) { $("#nlPlan").innerHTML = `<p class="err">ไม่สำเร็จ: ${esc(e.message)}</p>`; }
}
$("#nlRes").addEventListener("click", (ev) => { const tr = ev.target.closest("tr[data-inc]"); if (tr && tr.dataset.inc) location.hash = "#inc-" + tr.dataset.inc; });
$("#enForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const q = $("#enQ").value.trim(); if (!q) return;
  $("#enOut").innerHTML = '<p class="muted"><span class="spin"></span> กำลังค้นในฟีด CTI และเหตุการณ์ในระบบ…</p>';
  try {
    const r = await api("/api/soc/enrich", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ indicator: q }) });
    const a = r.ai, t = (x) => esc(x ?? "");
    const VT = { malicious: "อันตราย", suspicious: "น่าสงสัย", benign: "ไม่อันตราย", unknown: "ไม่ทราบ", internal: "ภายในองค์กร", known_service: "บริการที่รู้จัก" };
    const m = r.matches.map((x) => `<div class="match"><b>${t(x.source)}</b> ${Object.entries(x).filter(([k]) => !["source", "source_url"].includes(k) && x[k] !== null && x[k] !== "")
      .map(([k, v]) => `<span class="muted">${t(k)}:</span> ${t(Array.isArray(v) ? v.join(", ") : v)}`).join(" · ")}
      ${/^https:\/\//.test(x.source_url || "") ? ` · <a class="link" target="_blank" rel="noopener" href="${t(x.source_url)}">source</a>` : ""}</div>`).join("") || '<p class="muted">ไม่พบในฟีด CTI ใดเลย</p>';
    const s = r.sightings;
    $("#enOut").innerHTML = `<div><span class="verdict ${t(a ? a.verdict : r.local_verdict)}">${t(VT[a ? a.verdict : r.local_verdict] || (a ? a.verdict : r.local_verdict))}</span>
        <span class="mono">${t(r.indicator)}</span> <span class="muted">(${t(r.type)}${a ? ` · ความมั่นใจ ${t(a.confidence)}` : ""})</span></div>
      ${a ? `<p>${t(a.explanation)}</p>${a.recommended_actions.length ? `<ul class="ai-actions">${a.recommended_actions.map((x) => `<li><span class="p ${t(x.priority)}">${t(PRIO_TH[x.priority] || x.priority)}</span><span>${t(x.action)}<small>${t(x.owner)}</small></span></li>`).join("")}</ul>` : ""}
        ${a.hunting_ideas.length ? `<h4>แนวทาง hunting ต่อ</h4><ul>${a.hunting_ideas.map((h) => `<li>${t(h)}</li>`).join("")}</ul>` : ""}
        <div class="ai-foot">วิเคราะห์โดย ${t(a.model)} จากหลักฐานด้านล่างเท่านั้น · ต้องตรวจสอบก่อนตัดสินใจ</div>` : `<p class="muted">${t(r.note)}</p>`}
      <h4>หลักฐานจากฟีด CTI (${r.matches.length})</h4>${m}
      <h4>พบในระบบ</h4><div class="muted">${s.alerts.length} alerts · ${s.agent_records.length} AI-agent records${s.incidents.length ? " · incidents: " + s.incidents.map((i) => `<a class="link" href="#inc-${i}">#${i}</a>`).join(", ") : ""}</div>`;
  } catch (e) { $("#enOut").innerHTML = `<p class="err">ไม่สำเร็จ: ${esc(e.message)}</p>`; }
});
const TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
  "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
state.chains = [];
async function loadChains() {
  try {
    const r = await api("/api/soc/chains"); state.chains = r.chains;
    $("#nb-chain").textContent = r.chains.length;
    $("#chains").innerHTML = r.chains.map((c) => `<div class="chain" data-c="${esc(c.id)}" style="--sevc:var(--${esc(c.severity)})">
      <div><div class="cid">${c.real ? '<span class="real">REAL</span>' : ""}${esc(c.id)}</div><span class="sev">${esc(c.severity)}</span></div>
      <div><div>${c.incidents.length} incidents · ${esc(c.hosts.slice(0, 4).join(", "))}${c.hosts.length > 4 ? " …" : ""}</div>
        <div class="meta">${t2(c.start)} → ${t2(c.end)} · เริ่มที่ incident #${c.entry}${c.accounts.length ? " · บัญชี " + esc(c.accounts.slice(0, 3).join(", ")) : ""}</div></div>
      <div><div class="stagebar" title="${esc(c.tactics.join(" → "))}">${TACTIC_ORDER.map((t) => `<i class="${c.tactics.includes(t) ? "on" : ""}" title="${t}"></i>`).join("")}</div>
        <div class="meta">${c.tactics.length}/14 ขั้นของ kill chain</div></div></div>`).join("")
      || '<p class="muted">ยังไม่พบ incident ที่เชื่อมโยงกัน</p>';
    if (state.chainSel) { const c = state.chains.find((x) => x.id === state.chainSel); if (c) drawChain(c); }
  } catch { /* retried on next refresh */ }
}
function drawChain(c) {
  $("#chainDetail").hidden = false;
  $("#chTitle").innerHTML = `${esc(c.id)} · ${c.incidents.length} incidents · <span class="sev" style="--sevc:var(--${esc(c.severity)})">${esc(c.severity)}</span>`;
  const W = 900, H = 220, pad = 50, span = Math.max(1, c.end - c.start);
  const x = (ts) => pad + ((ts - c.start) / span) * (W - 2 * pad);
  const pos = {}; c.incidents.forEach((i, n) => { pos[i.id] = [x(i.first_ts), 60 + (n % 3) * 55]; });
  let svg = `<line x1="${pad}" y1="${H - 24}" x2="${W - pad}" y2="${H - 24}" stroke="${css("--line")}"/>
    <text x="${pad}" y="${H - 8}">${esc(t2(c.start))}</text><text x="${W - pad}" y="${H - 8}" text-anchor="end">${esc(t2(c.end))}</text>`;
  c.edges.forEach((e) => {
    const [x1, y1] = pos[e.from] || [], [x2, y2] = pos[e.to] || []; if (x1 === undefined || x2 === undefined) return;
    svg += `<path d="M${x1} ${y1} C ${(x1 + x2) / 2} ${Math.min(y1, y2) - 40}, ${(x1 + x2) / 2} ${Math.min(y1, y2) - 40}, ${x2} ${y2}" stroke="${css("--xdr")}" fill="none" stroke-width="1.5" class="flow"/>
      <text x="${(x1 + x2) / 2}" y="${Math.min(y1, y2) - 34}" text-anchor="middle" style="font-size:10px;fill:${css("--muted")}">${esc(e.shared[0])}</text>`;
  });
  c.incidents.forEach((i) => {
    const [px, py] = pos[i.id];
    svg += `<a href="#inc-${i.id}"><circle cx="${px}" cy="${py}" r="11" fill="${css("--" + i.severity)}" stroke="${css("--panel")}" stroke-width="2"/>
      <text x="${px}" y="${py + 26}" text-anchor="middle">#${i.id}</text></a>`;
  });
  $("#chGraph").innerHTML = svg;
}
$("#chains").addEventListener("click", (ev) => {
  const el = ev.target.closest(".chain"); if (!el) return;
  state.chainSel = el.dataset.c; $("#chAi").innerHTML = "";
  drawChain(state.chains.find((c) => c.id === state.chainSel));
});
$("#chClose").onclick = () => { state.chainSel = null; $("#chainDetail").hidden = true; };
$("#chainsRefresh").onclick = loadChains;
$("#chAiBtn").onclick = async () => {
  if (!state.chainSel) return;
  $("#chAi").innerHTML = '<p class="muted"><span class="spin"></span> กำลังวิเคราะห์เส้นทางการโจมตี…</p>';
  try { renderAiInto($("#chAi"), await api(`/api/soc/chains/${encodeURIComponent(state.chainSel)}/ai`, { method: "POST" })); }
  catch (e) { $("#chAi").innerHTML = `<p class="err">ไม่สำเร็จ: ${esc(e.message)}</p>`; }
};
setInterval(() => { if (state.me) loadChains(); }, 30000);

// ---------- phase 4: rule assistant, agent risk, response plan ----------
state.risk = {};
const riskOf = (a) => state.risk?.[a.id]?.score ?? a.risk;
const riskTip = (id) => (state.risk?.[id]?.factors || []).map((f) => `+${f.points} ${f.category}: ${f.reason}`).join("\n") || "";
async function loadRisk() {
  try { const r = await api("/api/soc/agents/risk"); state.risk = Object.fromEntries(r.agents.map((x) => [x.agent, x])); if (state.agents) renderAgents(state.agents); } catch {}
}
setInterval(() => { if (state.me) loadRisk(); }, 20000);

let RDRAFT = null, RCODE = "sigma";
function renderRuleResult(res) {
  const d = res.draft || RDRAFT?.draft || {}, r = res.rule, t = (x) => esc(x ?? "");
  const tests = res.tests || [], bt = res.backtest;
  $("#ruleOut").innerHTML = `${d.title ? `<div class="ai-head">${t(d.title)}</div><div class="muted">${t(d.description)}</div>` : ""}
    <div class="ai-badges"><span>${t(r.severity)}</span><span>${t(r.technique || "—")}</span><span>${t(r.tactic || "")}</span><span>kind=${t(r.kind)}</span></div>
    ${res.errors?.length ? `<p class="bad">ข้อผิดพลาด: ${res.errors.map(t).join(" · ")}</p>` : '<p class="ok">✓ กฎถูกรูปแบบ</p>'}
    ${res.sigma_errors?.length ? `<p class="bad">${res.sigma_errors.map(t).join(" · ")}</p>` : ""}
    <h4>กฎสำหรับระบบ (แก้ได้ แล้วกด "ทดสอบอีกครั้ง")</h4>
    <textarea id="ruleJson" rows="9">${t(JSON.stringify({ kind: r.kind, match: r.match, conditions: r.conditions, threshold: r.threshold,
      title: r.title, severity: r.severity, technique: r.technique, tactic: r.tactic }, null, 2))}</textarea>
    ${tests.length ? `<h4>กรณีทดสอบ (${tests.filter((x) => x.passed).length}/${tests.length} ผ่าน)</h4><ul class="tests">${tests.map((x) =>
      `<li class="${x.passed ? "ok" : "bad"}">${x.passed ? "✓" : "✗"} ${t(x.description)} — ควร${x.should_match ? "ตรง" : "ไม่ตรง"}, ผล: ${x.matched ? "ตรง" : "ไม่ตรง"}${x.error ? " (" + t(x.error) + ")" : ""}</li>`).join("")}</ul>` : ""}
    ${bt ? `<h4>ย้อนทดสอบกับข้อมูลล่าสุด</h4><div>${bt.hits} ครั้ง จาก ${bt.scanned} records (ช่วง ${bt.span_minutes} นาที${bt.real_hits ? `, ข้อมูลจริง ${bt.real_hits}` : ""})
      ${bt.hits > 20 ? ' <span class="bad">— อาจแจ้งเตือนถี่เกินไป</span>' : ""}</div>` : ""}
    ${d.false_positives?.length ? `<h4>False positive ที่อาจเกิด</h4><ul>${d.false_positives.map((x) => `<li>${t(x)}</li>`).join("")}</ul>` : ""}
    ${d.sigma || d.kql || d.spl ? `<div class="code-tabs">${["sigma", "kql", "spl"].filter((k) => d[k]).map((k) => `<button type="button" data-k="${k}" class="${k === RCODE ? "on" : ""}">${k.toUpperCase()}</button>`).join("")}
      <button type="button" class="mini" id="codeCopy">คัดลอก</button></div><pre class="code" id="ruleCode">${t(d[RCODE] || d.sigma || d.kql || d.spl)}</pre>` : ""}
    ${d.model ? `<div class="ai-foot">ร่างโดย ${t(d.model)} · ต้องตรวจทานก่อนเปิดใช้</div>` : ""}`;
  $("#ruleRetest").hidden = $("#ruleSave").hidden = false;
}
$("#ruleOut").addEventListener("click", (ev) => {
  const b = ev.target.closest(".code-tabs button[data-k]");
  if (b) { RCODE = b.dataset.k; $("#ruleCode").textContent = RDRAFT.draft[RCODE]; document.querySelectorAll(".code-tabs button[data-k]").forEach((x) => x.classList.toggle("on", x === b)); }
  if (ev.target.id === "codeCopy") navigator.clipboard.writeText($("#ruleCode").textContent).catch(() => {});
});
$("#ruleForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const desc = $("#ruleDesc").value.trim(); if (desc.length < 10) return;
  $("#ruleOut").innerHTML = '<p class="muted"><span class="spin"></span> AI กำลังร่างกฎ (อาจใช้ 20–60 วินาที)…</p>';
  try {
    const r = await api("/api/soc/rules/draft", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ description: desc }) });
    if (r.error) { $("#ruleOut").innerHTML = `<p class="err">${esc(r.error)}</p>`; return; }
    RDRAFT = r; RCODE = "sigma"; renderRuleResult(r);
  } catch (e) { $("#ruleOut").innerHTML = `<p class="err">ไม่สำเร็จ: ${esc(e.message)}</p>`; }
});
$("#ruleManual").onclick = () => {
  RDRAFT = { draft: {}, rule: { kind: "process", match: "all", title: "กฎใหม่", severity: "medium", technique: "", tactic: "",
    conditions: [{ field: "cmdline", op: "contains", value: "" }], threshold: { count: 0, window_sec: 0, group_by: "" } }, errors: [] };
  renderRuleResult(RDRAFT);
};
function editedRule() {
  try { return JSON.parse($("#ruleJson").value); } catch { alert("JSON ของกฎไม่ถูกต้อง"); return null; }
}
$("#ruleRetest").onclick = async () => {
  const rule = editedRule(); if (!rule) return;
  try {
    const r = await api("/api/soc/rules/test", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule, test_cases: RDRAFT?.draft?.test_cases || [] }) });
    RDRAFT = { ...(RDRAFT || {}), ...r, draft: RDRAFT?.draft || {} }; renderRuleResult(RDRAFT);
  } catch (e) { alert("ไม่สำเร็จ: " + e.message); }
};
$("#ruleSave").onclick = async () => {
  const rule = editedRule(); if (!rule) return;
  const d = RDRAFT?.draft || {};
  try {
    const r = await api("/api/soc/rules", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule: { ...rule, description: d.description, sigma: d.sigma, kql: d.kql, spl: d.spl, false_positives: d.false_positives } }) });
    alert(`บันทึก ${r.id} เป็น draft (ปิดอยู่) แล้ว — หัวหน้าทีมเปิดใช้ได้ในรายการด้านขวา`); loadRules();
  } catch (e) { alert("บันทึกไม่สำเร็จ: " + e.message); }
};
async function loadRules() {
  try {
    const r = await api("/api/soc/rules");
    $("#nb-rules").textContent = r.rules.filter((x) => x.status === "enabled").length;
    $("#customRules").innerHTML = r.rules.map((x) => `<li class="${x.hits ? "hit" : ""}"><span class="mono">${esc(x.id)}</span>
      <span>${esc(x.title)} <span class="sev" style="--sevc:var(--${esc(x.severity)})">${esc(x.severity)}</span>
      <span class="st ${esc(x.status)}">${x.status === "enabled" ? "เปิด" : "ปิด"}</span><small class="muted"> · ${esc(x.kind)} · โดย ${esc(x.created_by || "")}</small>
      ${can("rules.manage") ? `<button class="mini release" data-rid="${esc(x.id)}" data-to="${x.status === "enabled" ? "disabled" : "enabled"}">${x.status === "enabled" ? "ปิด" : "เปิดใช้"}</button>` : ""}</span><b>${x.hits}</b></li>`).join("")
      || '<li class="muted">ยังไม่มีกฎที่สร้างเอง</li>';
  } catch {}
}
$("#customRules").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-rid]"); if (!b) return;
  if (b.dataset.to === "enabled" && !confirm(`เปิดใช้ ${b.dataset.rid}? กฎจะเริ่มตรวจ log ทุกรายการทันที`)) return;
  try { await api(`/api/soc/rules/${encodeURIComponent(b.dataset.rid)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: b.dataset.to }) }); loadRules(); }
  catch (e) { alert("ไม่สำเร็จ: " + e.message); }
});
setInterval(() => { if (state.me) loadRules(); }, 30000);

const PHASE_ICON = { contain: "🛡️", eradicate: "🧹", recover: "♻️", notify: "📣", lessons: "📝" };
async function loadResponse(id) {
  try { renderResponse(await api(`/api/soc/incidents/${id}/response`)); } catch { $("#respPlan").innerHTML = ""; }
}
function renderResponse(p) {
  if (p.incident !== state.selected) return;
  const left = p.pdpa_deadline ? p.pdpa_deadline - Date.now() / 1000 : null;
  const fmt = (s) => s <= 0 ? "เลยกำหนดแล้ว" : `เหลือ ${Math.floor(s / 3600)} ชม. ${Math.floor((s % 3600) / 60)} นาที`;
  const canW = can("incident.write");
  $("#respPlan").innerHTML = `<h3><span>แผนตอบสนอง (Response plan)</span><small class="muted">${Math.round(p.progress * 100)}% เสร็จ</small></h3>
    <div class="bar"><i style="width:${p.progress * 100}%"></i></div>
    ${left !== null ? `<div class="pdpa">⏱ PDPA ม.37(4): หากมีข้อมูลส่วนบุคคลรั่วไหลและมีความเสี่ยงต่อสิทธิ ต้องแจ้ง สคส. ภายใน 72 ชม. — ${fmt(left)}
      (นับจากเวลาที่ตรวจพบครั้งแรก — ควรยืนยันเวลาที่องค์กร "ทราบเหตุ" กับ DPO)</div>` : ""}
    ${p.phases.map((ph) => { const st = p.steps.filter((x) => x.phase === ph.id); return st.length ? `<h4>${PHASE_ICON[ph.id] || ""} ${esc(ph.name)}</h4>${st.map((x) =>
      `<label class="${x.done ? "done" : ""}"><input type="checkbox" data-step="${esc(x.id)}" ${x.done ? "checked" : ""} ${canW ? "" : "disabled"}>
       <span>${esc(x.action)}<small>${esc(x.owner)} · ${esc(x.why)}${x.done ? ` · ✓ ${esc(x.done_by || "")} ${x.done_at ? new Date(x.done_at * 1000).toLocaleString("th-TH", { hour12: false }) : ""}` : ""}</small></span></label>`).join("")}` : ""; }).join("")}`;
}
$("#respPlan").addEventListener("change", async (ev) => {
  const cb = ev.target.closest("input[data-step]"); if (!cb || !state.selected) return;
  try { renderResponse(await api(`/api/soc/incidents/${state.selected}/response/${encodeURIComponent(cb.dataset.step)}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ done: cb.checked }) })); }
  catch (e) { cb.checked = !cb.checked; alert("ไม่สำเร็จ: " + e.message); }
});

// ---------- phase 5: tenants, governance, AI feedback ----------
function fbButtons(feature, ref) {
  return `<span class="fb" data-feature="${esc(feature)}" data-ref="${esc(ref)}"><button type="button" data-r="up" title="คำตอบมีประโยชน์">👍</button><button type="button" data-r="down" title="คำตอบผิด/ไม่มีประโยชน์">👎</button></span>`;
}
document.addEventListener("click", async (ev) => {
  const b = ev.target.closest(".fb button"); if (!b) return;
  const box = b.closest(".fb");
  let comment = null;
  if (b.dataset.r === "down") comment = prompt("อะไรผิด? (ไม่บังคับ — ช่วยให้ปรับปรุง AI ได้)") || null;
  try {
    await api("/api/ai/feedback", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ feature: box.dataset.feature, ref: box.dataset.ref, rating: b.dataset.r, comment }) });
    box.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  } catch (e) { alert("ส่งความเห็นไม่สำเร็จ: " + e.message); }
});
async function loadTenants() {
  try {
    const r = await api("/api/tenants");
    $("#tenantPick").hidden = false;
    $("#tenantSel").innerHTML = r.tenants.map((t) => `<option ${t === r.current ? "selected" : ""}>${esc(t)}</option>`).join("");
  } catch {}
}
$("#tenantSel").onchange = () => {
  store.set("tenant", $("#tenantSel").value === "default" ? "" : $("#tenantSel").value);
  location.reload();  // reconnect the live stream to the chosen tenant
};
async function loadGov() {
  try {
    const u = await api("/api/governance/ai-usage?days=30");
    $("#govTenant").textContent = `tenant: ${u.tenant}`;
    const rows = Object.entries(u.features).sort((a, b) => b[1].calls - a[1].calls);
    $("#aiUsage tbody").innerHTML = rows.map(([k, f]) => `<tr><td>${esc(k)}</td><td>${f.calls}</td><td>${f.claude}</td><td>${f.fallback}</td>
      <td>${f.input_tokens.toLocaleString()} / ${f.output_tokens.toLocaleString()}</td><td>${f.cost_usd.toFixed(4)}</td><td>${f.up} / ${f.down}</td></tr>`).join("")
      || '<tr><td colspan="7" class="muted">ยังไม่มีการใช้ AI ในช่วงนี้</td></tr>';
    $("#aiUsageFoot").textContent = `รวมประมาณ $${u.total_cost_usd} · ${u.ai.enabled ? `Claude ${u.ai.model}` : "ยังไม่ตั้งค่า API key"} · ${u.note}`;
    const a = await api("/api/audit?limit=40");
    $("#auditRows").innerHTML = a.rows.map((r) => `<li><span class="mono muted">${esc(r.ts.slice(5, 16).replace("T", " "))}</span>
      <span class="mono">${esc(r.analyst)}</span><span class="sum"><span class="kind">${esc(r.module)}</span>${esc(r.target)} <span class="muted">${esc((r.purpose || "").slice(0, 80))}</span></span><span></span></li>`).join("");
  } catch (e) { $("#aiUsage tbody").innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`; }
}
$("#govRefresh").onclick = loadGov;
$("#auditCsv").onclick = () => download("/api/audit.csv", "audit-log.csv", false).catch((e) => alert(e.message));
$("#dbBackup").onclick = () => download("/api/admin/backup", "soc-backup.db", false).catch((e) => alert(e.message));
$("#auditVerify").onclick = async () => {
  try {
    const v = await api("/api/audit/verify");
    $("#auditVerifyOut").innerHTML = v.ok ? `<span style="color:var(--ok-ink)">✓ ครบถ้วน ตรวจ ${v.checked} รายการ${v.legacy_rows ? ` (รายการเก่าก่อนเปิดใช้ hash ${v.legacy_rows})` : ""}${v.starts_after_purge ? " · เริ่มหลังการลบตามระยะเก็บข้อมูล" : ""}</span>`
      : `<span class="err">✗ พบการแก้ไข/ลบ ที่รายการ #${v.broken_at}: ${esc(v.reason)}</span>`;
  } catch (e) { $("#auditVerifyOut").textContent = e.message; }
};

// ---------- alert channels + deep links ----------
async function loadNotify() {
  const el = $("#notifyPill");
  try {
    const n = await api("/api/soc/notify");
    el.textContent = n.channels.length ? `แจ้งเตือน: ${n.channels.join(", ")} · ≥ ${n.min_severity}` : "แจ้งเตือน: ยังไม่ตั้งค่า";
    el.className = "pill " + (n.channels.length ? "ok" : "");
    el.dataset.ready = n.channels.length ? "1" : "";
  } catch { el.textContent = "แจ้งเตือน: ?"; }
}
$("#notifyPill").onclick = async () => {
  if (!$("#notifyPill").dataset.ready) { alert("ยังไม่ได้ตั้งค่าช่องทางแจ้งเตือน — ตั้ง SOC_NOTIFY_TEAMS_URL / SOC_NOTIFY_LINE_TOKEN ฯลฯ ใน environment ของเซิร์ฟเวอร์"); return; }
  const analyst = analystName(); if (!analyst || !confirm("ส่งข้อความทดสอบไปทุกช่องทางแจ้งเตือน?")) return;
  try {
    const r = await api("/api/soc/notify/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ analyst }) });
    alert(Object.entries(r.results).map(([k, v]) => `${k}: ${v.ok ? "สำเร็จ" : "ล้มเหลว (" + v.detail + ")"}`).join("\n"));
  } catch (e) { alert("ไม่สำเร็จ: " + e.message); }
};
async function openIncidentFromHash() {
  const m = /^#inc-(\d+)$/.exec(location.hash); if (!m) return;
  const id = Number(m[1]);
  let inc = state.incidents.find((i) => i.id === id);
  if (!inc) { try { inc = await api(`/api/soc/incidents/${id}`); } catch { return; } }
  state.selected = id; renderDetail(inc);
  $("#detailCard").scrollIntoView({ behavior: "smooth", block: "start" });
}
window.addEventListener("hashchange", openIncidentFromHash);

// ---------- incident workflow ----------
function analystName() {
  if (state.me?.named) return state.me.name;  // named users: identity comes from their token
  let a = store.get("analyst");
  if (!a) { a = prompt("ชื่อผู้ปฏิบัติงาน (analyst)") || ""; if (a.length >= 2) store.set("analyst", a); }
  return a.length >= 2 ? a : "";
}
function renderWorkflow(inc) {
  if (state.wfFor !== inc.id) {  // only reset the form when switching incidents, never while typing
    state.wfFor = inc.id;
    $("#wfStatus").value = inc.status; $("#wfVerdict").value = inc.verdict || ""; $("#wfAssignee").value = inc.assignee || ""; $("#wfNote").value = ""; $("#wfMsg").textContent = "";
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
  const body = { analyst, status: $("#wfStatus").value, assignee: $("#wfAssignee").value.trim(), verdict: $("#wfVerdict").value };
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
    <td class="riskbtn" title="${esc(riskTip(a.id))}"><span class="risk"><i style="width:${riskOf(a)}%"></i></span>${riskOf(a)}${state.risk?.[a.id] ? ` <span class="st ${esc(state.risk[a.id].level === "low" ? "normal" : state.risk[a.id].level === "medium" ? "suspicious" : "compromised")}">${esc(state.risk[a.id].level)}</span>` : ""}</td>
    <td><span class="st ${esc(a.status)}">${esc(a.status)}</span>${a.registered === false ? ' <span class="st unregistered" title="seen in logs but not in the agent inventory">unregistered</span>' : ""}</td>
    <td>${can("respond") ? `<button title="บันทึกสถานะ contained และ audit log — ยังไม่มี connector สั่ง revoke token จริง" class="mini ${a.contained ? "release" : ""}" data-agent="${esc(a.id)}" data-on="${a.contained ? 0 : 1}">${a.contained ? "Release" : "Contain"}</button>` : ""}</td></tr>`).join("");
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
    <div class="n"><span>${esc(f.name)}</span><b title="indicator matches (IOC) for this framework">${f.hits}</b></div>
    <div class="focus">${esc(f.focus || "")}</div><div class="d">${esc(f.desc)}</div>
    <div class="fr">${(f.rules || []).map((r) => `<span class="${r.hits ? "on" : ""}" title="${r.hits == null ? "agent rule" : r.hits + " hits (all sources)"}">${esc(r.id)}</span>`).join("")}</div>
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

// ---------- workspace: overview widgets, tasks, notifications ----------
const TASK_TH = { pending: "รอดำเนินการ", awaiting_input: "รอข้อมูล", in_progress: "กำลังทำ", completed: "เสร็จแล้ว", cancelled: "ยกเลิก" };
const ALERT_ST = { new: "ใหม่", open: "open", investigating: "investigating", resolved: "resolved", false_positive: "false positive", closed: "closed" };
const SRC_COLORS = ["--endpoint", "--network", "--identity", "--agent", "--email", "--cloud", "--data", "--off", "--xdr", "--low", "--medium", "--info"];
const ago = (ts) => { const s = Math.max(0, Date.now() / 1000 - ts); return s < 60 ? `${s | 0} วิ` : s < 3600 ? `${(s / 60) | 0} นาที` : s < 86400 ? `${(s / 3600) | 0} ชม.` : `${(s / 86400) | 0} วัน`; };
function urgRing(u) {
  const c = u >= 80 ? "--critical" : u >= 60 ? "--high" : u >= 40 ? "--medium" : "--low";
  const r = 14, len = 2 * Math.PI * r;
  return `<svg class="urg" viewBox="0 0 36 36" role="img" aria-label="urgency ${u}"><circle cx="18" cy="18" r="${r}" class="urg-bg"/>
    <circle cx="18" cy="18" r="${r}" style="stroke:var(${c})" stroke-dasharray="${(len * u / 100).toFixed(1)} ${len.toFixed(1)}" transform="rotate(-90 18 18)"/>
    <text x="18" y="22" text-anchor="middle">${u}</text></svg>`;
}
function renderDonut(srcs, total) {
  const svg = $("#donut"), r = 46, len = 2 * Math.PI * r;
  let off = 0, arcs = `<circle cx="60" cy="60" r="${r}" class="donut-bg"/>`;
  srcs.forEach((s, i) => {
    const l = len * s.share;
    arcs += `<circle cx="60" cy="60" r="${r}" style="stroke:var(${SRC_COLORS[i % SRC_COLORS.length]})" stroke-dasharray="${Math.max(0, l - 1).toFixed(2)} ${len.toFixed(2)}"
      stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 60 60)"><title>${esc(s.source)}: ${s.events.toLocaleString()}</title></circle>`;
    off += l;
  });
  svg.innerHTML = arcs;
  $("#srcTotal").textContent = total >= 1e6 ? (total / 1e6).toFixed(1) + "M" : total >= 1e4 ? (total / 1e3).toFixed(1) + "K" : total.toLocaleString();
  $("#srcLegend").innerHTML = srcs.map((s, i) => `<li><i style="background:var(${SRC_COLORS[i % SRC_COLORS.length]})"></i><span>${esc(s.source)}</span>
    <b>${s.events.toLocaleString()}</b><small>${(s.share * 100).toFixed(1)}%</small></li>`).join("") || '<li class="muted">ยังไม่มีข้อมูลเข้า</li>';
}
async function loadOverview() {
  try {
    const o = await api("/api/soc/overview");
    setKpi("#ov-pending", o.pending_alerts); setKpi("#ov-cases", o.opened_cases);
    $("#ov-formula").textContent = "urgency คืออะไร?"; $("#ov-formula").title = o.urgency_formula;
    $("#srcNote").textContent = o.simulated ? "รวมข้อมูลจำลอง" : "log จริง";
    $("#alertsTbl tbody").innerHTML = o.alerts.slice(0, 25).map((a) => `<tr data-inc="${a.incident_id ?? ""}" class="${a.incident_id ? "clk" : ""}">
      <td>${urgRing(a.urgency)}</td>
      <td class="a-title">${a.real ? '<span class="real">REAL</span>' : ""}${esc(a.title)}<div class="sub">${esc(a.technique || "")}${a.rule ? " · " + esc(a.rule) : ""}${a.cti ? ' · <span class="c-cti">CTI</span>' : ""}</div></td>
      <td>${esc(a.host || "-")}</td><td class="num"><b>${a.occurrences}</b></td>
      <td><span class="ist ${esc(a.status)}">${esc(ALERT_ST[a.status] || a.status)}</span>${a.assignee ? `<div class="sub">${esc(a.assignee)}</div>` : ""}</td>
      <td title="${esc(t2(a.first_ts))} → ${esc(t2(a.last_ts))}">${ago(a.last_ts)}</td></tr>`).join("")
      || '<tr><td colspan="6" class="muted">ยังไม่มี alert</td></tr>';
    renderDonut(o.data_sources, o.events_total);
    const max = Math.max(1, ...o.top_threats.map((t) => t.alerts));
    $("#threats").innerHTML = o.top_threats.map((t) => `<li><div><span class="mono">${esc(t.technique)}</span> ${esc(t.name)}</div>
      <div class="bar"><i style="width:${(100 * t.alerts / max).toFixed(1)}%"></i></div><b>${t.alerts}</b></li>`).join("")
      || '<li class="muted">ยังไม่มี alert ใน 24 ชม.</li>';
  } catch (e) { $("#alertsTbl tbody").innerHTML = `<tr><td colspan="6" class="err">${esc(e.message)}</td></tr>`; }
}
$("#alertsTbl").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr[data-inc]"); if (tr?.dataset.inc) location.hash = "#inc-" + tr.dataset.inc;
});

const TS = { tasks: [], users: [], edit: null };
const toLocalInput = (ts) => { if (!ts) return ""; const d = new Date(ts * 1000); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
async function loadTasks() {
  const p = new URLSearchParams();
  if ($("#taskQ").value.trim()) p.set("q", $("#taskQ").value.trim());
  if ($("#taskStatus").value) p.set("status", $("#taskStatus").value);
  if ($("#taskMine").checked && state.me?.name) p.set("assignee", state.me.name);
  try {
    const r = await api("/api/soc/tasks?" + p);
    TS.tasks = r.tasks;
    if ($("#taskStatus").options.length === 1)
      $("#taskStatus").insertAdjacentHTML("beforeend", r.statuses.map((s) => `<option value="${s.id}">${esc(s.th)}</option>`).join(""));
    const open = (r.by_status.pending || 0) + (r.by_status.awaiting_input || 0) + (r.by_status.in_progress || 0);
    $("#nb-task").textContent = open;
    $("#taskCounts").textContent = r.statuses.map((s) => `${s.th} ${r.by_status[s.id] || 0}`).join(" · ");
    const now = Date.now() / 1000, edit = can("incident.write");
    $("#tasksTbl tbody").innerHTML = r.tasks.map((t) => {
      const overdue = t.due && t.due < now && !["completed", "cancelled"].includes(t.status);
      return `<tr data-task="${t.id}" class="clk"><td>${t.id}</td>
        <td class="a-title">${esc(t.name)}${t.description ? `<div class="sub">${esc(t.description.slice(0, 90))}</div>` : ""}</td>
        <td>${t.assignee ? `<span class="who">${esc(t.assignee[0].toUpperCase())}</span>${esc(t.assignee)}` : '<span class="muted">—</span>'}</td>
        <td>${edit ? `<select class="tstat ${t.status}" data-id="${t.id}" aria-label="สถานะงาน ${t.id}">${Object.entries(TASK_TH).map(([k, v]) => `<option value="${k}" ${k === t.status ? "selected" : ""}>${v}</option>`).join("")}</select>`
          : `<span class="tstat ${t.status}">${TASK_TH[t.status]}</span>`}</td>
        <td class="${overdue ? "overdue" : ""}">${t.due ? esc(t2(t.due)) + (overdue ? " · เลยกำหนด" : "") : '<span class="muted">—</span>'}</td>
        <td>${t.incident_id ? `<a href="#inc-${t.incident_id}">INC-${t.incident_id}</a>` : ""}</td></tr>`;
    }).join("") || '<tr><td colspan="6" class="muted">ยังไม่มีงาน — กด “+ สร้างงาน”</td></tr>';
  } catch (e) { $("#tasksTbl tbody").innerHTML = `<tr><td colspan="6" class="err">${esc(e.message)}</td></tr>`; }
}
async function loadAssignees() {
  try { TS.users = (await api("/api/soc/assignees")).users; } catch { TS.users = []; }
}
function openTask(t, preset = {}) {
  TS.edit = t;
  const f = $("#taskForm");
  f.reset();
  $("#taskDlgTitle").textContent = t ? `งาน #${t.id}` : "สร้างงาน";
  f.assignee.innerHTML = '<option value="">— ยังไม่มอบหมาย —</option>' + TS.users.map((u) => `<option>${esc(u)}</option>`).join("");
  f.status.innerHTML = Object.entries(TASK_TH).map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
  const v = t || preset;
  f.name.value = v.name || ""; f.description.value = v.description || "";
  f.assignee.value = v.assignee || ""; f.status.value = v.status || "pending";
  f.due.value = toLocalInput(v.due); f.incident_id.value = v.incident_id || "";
  $("#taskNoteRow").hidden = !t;
  $("#taskHist").hidden = !t?.history?.length;
  $("#taskHist").innerHTML = (t?.history || []).concat((t?.notes || []).map((n) => ({ ...n, change: "📝 " + n.text })))
    .sort((a, b) => a.ts - b.ts).map((h) => `<li><span class="muted">${esc(t2(h.ts))}</span> <b>${esc(h.analyst)}</b> ${esc(h.change)}</li>`).join("");
  $("#taskErr").textContent = "";
  const ro = !can("incident.write");
  f.querySelectorAll("input,textarea,select").forEach((el) => { el.disabled = ro; });
  if (t) f.incident_id.disabled = true;
  $("#taskSave").hidden = ro;
  $("#taskDlg").showModal();
}
$("#taskForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const f = ev.target, due = f.due.value ? new Date(f.due.value).getTime() / 1000 : null;
  const body = { name: f.name.value.trim(), description: f.description.value, assignee: f.assignee.value, status: f.status.value };
  try {
    if (TS.edit) {
      Object.assign(body, due ? { due } : { clear_due: !!TS.edit.due });
      if (f.note.value.trim()) body.note = f.note.value.trim();
      for (const k of ["name", "description", "assignee", "status"]) if ((TS.edit[k] || "") === body[k]) delete body[k];
      if (Object.keys(body).length) await api(`/api/soc/tasks/${TS.edit.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } else {
      if (due) body.due = due;
      if (f.incident_id.value) body.incident_id = Number(f.incident_id.value);
      await api("/api/soc/tasks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    }
    $("#taskDlg").close(); loadTasks(); loadBell();
  } catch (e) { $("#taskErr").textContent = e.message; }
});
$("#taskNew").onclick = () => openTask(null, state.selected ? { incident_id: state.selected } : {});
$("#tasksTbl").addEventListener("click", (ev) => {
  if (ev.target.closest("select,a")) return;
  const tr = ev.target.closest("tr[data-task]"); if (!tr) return;
  openTask(TS.tasks.find((t) => t.id === Number(tr.dataset.task)));
});
$("#tasksTbl").addEventListener("change", async (ev) => {
  const s = ev.target.closest("select.tstat"); if (!s) return;
  try {
    await api(`/api/soc/tasks/${s.dataset.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: s.value }) });
    loadTasks(); loadBell();
  } catch (e) { alert(e.message); loadTasks(); }
});
let taskQT;
$("#taskQ").addEventListener("input", () => { clearTimeout(taskQT); taskQT = setTimeout(loadTasks, 250); });
$("#taskStatus").onchange = loadTasks;
$("#taskMine").onchange = loadTasks;

async function loadBell() {
  try {
    const r = await api("/api/soc/notifications");
    const cnt = r.items.length + (r.unread || 0);
    $("#bellN").hidden = !cnt;
    $("#bellN").textContent = cnt;
    $("#inboxList").innerHTML = (r.inbox || []).slice(0, 10).map((n) => `<li class="${n.read ? "read" : ""} ${n.severity === "critical" ? "urgent" : ""}">
      <a href="#inc-${n.ref}"><span class="kind">INC-${n.ref}</span><span>${n.real ? '<span class="real">REAL</span>' : ""}${esc(n.title)}
      <small>${esc(n.rule)} · ${esc(n.severity)} · urgency ${n.urgency} · ${ago(n.ts)}ที่แล้ว</small></span></a></li>`).join("")
      || '<li class="muted">ยังไม่มี — สร้างกฎได้ที่ “จัดการกฎการแจ้งเตือน”</li>';
    $("#bellBtn").classList.toggle("bad", r.urgent > 0);
    $("#bellList").innerHTML = r.items.map((n) => `<li class="${n.urgent ? "urgent" : ""}"><a href="${n.kind === "task" ? "#task-" + n.id : "#inc-" + n.id}">
      <span class="kind">${n.kind === "task" ? "TASK" : "INC-" + n.id}</span><span>${esc(n.title)}<small>${esc(n.detail)}</small></span></a></li>`).join("")
      || '<li class="muted">ไม่มีรายการค้าง 🎉</li>';
  } catch {}
}
$("#bellBtn").onclick = (ev) => {
  ev.stopPropagation();
  const p = $("#bellPanel"); p.hidden = !p.hidden; $("#bellBtn").setAttribute("aria-expanded", String(!p.hidden));
  if (!p.hidden) loadBell();
};
document.addEventListener("click", (ev) => { if (!ev.target.closest(".bell-wrap")) { $("#bellPanel").hidden = true; $("#bellBtn").setAttribute("aria-expanded", "false"); } });
window.addEventListener("hashchange", () => {
  const m = /^#task-(\d+)$/.exec(location.hash); if (!m) return;
  const t = TS.tasks.find((x) => x.id === Number(m[1]));
  $("#bellPanel").hidden = true;
  if (t) openTask(t); else $("#tasksCard").scrollIntoView({ behavior: "smooth" });
});
function loadWorkspace() { loadOverview(); loadTasks(); loadBell(); loadAssignees(); loadAlertsList(); loadEvents(); loadLandscape(); loadNotifyRules();
  loadCases(); loadSavedQueries(); loadNotebooks(); loadCatalog(); loadCaseMeta(); }
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) loadOverview(); }, 15000);
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) loadBell(); }, 60000);

$("#inboxRead").onclick = async (ev) => {
  ev.stopPropagation();
  try { await api("/api/soc/notifications/read", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); loadBell(); } catch (e) { alert(e.message); }
};

// ---------- alerts list ----------
const VERDICT_TH = { true_positive: "True positive", false_positive: "False positive", benign: "Benign", undetermined: "ยังสรุปไม่ได้" };
const AL = { page: 1 };
async function loadAlertsList() {
  const p = new URLSearchParams({ page: AL.page, size: 25, sort: $("#alSort").value, hours: $("#alHours").value });
  if ($("#alQ").value.trim()) p.set("q", $("#alQ").value.trim());
  if ($("#alStatus").value) p.set("status", $("#alStatus").value);
  if ($("#alSev").value) p.set("severity", $("#alSev").value);
  if ($("#alReal").checked) p.set("real_only", "true");
  try {
    const r = await api("/api/soc/alerts?" + p);
    AL.page = r.page;
    $("#alTotal").textContent = `${r.total.toLocaleString()} รายการ (จัดกลุ่มตาม alert + host)`;
    $("#alPage").textContent = `หน้า ${r.page} / ${r.pages}`;
    $("#alPrev").disabled = r.page <= 1; $("#alNext").disabled = r.page >= r.pages;
    $("#alTbl tbody").innerHTML = r.items.map((a) => `<tr data-inc="${a.incident_id ?? ""}" class="${a.incident_id ? "clk" : ""}">
      <td class="num"><span class="occ sev-${esc(a.severity)}">${a.occurrences}</span></td>
      <td>${a.incident_id ? `<a href="#inc-${a.incident_id}">INC-${a.incident_id}</a>` : '<span class="muted">—</span>'}</td>
      <td title="${esc(t2(a.first_ts))} → ${esc(t2(a.last_ts))}">${esc(new Date(a.last_ts * 1000).toLocaleString("th-TH", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }))}</td>
      <td class="a-title">${a.real ? '<span class="real">REAL</span>' : ""}${esc(a.title)}<div class="sub">${esc(a.technique || "")}${a.rule ? " · " + esc(a.rule) : ""}</div></td>
      <td><span class="ist ${esc(a.status)}">${esc(ALERT_ST[a.status] || a.status)}</span></td>
      <td>${a.verdict ? `<span class="vd ${esc(a.verdict)}">${esc(VERDICT_TH[a.verdict] || a.verdict)}</span>` : '<span class="muted">—</span>'}</td>
      <td>${a.assignee ? esc(a.assignee) : '<span class="muted">—</span>'}</td>
      <td class="mono">${esc(a.host || "-")}</td>
      <td>${urgRing(a.urgency)}</td>
      <td><span class="dt">${esc(a.detection_type)}</span></td>
      <td>${esc(a.type || "-")}</td>
      <td>${a.threats.map((t) => `<span class="thr">${esc(t)}</span>`).join(" ") || '<span class="muted">—</span>'}</td></tr>`).join("")
      || '<tr><td colspan="12" class="muted">ไม่พบ alert ตามเงื่อนไข</td></tr>';
  } catch (e) { $("#alTbl tbody").innerHTML = `<tr><td colspan="12" class="err">${esc(e.message)}</td></tr>`; }
}
let alT;
$("#alQ").addEventListener("input", () => { clearTimeout(alT); alT = setTimeout(() => { AL.page = 1; loadAlertsList(); }, 300); });
["#alStatus", "#alSev", "#alSort", "#alReal", "#alHours"].forEach((s) => { $(s).onchange = () => { AL.page = 1; loadAlertsList(); }; });
$("#alPrev").onclick = () => { AL.page--; loadAlertsList(); };
$("#alNext").onclick = () => { AL.page++; loadAlertsList(); };
$("#alTbl").addEventListener("click", (ev) => {
  if (ev.target.closest("a")) return;
  const tr = ev.target.closest("tr[data-inc]"); if (tr?.dataset.inc) location.hash = "#inc-" + tr.dataset.inc;
});

// ---------- events explorer ----------
const svgW = (el) => Math.max(280, el.clientWidth || el.parentElement.clientWidth || 600);
function drawHist(r) {
  const el = $("#evHist"), w = svgW(el), h = 120, padL = 30, padB = 18;
  const max = Math.max(1, ...r.histogram.map((b) => b.real + b.simulated));
  const bw = (w - padL) / r.histogram.length;
  const y = (v) => (h - padB) * (1 - v / max);
  const span = r.end - r.start, fmt = (ts) => new Date(ts * 1000).toLocaleTimeString("th-TH", span > 86400 ? { day: "numeric", month: "short", hour: "2-digit" } : { hour12: false, hour: "2-digit", minute: "2-digit", ...(span <= 900 ? { second: "2-digit" } : {}) });
  let out = `<line x1="${padL}" y1="${h - padB}" x2="${w}" y2="${h - padB}" class="ax"/><text x="2" y="10" class="tk">${max}</text><text x="2" y="${h - padB}" class="tk">0</text>`;
  r.histogram.forEach((b, i) => {
    const x = padL + i * bw, tot = b.real + b.simulated;
    if (tot) {
      out += `<rect x="${(x + 1).toFixed(1)}" y="${y(tot).toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${(y(b.real) - y(tot)).toFixed(1)}" class="s"><title>${fmt(b.ts)} · จำลอง ${b.simulated}</title></rect>`;
      if (b.real) out += `<rect x="${(x + 1).toFixed(1)}" y="${y(b.real).toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${(h - padB - y(b.real)).toFixed(1)}" class="r"><title>${fmt(b.ts)} · จริง ${b.real}</title></rect>`;
    }
    if (i % Math.ceil(r.histogram.length / 6) === 0) out += `<text x="${x.toFixed(1)}" y="${h - 4}" class="tk">${esc(fmt(b.ts))}</text>`;
  });
  el.setAttribute("viewBox", `0 0 ${w} ${h}`); el.innerHTML = out;
}
async function loadEvents() {
  const p = new URLSearchParams({ minutes: $("#evRange").value, limit: 200 });
  if ($("#evQ").value.trim()) p.set("q", $("#evQ").value.trim());
  try {
    const r = await api("/api/soc/events?" + p);
    drawHist(r);
    $("#evMeta").textContent = `${r.total.toLocaleString()} events · แสดง ${r.rows.length} ล่าสุด · log จริงเก็บ ${r.retention_days} วัน`;
    $("#evTbl tbody").innerHTML = r.rows.map((x, i) => `<tr class="clk" data-i="${i}"><td class="mono">${esc(t2(x.ts))}</td>
      <td><span class="kindtag">${esc(x.kind)}</span>${x.real ? ' <span class="real">REAL</span>' : ""}</td><td class="mono">${esc(x.host || "-")}</td>
      <td class="ev-desc">${esc(x.description)}${x.source ? ` <span class="muted">· ${esc(x.source)}</span>` : ""}</td></tr>
      <tr class="ev-raw" hidden><td colspan="4"><pre>${esc(JSON.stringify(x.record, null, 2))}</pre></td></tr>`).join("")
      || '<tr><td colspan="4" class="muted">ไม่พบ event ในช่วงเวลานี้</td></tr>';
  } catch (e) { $("#evTbl tbody").innerHTML = `<tr><td colspan="4" class="err">${esc(e.message)}</td></tr>`; }
}
$("#evForm").addEventListener("submit", (ev) => { ev.preventDefault(); loadEvents(); });
$("#evRange").onchange = loadEvents;
$("#evTbl").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr.clk"); if (!tr) return;
  const raw = tr.nextElementSibling; if (raw?.classList.contains("ev-raw")) raw.hidden = !raw.hidden;
});

// ---------- threat landscape ----------
const LCOL = ["--off", "--endpoint", "--medium", "--network", "--cloud", "--identity"];
function lineChart(el, labels, series, fmt) {
  const w = svgW(el), h = 170, padL = 34, padB = 20, padT = 8;
  const max = Math.max(1, ...series.flatMap((s) => s.points));
  const n = Math.max(1, labels.length - 1);
  const x = (i) => padL + (w - padL - 8) * (labels.length === 1 ? 0.5 : i / n);
  const y = (v) => padT + (h - padT - padB) * (1 - v / max);
  let out = "";
  for (let g = 0; g <= 2; g++) { const v = Math.round(max * g / 2); out += `<line x1="${padL}" x2="${w}" y1="${y(v)}" y2="${y(v)}" class="grid"/><text x="2" y="${y(v) + 3}" class="tk">${v}</text>`; }
  const step = Math.ceil(labels.length / 6);
  labels.forEach((l, i) => {
    const last = i === labels.length - 1;
    if ((i % step === 0 && labels.length - 1 - i >= step / 2) || last) out += `<text x="${x(i)}" y="${h - 4}" class="tk" text-anchor="${last && labels.length > 1 ? "end" : i === 0 ? "start" : "middle"}">${esc(fmt(l))}</text>`;
  });
  series.forEach((s, k) => {
    const col = `var(${LCOL[k % LCOL.length]})`;
    out += `<polyline fill="none" stroke="${col}" stroke-width="2" stroke-linejoin="round" points="${s.points.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ")}"/>`;
    s.points.forEach((v, i) => { out += `<circle cx="${x(i).toFixed(1)}" cy="${y(v).toFixed(1)}" r="2.6" fill="${col}"><title>${esc(s.label)} · ${esc(fmt(labels[i]))}: ${v}</title></circle>`; });
  });
  el.setAttribute("viewBox", `0 0 ${w} ${h}`); el.innerHTML = out || "";
}
function legend(el, series) {
  el.innerHTML = series.map((s, k) => `<span><i style="background:var(${LCOL[k % LCOL.length]})"></i>${esc(s.label)} <b>${s.total}</b></span>`).join("");
}
function barChart(el, labels, vals, fmt) {
  const w = svgW(el), h = 170, padL = 34, padB = 20, padT = 8, max = Math.max(1, ...vals), bw = (w - padL) / labels.length;
  let out = `<line x1="${padL}" x2="${w}" y1="${h - padB}" y2="${h - padB}" class="grid"/><text x="2" y="${padT + 6}" class="tk">${max}</text>`;
  vals.forEach((v, i) => {
    const bh = (h - padT - padB) * v / max, x = padL + i * bw;
    out += `<rect x="${x + 3}" y="${h - padB - bh}" width="${Math.max(2, bw - 6)}" height="${bh}" rx="2" class="bar"><title>${esc(fmt(labels[i]))}: ${v}</title></rect>`;
    if (i % Math.ceil(labels.length / 6) === 0) out += `<text x="${x + bw / 2}" y="${h - 4}" class="tk" text-anchor="middle">${esc(fmt(labels[i]))}</text>`;
  });
  el.setAttribute("viewBox", `0 0 ${w} ${h}`); el.innerHTML = out;
}
const dShort = (d) => new Date(d + "T00:00:00").toLocaleDateString("th-TH", { day: "numeric", month: "short" });
async function loadLandscape() {
  try {
    const r = await api("/api/soc/landscape?hours=" + $("#landHours").value);
    const mw = r.malware_trend;
    $("#mwSrc").textContent = r.feeds_loaded.threatfox ? `${mw.source} · IOC ต่อวัน` : "ยังโหลด ThreatFox ไม่ได้";
    const mws = mw.series.map((s) => ({ label: s.name, points: s.points, total: s.total }));
    if (mws.length) { lineChart($("#mwChart"), mw.days, mws, dShort); legend($("#mwLegend"), mws); }
    else { $("#mwChart").innerHTML = ""; $("#mwLegend").innerHTML = '<span class="muted">ไม่มีข้อมูลจาก feed</span>'; }
    const tt = r.technique_trend, hrs = r.hours;
    const tts = tt.series.map((s) => ({ label: `${s.technique} ${s.name}`, points: s.points, total: s.total }));
    const tf = (ts) => new Date(ts * 1000).toLocaleString("th-TH", hrs <= 48 ? { hour: "2-digit", minute: "2-digit", hour12: false } : { day: "numeric", month: "short" });
    $("#ttSrc").textContent = `alert ของ tenant นี้ · ${hrs <= 48 ? hrs + " ชม." : hrs / 24 + " วัน"}${r.simulated ? " · รวมข้อมูลจำลอง" : ""}`;
    if (tts.length) { lineChart($("#ttChart"), tt.buckets, tts, tf); legend($("#ttLegend"), tts); }
    else { $("#ttChart").innerHTML = ""; $("#ttLegend").innerHTML = '<span class="muted">ยังไม่มี alert ในช่วงนี้</span>'; }
    const k = r.kev_trend;
    $("#kevSrc").textContent = r.feeds_loaded.kev ? `${k.total} CVE ใน 12 สัปดาห์ · ransomware ${k.ransomware}` : "ยังโหลด KEV ไม่ได้";
    barChart($("#kevChart"), k.weeks, k.added, dShort);
    $("#kevVendors").textContent = k.top_vendors.length ? "ผู้ผลิตที่พบมาก: " + k.top_vendors.map((v) => `${v.vendor} (${v.cves})`).join(", ") : "";
    $("#kevLatest").innerHTML = r.latest_kev.map((v) => `<li><a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer" class="mono">${esc(v.cve)}</a>
      ${v.ransomware ? '<span class="tag">ransomware</span>' : ""}<div>${esc(v.title || "")}</div><small class="muted">${esc(v.vendor)} ${esc(v.product)} · เพิ่มเมื่อ ${esc(v.date)}</small></li>`).join("")
      || '<li class="muted">ยังไม่มีข้อมูล</li>';
    $("#thrTbl tbody").innerHTML = r.threats.map((t) => `<tr><td>${esc(t.threat)}</td><td class="num">${t.alerts}</td><td class="num">${t.last_7d}</td>
      <td class="num">${t.hosts}</td><td class="num">${t.related_iocs.toLocaleString()}</td><td>${ago(t.last_ts)}ที่แล้ว</td>
      <td>${t.reference ? `<a href="${esc(t.reference)}" target="_blank" rel="noopener noreferrer">NVD</a>` : '<span class="muted">—</span>'}</td></tr>`).join("")
      || '<tr><td colspan="7" class="muted">ยังไม่พบ threat ที่ระบุชื่อได้ (framework / malware / CVE) ใน alert</td></tr>';
  } catch (e) { $("#thrTbl tbody").innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`; }
}
$("#landHours").onchange = loadLandscape;

// ---------- notification rules ----------
const NR = { rules: [], edit: null, server: [] };
const CH_TH = { in_app: "ในระบบ (กระดิ่ง)", teams: "Microsoft Teams", line: "LINE", slack: "Slack", webhook: "Webhook", email: "Email" };
async function loadNotifyRules() {
  try {
    const r = await api("/api/soc/notify-rules");
    NR.rules = r.rules; NR.server = r.server_channels;
    $("#nrChannels").textContent = "ช่องทางภายนอกที่ตั้งค่าบนเซิร์ฟเวอร์แล้ว: " + (r.server_channels.map((c) => CH_TH[c]).join(", ") || "ยังไม่มี (ใช้ได้เฉพาะแจ้งเตือนในระบบ)");
    const edit = can("rules.manage");
    $("#nrTbl tbody").innerHTML = r.rules.map((x) => `<tr data-id="${x.id}"><td>${x.id}</td><td class="a-title">${esc(x.name)}</td>
      <td class="a-title small">≥ ${esc(x.min_severity)}${x.min_urgency ? ` · urgency ≥ ${x.min_urgency}` : ""}${x.domains.length ? " · " + x.domains.map(esc).join("/") : ""}${x.rule_prefixes.length ? " · rule " + x.rule_prefixes.map(esc).join(", ") : ""}${x.keyword ? ` · “${esc(x.keyword)}”` : ""}${x.real_only ? " · log จริง" : " · รวมจำลอง"}</td>
      <td>${x.channels.map((c) => `<span class="thr ${c !== "in_app" && !NR.server.includes(c) ? "off" : ""}" title="${c !== "in_app" && !NR.server.includes(c) ? "ยังไม่ได้ตั้งค่าช่องทางนี้บนเซิร์ฟเวอร์" : ""}">${esc(CH_TH[c] || c)}</span>`).join(" ")}</td>
      <td>${edit ? `<input type="checkbox" class="nr-en" ${x.enabled ? "checked" : ""} aria-label="เปิดใช้กฎ ${x.id}">` : (x.enabled ? "✓" : "—")}</td>
      <td>${edit ? `<button class="ghost sm nr-edit">แก้ไข</button> <button class="ghost sm nr-del">ลบ</button>` : ""}</td></tr>`).join("")
      || '<tr><td colspan="6" class="muted">ยังไม่มีกฎ — ตัวอย่าง: “critical จาก log จริง → ในระบบ + LINE”</td></tr>';
  } catch (e) { $("#nrTbl tbody").innerHTML = `<tr><td colspan="6" class="err">${esc(e.message)}</td></tr>`; }
}
function nrBody() {
  const f = $("#nrForm");
  return { name: f.name.value.trim(), min_severity: f.min_severity.value, min_urgency: Number(f.min_urgency.value || 0),
    keyword: f.keyword.value.trim(), real_only: f.real_only.checked, enabled: f.enabled.checked,
    rule_prefixes: f.rule_prefixes.value.split(",").map((x) => x.trim()).filter(Boolean),
    domains: [...f.querySelectorAll("#nrDomains input:checked")].map((x) => x.value),
    channels: [...f.querySelectorAll("#nrChans input:checked")].map((x) => x.value) };
}
function openRule(rule) {
  NR.edit = rule;
  const f = $("#nrForm"); f.reset();
  $("#nrDlgTitle").textContent = rule ? `แก้ไขกฎ #${rule.id}` : "สร้างกฎการแจ้งเตือน";
  $("#nrDomains").innerHTML = DOMAINS.map((d) => `<label class="chk"><input type="checkbox" value="${d}" ${rule?.domains.includes(d) ? "checked" : ""}> ${d}</label>`).join("");
  $("#nrChans").innerHTML = Object.entries(CH_TH).map(([c, t]) => `<label class="chk"><input type="checkbox" value="${c}" ${(rule ? rule.channels.includes(c) : c === "in_app") ? "checked" : ""}> ${t}${c !== "in_app" && !NR.server.includes(c) ? ' <span class="muted">(ยังไม่ตั้งค่า)</span>' : ""}</label>`).join("");
  if (rule) {
    f.name.value = rule.name; f.min_severity.value = rule.min_severity; f.min_urgency.value = rule.min_urgency;
    f.keyword.value = rule.keyword || ""; f.rule_prefixes.value = rule.rule_prefixes.join(", ");
    f.real_only.checked = rule.real_only; f.enabled.checked = rule.enabled;
  }
  $("#nrErr").textContent = ""; $("#nrTestOut").textContent = "";
  $("#nrDlg").showModal();
}
$("#nrNew").onclick = () => openRule(null);
$("#nrTest").onclick = async () => {
  try {
    const r = await api("/api/soc/notify-rules/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...nrBody(), name: nrBody().name || "test" }) });
    $("#nrTestOut").textContent = r.matches.length ? `ตรงกับ ${r.matches.length} incident: ` + r.matches.slice(0, 5).map((m) => `#${m.id} ${m.severity}`).join(", ") : "ไม่ตรงกับ incident ที่มีตอนนี้";
  } catch (e) { $("#nrTestOut").textContent = e.message; }
};
$("#nrForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  try {
    await api(NR.edit ? `/api/soc/notify-rules/${NR.edit.id}` : "/api/soc/notify-rules",
      { method: NR.edit ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(nrBody()) });
    $("#nrDlg").close(); loadNotifyRules();
  } catch (e) { $("#nrErr").textContent = e.message; }
});
$("#nrTbl").addEventListener("click", async (ev) => {
  const tr = ev.target.closest("tr[data-id]"); if (!tr) return;
  const rule = NR.rules.find((x) => x.id === Number(tr.dataset.id));
  if (ev.target.closest(".nr-edit")) openRule(rule);
  if (ev.target.closest(".nr-del") && confirm(`ลบกฎ “${rule.name}”?`)) {
    try { await api(`/api/soc/notify-rules/${rule.id}`, { method: "DELETE" }); loadNotifyRules(); } catch (e) { alert(e.message); }
  }
});
$("#nrTbl").addEventListener("change", async (ev) => {
  const cb = ev.target.closest(".nr-en"); if (!cb) return;
  const rule = NR.rules.find((x) => x.id === Number(cb.closest("tr").dataset.id));
  try {
    await api(`/api/soc/notify-rules/${rule.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...rule, enabled: cb.checked }) });
    loadNotifyRules();
  } catch (e) { alert(e.message); loadNotifyRules(); }
});
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) { loadAlertsList(); } }, 30000);
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) { loadLandscape(); } }, 120000);


// ---------- cases ----------
const CPRIO = { low: "Low", medium: "Medium", high: "High", critical: "Critical" };
const CS = { page: 1, fields: [], crit: {} };
async function loadCaseMeta() {
  try { CS.fields = (await api("/api/soc/case-fields")).fields; } catch {}
  try { CS.crit = (await api("/api/soc/assets/criticality")).criticality; } catch {}
}
const cfText = (cf) => Object.entries(cf || {}).map(([k, v]) => `${esc((CS.fields.find((f) => f.key === k) || {}).label || k)}: ${esc(v)}`).join(" · ");
async function loadCases() {
  const p = new URLSearchParams({ page: CS.page, size: 25, sort: $("#csSort").value });
  for (const [id, k] of [["#csQ", "q"], ["#csStatus", "status"], ["#csPrio", "priority"], ["#csType", "type"], ["#csTag", "tag"]])
    if ($(id).value.trim()) p.set(k, $(id).value.trim());
  if ($("#csMine").checked) p.set("assignee", "me");
  if ($("#csReal").checked) p.set("real_only", "true");
  try {
    const r = await api("/api/soc/cases?" + p);
    CS.page = r.page; CS.fields = r.fields;
    $("#csTotal").textContent = `${r.total.toLocaleString()} cases`;
    $("#nb-case").textContent = r.total;
    $("#csPage").textContent = `หน้า ${r.page} / ${r.pages}`;
    $("#csPrev").disabled = r.page <= 1; $("#csNext").disabled = r.page >= r.pages;
    const cur = $("#csTag").value;
    $("#csTag").innerHTML = '<option value="">ทุก tag</option>' + r.tags.map((t) => `<option ${t === cur ? "selected" : ""}>${esc(t)}</option>`).join("");
    $("#csTbl tbody").innerHTML = r.items.map((c) => `<tr class="clk" data-inc="${c.id}"><td>${c.id}</td>
      <td class="a-title">${c.real ? '<span class="real">REAL</span>' : ""}${esc(c.name)}<div class="sub">${esc(c.hosts.join(", "))}</div></td>
      <td><span class="ist ${esc(c.status)}">${esc(c.status)}</span></td>
      <td><span class="prio ${esc(c.priority)}">${esc(CPRIO[c.priority])}</span></td>
      <td>${c.verdict ? `<span class="vd ${esc(c.verdict)}">${esc(VERDICT_TH[c.verdict] || c.verdict)}</span>` : '<span class="muted">—</span>'}</td>
      <td class="small">${cfText(c.custom_fields) || '<span class="muted">—</span>'}</td>
      <td>${c.tags.map((t) => `<span class="thr">${esc(t)}</span>`).join(" ") || '<span class="muted">—</span>'}</td>
      <td>${c.assignee ? `<span class="who">${esc(c.assignee[0].toUpperCase())}</span>${esc(c.assignee)}` : '<span class="muted">—</span>'}</td>
      <td><span class="dt">${c.type === "manual" ? "Manual" : "✦ Automatic"}</span></td>
      <td class="num">${c.alerts}</td><td>${ago(c.updated_ts)}ที่แล้ว</td></tr>`).join("")
      || '<tr><td colspan="11" class="muted">ไม่พบ case ตามเงื่อนไข</td></tr>';
  } catch (e) { $("#csTbl tbody").innerHTML = `<tr><td colspan="11" class="err">${esc(e.message)}</td></tr>`; }
}
let csT;
$("#csQ").addEventListener("input", () => { clearTimeout(csT); csT = setTimeout(() => { CS.page = 1; loadCases(); }, 300); });
["#csStatus", "#csPrio", "#csType", "#csTag", "#csSort", "#csMine", "#csReal"].forEach((x) => { $(x).onchange = () => { CS.page = 1; loadCases(); }; });
$("#csPrev").onclick = () => { CS.page--; loadCases(); };
$("#csNext").onclick = () => { CS.page++; loadCases(); };
$("#csTbl").addEventListener("click", (ev) => { const tr = ev.target.closest("tr[data-inc]"); if (tr) location.hash = "#inc-" + tr.dataset.inc; });
function cfInputs(box, values = {}) {
  box.innerHTML = CS.fields.map((f) => `<label>${esc(f.label)} ${f.type === "select"
    ? `<select data-cf="${esc(f.key)}"><option value="">—</option>${f.options.map((o) => `<option ${values[f.key] === o ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`
    : `<input data-cf="${esc(f.key)}" type="${f.type === "number" ? "number" : "text"}" value="${esc(values[f.key] ?? "")}">`}</label>`).join("");
}
const cfValues = (box) => Object.fromEntries([...box.querySelectorAll("[data-cf]")].map((el) => [el.dataset.cf, el.value.trim() || null]));
const splitList = (v) => v.split(",").map((x) => x.trim()).filter(Boolean);
$("#csNew").onclick = async () => {
  await loadCaseMeta();
  const f = $("#caseForm"); f.reset();
  f.assignee.innerHTML = '<option value="">— ยังไม่มอบหมาย —</option>' + TS.users.map((u) => `<option>${esc(u)}</option>`).join("");
  cfInputs($("#caseCf")); $("#caseErr").textContent = "";
  $("#caseDlg").showModal();
};
$("#caseForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const f = ev.target;
  try {
    const c = await api("/api/soc/cases", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name: f.name.value.trim(), description: f.description.value, priority: f.priority.value, assignee: f.assignee.value || null,
      tags: splitList(f.tags.value), hosts: splitList(f.hosts.value), custom_fields: cfValues($("#caseCf")) }) });
    $("#caseDlg").close(); loadCases(); location.hash = "#inc-" + c.id;
  } catch (e) { $("#caseErr").textContent = e.message; }
});
function cfRow(f = { key: "", label: "", type: "text", options: [] }) {
  return `<div class="cf-row"><input placeholder="key" value="${esc(f.key)}" data-k="key"><input placeholder="ชื่อที่แสดง" value="${esc(f.label)}" data-k="label">
    <select data-k="type">${["text", "number", "select"].map((t) => `<option ${t === f.type ? "selected" : ""}>${t}</option>`).join("")}</select>
    <input placeholder="ตัวเลือก (select)" value="${esc(f.options.join(", "))}" data-k="options"><button type="button" class="ghost sm cf-del">ลบ</button></div>`;
}
$("#cfEdit").onclick = async () => {
  await loadCaseMeta();
  $("#cfRows").innerHTML = CS.fields.map(cfRow).join("") || cfRow();
  $("#cfErr").textContent = ""; $("#cfDlg").showModal();
};
$("#cfAdd").onclick = () => $("#cfRows").insertAdjacentHTML("beforeend", cfRow());
$("#cfRows").addEventListener("click", (ev) => { if (ev.target.closest(".cf-del")) ev.target.closest(".cf-row").remove(); });
$("#cfForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const rows = [...$("#cfRows").querySelectorAll(".cf-row")].map((r) => {
    const g = (k) => r.querySelector(`[data-k=${k}]`).value.trim();
    return { key: g("key"), label: g("label"), type: g("type"), options: splitList(g("options")) };
  }).filter((x) => x.key);
  try { await api("/api/soc/case-fields", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rows) });
    $("#cfDlg").close(); await loadCaseMeta(); loadCases(); } catch (e) { $("#cfErr").textContent = e.message; }
});

// case header + tabs inside the incident detail
const CRIT_TH = ["—", "1 ต่ำ", "2", "3 กลาง", "4", "5 สำคัญที่สุด"];
function renderCase(inc) {
  const sev = inc.severity;
  $("#cbType").innerHTML = `<span class="dt">${inc.type === "manual" ? "Manual" : "✦ Automatic"}</span>
    <span class="muted small">เห็นครั้งแรก ${esc(t2(inc.first_ts))} · ล่าสุด ${esc(t2(inc.last_ts))}${inc.created_by ? " · สร้างโดย " + esc(inc.created_by) : ""}</span>`;
  if (state.caseFor !== inc.id) {
    state.caseFor = inc.id;
    $("#cbPrio").value = inc.priority || (CPRIO[sev] ? sev : "low");
    $("#cbTags").value = (inc.tags || []).join(", ");
    $("#cbMsg").textContent = "";
    cfInputs($("#cbFields"), inc.custom_fields || {});
    document.querySelectorAll("#caseTabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === "details"));
    document.querySelectorAll("#detailCard .tabpane").forEach((p) => { p.hidden = p.dataset.pane !== "details"; });
    $("#ctEvents").textContent = "–";
    loadCaseNotebooks(inc.id);
  }
  const ro = !can("incident.write");
  document.querySelectorAll("#caseBar [data-perm-dis], #cbFields [data-cf]").forEach((el) => { el.disabled = ro; });
  $("#cbImpact").innerHTML = '<b class="small">Impact</b> ' + (inc.hosts || []).filter(Boolean).map((h) => {
    const lv = CS.crit[h] || 0;
    return `<span class="asset l${lv}"><span class="mono">${esc(h)}</span><select data-host="${esc(h)}" ${can("agents.manage") ? "" : "disabled"} aria-label="ความสำคัญของ ${esc(h)}" title="Asset criticality">${CRIT_TH.map((t, i) => `<option value="${i}" ${i === lv ? "selected" : ""}>${t}</option>`).join("")}</select></span>`;
  }).join("") + (inc.description ? `<p class="case-desc">${esc(inc.description)}</p>` : "");
  $("#ctAlerts").textContent = (inc.alerts || []).length;
  $("#ctTasks").textContent = TS.tasks.filter((t) => t.incident_id === inc.id).length;
  $("#caseAlerts tbody").innerHTML = [...(inc.alerts || [])].reverse().map((a) => `<tr><td class="mono">${esc(t2(a.ts))}</td>
    <td class="a-title"><span class="sev" style="--sevc:var(--${esc(a.severity)})">${esc(a.severity)}</span> ${esc(a.title)}<div class="sub">${esc(a.technique || "")}</div></td>
    <td class="mono">${esc(a.host || "-")}</td><td>${esc(a.user || "-")}</td><td>${esc(a.rule || "-")}</td><td class="c-cti">${esc(a.cti_match || "")}</td></tr>`).join("")
    || '<tr><td colspan="6" class="muted">case นี้ยังไม่มี alert (สร้างด้วยมือ)</td></tr>';
  const tasks = TS.tasks.filter((t) => t.incident_id === inc.id);
  $("#caseTasks tbody").innerHTML = tasks.map((t) => `<tr class="clk" data-task="${t.id}"><td>${t.id}</td><td class="a-title">${esc(t.name)}</td>
    <td>${esc(t.assignee || "—")}</td><td><span class="tstat ${t.status}">${TASK_TH[t.status]}</span></td><td>${t.due ? esc(t2(t.due)) : "—"}</td></tr>`).join("")
    || '<tr><td colspan="5" class="muted">ยังไม่มีงานใน case นี้</td></tr>';
}
$("#cbImpact").addEventListener("change", async (ev) => {
  const sel = ev.target.closest("select[data-host]"); if (!sel) return;
  try {
    await api("/api/soc/assets/criticality", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: sel.dataset.host, level: Number(sel.value) }) });
    CS.crit[sel.dataset.host] = Number(sel.value);
    sel.closest(".asset").className = "asset l" + sel.value;
  } catch (e) { alert(e.message); }
});
$("#cbSave").onclick = async () => {
  const id = state.selected, analyst = analystName(); if (!id || !analyst) return;
  try {
    const inc = await api(`/api/soc/incidents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      analyst, priority: $("#cbPrio").value, tags: splitList($("#cbTags").value), custom_fields: cfValues($("#cbFields")) }) });
    const i = state.incidents.findIndex((x) => x.id === id); if (i >= 0) state.incidents[i] = inc;
    $("#cbMsg").textContent = "บันทึกแล้ว"; loadCases();
  } catch (e) { $("#cbMsg").textContent = "ไม่สำเร็จ: " + e.message; }
};
$("#caseTabs").addEventListener("click", (ev) => {
  const b = ev.target.closest("button[data-tab]"); if (!b) return;
  document.querySelectorAll("#caseTabs button").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll("#detailCard .tabpane").forEach((p) => { p.hidden = p.dataset.pane !== b.dataset.tab; });
  if (b.dataset.tab === "events") loadCaseEvents(state.selected);
  if (b.dataset.tab === "tasks") loadTasks();
});
async function loadCaseEvents(id) {
  $("#caseEvMeta").textContent = "กำลังโหลด…";
  try {
    const r = await api(`/api/soc/cases/${id}/events`);
    $("#ctEvents").textContent = r.total;
    $("#caseEvMeta").textContent = `log ดิบของ host ${r.hosts.join(", ") || "-"} และผู้ใช้ ${r.users.join(", ") || "-"} ระหว่าง ${t2(r.start)} – ${t2(r.end)} · ${r.total} events`;
    $("#caseEvents tbody").innerHTML = r.rows.map((x) => `<tr><td class="mono">${esc(t2(x.ts))}</td><td><span class="kindtag">${esc(x.kind)}</span></td>
      <td class="mono">${esc(x.host || "-")}</td><td class="ev-desc">${esc(x.description)}</td></tr>`).join("") || '<tr><td colspan="4" class="muted">ไม่พบ log ดิบที่เกี่ยวข้อง</td></tr>';
  } catch (e) { $("#caseEvMeta").textContent = e.message; }
}
$("#caseTasks").addEventListener("click", (ev) => { const tr = ev.target.closest("tr[data-task]"); if (tr) openTask(TS.tasks.find((t) => t.id === Number(tr.dataset.task))); });
$("#caseTaskNew").onclick = () => openTask(null, { incident_id: state.selected });
async function loadCaseNotebooks(id) {
  try {
    const r = await api(`/api/soc/notebooks?case_id=${id}`);
    $("#ctNb").textContent = r.notebooks.length;
    $("#caseNbs").innerHTML = r.notebooks.map((n) => `<li><a href="#nb-${n.id}">${esc(n.title)}</a> <small class="muted">แก้ไขโดย ${esc(n.updated_by)} · ${ago(n.updated_at)}ที่แล้ว</small></li>`).join("")
      || '<li class="muted">ยังไม่มี notebook ของ case นี้</li>';
  } catch {}
}
$("#caseNbNew").onclick = () => createNotebook(state.selected);

// ---------- query builder ----------
const QB = { last: null };
async function runQuery() {
  $("#qbErr").textContent = ""; $("#qbMeta").textContent = "กำลังรัน…";
  try {
    const r = await api("/api/soc/query", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: $("#qbText").value, minutes: Number($("#qbRange").value) }) });
    QB.last = r;
    const cols = r.columns || (r.source === "alerts" ? ["ts", "severity", "title", "host", "user", "rule", "technique"] : ["ts", "kind", "host", "description"]);
    $("#qbTbl thead").innerHTML = "<tr>" + cols.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr>";
    const cell = (c, v) => c === "ts" && typeof v === "number" ? esc(t2(v)) : esc(typeof v === "object" && v !== null ? JSON.stringify(v) : v ?? "");
    $("#qbTbl tbody").innerHTML = r.rows.map((row) => "<tr>" + cols.map((c) => `<td class="${c === "description" || c === "title" ? "ev-desc" : ""}">${cell(c, c.split(".").reduce((o, k) => o?.[k], row))}</td>`).join("") + "</tr>").join("")
      || `<tr><td colspan="${cols.length}" class="muted">ไม่มีผลลัพธ์</td></tr>`;
    $("#qbMeta").textContent = `${r.total.toLocaleString()} แถว${r.rows.length < r.total ? ` (แสดง ${r.rows.length})` : ""} · สแกน ${r.scanned.toLocaleString()} ${r.source} · ${r.duration_ms} ms`;
  } catch (e) { $("#qbErr").textContent = e.message; $("#qbMeta").textContent = ""; }
}
$("#qbRun").onclick = runQuery;
$("#qbText").addEventListener("keydown", (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") runQuery(); });
$("#qbHelp").onclick = () => { $("#qbDoc").hidden = !$("#qbDoc").hidden; };
$("#qbCsv").onclick = () => {
  if (!QB.last?.rows.length) return;
  const cols = QB.last.columns || Object.keys(QB.last.rows[0]).filter((k) => typeof QB.last.rows[0][k] !== "object");
  const q = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const csv = [cols.map(q).join(","), ...QB.last.rows.map((r) => cols.map((c) => q(r[c])).join(","))].join("\n");
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob(["﻿" + csv], { type: "text/csv" })); a.download = "query-results.csv"; a.click();
};
async function loadSavedQueries() {
  try {
    const r = await api("/api/soc/queries");
    QB.saved = r.queries;
    $("#qbSaved").innerHTML = r.queries.map((x) => `<li data-id="${x.id}"><a href="#queryCard" class="qb-load">${esc(x.name)}</a>
      ${can("incident.write") ? '<button class="ghost sm qb-del" title="ลบ">×</button>' : ""}<div class="mono small muted">${esc(x.query.replace(/\s+/g, " ").slice(0, 90))}</div></li>`).join("")
      || '<li class="muted">ยังไม่มี — กด “บันทึก query”</li>';
  } catch {}
}
$("#qbSaved").addEventListener("click", async (ev) => {
  const li = ev.target.closest("li[data-id]"); if (!li) return;
  const item = QB.saved.find((x) => x.id === Number(li.dataset.id));
  if (ev.target.closest(".qb-del")) { if (confirm(`ลบ “${item.name}”?`)) { await api(`/api/soc/queries/${item.id}`, { method: "DELETE" }).catch((e) => alert(e.message)); loadSavedQueries(); } return; }
  $("#qbText").value = item.query; $("#qbRange").value = String(item.minutes); runQuery();
});
$("#qbSave").onclick = async () => {
  const name = prompt("ตั้งชื่อ query"); if (!name) return;
  try { await api("/api/soc/queries", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, query: $("#qbText").value, minutes: Number($("#qbRange").value) }) }); loadSavedQueries(); }
  catch (e) { $("#qbErr").textContent = e.message; }
};

// ---------- notebooks ----------
const NB = { trash: false, items: [], cur: null, preview: true };
function md(src) {  // small, safe Markdown subset: everything is escaped first, then formatted
  const blocks = String(src || "").split(/```/);
  return blocks.map((b, i) => {
    if (i % 2) return `<pre class="nb-code">${esc(b.replace(/^\w*\n/, ""))}</pre>`;
    const lines = esc(b).split("\n");
    let html = "", list = null;
    const inline = (t) => t.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/\*([^*]+)\*/g, "<i>$1</i>")
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    const close = () => { if (list) { html += `</${list}>`; list = null; } };
    for (const l of lines) {
      let m;
      if ((m = /^(#{1,3})\s+(.*)$/.exec(l))) { close(); html += `<h${m[1].length + 2}>${inline(m[2])}</h${m[1].length + 2}>`; }
      else if ((m = /^\s*[-*]\s+(.*)$/.exec(l))) { if (list !== "ul") { close(); html += "<ul>"; list = "ul"; } html += `<li>${inline(m[1])}</li>`; }
      else if ((m = /^\s*\d+\.\s+(.*)$/.exec(l))) { if (list !== "ol") { close(); html += "<ol>"; list = "ol"; } html += `<li>${inline(m[1])}</li>`; }
      else if (!l.trim()) close();
      else { close(); html += `<p>${inline(l)}</p>`; }
    }
    close();
    return html;
  }).join("");
}
async function loadNotebooks() {
  try {
    const p = new URLSearchParams({ trash: NB.trash });
    if ($("#nbQ").value.trim()) p.set("q", $("#nbQ").value.trim());
    NB.items = (await api("/api/soc/notebooks?" + p)).notebooks;
    $("#nbList").innerHTML = NB.items.map((n) => `<li data-id="${n.id}" class="${NB.cur?.id === n.id ? "on" : ""}"><b>${esc(n.title)}</b>
      <small class="muted">${n.case_id ? `INC-${n.case_id} · ` : ""}${esc(n.updated_by)} · ${ago(n.updated_at)}ที่แล้ว</small></li>`).join("")
      || `<li class="muted">${NB.trash ? "ถังขยะว่าง" : "ยังไม่มี notebook"}</li>`;
  } catch (e) { $("#nbList").innerHTML = `<li class="err">${esc(e.message)}</li>`; }
}
function openNotebook(n) {
  NB.cur = n;
  const ro = !can("incident.write") || n.deleted;
  $("#nbMain").innerHTML = `<div class="nb-head"><input id="nbTitle" value="${esc(n.title)}" maxlength="200" ${ro ? "disabled" : ""} aria-label="ชื่อ notebook">
    <span class="muted small">${n.case_id ? `<a href="#inc-${n.case_id}">INC-${n.case_id}</a> · ` : ""}แก้ไขล่าสุดโดย ${esc(n.updated_by)} · ${esc(t2(n.updated_at))}</span></div>
    <div class="seg nb-mode"><button data-m="edit" class="${NB.preview ? "" : "on"}" ${ro ? "disabled" : ""}>แก้ไข</button><button data-m="view" class="${NB.preview ? "on" : ""}">แสดงผล</button></div>
    <textarea id="nbBody" class="code" rows="16" ${ro ? "disabled" : ""} ${NB.preview ? "hidden" : ""} aria-label="เนื้อหา">${esc(n.content)}</textarea>
    <div id="nbView" class="nb-view" ${NB.preview ? "" : "hidden"}>${md(n.content) || '<p class="muted">ว่าง — กด “แก้ไข”</p>'}</div>
    <div class="task-bar">${n.deleted ? `<button id="nbRestore" data-perm="incident.write">กู้คืน</button>` : `${ro ? "" : '<button id="nbSaveBtn">บันทึก</button><button id="nbTrash" class="ghost">ย้ายไปถังขยะ</button>'}`}
    <span id="nbMsg" class="muted small"></span></div>`;
  document.querySelectorAll("#nbList li").forEach((li) => li.classList.toggle("on", Number(li.dataset.id) === n.id));
}
async function createNotebook(caseId) {
  try {
    const n = await api("/api/soc/notebooks", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: caseId ? `บันทึกการสืบสวน INC-${caseId}` : "Untitled", content: caseId ? `# INC-${caseId}\n\n## สิ่งที่พบ\n- \n\n## ขั้นตอนต่อไป\n1. ` : "", ...(caseId ? { case_id: caseId } : {}) }) });
    NB.trash = false; NB.preview = false; await loadNotebooks(); openNotebook(n);
    if (caseId) loadCaseNotebooks(caseId);
    $("#nbCard").scrollIntoView({ behavior: "smooth" });
  } catch (e) { alert(e.message); }
}
async function saveNotebook(patch) {
  try {
    const n = await api(`/api/soc/notebooks/${NB.cur.id}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...patch, base_updated_at: NB.cur.updated_at }) });
    NB.cur = n; await loadNotebooks();
    if (patch.deleted !== undefined) { $("#nbMain").innerHTML = '<p class="muted">เลือกหรือสร้าง notebook</p>'; NB.cur = null; } else { openNotebook(n); $("#nbMsg").textContent = "บันทึกแล้ว"; }
  } catch (e) { $("#nbMsg").textContent = e.message; }
}
$("#nbNew").onclick = () => createNotebook(null);
$("#nbList").addEventListener("click", (ev) => { const li = ev.target.closest("li[data-id]"); if (li) openNotebook(NB.items.find((n) => n.id === Number(li.dataset.id))); });
document.querySelector("#nbCard .nb-side .seg").addEventListener("click", (ev) => {
  const b = ev.target.closest("button"); if (!b) return;
  NB.trash = b.dataset.trash === "1";
  b.parentElement.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  loadNotebooks();
});
let nbT;
$("#nbQ").addEventListener("input", () => { clearTimeout(nbT); nbT = setTimeout(loadNotebooks, 250); });
$("#nbMain").addEventListener("click", (ev) => {
  const m = ev.target.closest(".nb-mode button");
  if (m) { NB.preview = m.dataset.m === "view"; if (NB.cur) { NB.cur = { ...NB.cur, content: $("#nbBody").value, title: $("#nbTitle").value }; openNotebook(NB.cur); } return; }
  if (ev.target.id === "nbSaveBtn") saveNotebook({ title: $("#nbTitle").value.trim() || "Untitled", content: $("#nbBody").value });
  if (ev.target.id === "nbTrash" && confirm("ย้าย notebook นี้ไปถังขยะ?")) saveNotebook({ deleted: true });
  if (ev.target.id === "nbRestore") saveNotebook({ deleted: false });
});
window.addEventListener("hashchange", async () => {
  const m = /^#nb-(\d+)$/.exec(location.hash); if (!m) return;
  NB.trash = false; await loadNotebooks();
  const n = NB.items.find((x) => x.id === Number(m[1])); if (n) { NB.preview = true; openNotebook(n); }
  $("#nbCard").scrollIntoView({ behavior: "smooth" });
});

// ---------- rules catalog ----------
const CAT = { data: null };
async function loadCatalog() {
  try { CAT.data = await api("/api/soc/rules/catalog"); renderCatalog(); }
  catch (e) { $("#catList").innerHTML = `<p class="err">${esc(e.message)}</p>`; }
}
function renderCatalog() {
  const d = CAT.data; if (!d) return;
  setKpi("#catTotal", d.summary.total); setKpi("#catEnabled", d.summary.enabled); setKpi("#catCustom", d.summary.custom);
  setKpi("#catAlerts", d.summary.alerts_7d); setKpi("#catRejected", d.summary.rejected_7d);
  const max = Math.max(1, ...d.mitre.flatMap((m) => m.techniques.map((t) => t.alerts_7d)));
  const order = (t) => { const i = TACTIC_ORDER.indexOf(t); return i < 0 ? 99 : i; };
  $("#catHeat").innerHTML = [...d.mitre].sort((a, b) => order(a.tactic) - order(b.tactic)).map((m) => `<div class="heat-col"><div class="heat-h" title="${esc(m.tactic)}">${esc(m.tactic)}</div>
    ${m.techniques.map((t) => `<div class="heat-c" style="--a:${(0.12 + 0.88 * t.alerts_7d / max).toFixed(2)}" title="${esc(t.id)} ${esc(t.name)} · ${t.alerts_7d} alerts 7 วัน">${esc(t.id)}</div>`).join("")}</div>`).join("");
  const q = $("#catQ").value.trim().toLowerCase(), cat = $("#catCat").value, en = $("#catEn").value;
  let rows = d.rules.filter((r) => (!q || `${r.id} ${r.title} ${r.technique} ${r.technique_name}`.toLowerCase().includes(q))
    && (!cat || r.category === cat) && (en === "" || String(Number(r.enabled)) === en));
  const s = $("#catSort").value;
  rows.sort(s === "id" ? (a, b) => a.id.localeCompare(b.id) : s === "quality" ? (a, b) => (a.quality ?? 101) - (b.quality ?? 101) : (a, b) => b.alerts_7d - a.alerts_7d);
  const edit = can("rules.manage");
  $("#catList").innerHTML = rows.map((r) => `<div class="cat-rule ${r.enabled ? "" : "off"}">
    <div class="cr-main"><div class="cr-t"><span class="mono">${esc(r.id)}</span> ${esc(r.title)}</div>
      <div class="cr-m"><span class="sev" style="--sevc:var(--${esc(r.severity)})">${esc(r.severity)}</span> <span class="dt">${esc(r.category)}</span>
        <span class="muted small">${esc(r.technique || "")} ${esc(r.technique_name && r.technique_name !== r.technique ? r.technique_name : "")} · ${esc(r.tactic || "")}</span>
        ${r.exports.map((x) => `<span class="thr" title="${esc(x.file)}">${esc(x.format.split(" ")[0])}</span>`).join(" ")}</div></div>
    <div class="cr-stats"><div><b>${r.alerts_7d}</b><small>alerts 7 วัน</small></div><div><b>${r.rejected_7d}</b><small>ถูกปฏิเสธ</small></div>
      <div class="cr-q">${r.quality === null ? '<small class="muted">ยังไม่มีข้อมูลคุณภาพ</small>' : `<small>Quality ${r.quality}</small><span class="qbar"><i style="width:${r.quality}%" class="${r.quality >= 80 ? "good" : r.quality >= 50 ? "mid" : "bad"}"></i></span>`}</div></div>
    <label class="switch" title="${r.source === "custom" && r.status !== "enabled" ? "custom rule นี้ยังไม่ได้เปิดใน AI Rule Assistant" : ""}"><input type="checkbox" data-rule="${esc(r.id)}" ${r.enabled ? "checked" : ""} ${edit && !(r.source === "custom" && r.status !== "enabled") ? "" : "disabled"} aria-label="เปิดใช้ ${esc(r.id)}"><span></span></label>
  </div>`).join("") || '<p class="muted">ไม่พบ rule</p>';
}
["#catCat", "#catEn", "#catSort"].forEach((x) => { $(x).onchange = renderCatalog; });
$("#catQ").addEventListener("input", renderCatalog);
$("#catList").addEventListener("change", async (ev) => {
  const cb = ev.target.closest("input[data-rule]"); if (!cb) return;
  try { await api(`/api/soc/rules/${cb.dataset.rule}/enabled`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: cb.checked }) }); loadCatalog(); }
  catch (e) { alert(e.message); cb.checked = !cb.checked; }
});
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) loadCases(); }, 30000);
