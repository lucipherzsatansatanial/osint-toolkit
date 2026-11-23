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
    tmLive(msg.events);
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
    if (can("governance.read")) loadGov();
    document.querySelectorAll("[data-perm]").forEach((el) => { el.hidden = !can(el.dataset.perm); });
    if (can("users.read")) loadUsers();
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
    loadRoles();
    const t = (x) => x ? new Date(x * 1000).toLocaleString("th-TH", { hour12: false }) : "-";
    $("#usersTbl tbody").innerHTML = d.users.map((u) => `<tr><td>${esc(u.username)}${state.me?.platform && u.tenant ? `<div class="sub">${esc(u.tenant === "*" ? "platform" : u.tenant)}</div>` : ""}</td>
      <td><select data-u="${esc(u.username)}" class="roleSel" ${can("roles.manage") ? "" : "disabled"} aria-label="บทบาทของ ${esc(u.username)}">${d.roles.map((r) => `<option value="${esc(r.id)}" ${r.id === u.role ? "selected" : ""}>${esc(r.th)}</option>`).join("")}</select></td>
      <td><span class="st ${u.disabled ? "contained" : "healthy"}">${u.disabled ? "ปิดใช้งาน" : "ใช้งาน"}</span></td>
      <td class="muted">${t(u.last_seen)}</td><td class="muted">${esc(u.created_by || "")}</td>
      <td>${can("tokens.manage") ? `<button class="mini release" data-act="rotate" data-u="${esc(u.username)}">ออก token ใหม่</button>` : ""}
          ${can("users.manage") ? `<button class="mini release" data-act="${u.disabled ? "enable" : "disable"}" data-u="${esc(u.username)}">${u.disabled ? "เปิดใช้งาน" : "ปิดใช้งาน"}</button>` : ""}</td></tr>`).join("")
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
    $("#aiRefresh").hidden = !inc.ai || !can("ai.copilot");
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
      ${r.virustotal ? `<h4>VirusTotal</h4>${vtCard(r.virustotal)}` : ""}
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
      <span class="st ${esc(x.status)}">${x.status === "enabled" ? "เปิด" : "ปิด"}</span><small class="muted"> · v${x.version || 1} · ${esc(x.kind)} · โดย ${esc(x.created_by || "")}${x.published_by ? " · เผยแพร่โดย " + esc(x.published_by) : ""}</small>
      ${x.draft ? `<span class="vd" title="แก้โดย ${esc(x.draft.by)}">มี draft รอเผยแพร่ (${esc(x.draft.by)})</span>` : ""}
      ${can("rules.publish") ? (x.draft ? `<button class="mini release" data-rid="${esc(x.id)}" data-to="enabled">เผยแพร่ draft</button>` : "")
        + `<button class="mini release" data-rid="${esc(x.id)}" data-to="${x.status === "enabled" ? "disabled" : "enabled"}">${x.status === "enabled" ? "ปิด" : "เปิดใช้"}</button>` : ""}
      ${can("rules.rollback") && (x.versions || []).length > 1 ? `<select class="rb" data-rid="${esc(x.id)}" aria-label="ย้อนเวอร์ชัน ${esc(x.id)}"><option value="">ย้อนเวอร์ชัน…</option>${x.versions.filter((v) => v.version !== x.version).map((v) => `<option value="${v.version}">v${v.version} · ${esc(v.by || "")} · ${esc((v.note || "").slice(0, 30))}</option>`).join("")}</select>` : ""}</span><b>${x.hits}</b></li>`).join("")
      || '<li class="muted">ยังไม่มีกฎที่สร้างเอง</li>';
  } catch {}
}
$("#customRules").addEventListener("change", async (ev) => {
  const sel = ev.target.closest("select.rb"); if (!sel || !sel.value) return;
  const reason = prompt(`เหตุผลที่ย้อน ${sel.dataset.rid} ไป v${sel.value}`);
  if (!reason || reason.length < 3) { sel.value = ""; return; }
  try { await api(`/api/soc/rules/${encodeURIComponent(sel.dataset.rid)}/rollback`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ version: Number(sel.value), reason }) }); loadRules(); } catch (e) { alert("ไม่สำเร็จ: " + e.message); sel.value = ""; }
});
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
  const canW = can("cases.update");
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
    loadPolicies();
    if (!can("audit.read")) { $("#auditRows").innerHTML = '<li class="muted">ต้องมีสิทธิ์ audit.read</li>'; return; }
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
    <td>${can("agents.deploy") && a.registered && !a.demo ? `<button class="mini release" data-life="${esc(a.id)}" data-state="${a.retired ? "active" : "retired"}">${a.retired ? "นำกลับมาใช้" : "Retire"}</button> ` : ""}${a.retired ? '<span class="st contained">retired</span> ' : ""}${can("respond.execute") ? `<button title="บันทึกสถานะ contained และ audit log — ยังไม่มี connector สั่ง revoke token จริง" class="mini ${a.contained ? "release" : ""}" data-agent="${esc(a.id)}" data-on="${a.contained ? 0 : 1}">${a.contained ? "Release" : "Contain"}</button>` : ""}</td></tr>`).join("");
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
  try { const r = await api(`/api/soc/agents/${encodeURIComponent(b.dataset.agent)}/contain`, { method: "POST",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contain: on, analyst, reason }) });
    if (r.status === "pending_approval") { alert(`ส่งคำขอ #${r.request.id} แล้ว — รอผู้มีสิทธิ์ respond.approve คนอื่นอนุมัติ`); loadApprovals(); } }
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
const ALERT_ST = { new: "ใหม่", open: "open", investigating: "investigating", resolved: "resolved", false_positive: "false positive", closed: "closed", acknowledged: "รับทราบแล้ว", escalated: "ยกระดับแล้ว" };
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
    setKpi("#ov-pending", o.pending_alerts); setKpi("#ov-cases", o.opened_cases); setKpi("#ov-ongoing", o.ongoing_alerts ?? 0);
    const tr = (el, pct, cur, prev, what) => { const e = $(el); if (!e || !o.trend) return;
      e.textContent = pct === null ? `${cur} ${what} ใน 24 ชม.` : `${pct > 0 ? "▲" : pct < 0 ? "▼" : "•"} ${Math.abs(pct)}% (${cur} vs ${prev})`;
      e.className = "trend " + (pct > 0 ? "up" : pct < 0 ? "down" : ""); e.title = `24 ชม. ล่าสุด ${cur} · 24 ชม. ก่อนหน้า ${prev}`; };
    if (o.trend) { tr("#ov-at", o.trend.alerts_pct, o.trend.alerts_24h, o.trend.alerts_prev_24h, "alerts"); tr("#ov-ct", o.trend.cases_pct, o.trend.cases_24h, o.trend.cases_prev_24h, "cases"); }
    $("#lastComments").innerHTML = (o.last_comments || []).map((c) => `<li><a href="#inc-${c.incident_id}">INC-${c.incident_id}</a> <b>${esc(c.analyst)}</b>
      <small class="muted">${ago(c.ts)}ที่แล้ว</small><div>${esc(c.text.slice(0, 160))}</div></li>`).join("") || '<li class="muted">ยังไม่มีความเห็น</li>';
    $("#recentCases tbody").innerHTML = (o.recent_cases || []).map((c) => `<tr class="clk" data-inc="${c.id}"><td class="a-title">${c.real ? '<span class="real">REAL</span>' : ""}${esc(c.name)}</td>
      <td><span class="prio ${esc(c.priority)}">${esc(c.priority)}</span></td><td>${c.type === "manual" ? "analyst" : "✦ ระบบ"}</td>
      <td>${ago(c.first_ts)}ที่แล้ว</td><td><span class="dt">${c.type === "manual" ? "Manual" : "Automatic"}</span></td></tr>`).join("") || '<tr><td colspan="5" class="muted">ยังไม่มี case</td></tr>';
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
    const now = Date.now() / 1000, edit = can("cases.update");
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
  const ro = !can("cases.update");
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
  loadCases(); loadSavedQueries(); loadNotebooks(); loadCatalog(); loadCaseMeta(); loadIntakes(); loadEntities(); loadAssets();
  loadIntel(); loadFeeds(); loadIntegrations(); loadCollections(); loadGraphs(); loadWsSettings(); loadApprovals(); }
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
    const acts = (a) => [can("alerts.acknowledge") && ["new", "open"].includes(a.status) ? '<button class="mini" data-aa="acknowledge" title="รับทราบ">รับทราบ</button>' : "",
      can("alerts.assign") || can("alerts.acknowledge") ? '<button class="mini" data-aa="assign" title="มอบหมาย">มอบหมาย</button>' : "",
      can("alerts.escalate") && a.status !== "escalated" ? '<button class="mini" data-aa="escalate" title="ยกระดับเป็น case">ยกระดับ</button>' : "",
      can("alerts.close") ? (a.status === "closed" ? '<button class="mini" data-aa="reopen">เปิดใหม่</button>' : '<button class="mini" data-aa="close">ปิด</button>') : ""].join("");
    $("#alTbl tbody").innerHTML = r.items.map((a) => `<tr data-inc="${a.incident_id ?? ""}" data-title="${esc(a.title)}" data-host="${esc(a.host || "")}" class="${a.incident_id ? "clk" : ""}">
      <td class="num"><span class="occ sev-${esc(a.severity)}">${a.occurrences}</span></td>
      <td>${a.incident_id ? `<a href="#inc-${a.incident_id}">INC-${a.incident_id}</a>` : '<span class="muted">—</span>'}</td>
      <td title="${esc(t2(a.first_ts))} → ${esc(t2(a.last_ts))}">${esc(new Date(a.last_ts * 1000).toLocaleString("th-TH", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }))}</td>
      <td class="a-title">${a.real ? '<span class="real">REAL</span>' : ""}${esc(a.title)}<div class="sub">${esc(a.technique || "")}${a.rule ? " · " + esc(a.rule) : ""}</div></td>
      <td><span class="ist ${esc(a.status)}">${esc(ALERT_ST[a.status] || a.status)}</span>${a.reoccurred ? '<div class="sub">เกิดซ้ำหลังปิด</div>' : ""}</td>
      <td class="al-acts">${acts(a)}</td>
      <td>${a.verdict ? `<span class="vd ${esc(a.verdict)}">${esc(VERDICT_TH[a.verdict] || a.verdict)}</span>` : '<span class="muted">—</span>'}</td>
      <td>${a.assignee ? esc(a.assignee) : '<span class="muted">—</span>'}</td>
      <td class="mono">${esc(a.host || "-")}</td>
      <td>${urgRing(a.urgency)}</td>
      <td><span class="dt">${esc(a.detection_type)}</span></td>
      <td>${esc(a.type || "-")}</td>
      <td>${a.threats.map((t) => `<span class="thr">${esc(t)}</span>`).join(" ") || '<span class="muted">—</span>'}</td></tr>`).join("")
      || '<tr><td colspan="13" class="muted">ไม่พบ alert ตามเงื่อนไข</td></tr>';
  } catch (e) { $("#alTbl tbody").innerHTML = `<tr><td colspan="12" class="err">${esc(e.message)}</td></tr>`; }
}
let alT;
$("#alQ").addEventListener("input", () => { clearTimeout(alT); alT = setTimeout(() => { AL.page = 1; loadAlertsList(); }, 300); });
["#alStatus", "#alSev", "#alSort", "#alReal", "#alHours"].forEach((s) => { $(s).onchange = () => { AL.page = 1; loadAlertsList(); }; });
$("#alPrev").onclick = () => { AL.page--; loadAlertsList(); };
$("#alNext").onclick = () => { AL.page++; loadAlertsList(); };
$("#alTbl").addEventListener("click", (ev) => {
  if (ev.target.closest("a, button")) return;
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
    const edit = can("integrations.manage");
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
  f.template_id.innerHTML = '<option value="">— ไม่ใช้ template —</option>' + (WS.templates || []).map((t) => `<option value="${t.id}">${esc(t.name)}</option>`).join("");
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
      tags: splitList(f.tags.value), hosts: splitList(f.hosts.value), custom_fields: cfValues($("#caseCf")),
      ...(f.template_id.value ? { template_id: Number(f.template_id.value) } : {}) }) });
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
  const ro = !can("cases.update");
  document.querySelectorAll("#caseBar [data-perm-dis], #cbFields [data-cf]").forEach((el) => { el.disabled = ro; });
  $("#cbImpact").innerHTML = '<b class="small">Impact</b> ' + (inc.hosts || []).filter(Boolean).map((h) => {
    const lv = CS.crit[h] || 0;
    return `<span class="asset l${lv}"><span class="mono">${esc(h)}</span><select data-host="${esc(h)}" ${can("assets.manage") ? "" : "disabled"} aria-label="ความสำคัญของ ${esc(h)}" title="Asset criticality">${CRIT_TH.map((t, i) => `<option value="${i}" ${i === lv ? "selected" : ""}>${t}</option>`).join("")}</select></span>`;
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
      ${can("query.run") ? '<button class="ghost sm qb-del" title="ลบ">×</button>' : ""}<div class="mono small muted">${esc(x.query.replace(/\s+/g, " ").slice(0, 90))}</div></li>`).join("")
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
  const ro = !can("notebooks.write") || n.deleted;
  $("#nbMain").innerHTML = `<div class="nb-head"><input id="nbTitle" value="${esc(n.title)}" maxlength="200" ${ro ? "disabled" : ""} aria-label="ชื่อ notebook">
    <span class="muted small">${n.case_id ? `<a href="#inc-${n.case_id}">INC-${n.case_id}</a> · ` : ""}แก้ไขล่าสุดโดย ${esc(n.updated_by)} · ${esc(t2(n.updated_at))}</span></div>
    <div class="seg nb-mode"><button data-m="edit" class="${NB.preview ? "" : "on"}" ${ro ? "disabled" : ""}>แก้ไข</button><button data-m="view" class="${NB.preview ? "on" : ""}">แสดงผล</button></div>
    <textarea id="nbBody" class="code" rows="16" ${ro ? "disabled" : ""} ${NB.preview ? "hidden" : ""} aria-label="เนื้อหา">${esc(n.content)}</textarea>
    <div id="nbView" class="nb-view" ${NB.preview ? "" : "hidden"}>${md(n.content) || '<p class="muted">ว่าง — กด “แก้ไข”</p>'}</div>
    <div class="task-bar">${n.deleted ? `<button id="nbRestore" data-perm="notebooks.write">กู้คืน</button>` : `${ro ? "" : '<button id="nbSaveBtn">บันทึก</button><button id="nbTrash" class="ghost">ย้ายไปถังขยะ</button>'}`}
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
  const iocs = d.active_iocs || {}, tot = Object.values(iocs).reduce((a, b) => a + b, 0);
  setKpi("#catIocs", tot >= 1e6 ? (tot / 1e6).toFixed(1) + "M" : tot >= 1e4 ? (tot / 1e3).toFixed(1) + "K" : tot.toLocaleString());
  $("#catIocsS").textContent = `ThreatFox ${iocs.threatfox || 0} · Feodo ${iocs.feodo || 0} · KEV ${iocs.kev || 0} · agentic ${iocs.agentic || 0}`;
  const allSrc = [...new Set(d.rules.flatMap((r) => r.log_sources))].sort();
  CAT.sel = CAT.sel || new Set();
  $("#catSrcs").innerHTML = allSrc.filter((x) => CAT.mode !== "configured" || d.configured_sources.includes(x)).map((x) => `<label class="chk">
    <input type="checkbox" value="${esc(x)}" ${CAT.sel.has(x) ? "checked" : ""}> ${esc(x)} ${d.configured_sources.includes(x) ? '<span class="ok-ink">✓</span>' : ""}
    <small class="muted">${d.rules.filter((r) => r.log_sources.includes(x)).length}</small></label>`).join("");
  const max = Math.max(1, ...d.mitre.flatMap((m) => m.techniques.map((t) => t.alerts_7d)));
  const order = (t) => { const i = TACTIC_ORDER.indexOf(t); return i < 0 ? 99 : i; };
  $("#catHeat").innerHTML = [...d.mitre].sort((a, b) => order(a.tactic) - order(b.tactic)).map((m) => `<div class="heat-col"><div class="heat-h" title="${esc(m.tactic)}">${esc(m.tactic)}</div>
    ${m.techniques.map((t) => `<div class="heat-c" style="--a:${(0.12 + 0.88 * t.alerts_7d / max).toFixed(2)}" title="${esc(t.id)} ${esc(t.name)} · ${t.alerts_7d} alerts 7 วัน">${esc(t.id)}</div>`).join("")}</div>`).join("");
  const q = $("#catQ").value.trim().toLowerCase(), cat = $("#catCat").value, en = $("#catEn").value;
  let rows = d.rules.filter((r) => (!q || `${r.id} ${r.title} ${r.technique} ${r.technique_name}`.toLowerCase().includes(q))
    && (!cat || r.category === cat) && (en === "" || String(Number(r.enabled)) === en)
    && (!CAT.sel.size || r.log_sources.some((x) => CAT.sel.has(x)))
    && (CAT.mode !== "configured" || r.log_sources.some((x) => d.configured_sources.includes(x))));
  const s = $("#catSort").value;
  rows.sort(s === "id" ? (a, b) => a.id.localeCompare(b.id) : s === "quality" ? (a, b) => (a.quality ?? 101) - (b.quality ?? 101) : (a, b) => b.alerts_7d - a.alerts_7d);
  const edit = can("rules.publish");
  $("#catList").innerHTML = rows.map((r) => `<div class="cat-rule ${r.enabled ? "" : "off"}">
    <div class="cr-main"><div class="cr-t"><span class="mono">${esc(r.id)}</span> ${esc(r.title)}</div>
      <div class="cr-m"><span class="sev" style="--sevc:var(--${esc(r.severity)})">${esc(r.severity)}</span> <span class="dt">${esc(r.category)}</span>
        <span class="muted small">${esc(r.technique || "")} ${esc(r.technique_name && r.technique_name !== r.technique ? r.technique_name : "")} · ${esc(r.tactic || "")}</span>
        ${r.exports.map((x) => `<span class="thr" title="${esc(x.file)}">${esc(x.format.split(" ")[0])}</span>`).join(" ")}</div>
      <div class="cr-m small muted">ต้องใช้ log: ${r.log_sources.map((x) => `<span class="${d.configured_sources.includes(x) ? "ok-ink" : ""}">${esc(x)}</span>`).join(", ")}
        <button class="link cr-notify" data-rule="${esc(r.id)}" title="สร้างกฎแจ้งเตือนสำหรับ rule นี้">🔔 แจ้งเตือนเมื่อเจอ</button></div></div>
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

$("#catSrcs").addEventListener("change", (ev) => { const cb = ev.target.closest("input"); if (!cb) return; cb.checked ? CAT.sel.add(cb.value) : CAT.sel.delete(cb.value); renderCatalog(); });
$("#catSrcMode").addEventListener("click", (ev) => {
  const b = ev.target.closest("button"); if (!b) return;
  CAT.mode = b.dataset.m; b.parentElement.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); renderCatalog();
});
$("#catList").addEventListener("click", (ev) => {
  const b = ev.target.closest(".cr-notify"); if (!b) return;
  if (!can("integrations.manage")) { alert("ต้องมีสิทธิ์ integrations.manage เพื่อสร้างกฎแจ้งเตือน"); return; }
  openRule(null);
  const f = $("#nrForm");
  f.name.value = `แจ้งเตือนเมื่อ ${b.dataset.rule} ทำงาน`; f.rule_prefixes.value = b.dataset.rule; f.min_severity.value = "info";
});

// ---------- intakes ----------
const IN = { days: 1, items: [], ents: [] };
const FMT_TH = { auto: "auto", native: "Native JSON", ecs: "Elastic ECS", defender: "Microsoft Defender", access_log: "Web access log" };
const big = (n) => n >= 1e6 ? (n / 1e6).toFixed(2) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n);
async function loadIntakes() {
  try {
    const r = await api("/api/soc/intakes?days=" + IN.days);
    IN.items = r.intakes;
    $("#nb-intake").textContent = r.intakes.filter((i) => !i.disabled).length;
    const edit = can("ingest.sources.manage");
    $("#inList").innerHTML = r.intakes.map((i) => `<div class="intake ${i.disabled ? "off" : ""}" data-id="${i.id}">
      <div class="in-main"><b>${esc(i.name)}</b>${i.disabled ? ' <span class="ist">disabled</span>' : ""}
        <div class="cr-m"><span class="dt">${esc(FMT_TH[i.format] || i.format)}</span>${i.entity ? `<span class="thr">🏢 ${esc(i.entity)}</span>` : ""}
          ${i.mode === "monitor" ? '<span class="vd">monitor · ไม่สร้าง alert</span>' : ""}
          <span class="mono small muted">${esc(i.key_hint || "")}</span></div></div>
      <div class="in-stat"><b class="${i.valid ? "acc" : ""}">${big(i.valid)}</b><small>Valid events</small></div>
      <div class="in-stat"><b class="${i.invalid ? "bad-ink" : ""}">${big(i.invalid)}</b><small>Invalid events</small></div>
      <div class="in-stat"><b class="${i.warning ? "warn-ink" : ""}">${big(i.warning)}</b><small>Events in warning</small></div>
      <div class="in-stat"><b class="small">${i.last_event_at ? ago(i.last_event_at) + "ที่แล้ว" : "—"}</b><small>ส่งล่าสุด</small></div>
      <div class="in-act">${edit ? `<select class="in-ent" aria-label="Entity ของ ${esc(i.name)}"><option value="">— entity —</option>${IN.ents.map((e) => `<option value="${e.id}" ${e.id === i.entity_id ? "selected" : ""}>${esc(e.name)}</option>`).join("")}</select>
        <button class="ghost sm in-rot">Rotate key</button><button class="ghost sm in-dis">${i.disabled ? "เปิดใช้" : "ปิดใช้"}</button>` : ""}</div></div>`).join("")
      || '<p class="muted">ยังไม่มี intake — สร้าง intake แล้วนำ key ไปใส่ใน log shipper (เช่น tools/ship_logs.py, Fluent Bit, Logstash http output)</p>';
  } catch (e) { $("#inList").innerHTML = `<p class="err">${esc(e.message)}</p>`; }
}
$("#inDays").addEventListener("click", (ev) => {
  const b = ev.target.closest("button"); if (!b) return;
  IN.days = Number(b.dataset.d); b.parentElement.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); loadIntakes();
});
function showKey(name, key) {
  $("#keyFor").textContent = name; $("#keyVal").textContent = key;
  $("#keyCurl").textContent = `curl -X POST ${location.origin}/api/soc/intake \\\n  -H "X-Intake-Key: ${key}" \\\n  --data-binary @events.ndjson`;
  $("#keyDlg").showModal();
}
$("#keyCopy").onclick = () => navigator.clipboard?.writeText($("#keyVal").textContent).then(() => { $("#keyCopy").textContent = "คัดลอกแล้ว ✓"; });
$("#inNew").onclick = async () => {
  await loadEntities();
  const f = $("#inForm"); f.reset(); $("#inErr").textContent = "";
  f.entity_id.innerHTML = '<option value="">— ไม่ระบุ —</option>' + IN.ents.map((e) => `<option value="${e.id}">${esc(e.name)}</option>`).join("");
  $("#inDlg").showModal();
};
$("#inForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const f = ev.target;
  try {
    const r = await api("/api/soc/intakes", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.name.value.trim(), format: f.format.value, entity_id: f.entity_id.value ? Number(f.entity_id.value) : null }) });
    $("#inDlg").close(); loadIntakes(); loadEntities(); showKey(r.name, r.key);
  } catch (e) { $("#inErr").textContent = e.message; }
});
async function patchIntake(id, body) {
  return api(`/api/soc/intakes/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
$("#inList").addEventListener("click", async (ev) => {
  const row = ev.target.closest(".intake"); if (!row) return;
  const it = IN.items.find((x) => x.id === Number(row.dataset.id));
  try {
    if (ev.target.closest(".in-rot") && confirm(`สร้าง key ใหม่ให้ ${it.name}? key เดิมจะใช้ไม่ได้ทันที`)) { const r = await patchIntake(it.id, { rotate_key: true }); showKey(it.name, r.key); loadIntakes(); }
    if (ev.target.closest(".in-dis")) { await patchIntake(it.id, { disabled: !it.disabled }); loadIntakes(); }
  } catch (e) { alert(e.message); }
});
$("#inList").addEventListener("change", async (ev) => {
  const sel = ev.target.closest(".in-ent"); if (!sel) return;
  const id = Number(sel.closest(".intake").dataset.id);
  try { await patchIntake(id, sel.value ? { entity_id: Number(sel.value) } : { clear_entity: true }); loadIntakes(); loadEntities(); } catch (e) { alert(e.message); }
});

// ---------- entities ----------
async function loadEntities() {
  try {
    IN.ents = (await api("/api/soc/entities")).entities;
    const edit = can("ingest.sources.manage");
    $("#enTbl tbody").innerHTML = IN.ents.map((e) => `<tr data-id="${e.id}"><td><span class="who">${esc(e.name[0].toUpperCase())}</span><b>${esc(e.name)}</b></td>
      <td class="a-title">${esc(e.description || "")}</td><td class="num">${e.intakes}</td>
      <td><span class="${e.mode === "monitor" ? "vd" : "dt"}">${e.mode === "monitor" ? "monitor (log only)" : "automatic"}</span></td>
      <td>${edit ? '<button class="ghost sm en-edit">แก้ไข</button>' : ""} <button class="ghost sm en-in">ดู intakes</button></td></tr>`).join("")
      || '<tr><td colspan="5" class="muted">ยังไม่มี entity — เช่น แยกตามบริษัทลูก สาขา หรือหน่วยธุรกิจ</td></tr>';
  } catch (e) { $("#enTbl tbody").innerHTML = `<tr><td colspan="5" class="err">${esc(e.message)}</td></tr>`; }
}
const EN = { edit: null };
function openEntity(e) {
  EN.edit = e; const f = $("#entForm"); f.reset(); $("#enErr").textContent = "";
  $("#enDlgTitle").textContent = e ? `แก้ไข ${e.name}` : "New entity";
  if (e) { f.name.value = e.name; f.description.value = e.description || ""; f.mode.value = e.mode; }
  $("#enDlg").showModal();
}
$("#enNew").onclick = () => openEntity(null);
$("#entForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const f = ev.target, body = { name: f.name.value.trim(), description: f.description.value.trim(), mode: f.mode.value };
  try {
    await api(EN.edit ? `/api/soc/entities/${EN.edit.id}` : "/api/soc/entities", { method: EN.edit ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    $("#enDlg").close(); loadEntities(); loadIntakes();
  } catch (e) { $("#enErr").textContent = e.message; }
});
$("#enTbl").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr[data-id]"); if (!tr) return;
  const e = IN.ents.find((x) => x.id === Number(tr.dataset.id));
  if (ev.target.closest(".en-edit")) openEntity(e);
  if (ev.target.closest(".en-in")) {
    document.querySelectorAll("#inList .intake").forEach((row) => { row.classList.toggle("hl", IN.items.find((i) => i.id === Number(row.dataset.id))?.entity_id === e.id); });
    $("#intakesCard").scrollIntoView({ behavior: "smooth" });
  }
});

// ---------- assets ----------
const AS = { type: "", page: 1, items: [] };
const TYPE_TH = { host: "🖥 Host", account: "👤 Account/User", ai_agent: "🤖 AI agent" };
async function loadAssets() {
  const p = new URLSearchParams({ page: AS.page, size: 50, sort: $("#asSort").value, revoked: $("#asRevoked").checked });
  if (AS.type) p.set("type", AS.type);
  if ($("#asReal").checked) p.set("real_only", "true");
  if ($("#asQ").value.trim()) p.set("q", $("#asQ").value.trim());
  try {
    const r = await api("/api/soc/assets?" + p);
    AS.items = r.items; AS.page = r.page;
    const bt = r.by_type, all = (bt.host || 0) + (bt.account || 0) + (bt.ai_agent || 0);
    $("#asAll").textContent = all; $("#asHost").textContent = bt.host || 0; $("#asAccount").textContent = bt.account || 0; $("#asAgent").textContent = bt.ai_agent || 0;
    $("#nb-asset").textContent = all;
    $("#asPage").textContent = `หน้า ${r.page} / ${r.pages} · ${r.total.toLocaleString()} รายการ`;
    $("#asPrev").disabled = r.page <= 1; $("#asNext").disabled = r.page >= r.pages;
    const edit = can("assets.manage");
    $("#asTbl tbody").innerHTML = r.items.map((a, i) => `<tr data-i="${i}"><td class="mono">${a.real ? "" : '<span class="muted small">(จำลอง) </span>'}${esc(a.name)}${a.description ? `<div class="sub">${esc(a.description)}</div>` : ""}</td>
      <td><span class="dt">${TYPE_TH[a.type] || esc(a.type)}</span>${a.manual ? ' <span class="muted small">manual</span>' : ""}</td>
      <td>${(a.tags || []).map((t) => `<span class="thr">${esc(t)}</span>`).join(" ") || '<span class="muted">—</span>'}</td>
      <td class="small">${(a.sources || []).slice(0, 3).map(esc).join(", ")}${(a.sources || []).length > 3 ? ` +${a.sources.length - 3}` : ""}</td>
      <td>${a.first_seen ? esc(t2(a.first_seen)) : "—"}</td><td>${a.last_seen ? ago(a.last_seen) + "ที่แล้ว" : "—"}</td>
      <td class="num">${a.events.toLocaleString()}</td><td class="num">${a.alerts ? `<b class="bad-ink">${a.alerts}</b>` : 0}</td>
      <td><span class="crit c${a.criticality}" title="Criticality ${a.criticality}/5">${a.criticality}</span></td>
      <td>${edit ? '<button class="ghost sm as-edit">แก้ไข</button>' : ""}</td></tr>`).join("")
      || '<tr><td colspan="10" class="muted">ยังไม่พบ asset — จะถูกเพิ่มอัตโนมัติเมื่อมี log เข้ามา</td></tr>';
  } catch (e) { $("#asTbl tbody").innerHTML = `<tr><td colspan="10" class="err">${esc(e.message)}</td></tr>`; }
}
$("#asTabs").addEventListener("click", (ev) => {
  const b = ev.target.closest("button"); if (!b) return;
  AS.type = b.dataset.t; AS.page = 1; b.parentElement.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); loadAssets();
});
let asT;
$("#asQ").addEventListener("input", () => { clearTimeout(asT); asT = setTimeout(() => { AS.page = 1; loadAssets(); }, 300); });
$("#asSort").onchange = $("#asRevoked").onchange = $("#asReal").onchange = () => { AS.page = 1; loadAssets(); };
$("#asPrev").onclick = () => { AS.page--; loadAssets(); };
$("#asNext").onclick = () => { AS.page++; loadAssets(); };
function openAsset(a) {
  const f = $("#asForm"); f.reset(); $("#asErr").textContent = "";
  $("#asDlgTitle").textContent = a ? `แก้ไข ${a.name}` : "New asset";
  f.type.disabled = f.name.disabled = !!a;
  if (a) { f.type.value = a.type; f.name.value = a.name; f.criticality.value = String(a.criticality || 0); f.tags.value = (a.tags || []).join(", "); f.description.value = a.description || ""; f.revoked.checked = !!a.revoked; }
  $("#asDlg").showModal();
}
$("#asNew").onclick = () => openAsset(null);
$("#asTbl").addEventListener("click", (ev) => { if (ev.target.closest(".as-edit")) openAsset(AS.items[Number(ev.target.closest("tr").dataset.i)]); });
$("#asForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const f = ev.target;
  try {
    await api("/api/soc/assets", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      type: f.type.value, name: f.name.value.trim(), criticality: Number(f.criticality.value), tags: splitList(f.tags.value),
      description: f.description.value.trim(), revoked: f.revoked.checked }) });
    $("#asDlg").close(); loadAssets(); loadCaseMeta();
  } catch (e) { $("#asErr").textContent = e.message; }
});
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) { loadIntakes(); loadAssets(); } }, 60000);


// ---------- VirusTotal API v3 ----------
const VT_TH = { malicious: "อันตราย", suspicious: "น่าสงสัย", clean: "ไม่พบการตรวจจับ", unknown: "ไม่มีข้อมูล" };
const VT_KIND = { file: "ไฟล์ (hash)", url: "URL", domain: "โดเมน", ip: "IP" };
function vtDetail(r) {
  const d = [];
  if (r.kind === "file") d.push(r.name, r.type, r.size ? (r.size / 1024).toFixed(0) + " KB" : null, r.first_seen ? "พบครั้งแรก " + r.first_seen : null);
  if (r.kind === "ip") d.push(r.as_owner, r.asn ? "AS" + r.asn : null, r.country, r.network);
  if (r.kind === "domain") d.push(r.registrar, r.created ? "จดทะเบียน " + r.created : null, (r.categories || []).join(", "));
  if (r.kind === "url") d.push(r.title, r.final_url && r.final_url !== r.indicator ? "→ " + r.final_url : null, (r.categories || []).join(", "));
  return d.filter(Boolean).map(esc).join(" · ");
}
function vtCard(r, opts = {}) {
  const t = (x) => esc(x ?? "");
  if (r.error) return `<div class="vt-row"><span class="mono">${t(r.indicator)}</span> <span class="${r.error === "disabled" ? "muted" : "err"}">${t(r.message)}</span></div>`;
  const local = [];
  if (r.in_intel) local.push(`อยู่ใน Intelligence ของเรา (${t(r.in_intel.source)}${r.in_intel.threat ? " · " + t(r.in_intel.threat) : ""})`);
  const s = r.sightings;
  if (s && (s.logs || s.alerts)) local.push(`<b class="bad-ink">เห็นใน tenant 7 วัน: ${s.logs} logs · ${s.alerts} alerts</b>${s.hosts.length ? " (" + t(s.hosts.join(", ")) + ")" : ""}`);
  const ratio = r.found ? `<b>${r.malicious}</b>/${r.engines} engines${r.suspicious ? ` · น่าสงสัย ${r.suspicious}` : ""}` : "";
  return `<div class="vt-row">
    <div class="vt-head"><span class="verdict ${t(r.verdict)}">${t(VT_TH[r.verdict] || r.verdict)}</span>
      <span class="kindtag">${t(VT_KIND[r.kind] || r.kind)}</span> <span class="mono vt-ind" title="${t(r.indicator)}">${t(r.indicator)}</span>
      ${ratio ? `<span class="vt-ratio">${ratio}</span>` : ""}
      ${r.reputation != null ? `<span class="muted small">reputation ${t(r.reputation)}</span>` : ""}
      ${r.threat_label ? `<span class="thr">${t(r.threat_label)}</span>` : ""}
      <a class="link small" href="${t(r.link)}" target="_blank" rel="noopener noreferrer">เปิดใน VirusTotal ↗</a>
      ${r.cached ? '<span class="muted small" title="ไม่ใช้โควตา">· จาก cache</span>' : ""}</div>
    ${r.found ? `<div class="small muted">${vtDetail(r)}${r.last_analysis ? ` · วิเคราะห์ล่าสุด ${t(r.last_analysis)}` : ""}</div>` : `<div class="small muted">${t(r.message)}</div>`}
    ${(r.flagged_by || []).length ? `<div class="small">ตรวจพบโดย: ${r.flagged_by.map((f) => `<span class="thr" title="${t(f.result)}">${t(f.engine)}</span>`).join(" ")}</div>` : ""}
    ${(r.tags || []).length ? `<div class="small muted">tags: ${r.tags.map(t).join(", ")}</div>` : ""}
    ${local.length ? `<div class="small">${local.join(" · ")}</div>` : ""}
    ${opts.scan && r.kind === "url" && can("threatintel.curate") ? `<button class="ghost sm vt-scan" data-url="${t(r.indicator)}">ส่งให้ VirusTotal สแกนใหม่…</button>` : ""}
  </div>`;
}
async function vtLookup() {
  const vals = $("#ciQ").value.split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
  const box = $("#vtOut"); box.hidden = false;
  if (!vals.length) { box.innerHTML = '<p class="muted">ใส่ hash, URL, domain หรือ IP ในช่องค้นหาก่อน (สูงสุด 10 ค่า)</p>'; return; }
  if (vals.length > 10) { box.innerHTML = `<p class="err">ตรวจได้ครั้งละไม่เกิน 10 ค่า (ใส่มา ${vals.length})</p>`; return; }
  box.innerHTML = '<p class="muted"><span class="spin"></span> กำลังถาม VirusTotal… (บัญชีฟรีได้ 4 ครั้ง/นาที ค่าที่เคยค้นจะมาจาก cache)</p>';
  try {
    const r = await api("/api/soc/vt/lookup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ indicators: vals }) });
    const u = r.usage;
    box.innerHTML = `<h4>VirusTotal <small class="muted">ใช้วันนี้ ${u.used_today}/${u.daily_quota} · นาทีนี้ ${u.used_last_minute}/${u.per_minute} · ค้นอย่างเดียว ไม่อัปโหลดไฟล์</small>
      <button class="ghost sm" id="vtClose">ปิด</button></h4>` + r.results.map((x) => vtCard(x, { scan: true })).join("");
  } catch (e) { box.innerHTML = `<p class="err">ไม่สำเร็จ: ${esc(e.message)}</p>`; }
}
$("#vtGo").onclick = vtLookup;
$("#vtOut").addEventListener("click", async (ev) => {
  if (ev.target.id === "vtClose") { $("#vtOut").hidden = true; return; }
  const b = ev.target.closest(".vt-scan"); if (!b) return;
  if (!confirm(`ส่ง URL นี้ให้ VirusTotal สแกน?\n\n${b.dataset.url}\n\nURL จะถูกเปิดเผยต่อชุมชน VirusTotal (ผู้ใช้อื่นค้นเจอได้) — ห้ามส่ง URL ที่มี token, ข้อมูลลูกค้า หรือระบบภายใน`)) return;
  b.disabled = true;
  try {
    const r = await api("/api/soc/vt/scan-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: b.dataset.url, confirm_public: true }) });
    b.outerHTML = `<span class="small muted">${esc(r.message)}</span>`;
  } catch (e) { b.disabled = false; alert(e.message); }
});
async function loadVtStatus() {
  try {
    const u = await api("/api/soc/vt/status");
    if (!u.enabled) { $("#vtGo").disabled = true; $("#vtGo").title = "ยังไม่ได้ตั้ง VT_API_KEY บนเซิร์ฟเวอร์ (ดู Integrations)"; }
  } catch (e) { /* no permission: the button is hidden by data-perm */ }
}

// ---------- intelligence ----------
const CI = { page: 1, meta: null };
const TLP_CLS = { clear: "clear", green: "green", amber: "amber", "amber+strict": "amber", red: "red" };
async function loadIntel() {
  const p = new URLSearchParams({ page: CI.page, size: 25, min_conf: $("#ciConf").value });
  if ($("#ciQ").value.trim()) p.set("q", $("#ciQ").value.trim());
  if ($("#ciType").value) p.set("types", $("#ciType").value);
  if ($("#ciSrc").value) p.set("sources", $("#ciSrc").value);
  try {
    const r = await api("/api/soc/intel?" + p);
    if (!CI.meta) {
      CI.meta = r; loadVtStatus();
      $("#ciType").insertAdjacentHTML("beforeend", r.types.map((t) => `<option>${t}</option>`).join(""));
      $("#ciSrc").insertAdjacentHTML("beforeend", Object.entries(r.sources).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join(""));
    }
    CI.page = r.page;
    $("#nb-intel").textContent = big(r.indexed);
    $("#ciMeta").textContent = `${r.total.toLocaleString()} รายการ จาก ${r.indexed.toLocaleString()} indicators · ` +
      Object.entries(r.by_source).map(([k, n]) => `${r.sources[k] || k} ${n}`).join(" · ");
    $("#ciMissing").textContent = r.not_found.length ? `ไม่พบในฐานข้อมูล: ${r.not_found.join(", ")}` : "";
    $("#ciPage").textContent = `หน้า ${r.page} / ${r.pages}`;
    $("#ciPrev").disabled = r.page <= 1; $("#ciNext").disabled = r.page >= r.pages;
    $("#ciTbl tbody").innerHTML = r.items.map((i) => {
      const s = i.sightings;
      const seen = s && (s.logs || s.alerts) ? `<b class="bad-ink">${s.logs} logs · ${s.alerts} alerts</b><div class="sub">${esc(s.hosts.join(", "))}${s.last_seen ? " · ล่าสุด " + ago(s.last_seen) + "ที่แล้ว" : ""}</div>`
        : '<span class="muted">ไม่พบ</span>';
      return `<tr><td><span class="tlp ${TLP_CLS[i.tlp] || ""}">${esc(i.tlp.toUpperCase())}</span></td><td><span class="kindtag">${esc(i.type)}</span></td>
        <td class="mono ci-val" title="${esc(i.value)}">${esc(i.value)}</td>
        <td><span class="conf" style="--c:${i.confidence}" title="confidence ${i.confidence}">${i.confidence}</span></td>
        <td class="small">${i.reference ? `<a href="${esc(i.reference)}" target="_blank" rel="noopener noreferrer">${esc(i.source_name)}</a>` : esc(i.source_name)}</td>
        <td class="a-title small">${i.threat ? `<b>${esc(i.threat)}</b> ` : ""}${esc((i.description || "").slice(0, 120))}${(i.tags || []).map((t) => ` <span class="thr">${esc(t)}</span>`).join("")}</td>
        <td class="small">${esc(String(i.first_seen || "—").slice(0, 10))}</td><td class="small">${seen}</td></tr>`;
    }).join("") || '<tr><td colspan="8" class="muted">ไม่พบ indicator</td></tr>';
  } catch (e) { $("#ciTbl tbody").innerHTML = `<tr><td colspan="8" class="err">${esc(e.message)}</td></tr>`; }
}
$("#ciGo").onclick = () => { CI.page = 1; loadIntel(); };
$("#ciQ").addEventListener("keydown", (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") { CI.page = 1; loadIntel(); } });
["#ciType", "#ciSrc", "#ciConf"].forEach((x) => { $(x).onchange = () => { CI.page = 1; loadIntel(); }; });
$("#ciPrev").onclick = () => { CI.page--; loadIntel(); };
$("#ciNext").onclick = () => { CI.page++; loadIntel(); };
function openIocDlg(collectionId) {
  const f = $("#iocForm"); f.reset(); $("#iocErr").textContent = "";
  f.collection_id.innerHTML = '<option value="">— ไม่ระบุ —</option>' + (COL.items || []).map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join("");
  if (collectionId) f.collection_id.value = String(collectionId);
  $("#iocDlg").showModal();
}
$("#iocAdd").onclick = () => openIocDlg(null);
$("#iocFile").onchange = async (ev) => {
  const file = ev.target.files[0]; if (!file) return;
  if (file.size > 2_000_000) { $("#iocErr").textContent = "ไฟล์ใหญ่เกิน 2 MB"; return; }
  const text = await file.text();
  // CSV: take the first column of each row (skip a header named value/indicator/ioc)
  const vals = text.split(/\r?\n/).map((l) => l.split(",")[0].replace(/^"|"$/g, "").trim()).filter((v) => v && !/^(value|indicator|ioc|observable)$/i.test(v));
  const f = $("#iocForm"); f.values.value = (f.values.value ? f.values.value + "\n" : "") + vals.join("\n");
  $("#iocErr").textContent = `อ่านจากไฟล์ ${vals.length} บรรทัด`;
};
$("#iocForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  const f = ev.target;
  try {
    const r = await api("/api/soc/iocs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      values: f.values.value, tlp: f.tlp.value, confidence: Number(f.confidence.value || 80), threat: f.threat.value.trim(),
      description: f.description.value.trim(), tags: splitList(f.tags.value), severity: f.severity.value || null,
      expires_days: f.expires_days.value ? Number(f.expires_days.value) : null,
      collection_id: f.collection_id.value ? Number(f.collection_id.value) : null, kill_chain_phase: f.kill_chain_phase.value }) });
    if (r.invalid.length && !confirm(`เพิ่มแล้ว ${r.added} รายการ\nไม่ใช่ IOC ที่รองรับ ${r.invalid.length} รายการ: ${r.invalid.slice(0, 5).join(", ")}\nปิดหน้าต่าง?`)) return;
    $("#iocDlg").close(); $("#ciSrc").value = "tenant"; CI.page = 1; loadIntel(); loadFeeds(); loadCollections(true);
  } catch (e) { $("#iocErr").textContent = e.message; }
});

// ---------- outgoing feeds ----------
const FD = { items: [], edit: null };
const FMT_OUT = { stix: "STIX 2.1", text: "Text", csv: "CSV" };
async function loadFeeds() {
  try {
    FD.items = (await api("/api/soc/feeds")).feeds;
    const edit = can("threatintel.curate");
    $("#fdTbl tbody").innerHTML = FD.items.map((f) => `<tr data-id="${f.id}"><td><b>${esc(f.name)}</b><div class="sub">${esc(f.description || "")} <span class="mono">${esc(f.key_hint)}</span></div></td>
      <td><span class="dt">${FMT_OUT[f.format]}</span></td>
      <td class="small">${f.types.length ? esc(f.types.join(", ")) : "ทุกชนิด"} · ${f.sources.length ? esc(f.sources.join(", ")) : "ทุกแหล่ง"} · conf ≥ ${f.min_confidence} · TLP ≤ ${esc(f.max_tlp.toUpperCase())}</td>
      <td class="num">${f.would_export.toLocaleString()}</td>
      <td class="small">${f.last_pull ? `${ago(f.last_pull)}ที่แล้ว · ${f.pulls} ครั้ง<div class="sub mono">${esc(f.last_pull_ip || "")}</div>` : '<span class="muted">ยังไม่เคยถูกดึง</span>'}</td>
      <td>${f.enabled ? '<span class="vd true_positive" style="background:var(--ok-bg);color:var(--ok-ink)">เปิด</span>' : '<span class="ist">ปิด</span>'}</td>
      <td>${edit ? '<button class="ghost sm fd-edit">แก้ไข</button> <button class="ghost sm fd-rot">สร้าง URL ใหม่</button>' : ""}</td></tr>`).join("")
      || '<tr><td colspan="7" class="muted">ยังไม่มี feed — เช่น สร้าง feed แบบ Text ให้ FortiGate ใช้เป็น External Block List</td></tr>';
  } catch (e) { $("#fdTbl tbody").innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`; }
}
function fdBody() {
  const f = $("#fdForm");
  return { name: f.name.value.trim(), description: f.description.value.trim(), format: f.format.value, max_tlp: f.max_tlp.value,
    min_confidence: Number(f.min_confidence.value || 0), sort: f.sort.value, max_size: Number(f.max_size.value || 2000), enabled: f.enabled.checked,
    types: [...f.querySelectorAll("#fdTypes input:checked")].map((x) => x.value), sources: [...f.querySelectorAll("#fdSrcs input:checked")].map((x) => x.value) };
}
async function openFeed(feed) {
  FD.edit = feed;
  if (!CI.meta) await loadIntel();
  const f = $("#fdForm"); f.reset(); $("#fdErr").textContent = ""; $("#fdPreview").textContent = "";
  $("#fdDlgTitle").textContent = feed ? `แก้ไข ${feed.name}` : "New feed";
  $("#fdTypes").innerHTML = CI.meta.types.map((t) => `<label class="chk"><input type="checkbox" value="${t}" ${feed?.types.includes(t) ? "checked" : ""}> ${t}</label>`).join("");
  $("#fdSrcs").innerHTML = Object.entries(CI.meta.sources).map(([k, v]) => `<label class="chk"><input type="checkbox" value="${k}" ${feed?.sources.includes(k) ? "checked" : ""}> ${esc(v)}</label>`).join("");
  if (feed) for (const k of ["name", "description", "format", "max_tlp", "min_confidence", "sort", "max_size"]) f[k].value = feed[k];
  if (feed) f.enabled.checked = feed.enabled;
  $("#fdDlg").showModal();
}
function showFeedUrl(name, url) {
  $("#keyFor").textContent = name; $("#keyVal").textContent = url;
  $("#keyDlg h2").firstChild.textContent = "Feed URL "; $("#keyExLabel").textContent = "ทดสอบ / ตั้งค่าในไฟร์วอลล์:"; $("#keyCopy").textContent = "คัดลอก";
  $("#keyCurl").textContent = `curl -s "${url}" | head\n\nFortiGate: Security Fabric → External Connectors → Threat Feeds → IP Address / Domain Name\n  URI of external resource = URL ด้านบน (ใช้ feed แบบ Text)`;
  $("#keyDlg").showModal();
}
$("#fdNew").onclick = () => openFeed(null);
$("#fdPrev").onclick = async () => {
  try {
    const r = await api("/api/soc/feeds/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...fdBody(), name: fdBody().name || "preview" }) });
    $("#fdPreview").innerHTML = `จะส่งออก <b>${r.count.toLocaleString()}</b> รายการ (${Object.entries(r.by_type).map(([k, n]) => `${k} ${n}`).join(", ") || "-"}) · ตัวอย่าง: <span class="mono">${r.sample.slice(0, 5).map((i) => esc(i.value)).join(", ")}</span>`;
  } catch (e) { $("#fdPreview").textContent = e.message; }
};
$("#fdForm").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value !== "save") return;
  ev.preventDefault();
  try {
    const r = await api(FD.edit ? `/api/soc/feeds/${FD.edit.id}` : "/api/soc/feeds", { method: FD.edit ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(fdBody()) });
    $("#fdDlg").close(); loadFeeds(); loadIntegrations();
    if (r.url) showFeedUrl(r.name, r.url);
  } catch (e) { $("#fdErr").textContent = e.message; }
});
$("#fdTbl").addEventListener("click", async (ev) => {
  const tr = ev.target.closest("tr[data-id]"); if (!tr) return;
  const feed = FD.items.find((x) => x.id === Number(tr.dataset.id));
  if (ev.target.closest(".fd-edit")) openFeed(feed);
  if (ev.target.closest(".fd-rot") && confirm(`สร้าง URL ใหม่ให้ ${feed.name}? URL เดิมจะใช้ไม่ได้ทันที`)) {
    try {
      const body = Object.fromEntries(["name", "description", "format", "max_tlp", "min_confidence", "sort", "max_size", "enabled", "types", "sources"].map((k) => [k, feed[k]]));
      const r = await api(`/api/soc/feeds/${feed.id}?rotate_key=true`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      loadFeeds(); showFeedUrl(feed.name, r.url);
    } catch (e) { alert(e.message); }
  }
});
// the intake-key dialog is shared: restore its title when used for intakes
const _showKey = showKey;
showKey = function (name, key) {
  $("#keyDlg h2").firstChild.textContent = "Intake key "; $("#keyExLabel").textContent = "ตัวอย่างการส่ง log:"; $("#keyCopy").textContent = "คัดลอก";
  _showKey(name, key);
};

// ---------- integrations ----------
const IG = { items: [], meta: null };
const IG_ST = { configured: "ตั้งค่าแล้ว", active: "ทำงานอยู่", built_in: "มีในระบบ", available: "พร้อมให้ตั้งค่า", error: "เชื่อมต่อไม่ได้" };
const IG_ICON = { intake: "📥", feed_in: "🛰", feed_out: "📤", notify: "🔔", enrich: "🔎", ai: "✦", export: "🧾" };
async function loadIntegrations() {
  try {
    const r = await api("/api/soc/integrations");
    IG.items = r.integrations;
    if (!IG.meta) {
      IG.meta = r;
      const chk = (id, entries) => { $(id).innerHTML = entries.map(([v, t]) => `<label class="chk"><input type="checkbox" value="${esc(v)}"> ${esc(t)}</label>`).join(""); };
      chk("#igStatus", Object.entries(IG_ST));
      chk("#igCat", r.categories.map((c) => [c, c]));
      chk("#igType", Object.entries(r.content_types));
    }
    renderIntegrations();
  } catch (e) { $("#igGrid").innerHTML = `<p class="err">${esc(e.message)}</p>`; }
}
function renderIntegrations() {
  const sel = (id) => new Set([...document.querySelectorAll(`${id} input:checked`)].map((x) => x.value));
  const st = sel("#igStatus"), cat = sel("#igCat"), ty = sel("#igType"), q = $("#igQ").value.trim().toLowerCase();
  const rows = IG.items.filter((i) => (!st.size || st.has(i.status)) && (!cat.size || cat.has(i.category)) && (!ty.size || ty.has(i.content_type))
    && (!q || `${i.name} ${i.description} ${i.category}`.toLowerCase().includes(q)));
  $("#igGrid").innerHTML = rows.map((i) => `<div class="ig-card st-${i.status}"><div class="ig-h"><span class="ig-ico">${IG_ICON[i.content_type] || "•"}</span><b>${esc(i.name)}</b></div>
    <div class="cr-m"><span class="dt">${esc(i.category)}</span><span class="thr">${esc(i.content_type_name)}</span></div>
    <p class="small">${esc(i.description)}</p>
    <div class="ig-f"><span class="ig-st">${esc(IG_ST[i.status] || i.status)}${i.count ? ` · ${i.count} intake` : ""}</span></div>
    <p class="small muted ig-how">${esc(i.setup)}</p></div>`).join("") || '<p class="muted">ไม่พบ</p>';
}
$("#igQ").addEventListener("input", renderIntegrations);
["#igStatus", "#igCat", "#igType"].forEach((x) => $(x).addEventListener("change", renderIntegrations));


// ---------- AI assistant ----------
const AIA = { log: [], busy: false };
function aiRender() {
  const body = $("#aiBody");
  if (!AIA.log.length) return;
  body.innerHTML = AIA.log.map((m) => m.role === "user" ? `<div class="ai-msg u">${esc(m.content)}</div>`
    : `<div class="ai-msg a">${m.pending ? '<span class="muted">กำลังค้นข้อมูล…</span>' : md(m.content)}
      ${(m.calls || []).length ? `<div class="ai-calls">${m.calls.map((c) => `<span class="thr ${c.ok ? "" : "off"}" title="${esc(JSON.stringify(c.input || {}))}">🔧 ${esc(c.tool)}</span>`).join(" ")}</div>` : ""}
      ${m.data ? aiData(m.data) : ""}
      ${m.meta ? `<div class="small muted">${esc(m.meta)}</div>` : ""}</div>`).join("");
  body.scrollTop = body.scrollHeight;
}
function aiData(d) {
  const rows = d.items || d.rows || [];
  if (!rows.length) return `<p class="muted small">ไม่พบข้อมูล${d.not_found?.length ? ": " + esc(d.not_found.join(", ")) : ""}</p>`;
  const cols = Object.keys(rows[0]).filter((k) => typeof rows[0][k] !== "object" || rows[0][k] === null).slice(0, 6);
  return `<div class="tbl-wrap"><table class="tbl small"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${rows.slice(0, 15).map((r) =>
    `<tr>${cols.map((c) => `<td>${esc(c.endsWith("ts") || c.endsWith("_seen") ? (r[c] ? t2(r[c]) : "") : r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
async function aiAsk(q) {
  if (AIA.busy || !q.trim()) return;
  AIA.busy = true;
  const hist = AIA.log.filter((m) => !m.pending && m.content).map((m) => ({ role: m.role, content: m.content })).slice(-8);
  AIA.log.push({ role: "user", content: q }, { role: "assistant", pending: true });
  aiRender();
  try {
    const r = await api("/api/assistant", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: q, history: hist }) });
    AIA.log[AIA.log.length - 1] = { role: "assistant", content: r.answer, calls: r.calls, data: r.source === "fallback" ? r.data : null,
      meta: r.source === "claude" ? `${r.model} · ${r.usage ? r.usage.input_tokens + "/" + r.usage.output_tokens + " tokens" : ""}${r.redacted ? " · ใช้นามแฝง" : ""}` : "" };
  } catch (e) { AIA.log[AIA.log.length - 1] = { role: "assistant", content: "ไม่สำเร็จ: " + e.message }; }
  AIA.busy = false; aiRender();
}
$("#aiBtn").onclick = async () => {
  const p = $("#aiPanel"); p.hidden = !p.hidden;
  if (!p.hidden && !$("#aiSugg").childElementCount) {
    try {
      const r = await api("/api/assistant/suggestions");
      $("#aiPanelStatus").textContent = r.ai.enabled ? `Claude ${r.ai.model}` : "โหมดคำสั่งพื้นฐาน (ยังไม่ตั้ง API key)";
      $("#aiSugg").innerHTML = r.suggestions.map((x) => `<button type="button" class="ghost">${esc(x)}</button>`).join("");
    } catch {}
  }
  if (!p.hidden) $("#aiQ").focus();
};
$("#aiClose").onclick = () => { $("#aiPanel").hidden = true; };
$("#aiSugg").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) aiAsk(b.textContent); });
$("#aiForm").addEventListener("submit", (ev) => { ev.preventDefault(); const q = $("#aiQ").value; $("#aiQ").value = ""; aiAsk(q); });
$("#aiQ").addEventListener("keydown", (ev) => { if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); $("#aiForm").requestSubmit(); } });

// ---------- IOC collections ----------
const COL = { items: [], cur: null, page: 1, q: "" };
const KC_TH = { reconnaissance: "Recon", weaponization: "Weaponize", delivery: "Delivery", exploitation: "Exploit", installation: "Install", "command-and-control": "C2", "actions-on-objectives": "Actions" };
async function loadCollections(refreshCurrent) {
  try {
    const r = await api("/api/soc/ioc-collections");
    COL.items = r.collections;
    $("#colList").innerHTML = r.collections.map((c) => `<li data-id="${c.id}" class="${COL.cur?.id === c.id ? "on" : ""}"><b>${esc(c.name)}</b>
      <small class="muted">${c.iocs} IOC · ${esc(c.created_by)}</small></li>`).join("") || '<li class="muted">ยังไม่มี collection</li>';
    if (refreshCurrent && COL.cur) openCollection(COL.items.find((c) => c.id === COL.cur.id));
  } catch (e) { $("#colList").innerHTML = `<li class="err">${esc(e.message)}</li>`; }
}
async function openCollection(c) {
  if (!c) return;
  COL.cur = c;
  document.querySelectorAll("#colList li").forEach((li) => li.classList.toggle("on", Number(li.dataset.id) === c.id));
  const p = new URLSearchParams({ collection_id: c.id, page: COL.page, size: 50 });
  if (COL.q) p.set("q", COL.q);
  let r;
  try { r = await api("/api/soc/iocs?" + p); } catch (e) { $("#colMain").innerHTML = `<p class="err">${esc(e.message)}</p>`; return; }
  const edit = can("threatintel.curate");
  $("#colMain").innerHTML = `<div class="col-head"><div><h3>${esc(c.name)}</h3><p class="muted small">${esc(c.description || "")}</p></div>
    <div class="task-bar">${edit ? '<button id="colImport" class="ghost sm">นำเข้า / เพิ่ม IOC</button>' : ""}
      <select id="colDays" aria-label="ช่วงเวลา"><option value="7">7 วัน</option><option value="30" selected>30 วัน</option><option value="90">90 วัน</option></select>
      <button id="colReport" class="sm">สร้าง telemetry report</button></div></div>
    <div id="colRep"></div>
    <input id="colQ" type="search" placeholder="ค้นหาใน collection" value="${esc(COL.q)}" aria-label="ค้นหา IOC">
    <div class="tbl-wrap tall"><table class="tbl"><thead><tr><th>ชนิด</th><th>Observable</th><th>Threat</th><th>Valid from</th><th>Valid until</th><th>Kill chain</th><th>รายละเอียด</th><th>TLP</th><th></th></tr></thead><tbody>
    ${r.iocs.map((i) => `<tr class="${i.revoked ? "revoked" : ""}"><td><span class="kindtag">${esc(i.type)}</span></td><td class="mono">${esc(i.value)}</td>
      <td>${esc(i.threat || "")}</td><td>${i.valid_from ? esc(t2(i.valid_from).split(" ")[0]) : esc(i.first_seen || "")}</td>
      <td>${i.expires ? esc(t2(i.expires).split(" ")[0]) : "—"}</td><td>${i.kill_chain_phase ? `<span class="thr">${esc(KC_TH[i.kill_chain_phase] || i.kill_chain_phase)}</span>` : "—"}</td>
      <td class="a-title small">${esc(i.description || "")}</td><td><span class="tlp ${TLP_CLS[i.tlp] || ""}">${esc(i.tlp.toUpperCase())}</span></td>
      <td>${edit ? `<button class="ghost sm ioc-rev" data-v="${esc(i.value)}" data-r="${i.revoked ? 0 : 1}">${i.revoked ? "เปิดใช้อีกครั้ง" : "Revoke"}</button>` : ""}</td></tr>`).join("")
      || '<tr><td colspan="9" class="muted">ยังไม่มี IOC ใน collection นี้</td></tr>'}</tbody></table></div>
    <div class="pager"><button id="colPrev" class="ghost sm" ${r.page <= 1 ? "disabled" : ""}>‹</button><span class="muted">หน้า ${r.page}/${r.pages} · ${r.total} IOC</span><button id="colNext" class="ghost sm" ${r.page >= r.pages ? "disabled" : ""}>›</button></div>`;
}
$("#colList").addEventListener("click", (ev) => { const li = ev.target.closest("li[data-id]"); if (li) { COL.page = 1; COL.q = ""; openCollection(COL.items.find((c) => c.id === Number(li.dataset.id))); } });
$("#colNew").onclick = async () => {
  const name = prompt("ชื่อ collection (เช่น ชื่อแคมเปญ / incident)"); if (!name) return;
  const description = prompt("รายละเอียด (ไม่บังคับ)") || "";
  try { const c = await api("/api/soc/ioc-collections", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, description }) });
    await loadCollections(); openCollection(COL.items.find((x) => x.id === c.id)); } catch (e) { alert(e.message); }
};
let colT;
$("#colMain").addEventListener("input", (ev) => { if (ev.target.id === "colQ") { clearTimeout(colT); colT = setTimeout(() => { COL.q = ev.target.value.trim(); COL.page = 1; openCollection(COL.cur).then(() => $("#colQ")?.focus()); }, 350); } });
$("#colMain").addEventListener("click", async (ev) => {
  const t = ev.target;
  if (t.id === "colImport") openIocDlg(COL.cur.id);
  if (t.id === "colPrev") { COL.page--; openCollection(COL.cur); }
  if (t.id === "colNext") { COL.page++; openCollection(COL.cur); }
  if (t.closest(".ioc-rev")) {
    try { await api("/api/soc/iocs/revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ values: [t.dataset.v], revoked: t.dataset.r === "1" }) }); openCollection(COL.cur); }
    catch (e) { alert(e.message); }
  }
  if (t.id === "colReport") {
    const days = $("#colDays").value;
    $("#colRep").innerHTML = '<p class="muted">กำลังตรวจกับ log…</p>';
    try {
      const r = await api(`/api/soc/ioc-collections/${COL.cur.id}/report?days=${days}`);
      $("#colRep").innerHTML = `<div class="rep-box"><b>Telemetry report · ${days} วัน</b> — พบ ${r.seen} จาก ${r.iocs} IOC ใน log/alert ของ tenant
        ${r.hosts.length ? `· เครื่องที่เกี่ยวข้อง: <span class="mono">${r.hosts.map(esc).join(", ")}</span>` : ""}
        <button class="ghost sm" id="colCsv">ดาวน์โหลด CSV</button><div class="small muted">${esc(r.note)}</div>
        ${r.items.filter((x) => x.logs || x.alerts).slice(0, 10).map((x) => `<div class="small"><span class="mono">${esc(x.value)}</span> — ${x.logs} logs · ${x.alerts} alerts · ${esc(x.hosts.join(", "))}</div>`).join("")}</div>`;
    } catch (e) { $("#colRep").innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  }
  if (t.id === "colCsv") download(`/api/soc/ioc-collections/${COL.cur.id}/report?days=${$("#colDays").value}&format=csv`, `ioc-telemetry-${COL.cur.id}.csv`, false).catch((e) => alert(e.message));
});

// ---------- graph explorations ----------
const GR = { id: null, nodes: new Map(), edges: [], drag: null };
const GR_COL = { host: "--endpoint", account: "--identity", indicator: "--critical", incident: "--xdr", threat: "--off", rule: "--cti" };
const GR_TH = { host: "Host", account: "Account", indicator: "Indicator", incident: "Case", threat: "Threat", rule: "Rule" };
$("#grLegend").innerHTML = Object.entries(GR_TH).map(([k, v]) => `<span><i style="background:var(${GR_COL[k]})"></i>${v}</span>`).join("");
function grLayout(iter = 220) {
  const ns = [...GR.nodes.values()];
  for (let it = 0; it < iter; it++) {
    for (const a of ns) { a.vx = 0; a.vy = 0; }
    for (let i = 0; i < ns.length; i++) for (let j = i + 1; j < ns.length; j++) {
      const a = ns[i], b = ns[j]; let dx = a.x - b.x, dy = a.y - b.y; let d2 = dx * dx + dy * dy || 0.01;
      const f = 12000 / d2, d = Math.sqrt(d2); dx /= d; dy /= d;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    for (const e of GR.edges) {
      const a = GR.nodes.get(e.from), b = GR.nodes.get(e.to); if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - 110) * 0.02;
      a.vx += dx / d * f * 10; a.vy += dy / d * f * 10; b.vx -= dx / d * f * 10; b.vy -= dy / d * f * 10;
    }
    for (const a of ns) if (!a.fixed) { a.x += Math.max(-8, Math.min(8, a.vx)); a.y += Math.max(-8, Math.min(8, a.vy)); }
  }
}
function grDraw() {
  const svg = $("#grSvg"), ns = [...GR.nodes.values()];
  if (!ns.length) { svg.innerHTML = '<text x="20" y="40" class="tk">เพิ่ม node ด้วยช่องด้านบน หรือเปิด graph ที่บันทึกไว้</text>'; svg.setAttribute("viewBox", "0 0 800 420"); return; }
  const xs = ns.map((n) => n.x), ys = ns.map((n) => n.y), pad = 80;
  const minX = Math.min(...xs) - pad, minY = Math.min(...ys) - pad, w = Math.max(400, Math.max(...xs) - minX + pad), h = Math.max(300, Math.max(...ys) - minY + pad);
  svg.setAttribute("viewBox", `${minX} ${minY} ${w} ${h}`);
  svg.innerHTML = GR.edges.map((e) => { const a = GR.nodes.get(e.from), b = GR.nodes.get(e.to); if (!a || !b) return "";
      return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="gr-e"/><text x="${(a.x + b.x) / 2}" y="${(a.y + b.y) / 2 - 3}" class="gr-el">${esc(e.label || "")}</text>`; }).join("")
    + ns.map((n) => `<g class="gr-n" data-id="${esc(n.id)}" transform="translate(${n.x},${n.y})"><circle r="${n.expanded ? 15 : 12}" style="fill:var(${GR_COL[n.type] || "--muted"})"/>
      <text y="${n.expanded ? 30 : 27}" text-anchor="middle">${esc(String(n.label).slice(0, 34))}</text><title>${esc(GR_TH[n.type] || n.type)}: ${esc(n.value)} — ดับเบิลคลิกเพื่อขยาย</title></g>`).join("");
}
async function grExpand(type, value) {
  $("#grMsg").textContent = "กำลังขยาย…";
  try {
    const r = await api(`/api/soc/graph/expand?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`);
    let root = GR.nodes.get(r.node.id);
    if (!root) { root = { ...r.node, x: GR.nodes.size ? 0 : 0, y: 0 }; GR.nodes.set(root.id, root); }
    root.expanded = true;
    r.nodes.forEach((n, i) => { if (!GR.nodes.has(n.id)) { const ang = (2 * Math.PI * i) / Math.max(1, r.nodes.length); GR.nodes.set(n.id, { ...n, x: root.x + 140 * Math.cos(ang), y: root.y + 140 * Math.sin(ang) }); } });
    const have = new Set(GR.edges.map((e) => e.from + ">" + e.to));
    r.edges.forEach((e) => { if (!have.has(e.from + ">" + e.to) && !have.has(e.to + ">" + e.from)) GR.edges.push(e); });
    grLayout(); grDraw();
    $("#grMsg").textContent = `${r.nodes.length} ความเชื่อมโยง${r.truncated ? " (ตัดที่ 25)" : ""}${r.nodes.length ? "" : " — ไม่พบใน alert/log 7 วัน"}`;
  } catch (e) { $("#grMsg").textContent = e.message; }
}
$("#grAdd").onclick = () => { const v = $("#grValue").value.trim(); if (v) grExpand($("#grType").value, v); };
$("#grValue").addEventListener("keydown", (ev) => { if (ev.key === "Enter") $("#grAdd").click(); });
$("#grSvg").addEventListener("dblclick", (ev) => { const g = ev.target.closest(".gr-n"); if (g) { const n = GR.nodes.get(g.dataset.id); grExpand(n.type, n.value); } });
function svgPoint(ev) { const svg = $("#grSvg"), pt = svg.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY; return pt.matrixTransform(svg.getScreenCTM().inverse()); }
$("#grSvg").addEventListener("pointerdown", (ev) => { const g = ev.target.closest(".gr-n"); if (!g) return; GR.drag = GR.nodes.get(g.dataset.id); GR.moved = false; ev.preventDefault(); });
window.addEventListener("pointermove", (ev) => {
  if (!GR.drag) return; const p = svgPoint(ev); GR.drag.x = p.x; GR.drag.y = p.y; GR.drag.fixed = true; GR.moved = true;
  const g = $(`#grSvg .gr-n[data-id="${CSS.escape(GR.drag.id)}"]`); if (g) g.setAttribute("transform", `translate(${p.x},${p.y})`);
});
window.addEventListener("pointerup", () => { if (GR.drag) { const moved = GR.moved; GR.drag = null; if (moved) grDraw(); } });
async function loadGraphs() {
  try {
    const r = await api("/api/soc/graphs");
    $("#grList").innerHTML = r.graphs.map((g) => `<li data-id="${g.id}" class="${GR.id === g.id ? "on" : ""}"><b>${esc(g.name)}</b><small class="muted">${g.nodes} nodes · ${esc(g.created_by)} · ${ago(g.updated_at)}ที่แล้ว</small></li>`).join("")
      || '<li class="muted">ยังไม่มี graph ที่บันทึก</li>';
  } catch {}
  if (!GR.nodes.size) grDraw();
}
$("#grList").addEventListener("click", async (ev) => {
  const li = ev.target.closest("li[data-id]"); if (!li) return;
  const g = await api(`/api/soc/graphs/${li.dataset.id}`);
  GR.id = g.id; GR.nodes = new Map(g.nodes.map((n) => [n.id, { ...n, fixed: true }])); GR.edges = g.edges; $("#grName").value = g.name;
  grDraw(); loadGraphs(); $("#grMsg").textContent = `เปิด ${g.name} — แก้ไขล่าสุดโดย ${g.updated_by}`;
});
$("#grNew").onclick = () => { GR.id = null; GR.nodes = new Map(); GR.edges = []; $("#grName").value = ""; $("#grMsg").textContent = ""; grDraw(); loadGraphs(); };
$("#grSave").onclick = async () => {
  const name = $("#grName").value.trim() || prompt("ชื่อ graph") || ""; if (!name) return;
  const body = JSON.stringify({ name, nodes: [...GR.nodes.values()].map(({ id, type, value, label, x, y }) => ({ id, type, value, label, x, y })), edges: GR.edges });
  try { const g = await api(GR.id ? `/api/soc/graphs/${GR.id}` : "/api/soc/graphs", { method: GR.id ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body });
    GR.id = g.id; $("#grName").value = g.name; $("#grMsg").textContent = "บันทึกแล้ว"; loadGraphs(); } catch (e) { $("#grMsg").textContent = e.message; }
};

// ---------- workspace settings ----------
const WS = { templates: [] };
async function loadWsSettings() {
  try {
    const r = await api("/api/soc/workspace");
    WS.templates = r.templates;
    const f = $("#wsForm");
    if (f.sector.options.length === 1) f.sector.insertAdjacentHTML("beforeend", r.sectors.map((x) => `<option>${esc(x)}</option>`).join(""));
    for (const k of ["display_name", "legal_name", "description", "domain", "location", "sector", "size", "dpo_contact"]) f[k].value = r.profile[k] || "";
    WS.team = r.profile.security_team_size || "";
    document.querySelectorAll("#wsTeam button").forEach((b) => b.classList.toggle("on", b.dataset.v === WS.team));
    $("#wsTenant").textContent = `tenant: ${r.tenant}`;
    $("#wsMissing").hidden = !r.missing.length; $("#nb-ws").hidden = !r.missing.length;
    $("#wsMissing").title = "ยังไม่ได้กรอก: " + r.missing.join(", ");
    const ro = !can("governance.manage");
    f.querySelectorAll("input,select,textarea,button").forEach((el) => { el.disabled = ro; });
    renderTemplates();
  } catch (e) { $("#wsMsg").textContent = e.message; }
}
$("#wsTeam").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b || b.disabled) return; WS.team = b.dataset.v; document.querySelectorAll("#wsTeam button").forEach((x) => x.classList.toggle("on", x === b)); });
$("#wsForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target, body = Object.fromEntries(["display_name", "legal_name", "description", "domain", "location", "sector", "size", "dpo_contact"].map((k) => [k, f[k].value.trim()]));
  body.security_team_size = WS.team || "";
  try { await api("/api/soc/workspace", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); $("#wsMsg").textContent = "บันทึกแล้ว"; loadWsSettings(); }
  catch (e) { $("#wsMsg").textContent = e.message; }
});
function tplRow(t = { name: "", title: "", priority: "medium", tags: [], tasks: [], description: "" }) {
  return `<div class="tpl" data-id="${t.id ?? ""}"><div class="row3"><label>ชื่อ template <input data-k="name" value="${esc(t.name)}" maxlength="120"></label>
    <label>Priority <select data-k="priority">${["low", "medium", "high", "critical"].map((p) => `<option ${p === t.priority ? "selected" : ""}>${p}</option>`).join("")}</select></label>
    <label>Tags <input data-k="tags" value="${esc(t.tags.join(", "))}"></label></div>
    <label>งานที่สร้างอัตโนมัติ (บรรทัดละงาน) <textarea data-k="tasks" rows="3">${esc(t.tasks.join("\n"))}</textarea></label>
    <button type="button" class="ghost sm tpl-del">ลบ template</button></div>`;
}
function renderTemplates() {
  $("#tplList").innerHTML = WS.templates.map(tplRow).join("") || '<p class="muted small">ยังไม่มี — เช่น "Phishing": เก็บ header อีเมล, ค้นผู้รับรายอื่น, บล็อกโดเมนผู้ส่ง, รีเซ็ตรหัสผ่าน</p>';
  const ro = !can("governance.manage"); $("#tplList").querySelectorAll("input,select,textarea,button").forEach((el) => { el.disabled = ro; });
}
$("#tplAdd").onclick = () => { if (!$("#tplList .tpl")) $("#tplList").innerHTML = ""; $("#tplList").insertAdjacentHTML("beforeend", tplRow()); };
$("#tplList").addEventListener("click", (ev) => { if (ev.target.closest(".tpl-del")) ev.target.closest(".tpl").remove(); });
$("#tplSave").onclick = async () => {
  const rows = [...document.querySelectorAll("#tplList .tpl")].map((el) => {
    const g = (k) => el.querySelector(`[data-k=${k}]`).value;
    return { ...(el.dataset.id ? { id: Number(el.dataset.id) } : {}), name: g("name").trim(), priority: g("priority"), tags: splitList(g("tags")),
      tasks: g("tasks").split("\n").map((x) => x.trim()).filter(Boolean) };
  }).filter((t) => t.name);
  try { const r = await api("/api/soc/case-templates", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rows) });
    WS.templates = r.templates; renderTemplates(); $("#tplMsg").textContent = "บันทึกแล้ว"; } catch (e) { $("#tplMsg").textContent = e.message; }
};
$("#recentCases").addEventListener("click", (ev) => { const tr = ev.target.closest("tr[data-inc]"); if (tr) location.hash = "#inc-" + tr.dataset.inc; });


// ---------- roles & permission matrix ----------
const RL = { data: null };
async function loadRoles() {
  try {
    const d = RL.data = await api("/api/roles");
    const roles = d.roles;
    const head = `<thead><tr><th>สิทธิ์</th>${roles.map((r) => `<th class="rc ${r.custom ? "custom" : ""}" data-role="${esc(r.name)}" title="${esc(r.description || "")}">${esc(r.label)}<div class="sub">${esc(r.name)}${r.custom ? " ✎" : ""}</div></th>`).join("")}</tr></thead>`;
    const body = d.permissions.map((g) => `<tr class="grp"><td colspan="${roles.length + 1}">${esc(g.group)}</td></tr>` + g.items.map((p) =>
      `<tr><td><span class="mono">${esc(p.id)}</span><div class="sub">${esc(p.description)}</div></td>${roles.map((r) => `<td class="ck">${r.perms.includes(p.id) ? "✓" : ""}</td>`).join("")}</tr>`).join("")).join("");
    $("#permMatrix").innerHTML = head + "<tbody>" + body + "</tbody>";
    const f = $("#roleForm");
    f.hidden = !can("roles.manage");
    f.base.innerHTML = '<option value="">— ว่าง —</option>' + roles.map((r) => `<option value="${esc(r.name)}">${esc(r.label)}</option>`).join("");
    renderRolePerms(new Set());
  } catch (e) { $("#permMatrix").innerHTML = `<tr><td class="err">${esc(e.message)}</td></tr>`; }
}
function renderRolePerms(sel) {
  const mine = new Set(RL.data.mine);
  $("#rolePerms").innerHTML = RL.data.permissions.map((g) => `<fieldset><legend>${esc(g.group)}</legend>${g.items.map((p) =>
    `<label class="chk" title="${esc(p.description)}"><input type="checkbox" value="${esc(p.id)}" ${sel.has(p.id) ? "checked" : ""} ${mine.has(p.id) ? "" : "disabled"}> ${esc(p.id)}</label>`).join("")}</fieldset>`).join("");
}
$("#roleForm").base.onchange = (ev) => { const r = RL.data.roles.find((x) => x.name === ev.target.value); renderRolePerms(new Set(r ? r.perms : [])); };
$("#permMatrix").addEventListener("click", (ev) => {
  const th = ev.target.closest("th.custom"); if (!th || !can("roles.manage")) return;
  const r = RL.data.roles.find((x) => x.name === th.dataset.role);
  const f = $("#roleForm"); f.name.value = r.name; f.label.value = r.label; renderRolePerms(new Set(r.perms)); f.scrollIntoView({ behavior: "smooth", block: "center" });
});
$("#roleForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target, perms = [...f.querySelectorAll("#rolePerms input:checked")].map((x) => x.value);
  try { await api(`/api/roles/${encodeURIComponent(f.name.value.trim())}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label: f.label.value.trim(), permissions: perms }) });
    $("#roleMsg").textContent = "บันทึกแล้ว"; $("#newRole").innerHTML = ""; loadUsers(); } catch (e) { $("#roleMsg").textContent = e.message; }
});
$("#roleDel").onclick = async () => {
  const name = $("#roleForm").name.value.trim(); if (!name || !confirm(`ลบบทบาท ${name}?`)) return;
  try { await api(`/api/roles/${encodeURIComponent(name)}`, { method: "DELETE" }); $("#roleMsg").textContent = "ลบแล้ว"; $("#newRole").innerHTML = ""; loadUsers(); }
  catch (e) { $("#roleMsg").textContent = e.message; }
};

// ---------- governance policies ----------
async function loadPolicies() {
  try {
    const r = await api("/api/soc/policies");
    const f = $("#polForm");
    for (const k of Object.keys(r.policies)) if (f[k]) { f[k].checked = r.policies[k]; f[k].disabled = !can("governance.manage"); }
  } catch { $("#polForm").hidden = true; }
}
$("#polForm").addEventListener("change", async () => {
  const f = $("#polForm"), body = Object.fromEntries(["four_eyes_response", "four_eyes_agents", "four_eyes_rules"].map((k) => [k, f[k].checked]));
  try { await api("/api/soc/policies", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); $("#polMsg").textContent = "บันทึกแล้ว"; loadApprovals(); }
  catch (e) { $("#polMsg").textContent = e.message; loadPolicies(); }
});

// ---------- approvals ----------
const ACT_TH = { contain: "กักกัน (contain)", release: "ปล่อย (release)" };
async function loadApprovals() {
  let n = 0;
  const row = (r, kind) => {
    const pending = r.status === "pending";
    if (pending) n++;
    const mine = state.me?.named && r.requested_by === state.me.name;
    const perm = kind === "resp" ? "respond.approve" : "agents.approve";
    const what = kind === "resp" ? `${ACT_TH[r.action] || r.action} <span class="mono">${esc(r.agent)}</span> — ${esc(r.reason)}`
      : `${r.change === "new" ? "เพิ่ม" : "แก้"} agent <span class="mono">${esc(r.spec.id)}</span> · scopes: ${esc((r.spec.scopes || []).join(", ") || "-")}${r.spec.shell ? " · shell" : ""}${(r.spec.egress || []).length ? " · egress: " + esc(r.spec.egress.join(", ")) : ""}`;
    return `<li class="${pending ? "" : "read"}"><div>#${r.id} ${what}</div><small class="muted">ขอโดย ${esc(r.requested_by)} · ${ago(r.requested_at)}ที่แล้ว
      ${pending ? "" : ` · <b>${r.status === "approved" ? "อนุมัติ" : "ปฏิเสธ"}</b> โดย ${esc(r.decided_by)}${r.comment ? " — " + esc(r.comment) : ""}`}</small>
      ${pending && can(perm) ? (mine ? '<div class="small muted">คุณเป็นผู้ขอ — ต้องให้คนอื่นอนุมัติ</div>'
        : `<div><button class="sm ap-ok" data-k="${kind}" data-id="${r.id}">อนุมัติ</button> <button class="ghost sm ap-no" data-k="${kind}" data-id="${r.id}">ปฏิเสธ</button></div>`) : ""}</li>`;
  };
  try {
    const r = await api("/api/soc/response-requests");
    $("#apprRespNote").textContent = r.four_eyes ? "เปิด four-eyes" : "ปิด four-eyes — ปฏิบัติการทันที";
    $("#apprResp").innerHTML = r.requests.slice(0, 20).map((x) => row(x, "resp")).join("") || '<li class="muted">ไม่มีคำขอ</li>';
  } catch { $("#apprResp").innerHTML = '<li class="muted">ไม่มีสิทธิ์ดู</li>'; }
  try {
    const r = await api("/api/soc/agents/requests");
    $("#apprAgNote").textContent = r.four_eyes ? "เปิด four-eyes" : "ปิด four-eyes — มีผลทันที";
    $("#apprAg").innerHTML = r.requests.slice(0, 20).map((x) => row(x, "ag")).join("") || '<li class="muted">ไม่มีคำขอ</li>';
  } catch { $("#apprAg").innerHTML = '<li class="muted">ไม่มีสิทธิ์ดู</li>'; }
  $("#nb-appr").textContent = n;
}
$("#apprCard").addEventListener("click", async (ev) => {
  const b = ev.target.closest(".ap-ok, .ap-no"); if (!b) return;
  const approve = b.classList.contains("ap-ok");
  const comment = prompt(approve ? "หมายเหตุการอนุมัติ (ไม่บังคับ)" : "เหตุผลที่ปฏิเสธ") ?? null;
  if (comment === null) return;
  const url = b.dataset.k === "resp" ? `/api/soc/response-requests/${b.dataset.id}/decision` : `/api/soc/agents/requests/${b.dataset.id}/decision`;
  try { await api(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approve, comment }) }); loadApprovals(); }
  catch (e) { alert(e.message); }
});
$("#agents").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-life]"); if (!b) return;
  const reason = prompt(b.dataset.state === "retired" ? `เหตุผลที่ปลด ${b.dataset.life} ออกจากการใช้งาน` : `เหตุผลที่นำ ${b.dataset.life} กลับมาใช้`);
  if (!reason || reason.length < 5) return;
  try { await api(`/api/soc/agents/${encodeURIComponent(b.dataset.life)}/lifecycle`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state: b.dataset.state, reason }) }); alert("บันทึกแล้ว"); } catch (e) { alert(e.message); }
});
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden) loadApprovals(); }, 60000);

// ---------- alert actions (alerts list) ----------
$("#alTbl").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-aa]"); if (!b) return;
  ev.stopPropagation();
  const tr = b.closest("tr"), body = { title: tr.dataset.title, host: tr.dataset.host || null, action: b.dataset.aa };
  if (body.action === "assign") {
    const who = prompt(`มอบหมายให้ (username)${TS.users.length ? " — " + TS.users.join(", ") : ""}`, state.me?.name || ""); if (!who) return;
    body.assignee = who;
  }
  if (body.action === "close") {
    body.reason = prompt("เหตุผลที่ปิด alert (จำเป็น)") || ""; if (body.reason.trim().length < 3) return;
    body.verdict = confirm("เป็น false positive / benign หรือไม่? (OK = benign, Cancel = ไม่ระบุ)") ? "benign" : "";
  }
  if (body.action === "escalate") { body.reason = prompt("เหตุผลที่ยกระดับ") || ""; }
  try { const r = await api("/api/soc/alerts/action", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (r.incident_id) location.hash = "#inc-" + r.incident_id; loadAlertsList(); loadOverview(); }
  catch (e) { alert(e.message); }
});

// ---------- Threat Map ----------
const TM = { data: null, world: null, cent: null, rot: [-100, -12, 0], base: [-100, -12, 0], phase: 0, drag: null, lastDrag: 0,
  raf: 0, visible: false, t0: performance.now(), last: 0, shots: [], ripples: [], feed: [], stars: null };
const tmName = (() => { let dn = null; try { dn = new Intl.DisplayNames(["th"], { type: "region" }); } catch (e) {} return (cc) => { try { return (dn && dn.of(cc)) || cc; } catch (e) { return cc; } }; })();
const TM_RED = matchMedia("(prefers-reduced-motion: reduce)").matches;
function tmBars(el, rows, label, value, fmt) {
  const max = Math.max(1, ...rows.map(value));
  el.innerHTML = rows.map((r) => `<div class="tm-bar"><span class="tm-bl" title="${esc(label(r))}">${esc(label(r))}</span>
    <span class="tm-bt"><i data-w="${(100 * value(r) / max).toFixed(1)}"></i></span><b>${esc(fmt ? fmt(r) : value(r).toLocaleString())}</b></div>`).join("")
    || '<p class="tm-note">ยังไม่มีข้อมูล</p>';
  tmGrow(el);
}
// grow bars / rings / trend from their previous size on every refresh (CSS transitions do the motion)
function tmGrow(el) {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    el.querySelectorAll("[data-w]").forEach((i) => { i.style.width = i.dataset.w + "%"; });
    el.querySelectorAll("[data-h]").forEach((i) => { i.style.height = i.dataset.h + "%"; });
    el.querySelectorAll("[data-dash]").forEach((c) => { c.setAttribute("stroke-dasharray", c.dataset.dash); });
  }));
}
function tmCount(el, to) {
  const from = Number(el.dataset.v || 0); el.dataset.v = to;
  if (TM_RED || from === to) { el.textContent = to.toLocaleString(); return; }
  const t0 = performance.now(), dur = 900;
  const step = (now) => { const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 3);
    el.textContent = Math.round(from + (to - from) * e).toLocaleString(); if (k < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
async function tmAssets() {
  if (TM.world) return;
  const [w, c] = await Promise.all([fetch("/static/vendor/countries-110m.json").then((r) => r.json()), fetch("/static/vendor/country-centroids.json").then((r) => r.json())]);
  TM.world = { land: topojson.feature(w, w.objects.land), borders: topojson.mesh(w, w.objects.countries, (a, b) => a !== b) };
  TM.cent = c;
}
async function loadThreatMap() {
  if (!window.d3 || !window.topojson) { $("#tmSub").textContent = "โหลดไลบรารีแผนที่ไม่สำเร็จ"; return; }
  try {
    const days = Number($("#mapDays").value);
    const [r] = await Promise.all([api(`/api/soc/threatmap?days=${days}`), tmAssets()]);
    TM.data = r;
    if (!TM.rotSet && TM.cent[r.home]) { const [lon, lat] = TM.cent[r.home]; TM.rot = [-lon + 15, -lat + 8, 0]; TM.base = TM.rot.slice(); TM.rotSet = true; }
    const stamp = new Date(r.generated_at * 1000).toLocaleString("th-TH", { dateStyle: "medium", timeStyle: "short" });
    $("#tmSub").textContent = `ข้อมูล ณ ${stamp} · ${r.days} วัน · ${r.alerts.toLocaleString()} alerts` + (r.simulated_share > 0.5 ? " · ส่วนใหญ่เป็นข้อมูลจำลอง" : "");
    $("#tmIncLbl").textContent = `Incident (${r.days} วัน)`;
    tmCount($("#tmInc"), r.incidents); tmCount($("#tmIoc"), r.ioc_unique);
    const tmax = Math.max(1, ...r.trend);
    $("#tmTrend").innerHTML = r.trend.map((n, i) => `<i data-h="${Math.max(3, 100 * n / tmax).toFixed(1)}" style="height:3%;transition-delay:${i * 18}ms" title="${30 - i - 1 === 0 ? "วันนี้" : (30 - i - 1) + " วันก่อน"}: ${n} incident"></i>`).join(""); tmGrow($("#tmTrend"));
    $("#tmOrgSub").textContent = `${r.days} วัน`;
    tmBars($("#tmOrigins"), r.origins, (x) => tmName(x.country), (x) => x.count);
    $("#tmUnknown").textContent = r.unknown_origin ? `ระบุประเทศไม่ได้ ${r.unknown_origin.toLocaleString()} alerts (log ไม่มี src_country และ IP ไม่อยู่ใน Feodo)` : "";
    tmBars($("#tmTargets"), r.targets, (x) => x.host, (x) => x.alerts, (x) => x.alerts.toLocaleString() + (x.high ? ` · H${x.high}` : ""));
    tmBars($("#tmInfra"), r.infra.top, (x) => tmName(x.country), (x) => x.count);
    const tymax = Math.max(1, ...r.ioc_types.map((x) => x.count));
    $("#tmTypes").innerHTML = r.ioc_types.map((x) => { const d = 64 + 44 * Math.sqrt(x.count / tymax);
      return `<div class="tm-bub" style="width:${d}px;height:${d}px;animation-delay:${(Math.random() * 3).toFixed(2)}s"><b>${x.count.toLocaleString()}</b><span>${esc(x.type)}</span></div>`; }).join("") || '<p class="tm-note">ยังไม่มี IOC</p>';
    const COLS = ["#3b82f6", "#f5a524", "#8b5cf6", "#ef4444", "#14b8a6"];
    $("#tmRings").innerHTML = r.categories.map((c, i) => { const C = 2 * Math.PI * 34, L = C * c.share;
      return `<div class="tm-ring" title="${esc(c.name)}: ${c.count.toLocaleString()} alerts"><svg viewBox="0 0 84 84" aria-hidden="true"><circle cx="42" cy="42" r="34" class="bg"/>
        <circle cx="42" cy="42" r="34" stroke="${COLS[i]}" stroke-dasharray="0 ${C.toFixed(1)}" data-dash="${L.toFixed(1)} ${C.toFixed(1)}" style="transition-delay:${i * 120}ms" transform="rotate(-90 42 42)"/></svg>
        <span><small>${esc(c.name)}</small><b>${(100 * c.share).toFixed(1)}%</b></span></div>`; }).join("") || '<p class="tm-note">ยังไม่มี alert</p>';
    tmGrow($("#tmRings"));
    tmDraw(performance.now());
  } catch (e) { $("#tmSub").textContent = "โหลด Threat Map ไม่สำเร็จ: " + e.message; }
}
function tmCanvas() {
  const cv = $("#tmGlobe"), wrap = cv.parentElement, dpr = Math.min(2, window.devicePixelRatio || 1);
  const size = Math.min(wrap.clientWidth, 560);
  if (cv.width !== Math.round(size * dpr)) { cv.width = Math.round(size * dpr); cv.height = Math.round(size * dpr); cv.style.width = cv.style.height = size + "px"; }
  return { cv, ctx: cv.getContext("2d"), size, dpr };
}
const TM_SEV = { critical: "248,113,113", high: "251,146,60", medium: "250,204,21", low: "94,234,212" };
// one comet flying from an origin country to home. live = triggered by a real alert arriving on the stream
function tmShoot(cc, now, opts = {}) {
  const src = TM.cent && TM.cent[cc], home = TM.data && TM.cent && TM.cent[TM.data.home];
  if (!src || !home || cc === TM.data.home || TM.shots.length > 90) return;
  const dist = d3.geoDistance(src, home);
  TM.shots.push({ cc, src, interp: d3.geoInterpolate(src, home), lift: 0.08 + 0.22 * Math.min(1, dist / 1.6), t0: now,
    dur: (opts.live ? 1300 : 1900) + 900 * dist, col: opts.col || "94,234,212", live: !!opts.live });
  TM.ripples.push({ pos: src, t0: now, col: opts.col || "94,234,212", big: !!opts.live });
}
function tmLive(events) {  // called from the SSE tick handler for every batch of new alerts
  if (!TM.data || !TM.cent) return;
  const now = performance.now();
  for (const e of events) {
    const cc = String(e.src_country || "").toUpperCase();
    if (!TM.cent[cc] || e.severity === "info") continue;
    if (TM.visible && !TM_RED) tmShoot(cc, now, { live: true, col: TM_SEV[e.severity] || TM_SEV.low });
    TM.feed.unshift({ cc, title: e.title, sev: e.severity, host: e.host, ts: e.ts, real: e.simulated === false });
  }
  TM.feed = TM.feed.slice(0, 5);
  const box = $("#tmFeed");
  if (box && TM.feed.length) box.innerHTML = TM.feed.map((f, i) => `<div class="tm-fi${i === 0 ? " new" : ""}"><span class="sev ${esc(f.sev)}">${esc(f.sev)}</span>
    <b>${esc(f.cc)}</b> → ${esc(TM.data.home)} <span class="tm-ft">${esc(f.title)}</span><span class="tm-fh">${esc(f.host || "")}${f.real ? " · REAL" : ""}</span></div>`).join("");
}
function tmDraw(now) {
  if (!TM.world || !TM.data) return;
  const { ctx, size, dpr } = tmCanvas(), r = size / 2 - 18, cx = size / 2, cy = size / 2;
  if (r < 20) return;  // not laid out yet
  const dt = Math.min(100, now - (TM.last || now)); TM.last = now;
  // slow sway around where the user left the globe; paused while dragging and for 3 s after
  if (!TM_RED && !TM.drag && now - TM.lastDrag > 3000) {
    TM.phase += dt / 9000 * 2 * Math.PI;
    TM.rot = [TM.base[0] + 22 * Math.sin(TM.phase), TM.base[1] + 3 * Math.sin(TM.phase * 0.7), 0];
  }
  const proj = d3.geoOrthographic().scale(r).translate([cx, cy]).rotate(TM.rot).clipAngle(90);
  const path = d3.geoPath(proj, ctx);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, size, size);
  if (!TM.stars) TM.stars = Array.from({ length: 70 }, () => [Math.random(), Math.random(), Math.random() * 1.2 + 0.3, Math.random() * 6.28]);
  for (const [sx, sy, sr, sp] of TM.stars) {
    const a = TM_RED ? 0.35 : 0.2 + 0.3 * (Math.sin(now / 900 + sp) + 1) / 2;
    ctx.fillStyle = `rgba(203,213,225,${a.toFixed(2)})`; ctx.beginPath(); ctx.arc(sx * size, sy * size, sr, 0, 6.28); ctx.fill();
  }
  const breathe = TM_RED ? 0 : (Math.sin(now / 1600) + 1) / 2;
  const glow = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, r * (1.1 + 0.04 * breathe));
  glow.addColorStop(0, `rgba(45,212,191,${(0.3 + 0.15 * breathe).toFixed(2)})`); glow.addColorStop(1, "rgba(45,212,191,0)");
  ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(cx, cy, r * 1.15, 0, 2 * Math.PI); ctx.fill();
  const sea = ctx.createRadialGradient(cx - r * .35, cy - r * .4, r * .1, cx, cy, r);
  sea.addColorStop(0, "#1d6f6a"); sea.addColorStop(1, "#0b2f33");
  ctx.fillStyle = sea; ctx.beginPath(); path({ type: "Sphere" }); ctx.fill();
  ctx.strokeStyle = "rgba(255,255,255,.06)"; ctx.lineWidth = 1; ctx.beginPath(); path(d3.geoGraticule10()); ctx.stroke();
  ctx.fillStyle = "#2a8a7f"; ctx.beginPath(); path(TM.world.land); ctx.fill();
  ctx.strokeStyle = "rgba(10,40,44,.7)"; ctx.lineWidth = .6; ctx.beginPath(); path(TM.world.borders); ctx.stroke();
  if (!TM_RED) {  // radar sweep around the globe
    const ang = (now / 4000) % 1 * 2 * Math.PI;
    ctx.save(); ctx.beginPath(); path({ type: "Sphere" }); ctx.clip();
    const sw = ctx.createConicGradient ? ctx.createConicGradient(ang, cx, cy) : null;
    if (sw) { sw.addColorStop(0, "rgba(94,234,212,.16)"); sw.addColorStop(0.08, "rgba(94,234,212,0)"); sw.addColorStop(1, "rgba(94,234,212,0)");
      ctx.fillStyle = sw; ctx.fillRect(0, 0, size, size); }
    ctx.restore();
  }
  ctx.strokeStyle = "rgba(94,234,212,.55)"; ctx.lineWidth = 1.5; ctx.beginPath(); path({ type: "Sphere" }); ctx.stroke();
  const d = TM.data, home = TM.cent[d.home], centre = [-TM.rot[0], -TM.rot[1]];
  const vis = (p) => d3.geoDistance(p, centre) < Math.PI / 2 - 0.02;
  const rotate = d3.geoRotation(TM.rot), RAD = Math.PI / 180;
  // a lifted arc point is hidden only when it is behind the globe AND inside the disc the globe covers
  const shown = (g, h) => { const [l, p] = rotate(g), z = Math.cos(p * RAD) * Math.cos(l * RAD); return z > 0 || h * Math.sqrt(Math.max(0, 1 - z * z)) > 1; };
  const at = (interp, lift, t) => { const g = interp(t), h = 1 + lift * Math.sin(Math.PI * t); if (!shown(g, h)) return null;
    const [x, y] = proj(g); return [cx + (x - cx) * h, cy + (y - cy) * h]; };
  const maxc = Math.max(1, ...d.arcs.map((a) => a.count));
  // background traffic: each top origin fires comets at a rate that follows its alert count
  if (!TM_RED && home) for (const a of d.arcs) if (Math.random() < dt / 1000 * (0.25 + 1.4 * a.count / maxc)) tmShoot(a.from, now, { col: a === d.arcs[0] || a === d.arcs[1] || a === d.arcs[2] ? "245,165,36" : "94,234,212" });
  d.arcs.forEach((a, i) => {  // faint guide arcs
    const src = TM.cent[a.from]; if (!src || !home) return;
    const interp = d3.geoInterpolate(src, home), lift = 0.08 + 0.22 * Math.min(1, d3.geoDistance(src, home) / 1.6);
    ctx.strokeStyle = `rgba(${i < 3 ? "245,165,36" : "94,234,212"},.28)`; ctx.lineWidth = 0.8 + 1.8 * Math.sqrt(a.count / maxc);
    ctx.beginPath(); let pen = false;
    for (let k = 0; k <= 48; k++) { const q = at(interp, lift, k / 48); if (!q) { pen = false; continue; } pen ? ctx.lineTo(q[0], q[1]) : ctx.moveTo(q[0], q[1]); pen = true; }
    ctx.stroke();
    if (vis(src)) { const [x, y] = proj(src); ctx.fillStyle = `rgb(${i < 3 ? "245,165,36" : "94,234,212"})`; ctx.beginPath(); ctx.arc(x, y, 3, 0, 2 * Math.PI); ctx.fill();
      ctx.fillStyle = "rgba(226,232,240,.85)"; ctx.font = "600 11px system-ui, sans-serif"; ctx.fillText(a.from, x + 6, y - 4); }
  });
  // comets
  TM.shots = TM.shots.filter((s) => {
    const t = (now - s.t0) / s.dur;
    if (t >= 1) { TM.ripples.push({ pos: home, t0: now, col: s.col, big: s.live }); return false; }
    const head = at(s.interp, s.lift, t); if (!head) return true;
    const tail = s.live ? 0.22 : 0.14, n = 10;
    for (let k = n; k >= 1; k--) {
      const p = at(s.interp, s.lift, Math.max(0, t - tail * k / n)), q = at(s.interp, s.lift, Math.max(0, t - tail * (k - 1) / n));
      if (!p || !q) continue;
      ctx.strokeStyle = `rgba(${s.col},${(0.9 * (1 - k / n)).toFixed(2)})`; ctx.lineWidth = (s.live ? 3.2 : 2) * (1 - k / n) + 0.4;
      ctx.beginPath(); ctx.moveTo(p[0], p[1]); ctx.lineTo(q[0], q[1]); ctx.stroke();
    }
    ctx.fillStyle = "#fff"; ctx.shadowColor = `rgb(${s.col})`; ctx.shadowBlur = s.live ? 14 : 8;
    ctx.beginPath(); ctx.arc(head[0], head[1], s.live ? 3.2 : 2.2, 0, 2 * Math.PI); ctx.fill(); ctx.shadowBlur = 0;
    return true;
  });
  // ripples where comets launch and land
  TM.ripples = TM.ripples.filter((rp) => {
    const k = (now - rp.t0) / (rp.big ? 1400 : 900); if (k >= 1) return false;
    if (!vis(rp.pos)) return true;
    const [x, y] = proj(rp.pos);
    ctx.strokeStyle = `rgba(${rp.col},${(0.8 * (1 - k)).toFixed(2)})`; ctx.lineWidth = rp.big ? 2 : 1.2;
    ctx.beginPath(); ctx.arc(x, y, 3 + (rp.big ? 26 : 14) * k, 0, 2 * Math.PI); ctx.stroke();
    return true;
  });
  if (home && vis(home)) {
    const [x, y] = proj(home), pulse = TM_RED ? 0.5 : (Math.sin((now - TM.t0) / 350) + 1) / 2;
    ctx.fillStyle = `rgba(239,68,68,${0.25 + 0.25 * pulse})`; ctx.beginPath(); ctx.arc(x, y, 9 + 5 * pulse, 0, 2 * Math.PI); ctx.fill();
    ctx.fillStyle = "#ef4444"; ctx.beginPath(); ctx.arc(x, y, 5, 0, 2 * Math.PI); ctx.fill();
    const label = tmName(d.home).toUpperCase();
    ctx.fillStyle = "#f8fafc"; ctx.font = "700 13px system-ui, sans-serif";
    const lw = ctx.measureText(label).width; ctx.fillText(label, x + 9 + lw > size - 4 ? x - 9 - lw : x + 9, y + 15);
  }
}
function tmLoop(now) { TM.raf = 0; if (!TM.visible || document.hidden) return; tmDraw(now); if (!TM_RED) TM.raf = requestAnimationFrame(tmLoop); }
function tmKick() { if (!TM.raf && TM.visible) TM.raf = requestAnimationFrame(tmLoop); }
new IntersectionObserver((es) => { TM.visible = es.some((e) => e.isIntersecting); if (TM.visible) { if (!TM.data) loadThreatMap(); TM.last = 0; tmKick(); } }).observe($("#mapCard"));
document.addEventListener("visibilitychange", () => { TM.last = 0; TM.shots = []; tmKick(); });
window.addEventListener("resize", () => tmDraw(performance.now()));
$("#tmGlobe").addEventListener("pointerdown", (ev) => { TM.drag = { x: ev.clientX, y: ev.clientY, rot: TM.rot.slice() }; $("#tmGlobe").classList.add("drag"); });
window.addEventListener("pointermove", (ev) => {
  if (!TM.drag) return;
  const k = 0.35, rot = TM.drag.rot;
  TM.rot = [rot[0] + (ev.clientX - TM.drag.x) * k, Math.max(-80, Math.min(80, rot[1] - (ev.clientY - TM.drag.y) * k)), 0];
  if (TM_RED || !TM.raf) tmDraw(performance.now());
});
window.addEventListener("pointerup", () => {
  if (!TM.drag) return;
  TM.drag = null; TM.lastDrag = performance.now(); $("#tmGlobe").classList.remove("drag");
  TM.base = [TM.rot[0] - 22 * Math.sin(TM.phase), TM.rot[1] - 3 * Math.sin(TM.phase * 0.7), 0];  // keep swaying from here, no jump
});
$("#mapDays").onchange = loadThreatMap;
setInterval(() => { if ($("#live").classList.contains("on") && !document.hidden && TM.visible) loadThreatMap(); }, 60000);
