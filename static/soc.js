"use strict";
const $ = (s) => document.querySelector(s);
const DOMAINS = ["endpoint", "identity", "email", "network", "cloud"];
const TACTICS = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access",
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
    loadCti();
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
  } else if (ev === "tick") {
    msg.events.forEach((e) => addEvent(e, true));
    pushBucket(msg.events);
    if (msg.incidents) renderIncidents(msg.incidents);
    if (msg.endpoints) renderEndpoints(msg.endpoints);
    renderStats(msg.stats);
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
  setKpi("#k-open", s.open_incidents);
  setKpi("#k-coord", s.coordinated);
  setKpi("#k-cti", s.cti_hits);
  const ep = s.endpoints, total = ep.healthy + ep.at_risk + ep.compromised;
  setKpi("#k-ep", `${ep.healthy}/${total}`);
  $("#k-ep-s").innerHTML = `<span style="color:var(--high)">${ep.at_risk} at risk</span> · <span style="color:var(--critical)">${ep.compromised} compromised</span>`;
  setKpi("#k-crit", `${s.severity.critical} / ${s.severity.high}`);
  $("#k-crit-s").textContent = `medium ${s.severity.medium} · low ${s.severity.low}`;
  $("#k-open-s").textContent = `${s.open_incidents - s.coordinated} single-domain`;
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
  ctx.strokeStyle = css("--edr"); ctx.lineWidth = 1.5; ctx.stroke();
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
  ctx.strokeStyle = "#1a2440"; ctx.fillStyle = css("--muted"); ctx.font = "10px system-ui"; ctx.lineWidth = 1;
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
    <div><span class="sev" style="--sevc:var(--${esc(e.severity)})">${esc(e.severity)}</span> ${esc(e.title)}
    <div class="x">${esc(e.domain)} · ${esc(e.host)} · ${esc(e.user)} · ${esc(e.technique)} ${extra}
    ${e.cti_match ? `<span class="cti">⚑ CTI: ${esc(e.cti_match)}</span>` : ""}</div></div>`;
  const ul = $("#stream"); ul.prepend(li);
  while (ul.children.length > 60) ul.lastChild.remove();
}

// ---------- endpoints ----------
function renderEndpoints(eps) {
  const order = { compromised: 0, at_risk: 1, healthy: 2 };
  eps = [...eps].sort((a, b) => order[a.status] - order[b.status] || b.alerts - a.alerts);
  $("#endpoints tbody").innerHTML = eps.map((p) => `<tr><td>${esc(p.host)}</td><td class="muted">${esc(p.os)}</td>
    <td><span class="st ${esc(p.status)}">${esc(p.status.replace("_", " "))}</span></td>
    <td style="color:var(${p.realtime_protection ? "--cti" : "--critical"})">${p.realtime_protection ? "On" : "OFF"}</td>
    <td>${p.alerts}</td></tr>`).join("");
}

// ---------- incidents ----------
function renderIncidents(list) {
  state.incidents = list;
  $("#incidents").innerHTML = list.length ? list.map((i) => `<div class="inc ${i.coordinated ? "coord" : ""} ${i.status}"
      data-id="${i.id}" style="--sevc:var(--${esc(i.severity)})">
      <div class="t"><span>#${i.id} ${esc(i.title)}</span><span class="sev">${esc(i.severity)}</span></div>
      <div class="m">${i.domains.map((d) => `<span class="chip" style="color:var(--${esc(d)})">${esc(d)}</span>`).join("")}
        <span>${i.alerts.length} alerts</span><span>${esc(i.hosts.join(", "))}</span><span>${hhmmss(i.last_ts)}</span></div></div>`).join("")
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
  $("#d-title").innerHTML = `#${inc.id} · ${esc(inc.title)} · <span class="sev" style="--sevc:var(--${esc(inc.severity)})">${esc(inc.severity)}</span>
    <small class="muted">users: ${esc(inc.users.join(", "))} · tactics: ${esc(inc.tactics.join(" → "))}</small>`;
  // graph: domain nodes (left) → incident hub (center) → affected hosts (right)
  const W = 720, H = 300, doms = inc.domains, hosts = inc.hosts;
  const y = (i, n) => (H / (n + 1)) * (i + 1);
  let svg = "";
  doms.forEach((d, i) => {
    const yy = y(i, doms.length), col = css("--" + d), n = inc.alerts.filter((a) => a.domain === d).length;
    svg += `<path class="flow" d="M170 ${yy} C 260 ${yy}, 280 ${H / 2}, 330 ${H / 2}" stroke="${col}" fill="none" stroke-width="2"/>
      <rect x="20" y="${yy - 20}" width="150" height="40" rx="8" fill="#0d1424" stroke="${col}"/>
      <text x="34" y="${yy - 3}" style="fill:${col};font-weight:700;text-transform:uppercase">${esc(d)}</text>
      <text x="34" y="${yy + 13}" style="fill:${css("--muted")};font-size:11px">${n} alert(s)</text>`;
  });
  hosts.forEach((h, i) => {
    const yy = y(i, hosts.length);
    svg += `<path d="M450 ${H / 2} C 500 ${H / 2}, 510 ${yy}, 560 ${yy}" stroke="#3b4a72" fill="none" stroke-width="1.5"/>
      <rect x="560" y="${yy - 14}" width="145" height="28" rx="6" fill="#0d1424" stroke="#3b4a72"/>
      <text x="572" y="${yy + 4}" style="font-family:var(--mono);font-size:11px">${esc(h)}</text>`;
  });
  const sc = css("--" + inc.severity);
  svg += `<rect x="330" y="${H / 2 - 32}" width="120" height="64" rx="10" fill="#1a0d22" stroke="${sc}" stroke-width="2"/>
    <text x="390" y="${H / 2 - 8}" text-anchor="middle" style="fill:${sc};font-weight:700;font-size:11px">${inc.coordinated ? "COORDINATED" : "INCIDENT"}</text>
    <text x="390" y="${H / 2 + 10}" text-anchor="middle" style="font-weight:700">#${inc.id}</text>
    <text x="390" y="${H / 2 + 24}" text-anchor="middle" style="fill:${css("--muted")};font-size:10px">${inc.alerts.length} correlated</text>`;
  $("#graph").innerHTML = svg;
  $("#timeline").innerHTML = inc.alerts.map((a) => `<li style="--c:var(--${esc(a.domain)})">
    <span class="mono muted">${hhmmss(a.ts)}</span> <span class="sev" style="--sevc:var(--${esc(a.severity)})">${esc(a.severity)}</span>
    ${esc(a.title)}<div class="muted">${esc(a.domain)} · ${esc(a.host)} · ${esc(a.technique)}${a.cti_match ? ` · <span style="color:var(--cti)">CTI: ${esc(a.cti_match)}</span>` : ""}</div></li>`).join("");
}

// ---------- CTI ----------
async function loadCti(force) {
  $("#ctiStatus").textContent = "CTI: กำลังดึง…";
  try {
    const r = await fetch("/api/soc/cti" + (force ? "?refresh=true" : ""), { headers: headers() });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const f = await r.json();
    const ok = Object.values(f).filter((x) => x.ok).length;
    const el = $("#ctiStatus");
    el.textContent = `CTI: ${ok}/3 feeds live`;
    el.className = "pill " + (ok === 3 ? "ok" : ok ? "warn" : "bad");
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
renderTactics({});
connect();
