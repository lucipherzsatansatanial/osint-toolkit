"use strict";

const MODULES = {
  domain:   { ph: "example.com", hint: "DNS records, WHOIS (RDAP), subdomains จาก Certificate Transparency, HTTP security headers, เทคโนโลยีเว็บ, TLS certificate" },
  ip:       { ph: "8.8.8.8", hint: "Reverse DNS, เจ้าของเครือข่าย (RDAP), Geolocation/ASN (ต้องมี IPINFO_TOKEN)" },
  email:    { ph: "name@example.com", hint: "ข้อมูลส่วนบุคคล — ต้องระบุฐานทางกฎหมาย PDPA · ตรวจ SPF/DMARC/DKIM, Gravatar, Data breach (ต้องมี HIBP_API_KEY)" },
  brand:    { ph: "mybrand.co.th", hint: "ค้นหา lookalike / typosquatting domain ที่จดทะเบียนแล้ว และใบรับรอง SSL ที่มีชื่อแบรนด์ (phishing monitoring)" },
  username: { ph: "johndoe", hint: "ข้อมูลส่วนบุคคล — ต้องระบุฐานทางกฎหมาย PDPA · ตรวจ username บน 14 แพลตฟอร์ม (เป็นเพียง possible match)" },
};
const LABELS = {
  dns: "DNS Records", whois_rdap: "WHOIS / RDAP", subdomains_ct: "Subdomains (CT logs)", http: "HTTP & Web",
  tls: "TLS Certificate", reverse_dns: "Reverse DNS", rdap: "Network Owner (RDAP)", geolocation: "Geolocation",
  mail_security: "Mail Security (SPF/DMARC/DKIM)", gravatar: "Gravatar", breaches: "Data Breaches (HIBP)",
  lookalike_domains: "Lookalike Domains", ct_keyword: "Certificates containing keyword", footprint: "Username Footprint",
};
const WIDE = new Set(["http", "subdomains_ct", "lookalike_domains", "ct_keyword", "footprint", "breaches"]);
const LEGAL_TH = {
  consent: "ความยินยอม (Consent)", contract: "สัญญา (Contract)", legal_obligation: "หน้าที่ตามกฎหมาย",
  vital_interest: "ประโยชน์สำคัญต่อชีวิต", public_task: "ภารกิจเพื่อประโยชน์สาธารณะ",
  legitimate_interest: "ประโยชน์โดยชอบด้วยกฎหมาย (Legitimate interest)", own_asset: "ตรวจทรัพย์สิน/ข้อมูลขององค์กรเอง",
};

const $ = (s) => document.querySelector(s);
let module = "domain", meta = null, last = null;

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = { get: (k) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } },
                set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };

function badge(key, val) {
  const v = String(val).toLowerCase();
  let cls = null;
  if (key === "risk") cls = { none: "b-ok", low: "b-warn", medium: "b-warn", high: "b-bad" }[v];
  else if (key === "grade") cls = { a: "b-ok", b: "b-warn", c: "b-warn", f: "b-bad" }[v];
  else if (key === "status" && ["found", "not_found", "unknown"].includes(v))
    cls = { found: "b-ok", not_found: "b-muted", unknown: "b-warn" }[v];
  else if (typeof val === "boolean") cls = val ? "b-ok" : "b-muted";
  return cls ? `<span class="badge ${cls}">${esc(val)}</span>` : null;
}

function isUrl(s) { return typeof s === "string" && /^https?:\/\/[^\s]+$/.test(s); }

function render(val, key = "") {
  if (val === null || val === undefined || val === "") return `<span class="muted">—</span>`;
  const b = badge(key, val);
  if (b) return b;
  if (Array.isArray(val)) {
    if (!val.length) return `<span class="muted">(ว่าง)</span>`;
    if (val.every((x) => x && typeof x === "object" && !Array.isArray(x))) return table(val);
    return `<div class="chips">${val.map((x) => `<span class="chip">${esc(typeof x === "object" ? JSON.stringify(x) : x)}</span>`).join("")}</div>`;
  }
  if (typeof val === "object") {
    return `<div class="kv">${Object.entries(val).map(([k, v]) =>
      `<div class="k">${esc(k)}</div><div class="v">${render(v, k)}</div>`).join("")}</div>`;
  }
  if (isUrl(val)) return `<a href="${esc(val)}" target="_blank" rel="noopener noreferrer">${esc(val)}</a>`;
  return `<span class="mono">${esc(val)}</span>`;
}

function table(rows) {
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  const cell = (k, v) => {
    if (Array.isArray(v)) return esc(v.join(", "));
    if (k === "url" && isUrl(v)) return `<a href="${esc(v)}" target="_blank" rel="noopener noreferrer">เปิด</a>`;
    return badge(k, v) ?? esc(typeof v === "object" && v !== null ? JSON.stringify(v) : v);
  };
  return `<div class="tbl-wrap"><table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td>${cell(c, r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function showResult(res) {
  last = res;
  const r = res.result || {};
  const okCount = Object.values(r).filter((x) => x.ok).length;
  $("#summary").innerHTML = `<b>${esc(res.module)}</b> · <span class="mono">${esc(res.target)}</span> ·
    สำเร็จ ${okCount}/${Object.keys(r).length} checks · scan #${esc(res.id)}`;
  $("#cards").innerHTML = Object.entries(r).map(([name, c]) => `
    <article class="card ${WIDE.has(name) ? "wide" : ""}">
      <h4>${esc(LABELS[name] || name)} <small>${esc(c.ms ?? "")} ms</small></h4>
      ${c.ok ? render(c.data) : `<div class="err">${esc(c.error)}</div>`}
    </article>`).join("");
  $("#raw").textContent = JSON.stringify(res, null, 2);
  $("#actions").hidden = false;
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  const key = $("#apiKey").value;
  if (key) headers["X-API-Key"] = key;
  const r = await fetch(path, { ...opts, headers });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = body.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => `${x.loc?.slice(-1)[0]}: ${x.msg}`).join("; ") : d || r.statusText);
  }
  return body;
}

function selectModule(m) {
  module = m;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.module === m));
  $("#target").placeholder = MODULES[m].ph;
  $("#moduleHint").textContent = MODULES[m].hint;
  $("#keywordRow").hidden = m !== "brand";
  const personal = meta?.personal_data_modules?.includes(m);
  $("#legalBasis").required = !!personal;
  $("#legalRow").firstChild.textContent = personal ? "ฐานทางกฎหมาย PDPA (บังคับ)" : "ฐานทางกฎหมาย PDPA (Legal basis)";
}

async function loadHistory() {
  try {
    const rows = await api("/api/history?limit=50");
    const counts = {};
    rows.forEach((h) => { counts[h.module] = (counts[h.module] || 0) + 1; });
    Object.keys(MODULES).forEach((m) => { $("#nb-" + m).textContent = counts[m] || 0; });
    $("#nb-all").textContent = rows.length;
    $("#history").innerHTML = rows.map((h) => `<li data-id="${h.id}">
      <b>#${h.id}</b> ${esc(h.module)} · <span class="t">${esc(h.target)}</span><br>
      <span class="muted">${esc(h.ts)} · ${esc(h.analyst)}${h.case_ref ? " · " + esc(h.case_ref) : ""}</span></li>`).join("")
      || `<li class="muted">ยังไม่มีประวัติ</li>`;
  } catch (e) {
    $("#history").innerHTML = `<li class="err">${esc(e.message)}</li>`;
  }
}

async function init() {
  meta = await fetch("/api/meta").then((r) => r.json());
  $("#legalBasis").innerHTML += meta.legal_bases.map((b) => `<option value="${b}">${esc(LEGAL_TH[b] || b)}</option>`).join("");
  $("#apiKeyRow").hidden = !meta.auth_required;
  $("#integrations").innerHTML = Object.entries(meta.integrations).map(([k, on]) =>
    `<span class="badge ${on ? "b-ok" : "b-muted"}" title="${on ? "เปิดใช้งาน" : "ยังไม่ตั้งค่า API key"}">${k.toUpperCase()} ${on ? "on" : "off"}</span>`).join("")
    + `<span class="badge b-muted">retention ${meta.retention_days}d</span>`;
  $("#analyst").value = store.get("analyst");
  $("#apiKey").value = store.get("apiKey");
  selectModule("domain");
  loadHistory();
  loadMe();
}

async function loadMe() {
  try {
    const me = await api("/api/me");
    if (me.named) { $("#analyst").value = me.name; $("#analyst").readOnly = true; $("#analyst").title = "ชื่อจาก token ของคุณ"; }
    if (!me.permissions.includes("osint.scan")) {
      $("#runBtn").disabled = true;
      $("#summary").textContent = `บทบาท ${me.role_th} ไม่มีสิทธิ์สแกน OSINT — ติดต่อผู้ดูแลระบบ`;
    }
  } catch { /* not logged in yet */ }
}

$("#tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-module]"); if (b) selectModule(b.dataset.module); });
$("#themeBtn").addEventListener("click", () => {
  const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  store.set("theme", t);
  $("#themeBtn span").textContent = t === "dark" ? "Light Mode" : "Dark Mode";
});
$("#themeBtn span").textContent = document.documentElement.dataset.theme === "dark" ? "Light Mode" : "Dark Mode";
$("#refreshHist").addEventListener("click", loadHistory);
$("#history").addEventListener("click", async (e) => {
  const li = e.target.closest("li[data-id]");
  if (!li) return;
  const row = await api(`/api/scan/${li.dataset.id}`);
  showResult({ id: row.id, module: row.module, target: row.target, result: row.result });
});
$("#toggleRaw").addEventListener("click", () => { $("#raw").hidden = !$("#raw").hidden; $("#cards").hidden = !$("#raw").hidden; });
$("#exportJson").addEventListener("click", () => {
  if (!last) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(last, null, 2)], { type: "application/json" }));
  a.download = `osint-${last.module}-${last.target}-${last.id}.json`.replace(/[^\w.@-]/g, "_");
  a.click();
  URL.revokeObjectURL(a.href);
});

$("#scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#runBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> กำลังสแกน…`;
  $("#summary").innerHTML = `<span class="spinner"></span> กำลังรวบรวมข้อมูลจากแหล่งสาธารณะ (อาจใช้เวลา 10-60 วินาที)`;
  $("#cards").innerHTML = "";
  store.set("analyst", $("#analyst").value);
  store.set("apiKey", $("#apiKey").value);
  loadMe();
  try {
    const res = await api("/api/scan", { method: "POST", body: JSON.stringify({
      module, target: $("#target").value, keyword: $("#keyword").value || null,
      analyst: $("#analyst").value, purpose: $("#purpose").value,
      legal_basis: $("#legalBasis").value || null, case_ref: $("#caseRef").value || null,
    }) });
    showResult(res);
    loadHistory();
  } catch (err) {
    $("#summary").innerHTML = `<span class="err">ผิดพลาด: ${esc(err.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "เริ่มสแกน";
  }
});

init();
