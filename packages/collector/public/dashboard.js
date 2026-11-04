/**
 * Antirea control panel. Vanilla JS, no external deps (CSP-friendly).
 * i18n via window.I18N; admin token kept in sessionStorage only.
 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const statusEl = $("#status");
const TOKEN_KEY = "antirea_admin_token";
const LANG_KEY = "antirea_lang";

let lang = (() => {
  try {
    return localStorage.getItem(LANG_KEY) || (navigator.language || "en").slice(0, 2);
  } catch {
    return "en";
  }
})();
if (!window.I18N[lang]) lang = "en";

function t(key) {
  const dict = window.I18N[lang] || window.I18N.en;
  return dict[key] ?? window.I18N.en[key] ?? key;
}

function getToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
}
function setToken(v) {
  try { sessionStorage.setItem(TOKEN_KEY, v); } catch { /* ignore */ }
}
function setStatus(msg) { statusEl.textContent = msg || ""; }

function applyI18n() {
  const dict = window.I18N[lang] || window.I18N.en;
  document.documentElement.lang = lang;
  document.documentElement.dir = dict._dir || "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
}

function buildLangSelect() {
  const sel = $("#lang");
  sel.innerHTML = "";
  for (const code of Object.keys(window.I18N)) {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = window.I18N[code]._name;
    if (code === lang) opt.selected = true;
    sel.appendChild(opt);
  }
  sel.addEventListener("change", () => {
    lang = sel.value;
    try { localStorage.setItem(LANG_KEY, lang); } catch { /* ignore */ }
    applyI18n();
    load();
  });
}

async function api(path, opts) {
  const res = await fetch(path, {
    ...opts,
    headers: { Authorization: `Bearer ${getToken()}`, ...(opts && opts.headers) },
  });
  if (res.status === 401) { showAuth(); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function showAuth() { $("#auth").hidden = false; $("#content").hidden = true; }
function showContent() { $("#auth").hidden = true; $("#content").hidden = false; }

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function fmtTime(ms) {
  return new Date(ms).toLocaleString(lang, { dateStyle: "short", timeStyle: "medium" });
}
function num(n) { return Number(n).toLocaleString(lang); }

function renderBars(tableSel, rows) {
  const tbody = $(tableSel + " tbody");
  tbody.innerHTML = "";
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0) || 1;
  for (const r of rows) {
    const tr = document.createElement("tr");
    const pct = Math.round((r.count / max) * 100);
    tr.innerHTML = `<th scope="row">${esc(r.label)}</th>` +
      `<td><span class="bar-val">${num(r.count)}</span><span class="bar" style="width:${pct}%"></span></td>`;
    tbody.appendChild(tr);
  }
  if (rows.length === 0) tbody.innerHTML = `<tr><td colspan="2">${esc(t("empty"))}</td></tr>`;
}

function renderTimeline(points) {
  const el = $("#timeline");
  el.innerHTML = "";
  const max = points.reduce((m, p) => Math.max(m, p.count), 0) || 1;
  let total = 0;
  for (const p of points) {
    total += p.count;
    const bar = document.createElement("div");
    bar.className = "tl-bar";
    bar.style.height = Math.max(2, Math.round((p.count / max) * 100)) + "%";
    bar.title = `${fmtTime(Number(p.label))}: ${p.count}`;
    el.appendChild(bar);
  }
  el.setAttribute("aria-label", `${t("timeline")}: ${total}`);
  if (points.length === 0) el.textContent = t("empty");
}

function badge(action) {
  if (action === "decoy") return '<span class="badge decoy">decoy</span>';
  if (action === "would_decoy") return '<span class="badge would">shadow</span>';
  return '<span class="badge client">—</span>';
}

function renderRecent(events) {
  const tbody = $("#recent tbody");
  tbody.innerHTML = "";
  for (const e of events) {
    const names = Array.isArray(e.signals) ? e.signals.map((s) => s.name).join(", ") : "";
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${esc(fmtTime(e.ts))}</td><td>${esc(e.siteId)}</td><td>${esc(e.source)}</td>` +
      `<td>${esc(e.country || "??")}</td><td class="path">${esc(e.path)}</td>` +
      `<td>${badge(e.honeypot)}</td><td class="ua" title="${esc(names)}">${esc(names)}</td>`;
    tbody.appendChild(tr);
  }
  if (events.length === 0) tbody.innerHTML = `<tr><td colspan="7">${esc(t("empty"))}</td></tr>`;
}

function renderOffenders(rows) {
  const tbody = $("#offenders tbody");
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="path">${esc((r.label || "").slice(0, 16))}</td>` +
      `<td>${esc(r.country || "??")}</td><td>${num(r.count)}</td><td>${badge(r.lastAction)}</td>`;
    tbody.appendChild(tr);
  }
  if (rows.length === 0) tbody.innerHTML = `<tr><td colspan="4">${esc(t("empty"))}</td></tr>`;
}

function currentQuery() {
  const days = $("#days").value;
  const site = $("#site").value.trim();
  const p = new URLSearchParams({ days });
  if (site) p.set("site", site);
  return p.toString();
}

function fillSettings(cfg) {
  $("#s-enabled").checked = cfg.enabled !== false;
  $("#s-mode").value = cfg.mode === "live" ? "live" : "shadow";
  $("#s-threshold").value = typeof cfg.threshold === "number" ? cfg.threshold : 0.7;
  $("#s-sitekey").value = cfg.siteKey || "";
  $("#s-allow").value = (cfg.allowIps || []).join("\n");
  $("#s-block").value = (cfg.blockIps || []).join("\n");
}

async function loadSettings() {
  const site = $("#site").value.trim();
  if (!site) { $("#settings-form").style.opacity = "0.5"; return; }
  $("#settings-form").style.opacity = "1";
  try {
    const { config } = await api(`/api/config?site=${encodeURIComponent(site)}`);
    fillSettings(config);
  } catch { /* handled in api() */ }
}

async function load() {
  if (!getToken()) { showAuth(); return; }
  setStatus(t("status.loading"));
  try {
    const q = currentQuery();
    const [stats, recent, offenders] = await Promise.all([
      api(`/api/stats?${q}`), api(`/api/events?${q}`), api(`/api/offenders?${q}`),
    ]);
    showContent();
    $("#t-events").textContent = num(stats.totals.events);
    $("#t-uniques").textContent = num(stats.totals.uniques);
    $("#t-sites").textContent = num(stats.totals.sites);
    renderTimeline(stats.timeline);
    renderBars("#country", stats.byCountry);
    renderBars("#signal", stats.bySignal);
    renderRecent(recent.events);
    renderOffenders(offenders.offenders);
    await loadSettings();
    setStatus(`${t("status.updated")}: ${fmtTime(Date.now())}`);
  } catch (err) {
    if (err.message !== "unauthorized") setStatus(`${t("status.error")}: ${err.message}`);
  }
}

$("#controls").addEventListener("submit", (e) => { e.preventDefault(); load(); });
$("#auth-form").addEventListener("submit", (e) => {
  e.preventDefault();
  setToken($("#token").value.trim());
  $("#token").value = "";
  load();
});
$("#settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const site = $("#site").value.trim();
  if (!site) return;
  const toList = (v) => v.split("\n").map((s) => s.trim()).filter(Boolean);
  const body = {
    enabled: $("#s-enabled").checked,
    mode: $("#s-mode").value,
    threshold: Number($("#s-threshold").value),
    siteKey: $("#s-sitekey").value.trim(),
    allowIps: toList($("#s-allow").value),
    blockIps: toList($("#s-block").value),
  };
  try {
    await api(`/api/config?site=${encodeURIComponent(site)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    $("#settings-status").textContent = t("settings.saved");
  } catch (err) {
    if (err.message !== "unauthorized") $("#settings-status").textContent = `${t("status.error")}: ${err.message}`;
  }
});

buildLangSelect();
applyI18n();
load();
