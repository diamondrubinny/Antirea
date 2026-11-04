/**
 * Antirea dashboard. Vanilla JS, no external deps (CSP-friendly).
 * The admin token is kept in sessionStorage only and sent as a Bearer header.
 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const statusEl = $("#status");

const TOKEN_KEY = "antirea_admin_token";
function getToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
}
function setToken(t) {
  try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* ignore */ }
}

function setStatus(msg) { statusEl.textContent = msg || ""; }

async function api(path) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } });
  if (res.status === 401) {
    showAuth();
    throw new Error("unauthorized");
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function showAuth() {
  $("#auth").hidden = false;
  $("#content").hidden = true;
}
function showContent() {
  $("#auth").hidden = true;
  $("#content").hidden = false;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]),
  );
}

function fmtTime(ms) {
  const d = new Date(ms);
  return d.toLocaleString("he-IL", { dateStyle: "short", timeStyle: "medium" });
}

function renderBars(tableSel, rows) {
  const tbody = $(tableSel + " tbody");
  tbody.innerHTML = "";
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0) || 1;
  for (const r of rows) {
    const tr = document.createElement("tr");
    const pct = Math.round((r.count / max) * 100);
    tr.innerHTML =
      `<th scope="row">${esc(r.label)}</th>` +
      `<td><span class="bar-val">${r.count.toLocaleString("he-IL")}</span>` +
      `<span class="bar" style="width:${pct}%"></span></td>`;
    tbody.appendChild(tr);
  }
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2">אין נתונים בטווח שנבחר.</td></tr>';
  }
}

function renderTimeline(points, bucketMs) {
  const el = $("#timeline");
  el.innerHTML = "";
  const max = points.reduce((m, p) => Math.max(m, p.count), 0) || 1;
  const unit = bucketMs >= 864e5 ? "יום" : "שעה";
  let total = 0;
  for (const p of points) {
    total += p.count;
    const bar = document.createElement("div");
    bar.className = "tl-bar";
    bar.style.height = Math.max(2, Math.round((p.count / max) * 100)) + "%";
    const when = fmtTime(Number(p.label));
    bar.title = `${when}: ${p.count}`;
    el.appendChild(bar);
  }
  el.setAttribute("aria-label", `גרף ניסיונות לפי ${unit}. סה"כ ${total} אירועים ב-${points.length} מקטעים.`);
  if (points.length === 0) el.textContent = "אין נתונים בטווח שנבחר.";
}

function honeypotBadge(action) {
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
      `<td>${esc(fmtTime(e.ts))}</td>` +
      `<td>${esc(e.siteId)}</td>` +
      `<td>${esc(e.source)}</td>` +
      `<td>${esc(e.country || "??")}</td>` +
      `<td class="path">${esc(e.path)}</td>` +
      `<td>${honeypotBadge(e.honeypot)}</td>` +
      `<td class="ua" title="${esc(names)}">${esc(names)}</td>`;
    tbody.appendChild(tr);
  }
  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7">אין אירועים בטווח שנבחר.</td></tr>';
  }
}

function currentQuery() {
  const days = $("#days").value;
  const site = $("#site").value.trim();
  const p = new URLSearchParams({ days });
  if (site) p.set("site", site);
  return p.toString();
}

async function load() {
  if (!getToken()) { showAuth(); return; }
  setStatus("טוען…");
  try {
    const q = currentQuery();
    const [stats, recent] = await Promise.all([api(`/api/stats?${q}`), api(`/api/events?${q}`)]);
    showContent();
    $("#t-events").textContent = stats.totals.events.toLocaleString("he-IL");
    $("#t-uniques").textContent = stats.totals.uniques.toLocaleString("he-IL");
    $("#t-sites").textContent = stats.totals.sites.toLocaleString("he-IL");
    renderTimeline(stats.timeline, stats.bucketMs);
    renderBars("#country", stats.byCountry);
    renderBars("#signal", stats.bySignal);
    renderBars("#honeypot", stats.honeypot);
    renderRecent(recent.events);
    setStatus(`עודכן: ${fmtTime(Date.now())}`);
  } catch (err) {
    if (err.message !== "unauthorized") setStatus("שגיאה בטעינה: " + err.message);
  }
}

$("#controls").addEventListener("submit", (e) => { e.preventDefault(); load(); });
$("#auth-form").addEventListener("submit", (e) => {
  e.preventDefault();
  setToken($("#token").value.trim());
  $("#token").value = "";
  load();
});

load();
