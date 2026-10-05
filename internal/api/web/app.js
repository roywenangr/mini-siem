// Mini SIEM dashboard. Log data is attacker-controlled, so every value is
// written with textContent; nothing from the API is ever parsed as HTML.
"use strict";

const state = {
  range: "1h",
  alertStatus: "open",
  eventFilter: {},
  oldestEventId: 0,
  paged: false, // user loaded older events; live updates must not reset the table
  rules: [],
  ruleById: new Map(),
  ruleFilter: { q: "", origin: "" },
  token: readToken(),
};

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";

function readToken() {
  try { return localStorage.getItem("siem-token") || ""; } catch { return ""; }
}
function saveToken(t) {
  try { localStorage.setItem("siem-token", t); } catch { /* storage unavailable */ }
}

// ---------- API ----------

class AuthError extends Error {}

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) throw new AuthError();
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

function promptLogin() {
  const dlg = $("login");
  if (!dlg.open) dlg.showModal();
}

$("login-form").addEventListener("submit", () => {
  state.token = new FormData($("login-form")).get("token");
  saveToken(state.token);
  connectStream();
  refreshAll();
});

async function guarded(fn) {
  try {
    await fn();
  } catch (e) {
    if (e instanceof AuthError) promptLogin();
    else console.error(e);
  }
}

// ---------- helpers ----------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

const nf = new Intl.NumberFormat();
const fmtNum = (n) => nf.format(n || 0);

function fmtTime(iso, withSeconds = true) {
  const d = new Date(iso);
  const today = new Date();
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: withSeconds ? "2-digit" : undefined, hour12: false });
  if (d.toDateString() === today.toDateString()) return time;
  return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
}

function tiBadge(ev) {
  const lists = ev.fields && ev.fields.ti_lists;
  if (!lists) return null;
  return el("span", { class: "badge ti", title: "Listed in threat intel: " + lists }, "▲ TI");
}

function safeURL(s) {
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch { return null; }
}

function sevBadge(sev) {
  return el("span", { class: "sev sev-" + sev }, sev);
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function setPressed(group, attr, value) {
  for (const b of group.querySelectorAll("button")) {
    b.setAttribute("aria-pressed", String(b.dataset[attr] === value));
  }
}

// ---------- stats + chart ----------

async function loadStats() {
  const { stats } = await api("/api/stats?range=" + state.range);
  $("t-events").textContent = fmtNum(stats.window_events);
  const open = Object.values(stats.open_alerts_by_severity).reduce((a, b) => a + b, 0);
  const high = (stats.open_alerts_by_severity.high || 0) + (stats.open_alerts_by_severity.critical || 0);
  $("t-open").textContent = fmtNum(open);
  $("t-high").textContent = fmtNum(high);
  $("t-high").classList.toggle("alarm", high > 0);
  $("t-total").textContent = fmtNum(stats.total_events);
  drawChart(stats.timeline, stats.bucket_seconds);
  drawTopIPs(stats.top_source_ips, stats.top_alerted_ips);
}

function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function drawChart(buckets, bucketSeconds) {
  const host = $("chart");
  host.replaceChildren();
  const W = host.clientWidth || 800, H = host.clientHeight || 180;
  const padL = 40, padR = 4, padT = 8, padB = 34;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = niceMax(Math.max(0, ...buckets.map((b) => b.events)));
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });

  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i;
    const y = padT + plotH - (v / max) * plotH;
    root.append(svg("line", { class: "gridline", x1: padL, x2: W - padR, y1: y, y2: y }));
    const label = svg("text", { class: "axis", x: padL - 6, y: y + 4, "text-anchor": "end" });
    label.textContent = fmtNum(v);
    root.append(label);
  }

  const step = plotW / buckets.length;
  const gap = step > 6 ? 2 : 0;
  const barW = Math.max(1, step - gap);
  const r = Math.min(4, barW / 2);
  const labelEvery = Math.ceil(buckets.length / Math.max(1, Math.floor(plotW / 70)));
  const tip = $("tooltip");
  let alertBuckets = 0;

  buckets.forEach((b, i) => {
    const x = padL + i * step + gap / 2;
    const h = (b.events / max) * plotH;
    const base = padT + plotH;
    let bar = null;
    if (h > 0) {
      const rr = Math.min(r, h);
      bar = svg("path", {
        class: "bar",
        d: `M${x},${base} V${base - h + rr} Q${x},${base - h} ${x + rr},${base - h} H${x + barW - rr} Q${x + barW},${base - h} ${x + barW},${base - h + rr} V${base} Z`,
      });
      root.append(bar);
    }
    if (b.alerts > 0) {
      alertBuckets++;
      const cx = x + barW / 2, ty = base + 6;
      root.append(svg("path", { class: "alert-tick", d: `M${cx},${ty} l4,7 h-8 z` }));
    }
    if (i % labelEvery === 0) {
      const t = svg("text", { class: "axis", x: x + barW / 2, y: H - 4, "text-anchor": "middle" });
      t.textContent = fmtTime(b.start, false);
      root.append(t);
    }
    const hit = svg("rect", { class: "hit", x: padL + i * step, y: padT, width: step, height: plotH + 16 });
    hit.addEventListener("mouseenter", () => {
      bar?.classList.add("hover");
      const end = new Date(new Date(b.start).getTime() + bucketSeconds * 1000);
      tip.replaceChildren(
        el("div", {}, fmtTime(b.start) + " – " + fmtTime(end.toISOString())),
        el("div", {}, el("strong", {}, fmtNum(b.events)), " events"),
        b.alerts ? el("div", {}, el("strong", {}, fmtNum(b.alerts)), " alerts") : null,
      );
      tip.hidden = false;
      const card = host.parentElement.getBoundingClientRect();
      const box = host.getBoundingClientRect();
      const px = box.left - card.left + (x / W) * box.width;
      tip.style.left = Math.min(Math.max(8, px - tip.offsetWidth / 2), card.width - tip.offsetWidth - 8) + "px";
      tip.style.top = box.top - card.top - tip.offsetHeight + 4 + "px";
    });
    hit.addEventListener("mouseleave", () => { bar?.classList.remove("hover"); tip.hidden = true; });
    root.append(hit);
  });

  host.append(root);
  const per = bucketSeconds >= 60 ? bucketSeconds / 60 + " min" : bucketSeconds + " s";
  $("chart-note").textContent = `Per ${per}` + (alertBuckets ? " · ▲ marks intervals where alerts fired" : "");
}

function drawTopIPs(top, alerted) {
  const list = $("top-ips");
  list.replaceChildren();
  $("top-empty").hidden = top.length > 0;
  const flagged = new Map(alerted.map((a) => [a.key, a.count]));
  const max = Math.max(1, ...top.map((t) => t.count));
  for (const t of top) {
    const fill = el("div", { class: "fill" });
    fill.style.width = (t.count / max) * 100 + "%";
    const name = el("span", {},
      el("button", { class: "link", type: "button", title: "Show events from this IP", onclick: () => filterByIP(t.key) }, t.key),
      flagged.has(t.key) ? el("span", { class: "flag" }, "▲ " + flagged.get(t.key) + " alert" + (flagged.get(t.key) > 1 ? "s" : "")) : null,
    );
    list.append(el("li", {}, name, el("span", { class: "count" }, fmtNum(t.count)), el("div", { class: "track" }, fill)));
  }
}

function filterByIP(ip) {
  const form = $("event-filters");
  form.elements.src_ip.value = ip;
  form.requestSubmit();
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- alerts ----------

async function loadAlerts() {
  const qs = new URLSearchParams({ limit: "100" });
  if (state.alertStatus) qs.set("status", state.alertStatus);
  const { alerts } = await api("/api/alerts?" + qs);
  const body = $("alerts");
  body.replaceChildren();
  $("alerts-empty").hidden = alerts.length > 0;
  for (const a of alerts) {
    const actions = el("div", { class: "row-actions" });
    if (a.status === "open") actions.append(actionButton(a.id, "acknowledged", "Ack"));
    if (a.status !== "closed") actions.append(actionButton(a.id, "closed", "Close"));
    else actions.append(actionButton(a.id, "open", "Reopen"));
    const row = el("tr", { class: "clickable", onclick: () => openAlert(a.id) },
      el("td", {}, sevBadge(a.severity)),
      el("td", {}, el("div", {}, a.rule_name), el("div", { class: "muted" }, a.description)),
      el("td", { class: "mono" }, a.group_key || "–"),
      el("td", { class: "num" }, fmtNum(a.count)),
      el("td", { class: "nowrap" }, fmtTime(a.last_seen), el("div", { class: "status" }, a.status)),
      el("td", {}, actions),
    );
    body.append(row);
  }
}

function actionButton(id, status, label) {
  return el("button", {
    class: "ghost", type: "button",
    onclick: (e) => { e.stopPropagation(); setStatus(id, status); },
  }, label);
}

function setStatus(id, status) {
  return guarded(async () => {
    await api("/api/alerts/" + id, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if ($("detail").open) await openAlert(id);
    await Promise.all([loadAlerts(), loadStats()]);
  });
}

function openAlert(id) {
  return guarded(async () => {
    const { alert: a, events } = await api("/api/alerts/" + id);
    $("detail-title").replaceChildren(sevBadge(a.severity), " ", a.rule_name);
    $("detail-desc").textContent = a.description;
    const meta = $("detail-meta");
    meta.replaceChildren();
    const rows = [
      ["Alert", "#" + a.id],
      ["Rule", a.rule_id],
      ["Group", a.group_key || "–"],
      ["Status", a.status],
      ["First seen", new Date(a.first_seen).toLocaleString()],
      ["Last seen", new Date(a.last_seen).toLocaleString()],
      ["Matched events", fmtNum(a.count)],
    ];
    const rule = state.ruleById.get(a.rule_id);
    if (rule && rule.origin === "sigma") rows.push(["Source", "Sigma community rule"]);
    if (rule && rule.tags && rule.tags.length) rows.push(["Tags", rule.tags.join(", ")]);
    for (const [k, v] of rows) meta.append(el("dt", {}, k), el("dd", {}, v));
    const refs = $("detail-refs");
    refs.replaceChildren();
    for (const r of (rule && rule.references) || []) {
      const href = safeURL(r);
      if (href) refs.append(el("a", { href, target: "_blank", rel: "noopener noreferrer" }, href));
    }
    const actions = $("detail-actions");
    actions.replaceChildren();
    if (a.status === "open") actions.append(actionButton(a.id, "acknowledged", "Acknowledge"));
    if (a.status !== "closed") actions.append(actionButton(a.id, "closed", "Close"));
    else actions.append(actionButton(a.id, "open", "Reopen"));
    if (a.group_key) {
      actions.append(el("button", { class: "ghost", type: "button", onclick: () => { $("detail").close(); filterByIP(a.group_key); } }, "All events from " + a.group_key));
    }
    const tbody = $("detail-events");
    tbody.replaceChildren();
    for (const ev of events) {
      tbody.append(el("tr", {},
        el("td", { class: "nowrap" }, fmtTime(ev.timestamp)),
        el("td", {}, ev.type, tiBadge(ev)),
        el("td", {}, ev.user || "–"),
        el("td", {}, ev.message),
      ));
    }
    if (!events.length) tbody.append(el("tr", {}, el("td", { colspan: "4", class: "muted" }, "Events were removed by retention.")));
    if (!$("detail").open) $("detail").showModal();
  });
}

$("detail-close").addEventListener("click", () => $("detail").close());
$("detail").addEventListener("click", (e) => { if (e.target === $("detail")) $("detail").close(); });

// ---------- events ----------

async function loadEvents(append = false) {
  const qs = new URLSearchParams({ limit: "50" });
  for (const [k, v] of Object.entries(state.eventFilter)) if (v) qs.set(k, v);
  if (append && state.oldestEventId) qs.set("before_id", state.oldestEventId);
  const { events } = await api("/api/events?" + qs);
  const body = $("events");
  if (!append) body.replaceChildren();
  for (const ev of events) {
    body.append(el("tr", {},
      el("td", { class: "nowrap" }, fmtTime(ev.timestamp)),
      el("td", {}, ev.source),
      el("td", {}, ev.type),
      el("td", { class: "nowrap" }, ev.src_ip ? el("button", { class: "link", type: "button", onclick: () => filterByIP(ev.src_ip) }, ev.src_ip) : "–", tiBadge(ev)),
      el("td", {}, ev.user || "–"),
      el("td", {}, ev.message),
    ));
  }
  if (events.length) state.oldestEventId = events[events.length - 1].id;
  $("more").hidden = events.length < 50;
  if (!append && !events.length) {
    body.append(el("tr", {}, el("td", { colspan: "6", class: "muted" }, "No events match.")));
  }
}

$("event-filters").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  state.eventFilter = { type: fd.get("type"), src_ip: fd.get("src_ip").trim(), q: fd.get("q").trim() };
  state.oldestEventId = 0;
  state.paged = false;
  guarded(() => loadEvents());
});
$("event-filters").addEventListener("reset", () => {
  state.eventFilter = {};
  state.oldestEventId = 0;
  state.paged = false;
  setTimeout(() => guarded(() => loadEvents()));
});
$("more").addEventListener("click", () => {
  state.paged = true;
  guarded(() => loadEvents(true));
});

// ---------- rules ----------

function describeCondition(cond) {
  if (!cond) return "";
  return Object.entries(cond).map(([field, m]) => {
    const parts = [];
    if (m.equals !== undefined) parts.push(`= ${m.equals}`);
    if (m.not !== undefined) parts.push(`≠ ${m.not}`);
    if (m.in) parts.push(`in [${m.in.join(", ")}]`);
    if (m.not_in) parts.push(`not in [${m.not_in.join(", ")}]`);
    if (m.contains) parts.push(`contains "${m.contains}"`);
    if (m.prefix) parts.push(`starts with "${m.prefix}"`);
    if (m.regex) parts.push(`~ /${m.regex}/`);
    if (m.gte !== undefined) parts.push(`≥ ${m.gte}`);
    if (m.lte !== undefined) parts.push(`≤ ${m.lte}`);
    if (m.exists !== undefined) parts.push(m.exists ? "exists" : "missing");
    return `${field} ${parts.join(" and ")}`;
  }).join(", ");
}

function describeRule(r) {
  const where = describeCondition(r.where);
  switch (r.type) {
    case "threshold":
      return `${r.threshold}+ ${r.distinct ? "distinct " + r.distinct : "events"} per ${r.group_by} in ${r.window} where ${where}`;
    case "sequence":
      return `${r.threshold}+ where ${where}, then ${describeCondition(r.then)}, per ${r.group_by} in ${r.window}`;
    default:
      return `any event where ${where}` + (r.window ? ` (once per ${r.group_by || "rule"} per ${r.window})` : "");
  }
}

async function loadRules() {
  const { rules, sigma } = await api("/api/rules");
  state.rules = rules;
  state.ruleById = new Map(rules.map((r) => [r.id, r]));
  const active = rules.filter((r) => !r.disabled);
  const nSigma = active.filter((r) => r.origin === "sigma").length;
  $("rules-count").textContent = `${active.length} active · ${active.length - nSigma} built-in · ${nSigma} Sigma`;
  if (sigma) {
    const skipped = Object.values(sigma.skipped || {}).reduce((x, y) => x + y, 0);
    $("sigma-report").textContent =
      `Sigma: ${fmtNum(sigma.loaded)} rules loaded from ${fmtNum(sigma.files)} files. ` +
      `${fmtNum(skipped)} skipped, mostly rules for log sources this SIEM does not ingest (Windows, cloud, EDR).`;
  } else {
    $("sigma-report").textContent = "No Sigma rules loaded. Run `make sigma` and add sigma.paths to the config.";
  }
  renderRules();
}

function renderRules() {
  const q = state.ruleFilter.q.toLowerCase();
  const body = $("rules");
  body.replaceChildren();
  const shown = state.rules.filter((r) => {
    if (state.ruleFilter.origin && r.origin !== state.ruleFilter.origin) return false;
    if (!q) return true;
    return [r.name, r.id, r.description, ...(r.tags || [])].some((x) => x && x.toLowerCase().includes(q));
  });
  shown.sort((x, y) => sevRank(y.severity) - sevRank(x.severity) || x.name.localeCompare(y.name));
  for (const r of shown) {
    body.append(el("tr", {},
      el("td", {}, sevBadge(r.severity)),
      el("td", {},
        el("div", {}, r.name + (r.disabled ? " (disabled)" : ""), r.origin === "sigma" ? el("span", { class: "badge sigma" }, "Sigma") : null),
        el("div", { class: "muted mono" }, r.id)),
      el("td", {}, r.type),
      el("td", { class: "logic" }, r.logic || describeRule(r)),
      el("td", {}, ...(r.tags || []).map((t) => el("span", { class: "tag" }, t))),
    ));
  }
  if (!shown.length) body.append(el("tr", {}, el("td", { colspan: "5", class: "muted" }, "No rules match.")));
}

function sevRank(s) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[s] || 0;
}

$("rule-search").addEventListener("input", debounce((e) => {
  state.ruleFilter.q = e.target.value.trim();
  renderRules();
}, 150));
$("rule-origin").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  state.ruleFilter.origin = b.dataset.origin;
  setPressed($("rule-origin"), "origin", state.ruleFilter.origin);
  renderRules();
});

// ---------- threat intel ----------

async function loadIntel() {
  const { feeds } = await api("/api/intel");
  const list = $("feeds");
  list.replaceChildren();
  $("feeds-empty").hidden = feeds.length > 0;
  for (const f of feeds) {
    list.append(el("li", {},
      el("span", { class: "feed-name" }, f.name),
      el("span", { class: "count" }, fmtNum(f.entries) + " entries"),
      el("span", { class: "feed-meta" }, (f.url || f.path) + (f.loaded_at ? " · updated " + fmtTime(f.loaded_at, false) : "")),
      f.error ? el("span", { class: "feed-err" }, "Last refresh failed: " + f.error) : null,
    ));
  }
}

// ---------- live stream ----------

let stream;
const liveRefresh = debounce(() => guarded(() =>
  Promise.all([loadStats(), loadAlerts(), state.paged ? null : loadEvents()]),
), 1000);

function setLive(st, label) {
  $("live").dataset.state = st;
  $("live-label").textContent = label;
}

function connectStream() {
  if (stream) stream.close();
  const url = "/api/stream" + (state.token ? "?token=" + encodeURIComponent(state.token) : "");
  stream = new EventSource(url);
  stream.onopen = () => setLive("live", "Live");
  stream.onerror = () => setLive("down", "Reconnecting");
  stream.addEventListener("alert", liveRefresh);
  stream.addEventListener("events", liveRefresh);
}

// ---------- wiring ----------

$("range").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  state.range = b.dataset.range;
  setPressed($("range"), "range", state.range);
  guarded(loadStats);
});

$("alert-status").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  state.alertStatus = b.dataset.status;
  setPressed($("alert-status"), "status", state.alertStatus);
  guarded(loadAlerts);
});

$("theme").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme
    ? root.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("siem-theme", root.dataset.theme); } catch { /* ignore */ }
});
try {
  const t = localStorage.getItem("siem-theme");
  if (t) document.documentElement.dataset.theme = t;
} catch { /* ignore */ }

window.addEventListener("resize", debounce(() => guarded(loadStats), 200));

function refreshAll() {
  // Rules first: alert details look up references and tags in them.
  return guarded(async () => {
    await loadRules();
    await Promise.all([loadStats(), loadAlerts(), loadEvents(), loadIntel()]);
  });
}

setInterval(() => guarded(loadIntel), 5 * 60 * 1000);

connectStream();
refreshAll();
