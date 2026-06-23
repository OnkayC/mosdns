const base = "/plugins/query_dashboard";
let paused = false;
let lastRecords = [];
let latestHealth = null;
let themeMode = localStorage.getItem("mosdns-dashboard-theme") || "auto";
let queryLimit = Number(localStorage.getItem("mosdns-dashboard-query-limit") || 500);
if (![50, 100, 500, 1000].includes(queryLimit)) queryLimit = 500;

const el = (id) => document.getElementById(id);
const fmt = (value) => value === undefined || value === null || value === "" ? "—" : String(value);
const fmtNum = (value) => Number(value || 0).toLocaleString();
const pct = (part, total) => total > 0 ? Math.round((part / total) * 100) : 0;
const escapeHTML = (value) => fmt(value).replace(/[&<>'"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[c]));

function qtypeName(type) {
  return ({1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS"})[type] || String(type);
}

function rcodeLabel(rcode) {
  if (rcode === undefined || rcode === null) return "—";
  return ({0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"})[rcode] || String(rcode);
}

function latency(value) {
  value = Number(value || 0);
  return value >= 1000 ? `${(value / 1000).toFixed(1)}ms` : `${value}µs`;
}

function routeClass(value) {
  return String(value || "neutral").replace(/[^a-zA-Z0-9_-]/g, "_");
}

async function getJSON(path) {
  const res = await fetch(`${base}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

function setStatus(ok, text) {
  el("statusDot").classList.toggle("error", !ok);
  el("statusText").textContent = text;
}

function updateThemeButton() {
  el("themeBtn").textContent = themeMode === "auto" ? "Auto" : themeMode[0].toUpperCase() + themeMode.slice(1);
}

function cycleTheme() {
  themeMode = themeMode === "auto" ? "light" : themeMode === "light" ? "dark" : "auto";
  if (themeMode === "auto") {
    localStorage.removeItem("mosdns-dashboard-theme");
    document.documentElement.removeAttribute("data-theme");
  } else {
    localStorage.setItem("mosdns-dashboard-theme", themeMode);
    document.documentElement.setAttribute("data-theme", themeMode);
  }
  updateThemeButton();
}

function renderBars(id, counts, options = {}) {
  const entries = Object.entries(counts || {}).filter(([, count]) => count > 0).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  const container = el(id);
  if (!entries.length) {
    container.innerHTML = `<div class="empty-state">No data yet</div>`;
    return total;
  }
  container.innerHTML = entries.map(([label, count]) => {
    const width = Math.max(2, pct(count, total));
    const cls = routeClass(label || "other");
    const shown = options.label ? options.label(label) : label;
    return `<div class="path-bar-row">
      <div class="path-label" title="${escapeHTML(shown)}">${escapeHTML(shown)}</div>
      <div class="path-bar-track"><div class="path-bar-fill ${cls}" style="width:${width}%"></div></div>
      <div class="path-pct">${pct(count, total)}%</div>
    </div>`;
  }).join("");
  return total;
}

function renderList(id, items, key) {
  const container = el(id);
  if (!items || !items.length) {
    container.innerHTML = `<div class="empty-state">No data yet</div>`;
    return;
  }
  container.innerHTML = items.map((item) => `<div class="list-item">
    <span class="list-label" title="${escapeHTML(item[key])}">${escapeHTML(item[key])}</span>
    <span class="list-count">${fmtNum(item.count)}</span>
  </div>`).join("");
}

function populateRouteFilter(routeCounts) {
  const select = el("logFilterPath");
  const current = select.value;
  const routes = Object.keys(routeCounts || {}).sort();
  select.innerHTML = `<option value="">all routes</option>` + routes.map((route) => `<option value="${escapeHTML(route)}">${escapeHTML(route)}</option>`).join("");
  select.value = routes.includes(current) ? current : "";
}

function filteredRecords() {
  const domain = el("logFilterDomain").value.trim().toLowerCase();
  const route = el("logFilterPath").value;
  const transport = el("logFilterTransport").value;
  const cache = el("logFilterCache").value;
  return lastRecords.filter((record) => {
    if (domain && !String(record.qname || "").toLowerCase().includes(domain)) return false;
    if (route && record.route !== route) return false;
    if (transport && record.transport !== transport) return false;
    if (cache && record.cache_status !== cache) return false;
    return true;
  });
}

function renderRecords(records) {
  el("queryCount").textContent = `${fmtNum(records.length)} shown · ${fmtNum(lastRecords.length)} fetched`;
  if (!records.length) {
    el("records").innerHTML = `<tr><td colspan="10" class="empty-state">No matching queries</td></tr>`;
    return;
  }
  el("records").innerHTML = records.map((record) => {
    const route = record.route || record.entry || "—";
    const cache = record.cache_status || "—";
    const rcode = rcodeLabel(record.rcode);
    const rcodeClass = record.rcode && record.rcode !== 0 ? " error" : " neutral";
    return `<tr>
      <td>${new Date(record.time).toLocaleTimeString()}</td>
      <td>${escapeHTML(record.client)}</td>
      <td class="domain-cell" title="${escapeHTML(record.qname)}">${escapeHTML(record.qname)}</td>
      <td>${escapeHTML(qtypeName(record.qtype))}</td>
      <td><span class="path-tag ${routeClass(route)}">${escapeHTML(route)}</span></td>
      <td><span class="path-tag ${routeClass(record.transport)}">${escapeHTML(record.transport)}</span></td>
      <td><span class="path-tag${rcodeClass}">${escapeHTML(rcode)}</span></td>
      <td><span class="path-tag ${routeClass(cache)}">${escapeHTML(cache)}</span></td>
      <td>${latency(record.latency_us)}</td>
      <td title="${escapeHTML(record.error || record.upstream)}">${escapeHTML(record.error || record.upstream)}</td>
    </tr>`;
  }).join("");
}

function applyLogFilter() {
  renderRecords(filteredRecords());
}

function updateStats(health, stats, domains, clients, routes) {
  const total = stats.total || 0;
  const cacheCounts = stats.cache_status_counts || {};
  const hit = (cacheCounts.hit || 0) + (cacheCounts.lazy_hit || 0);
  const miss = cacheCounts.miss || 0;
  const cacheKnown = hit + miss;
  const errorCount = Object.entries(stats.rcode_counts || {}).reduce((sum, [rcode, count]) => rcode === "0" ? sum : sum + count, 0);

  el("totalQueries").textContent = fmtNum(total);
  el("qps").textContent = `${(total / 300).toFixed(2)} qps · 5m window`;
  el("cacheRate").textContent = cacheKnown ? `${pct(hit, cacheKnown)}%` : "—";
  el("cacheEntries").textContent = `${fmtNum(hit)} hits · ${fmtNum(miss)} misses`;
  el("errorCount").textContent = fmtNum(errorCount);
  el("errorSub").textContent = `${fmtNum(stats.rcode_counts?.["3"] || 0)} NXDOMAIN`;
  el("recentSize").textContent = fmtNum(health.recent_size);
  el("recentSub").textContent = `/ ${fmtNum(health.recent_capacity)} capacity`;
  el("p95Latency").textContent = latency(stats.latency_us?.p95);
  el("p99Latency").textContent = `p99 ${latency(stats.latency_us?.p99)}`;
  el("sqliteStatus").textContent = health.sqlite_enabled ? "on" : "off";
  el("sqliteErrors").textContent = `${fmtNum(health.sqlite_write_errors_total)} write errors`;

  el("healthCapacity").textContent = `${fmtNum(health.recent_size)} / ${fmtNum(health.recent_capacity)}`;
  el("healthDropped").textContent = fmtNum(health.dropped_total);
  el("healthSqliteErrors").textContent = fmtNum(health.sqlite_write_errors_total);
  el("healthNewest").textContent = health.newest_time ? new Date(health.newest_time).toLocaleTimeString() : "—";

  const routeTotal = renderBars("pathBars", stats.route_counts || {});
  el("routeTotal").textContent = `${fmtNum(routeTotal)} queries`;
  const transportCounts = Object.fromEntries(Object.entries((lastRecords || []).reduce((acc, r) => (acc[r.transport || "unknown"] = (acc[r.transport || "unknown"] || 0) + 1, acc), {})));
  const transportTotal = renderBars("transportBars", transportCounts);
  el("transportTotal").textContent = `${fmtNum(transportTotal)} recent`;
  const cacheTotal = renderBars("cacheBars", stats.cache_status_counts || {}, { label: (v) => v === "lazy_hit" ? "lazy hit" : v });
  el("cacheTotal").textContent = `${fmtNum(cacheTotal)} queries`;

  renderList("topDomains", domains.items || [], "qname");
  renderList("topClients", clients.items || [], "client");
  renderList("routesList", routes.items || [], "route");
  populateRouteFilter(stats.route_counts || {});
}

async function refresh() {
  if (paused) return;
  try {
    const [health, stats, recent, domains, clients, routes] = await Promise.all([
      getJSON("/health"),
      getJSON("/api/stats?window=5m"),
      getJSON(`/api/query-log?limit=${queryLimit}`),
      getJSON("/api/top-domains?since=1h&limit=12"),
      getJSON("/api/top-clients?since=1h&limit=12"),
      getJSON("/api/routes?since=1h"),
    ]);
    latestHealth = health;
    lastRecords = recent.records || [];
    updateStats(health, stats, domains, clients, routes);
    applyLogFilter();
    setStatus(true, "connected");
  } catch (err) {
    setStatus(false, "dashboard error");
    el("records").innerHTML = `<tr><td colspan="10" class="error-text">${escapeHTML(err.message)}</td></tr>`;
  }
}

el("pauseBtn").addEventListener("click", () => {
  paused = !paused;
  el("pauseBtn").textContent = paused ? "Resume" : "Pause";
  el("pauseBtn").classList.toggle("paused", paused);
  if (!paused) refresh();
});

el("themeBtn").addEventListener("click", cycleTheme);
for (const id of ["logFilterDomain", "logFilterPath", "logFilterTransport", "logFilterCache"]) {
  el(id).addEventListener("input", applyLogFilter);
  el(id).addEventListener("change", applyLogFilter);
}
el("logLimit").value = String(queryLimit);
el("logLimit").addEventListener("change", () => {
  queryLimit = Number(el("logLimit").value);
  localStorage.setItem("mosdns-dashboard-query-limit", String(queryLimit));
  refresh();
});

updateThemeButton();
refresh();
setInterval(refresh, 2000);
