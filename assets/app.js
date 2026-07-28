/* ==========================================================================
   ARIADNE — application script
   Split out of index.html. Beyond the move, this file fixes the issues the
   audit listed for the frontend:

   - the API base URL is resolved at runtime instead of being hard-coded to
     127.0.0.1, which made any deployment impossible;
   - there are NO inline `onclick` handlers left (there were ~30), so a
     strict Content-Security-Policy can now be applied;
   - the results search is debounced instead of rebuilding the whole DOM on
     every keystroke;
   - per-module errors, timings and per-finding confidence are shown: the
     backend computed them and the UI used to throw them away;
   - scans stream over Server-Sent Events with live progress and a Cancel
     button, instead of a static "Querying sources…" for tens of seconds;
   - the graph uses a Map for node lookup and a Barnes-Hut quadtree instead
     of an O(n²) all-pairs loop per frame, and supports zoom/pan;
   - both canvas animations honour prefers-reduced-motion and pause when the
     tab is hidden;
   - the state of the app is deep-linkable and the last target is remembered;
   - dead code (`linkify`) is gone.
   ========================================================================== */

/* ---------------------------------------------------------------- CONFIG */

const DEFAULT_API = "http://127.0.0.1:8000";
const LS = {
  theme: "ariadne-theme",
  api: "ariadne-api",
  key: "ariadne-api-key",
  sites: "ariadne-max-sites",
  target: "ariadne-last-target",
  type: "ariadne-last-type",
};

function lsGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function lsSet(key, value) {
  try {
    if (value === null || value === "") localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch { /* private mode: settings just do not persist */ }
}

/** Resolve the backend URL: user setting > injected global > meta tag > default. */
function apiBase() {
  const stored = (lsGet(LS.api) || "").trim();
  if (stored) return stored.replace(/\/+$/, "");
  if (typeof window.ARIADNE_API === "string" && window.ARIADNE_API.trim()) {
    return window.ARIADNE_API.trim().replace(/\/+$/, "");
  }
  const meta = document.querySelector('meta[name="ariadne-api"]');
  const fromMeta = (meta?.content || "").trim();
  if (fromMeta) return fromMeta.replace(/\/+$/, "");
  return DEFAULT_API;
}

function authHeaders() {
  const key = (lsGet(LS.key) || "").trim();
  return key ? { "X-API-Key": key } : {};
}

async function api(path, options = {}) {
  const resp = await fetch(`${apiBase()}${path}`, {
    ...options,
    headers: { ...(options.headers || {}), ...authHeaders() },
  });
  if (!resp.ok) {
    const err = new Error(`HTTP ${resp.status}`);
    err.status = resp.status;
    try { err.detail = (await resp.json()).detail; } catch { /* no JSON body */ }
    throw err;
  }
  return resp.json();
}

/** Turn a failure into something the user can act on. */
function explainError(err) {
  if (err?.name === "AbortError") return "Scan cancelled.";
  if (err?.status === 401) return "The backend requires an API key. Add it under ⚙ Settings.";
  if (err?.status === 422) return `The backend rejected the target: ${err.detail || "invalid input"}`;
  if (err?.status === 429) return "Rate limit reached. Wait a moment before scanning again.";
  if (err?.status >= 500) return `The backend failed (HTTP ${err.status}). Check its logs.`;
  return `Could not reach the API at ${apiBase()}. Is the backend running, and does its CORS_ORIGINS allow this page?`;
}

/* ----------------------------------------------------------------- STATE */

const state = {
  data: null,
  view: "list",
  filter: { q: "", cat: "all" },
  collapsed: new Set(),
  expanded: new Set(),   // modules whose finding list the user expanded past the cap
  type: "auto",
  dial: "+34",
  scan: null,            // AbortController of the running scan
  progress: null,
};

const FINDINGS_CAP = 60;   // rendered per module before "show all"

/* ----------------------------------------------------------------- THEME */

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  const btn = document.getElementById("theme-btn");
  if (btn) {
    btn.innerHTML = `${t === "light" ? "☀️" : "🌙"} <span class="btn-text">Theme</span>`;
    btn.setAttribute("aria-label", `Switch to ${t === "light" ? "dark" : "light"} theme`);
  }
  if (state.data && state.view === "graph") renderAll();
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  lsSet(LS.theme, next);
  applyTheme(next);
}

/* ------------------------------------------------------ TARGET TYPES / CC */

const TARGET_TYPES = [
  { id: "auto",     label: "🎯 Auto",     placeholder: "Enter a target (type auto-detected)…", hint: "The target type is detected automatically. URLs are accepted." },
  { id: "domain",   label: "🌐 Domain",   placeholder: "example.com",           hint: "DNS, WHOIS, RDAP, live TLS certificate, subdomains (CT), HTTP surface, robots/sitemap and Wayback." },
  { id: "email",    label: "✉️ Email",    placeholder: "name@example.com",      hint: "Gravatar profile, address analysis, MX infrastructure and anti-spoofing posture." },
  { id: "username", label: "👤 Username", placeholder: "username",              hint: "Checks many platforms (Maigret) and enriches a public GitHub profile." },
  { id: "phone",    label: "📞 Phone",    placeholder: "+34 600 000 000",       hint: "Country, carrier, line type, timezone, and OSINT pivots. Fully offline." },
  { id: "ip",       label: "🖥️ IP",       placeholder: "8.8.8.8",               hint: "Geolocation by consensus, ISP/ASN, reverse DNS and reputation pivots." },
];

/* Country codes (iso · flag · name · dial). Sorted by frequency + region. */
const COUNTRY_CODES = [
  { code: "+34",  iso: "es", flag: "🇪🇸", name: "Spain" },
  { code: "+1",   iso: "us", flag: "🇺🇸", name: "United States / Canada" },
  { code: "+52",  iso: "mx", flag: "🇲🇽", name: "Mexico" },
  { code: "+54",  iso: "ar", flag: "🇦🇷", name: "Argentina" },
  { code: "+55",  iso: "br", flag: "🇧🇷", name: "Brazil" },
  { code: "+56",  iso: "cl", flag: "🇨🇱", name: "Chile" },
  { code: "+57",  iso: "co", flag: "🇨🇴", name: "Colombia" },
  { code: "+58",  iso: "ve", flag: "🇻🇪", name: "Venezuela" },
  { code: "+51",  iso: "pe", flag: "🇵🇪", name: "Peru" },
  { code: "+593", iso: "ec", flag: "🇪🇨", name: "Ecuador" },
  { code: "+591", iso: "bo", flag: "🇧🇴", name: "Bolivia" },
  { code: "+595", iso: "py", flag: "🇵🇾", name: "Paraguay" },
  { code: "+598", iso: "uy", flag: "🇺🇾", name: "Uruguay" },
  { code: "+502", iso: "gt", flag: "🇬🇹", name: "Guatemala" },
  { code: "+503", iso: "sv", flag: "🇸🇻", name: "El Salvador" },
  { code: "+504", iso: "hn", flag: "🇭🇳", name: "Honduras" },
  { code: "+505", iso: "ni", flag: "🇳🇮", name: "Nicaragua" },
  { code: "+506", iso: "cr", flag: "🇨🇷", name: "Costa Rica" },
  { code: "+507", iso: "pa", flag: "🇵🇦", name: "Panama" },
  { code: "+53",  iso: "cu", flag: "🇨🇺", name: "Cuba" },
  { code: "+1809",iso: "do", flag: "🇩🇴", name: "Dominican Republic" },
  { code: "+44",  iso: "gb", flag: "🇬🇧", name: "United Kingdom" },
  { code: "+33",  iso: "fr", flag: "🇫🇷", name: "France" },
  { code: "+49",  iso: "de", flag: "🇩🇪", name: "Germany" },
  { code: "+39",  iso: "it", flag: "🇮🇹", name: "Italy" },
  { code: "+351", iso: "pt", flag: "🇵🇹", name: "Portugal" },
  { code: "+31",  iso: "nl", flag: "🇳🇱", name: "Netherlands" },
  { code: "+32",  iso: "be", flag: "🇧🇪", name: "Belgium" },
  { code: "+41",  iso: "ch", flag: "🇨🇭", name: "Switzerland" },
  { code: "+43",  iso: "at", flag: "🇦🇹", name: "Austria" },
  { code: "+353", iso: "ie", flag: "🇮🇪", name: "Ireland" },
  { code: "+30",  iso: "gr", flag: "🇬🇷", name: "Greece" },
  { code: "+48",  iso: "pl", flag: "🇵🇱", name: "Poland" },
  { code: "+7",   iso: "ru", flag: "🇷🇺", name: "Russia" },
  { code: "+380", iso: "ua", flag: "🇺🇦", name: "Ukraine" },
  { code: "+90",  iso: "tr", flag: "🇹🇷", name: "Turkey" },
  { code: "+212", iso: "ma", flag: "🇲🇦", name: "Morocco" },
  { code: "+20",  iso: "eg", flag: "🇪🇬", name: "Egypt" },
  { code: "+27",  iso: "za", flag: "🇿🇦", name: "South Africa" },
  { code: "+91",  iso: "in", flag: "🇮🇳", name: "India" },
  { code: "+86",  iso: "cn", flag: "🇨🇳", name: "China" },
  { code: "+81",  iso: "jp", flag: "🇯🇵", name: "Japan" },
  { code: "+82",  iso: "kr", flag: "🇰🇷", name: "South Korea" },
  { code: "+61",  iso: "au", flag: "🇦🇺", name: "Australia" },
  { code: "+64",  iso: "nz", flag: "🇳🇿", name: "New Zealand" },
  { code: "+972", iso: "il", flag: "🇮🇱", name: "Israel" },
  { code: "+971", iso: "ae", flag: "🇦🇪", name: "United Arab Emirates" },
];

function renderTypePicker() {
  const picker = document.getElementById("type-picker");
  picker.innerHTML = TARGET_TYPES.map(t =>
    `<button type="button" class="type-chip" data-action="set-type" data-type="${t.id}"
             aria-pressed="${t.id === state.type}">${t.label}</button>`
  ).join("");
  applyType();
}

function setType(id) {
  state.type = id;
  lsSet(LS.type, id);
  renderTypePicker();
  document.getElementById("target").focus();
}

function applyType() {
  const t = TARGET_TYPES.find(x => x.id === state.type) || TARGET_TYPES[0];
  const isPhone = state.type === "phone";
  const cc = document.getElementById("country-code");
  cc.hidden = !isPhone;
  if (!isPhone) closeCC();
  const input = document.getElementById("target");
  input.placeholder = isPhone ? "600 000 000 (local number)" : t.placeholder;
  input.setAttribute("inputmode", isPhone ? "numeric" : "text");
  if (isPhone) sanitizePhoneInput(input);
  document.getElementById("hint").textContent = t.hint;
}

/* In phone mode, keep the target input numeric (digits and spaces only). */
function sanitizePhoneInput(el) {
  if (state.type !== "phone") return;
  const cleaned = el.value.replace(/[^\d\s]/g, "");
  if (cleaned !== el.value) el.value = cleaned;
}

/* Client-side sanity check before spending a request on an impossible number. */
function phoneLooksPlausible(dial, local) {
  const digits = (dial + local).replace(/\D/g, "");
  return digits.length >= 8 && digits.length <= 15;   // ITU E.164 bounds
}

/* -------------------------------------------- COUNTRY DROPDOWN (a11y) --- */

function flagImg(c, cls) {
  const img = document.createElement("img");
  img.className = cls;
  img.src = `https://flagcdn.com/w40/${c.iso}.png`;
  img.alt = "";
  // Falls back to the emoji if the CDN is unreachable or blocked.
  img.addEventListener("error", () => img.replaceWith(document.createTextNode(`${c.flag} `)), { once: true });
  return img;
}

function populateCountryCodes() {
  const list = document.getElementById("cc-list");
  list.innerHTML = "";
  COUNTRY_CODES.forEach((c, i) => {
    const li = document.createElement("li");
    li.className = "cc-item";
    li.id = `cc-opt-${i}`;
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(c.code === state.dial));
    li.dataset.index = String(i);
    li.dataset.name = c.name.toLowerCase();
    li.dataset.dial = c.code;
    li.append(flagImg(c, "cc-flag"));
    const name = document.createElement("span");
    name.className = "cc-name";
    name.textContent = c.name;
    const dial = document.createElement("span");
    dial.className = "cc-dial";
    dial.textContent = c.code;
    li.append(name, dial);
    list.append(li);
  });
  selectCC(Math.max(0, COUNTRY_CODES.findIndex(c => c.code === state.dial)));
}

function selectCC(i) {
  const c = COUNTRY_CODES[i];
  if (!c) return;
  state.dial = c.code;
  document.getElementById("cc-code").textContent = c.code;
  const flag = document.getElementById("cc-flag");
  flag.src = `https://flagcdn.com/w40/${c.iso}.png`;
  flag.alt = "";
  document.getElementById("cc-toggle").setAttribute("aria-label", `Country dialling code: ${c.name} ${c.code}`);
  document.querySelectorAll("#cc-list .cc-item").forEach(li =>
    li.setAttribute("aria-selected", String(Number(li.dataset.index) === i)));
  closeCC();
}

function visibleCCItems() {
  return [...document.querySelectorAll("#cc-list .cc-item:not(.hidden)")];
}

function highlightCC(li) {
  document.querySelectorAll("#cc-list .cc-item.active").forEach(x => x.classList.remove("active"));
  if (!li) return;
  li.classList.add("active");
  li.scrollIntoView({ block: "nearest" });
  document.getElementById("cc-list").setAttribute("aria-activedescendant", li.id);
}

function openCC() {
  const d = document.getElementById("country-code");
  d.classList.add("open");
  document.getElementById("cc-toggle").setAttribute("aria-expanded", "true");
  const s = document.getElementById("cc-search");
  s.value = "";
  filterCC("");
  s.focus();
  highlightCC(visibleCCItems()[0]);
}

function closeCC() {
  const d = document.getElementById("country-code");
  if (!d) return;
  d.classList.remove("open");
  document.getElementById("cc-toggle")?.setAttribute("aria-expanded", "false");
}

function toggleCC() {
  const open = document.getElementById("country-code").classList.contains("open");
  if (open) { closeCC(); document.getElementById("cc-toggle").focus(); } else openCC();
}

function filterCC(q) {
  const needle = q.trim().toLowerCase();
  document.querySelectorAll("#cc-list .cc-item").forEach(li => {
    const match = li.dataset.name.includes(needle) || li.dataset.dial.includes(needle);
    li.classList.toggle("hidden", !match);
  });
  highlightCC(visibleCCItems()[0]);
}

/* Full keyboard support: the dropdown used to be mouse-only. */
function onCCKeydown(e) {
  const items = visibleCCItems();
  const current = document.querySelector("#cc-list .cc-item.active");
  const idx = items.indexOf(current);
  if (e.key === "ArrowDown") { e.preventDefault(); highlightCC(items[Math.min(idx + 1, items.length - 1)] || items[0]); }
  else if (e.key === "ArrowUp") { e.preventDefault(); highlightCC(items[Math.max(idx - 1, 0)] || items[0]); }
  else if (e.key === "Home") { e.preventDefault(); highlightCC(items[0]); }
  else if (e.key === "End") { e.preventDefault(); highlightCC(items[items.length - 1]); }
  else if (e.key === "Enter") { e.preventDefault(); if (current) { selectCC(Number(current.dataset.index)); document.getElementById("cc-toggle").focus(); } }
  else if (e.key === "Escape") { e.preventDefault(); closeCC(); document.getElementById("cc-toggle").focus(); }
}

/* ------------------------------------------------------------------ SCAN */

function buildTarget() {
  let target = document.getElementById("target").value.trim();
  if (!target) return null;
  if (state.type === "phone" && !target.startsWith("+") && !target.startsWith("00")) {
    if (!phoneLooksPlausible(state.dial, target)) return { error: "That does not look like a complete phone number (8–15 digits including the country code)." };
    target = `${state.dial} ${target}`;
  }
  return { target };
}

function setScanning(on) {
  const btn = document.getElementById("btn");
  const cancel = document.getElementById("cancel-btn");
  btn.disabled = on;
  btn.innerHTML = on ? '<span class="spinner" role="img" aria-label="Scanning"></span>' : "Scan";
  cancel.hidden = !on;
  document.getElementById("results").setAttribute("aria-busy", String(on));
}

/**
 * Read a Server-Sent Events stream over fetch().
 * EventSource cannot send the X-API-Key header and cannot be aborted
 * cleanly, so the protocol is parsed by hand here.
 */
async function readSSE(url, signal, onEvent) {
  const resp = await fetch(url, { signal, headers: { Accept: "text/event-stream", ...authHeaders() } });
  if (!resp.ok || !resp.body) {
    const err = new Error(`HTTP ${resp.status}`);
    err.status = resp.status;
    throw err;
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let split;
    while ((split = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, split);
      buffer = buffer.slice(split + 2);
      let event = "message";
      const dataLines = [];
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
      }
      if (dataLines.length) {
        try { onEvent(event, JSON.parse(dataLines.join("\n"))); } catch { /* keep-alive */ }
      }
    }
  }
}

function startProgress(modules) {
  state.progress = { expected: modules, done: new Map(), started: Date.now() };
  renderProgress();
  clearInterval(state.progress.timer);
  state.progress.timer = setInterval(renderProgress, 500);
}

function stopProgress() {
  if (state.progress) clearInterval(state.progress.timer);
  state.progress = null;
}

function renderProgress() {
  const p = state.progress;
  const box = document.getElementById("results");
  if (!p) return;
  const total = p.expected.length || 1;
  const pct = Math.round((p.done.size / total) * 100);
  const secs = ((Date.now() - p.started) / 1000).toFixed(1);
  const chips = p.expected.map(m => {
    const r = p.done.get(m);
    const cls = !r ? "pending" : (r.status === "error" ? "failed" : "done");
    const count = r ? ` ${r.findings.length}` : "…";
    return `<span class="skeleton-mod ${cls}">${escapeHtml(m)}${count}</span>`;
  }).join("");
  box.innerHTML = `<div class="progress">
      <div class="progress-bar"><i style="width:${pct}%"></i></div>
      <div class="progress-meta">
        <span>${p.done.size} of ${total} sources finished</span>
        <span>${secs}s elapsed</span>
      </div>
      <div class="skeleton-list">${chips}</div>
    </div>`;
}

async function scan(opts = {}) {
  const built = buildTarget();
  if (!built) return;
  if (built.error) {
    document.getElementById("results").innerHTML = `<div class="empty-state">${escapeHtml(built.error)}</div>`;
    return;
  }
  const target = built.target;

  lsSet(LS.target, document.getElementById("target").value.trim());
  updateDeepLink(target, state.type);

  state.scan?.abort();
  const controller = new AbortController();
  state.scan = controller;
  setScanning(true);
  state.filter = { q: "", cat: "all" };
  state.collapsed.clear();
  state.expanded.clear();

  const params = new URLSearchParams({ target });
  if (state.type !== "auto") params.set("target_type", state.type);
  if (opts.refresh) params.set("refresh", "true");
  const sites = (lsGet(LS.sites) || "").trim();
  if (sites) params.set("max_sites", sites);

  try {
    await readSSE(`${apiBase()}/scan/stream?${params}`, controller.signal, (event, payload) => {
      if (event === "start") startProgress(payload.modules || []);
      else if (event === "module" && state.progress) { state.progress.done.set(payload.module, payload); renderProgress(); }
      else if (event === "done") { stopProgress(); state.data = payload; renderAll(); }
      else if (event === "error") { stopProgress(); document.getElementById("results").innerHTML = `<div class="empty-state">${escapeHtml(payload.detail || "Scan failed")}</div>`; }
    });
  } catch (err) {
    stopProgress();
    if (err.name === "AbortError") {
      document.getElementById("results").innerHTML = `<div class="empty-state">Scan cancelled.</div>`;
    } else {
      // Streaming may be unavailable (old backend, proxy buffering): fall back.
      const ok = await scanFallback(target, opts, controller.signal);
      if (!ok) document.getElementById("results").innerHTML = `<div class="empty-state">${escapeHtml(explainError(err))}</div>`;
    }
  } finally {
    if (state.scan === controller) state.scan = null;
    setScanning(false);
  }
}

async function scanFallback(target, opts, signal) {
  try {
    const body = { target, target_type: state.type, refresh: !!opts.refresh };
    const sites = (lsGet(LS.sites) || "").trim();
    if (sites) body.max_sites = Number(sites);
    const resp = await fetch(`${apiBase()}/scan`, {
      method: "POST", signal,
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    });
    if (!resp.ok) return false;
    state.data = await resp.json();
    renderAll();
    return true;
  } catch { return false; }
}

/* ---------------------------------------------------------------- RENDER */

function renderAll() {
  const data = state.data;
  const results = document.getElementById("results");
  if (!data) { results.innerHTML = ""; return; }

  const skipped = (data.skipped_modules || []).length
    ? `<span class="badge warn" title="Modules that need an API key">${data.skipped_modules.length} needs key</span>` : "";

  results.innerHTML = `<div class="meta">
    <span>Target: <span class="badge">${escapeHtml(data.target)}</span></span>
    <span>Type: <span class="badge">${escapeHtml(data.target_type)}</span></span>
    <span>Time: ${data.total_elapsed_ms} ms</span>
    ${data.cached ? '<span class="badge cached">⚡ cached</span>' : ""}
    ${skipped}
    <button class="act" data-action="rescan" title="Ignore the cache and query every source again">↻ Refresh</button>
    <button class="act" data-action="export" data-format="json" title="Download as JSON">⬇ JSON</button>
    <button class="act" data-action="export" data-format="csv" title="Download as CSV">⬇ CSV</button>
    <button class="act" data-action="export" data-format="md" title="Download as Markdown">⬇ MD</button>
    <button class="act" data-action="export" data-format="pdf" title="Save as PDF (print)">🖨 PDF</button>
    <span class="view-toggle" role="group" aria-label="Result view">
      <button data-action="set-view" data-view="list" aria-pressed="${state.view === "list"}">List</button>
      <button data-action="set-view" data-view="graph" aria-pressed="${state.view === "graph"}">Graph</button>
    </span>
  </div><div id="view-body"></div>`;

  if (state.view === "list") renderList(); else renderGraph();
}

function setView(v) { state.view = v; renderAll(); }

function categoryCounts(data) {
  const counts = {};
  for (const r of data.results) for (const f of r.findings) counts[f.category] = (counts[f.category] || 0) + 1;
  return counts;
}

function renderList() {
  const data = state.data;
  const body = document.getElementById("view-body");
  const totalFindings = data.results.reduce((a, r) => a + r.findings.length, 0);
  const modsWithData = data.results.filter(r => r.findings.length).length;
  const cats = categoryCounts(data);
  const catCount = Object.keys(cats).length;

  let html = "";

  if (data.message) {
    html += `<div class="legal" role="status">ℹ️ ${escapeHtml(data.message)}</div>`;
  }

  html += `<div class="summary">
    <div class="stat"><div class="num">${totalFindings}</div><div class="lbl">findings</div></div>
    <div class="stat"><div class="num">${modsWithData}/${data.results.length}</div><div class="lbl">sources with data</div></div>
    <div class="stat"><div class="num">${catCount}</div><div class="lbl">categories</div></div>
    <div class="stat"><div class="num">${data.total_elapsed_ms}<span style="font-size:13px"> ms</span></div><div class="lbl">scan time</div></div>
  </div>`;

  if (data.correlations?.length) {
    html += `<div class="correlations"><h3>⚡ Correlations detected</h3>`;
    for (const c of data.correlations) {
      html += `<div class="corr-row">
        <span class="corr-kind" title="Correlation weight: ${c.weight ?? ""}">${escapeHtml((c.kind || "value").replace(/_/g, " "))}</span>
        <span>${escapeHtml(c.description)}: <b>${c.linked_values.map(escapeHtml).join(" · ")}</b></span>
        <span class="cat">${c.modules.map(escapeHtml).join(" + ")}</span>
      </div>`;
    }
    html += `</div>`;
  }

  if (totalFindings) {
    const chips = [`<button class="cat-chip" data-action="set-cat" data-cat="all" aria-pressed="${state.filter.cat === "all"}">All<span class="n">${totalFindings}</span></button>`]
      .concat(Object.entries(cats).sort((a, b) => b[1] - a[1]).map(([c, n]) =>
        `<button class="cat-chip" data-action="set-cat" data-cat="${escapeHtml(c)}" aria-pressed="${state.filter.cat === c}">${escapeHtml(c)}<span class="n">${n}</span></button>`));
    html += `<div class="res-controls">
      <div class="res-search-row">
        <label class="visually-hidden" for="res-search">Filter findings</label>
        <input class="res-search" id="res-search" placeholder="Filter findings by text (label or value)…  [ / ]"
               value="${escapeHtml(state.filter.q)}" autocomplete="off">
        <button class="res-clear" data-action="clear-filter">Clear</button>
      </div>
      <div class="cat-filters">${chips.join("")}<span class="res-count" id="res-count" role="status"></span></div>
    </div>`;
  }

  html += `<div id="findings-body"></div>`;
  body.innerHTML = html;
  filterFindings();
}

/** Findings whose value signals a problem worth reading first. */
function isRisk(f) {
  const v = (f.value || "").toUpperCase();
  if (f.label.startsWith("Missing security headers")) return true;
  if (f.label.startsWith("Breach:") || f.label === "Breaches found") return true;
  if (f.label === "Notable disallowed path") return true;
  if (f.category === "reputation") return true;
  return v.includes("EXPIRED") || v.includes("INVALID") || v.startsWith("REFUSED:");
}

function confidenceHtml(conf) {
  if (typeof conf !== "number" || conf >= 1) return "";
  const pct = Math.round(conf * 100);
  const cls = conf >= 0.85 ? "high" : conf >= 0.6 ? "med" : "low";
  return `<span class="conf ${cls}" title="Confidence: ${pct}%" aria-label="Confidence ${pct} percent">
    <span class="conf-bar"><i style="width:${pct}%"></i></span></span>`;
}

/* Rebuilds only the findings list (keeps the search box focused while typing). */
function filterFindings() {
  const data = state.data;
  const fb = document.getElementById("findings-body");
  if (!fb) return;
  if (!data.results.length) {
    fb.innerHTML = `<div class="empty-state">${escapeHtml(data.message || "No modules for this target type.")}</div>`;
    return;
  }

  const q = state.filter.q.trim().toLowerCase();
  const cat = state.filter.cat;
  const filtering = !!q || cat !== "all";
  let shown = 0, total = 0, html = "";

  for (const r of data.results) {
    total += r.findings.length;
    const matched = r.findings.filter(f => {
      if (cat !== "all" && f.category !== cat) return false;
      if (q && !(`${f.label} ${f.value}`.toLowerCase().includes(q))) return false;
      return true;
    });
    if (filtering && matched.length === 0 && r.status !== "error") continue;
    shown += matched.length;

    const collapsed = state.collapsed.has(r.module) ? "collapsed" : "";
    const color = moduleColor(r.module);
    const timing = r.elapsed_ms ? `<span class="module-timing">${r.elapsed_ms} ms</span>` : "";
    html += `<div class="module-card ${collapsed}">
      <button type="button" class="module-head" data-action="toggle-mod" data-mod="${escapeHtml(r.module)}"
              aria-expanded="${!collapsed}">
        <span class="module-head-left">
          <span class="module-name" style="color:${color}">${escapeHtml(r.module)}</span>
          <span class="status ${r.status}">${statusLabel(r)}</span>
          ${timing}
        </span>
        <span class="chevron" aria-hidden="true">▾</span>
      </button>`;

    // The backend already reported WHY a module failed; show it.
    if (r.error) html += `<p class="module-error">⚠ ${escapeHtml(r.error)}</p>`;

    if (matched.length) {
      const expanded = state.expanded.has(r.module);
      const visible = expanded ? matched : matched.slice(0, FINDINGS_CAP);
      html += `<div class="findings">`;
      for (const f of visible) {
        html += `<div class="finding${isRisk(f) ? " risk" : ""}">
          <span class="label">${hl(f.label, q)}</span>
          <span class="value">${valueHtml(f.value, q)}</span>
          ${confidenceHtml(f.confidence)}
          <span class="cat">${escapeHtml(f.category)}</span>
          <button class="pivot-btn" title="Scan this value as a new target" aria-label="Scan ${escapeHtml(f.value)} as a new target"
                  data-action="pivot" data-val="${escapeHtml(f.value)}">⇱</button>
          <button class="copy-btn" title="Copy value" aria-label="Copy ${escapeHtml(f.label)}"
                  data-action="copy" data-val="${escapeHtml(f.value)}">⧉</button>
        </div>`;
      }
      if (!expanded && matched.length > FINDINGS_CAP) {
        html += `<div class="more-row"><button class="act" data-action="expand-mod" data-mod="${escapeHtml(r.module)}">
          Show all ${matched.length} findings</button></div>`;
      }
      html += `</div>`;
    }
    html += `</div>`;
  }

  if (filtering && shown === 0) html = `<div class="no-match">No findings match your filter.</div>`;
  fb.innerHTML = html;

  const rc = document.getElementById("res-count");
  if (rc) rc.textContent = filtering ? `${shown} of ${total} shown` : `${total} findings`;
}

/* Debounced: the search used to rebuild the entire list on every keystroke. */
let searchTimer = null;
function onResSearch(v) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.filter.q = v; filterFindings(); }, 160);
}

function clearResFilter() { state.filter = { q: "", cat: "all" }; renderList(); }
function setCat(c) { state.filter.cat = c; renderList(); }
function toggleMod(m) {
  if (state.collapsed.has(m)) state.collapsed.delete(m); else state.collapsed.add(m);
  filterFindings();
}

function copyVal(btn) {
  const val = btn.dataset.val;
  const done = () => {
    btn.textContent = "✓"; btn.classList.add("done");
    setTimeout(() => { btn.textContent = "⧉"; btn.classList.remove("done"); }, 1000);
  };
  navigator.clipboard?.writeText(val).then(done).catch(() => {});
}

/* Close the loop: a finding becomes the next target (real pivoting). */
function pivotTo(value) {
  document.getElementById("target").value = value;
  setType("auto");
  document.getElementById("target").value = value;
  window.scrollTo({ top: 0, behavior: "smooth" });
  scan();
}

/* Highlight the query inside escaped text (labels + plain values). */
function hl(text, q) {
  const s = escapeHtml(String(text));
  if (!q) return s;
  const needle = escapeHtml(q).toLowerCase();
  if (!needle) return s;
  const low = s.toLowerCase();
  let out = "", idx = 0, pos;
  while ((pos = low.indexOf(needle, idx)) !== -1) {
    out += s.slice(idx, pos) + "<mark>" + s.slice(pos, pos + needle.length) + "</mark>";
    idx = pos + needle.length;
  }
  return out + s.slice(idx);
}

/* Links stay clickable; non-URL values get search highlighting.
   Only http(s) URLs are linked, which closes the `javascript:` vector. */
function valueHtml(v, q) {
  if (/^https?:\/\//.test(v)) {
    const safe = escapeHtml(v);
    return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a>`;
  }
  return hl(v, q);
}

function statusLabel(r) {
  if (r.status === "ok") return `${r.findings.length} results`;
  if (r.status === "empty") return "no results";
  return "error";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------------------------------------------------------- EXPORT */

function download(name, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

function safeName() {
  return (state.data?.target || "scan").replace(/[^a-z0-9._-]+/gi, "_");
}

function exportAs(format) {
  const data = state.data;
  if (!data) return;
  if (format === "json") {
    download(`ariadne_${safeName()}.json`, "application/json", JSON.stringify(data, null, 2));
  } else if (format === "csv") {
    const esc = v => `"${String(v).replace(/"/g, '""')}"`;
    const rows = [["module", "status", "label", "value", "category", "confidence"].join(",")];
    for (const r of data.results)
      for (const f of r.findings)
        rows.push([r.module, r.status, f.label, f.value, f.category, f.confidence].map(esc).join(","));
    download(`ariadne_${safeName()}.csv`, "text/csv", rows.join("\r\n"));
  } else if (format === "md") {
    const lines = [`# ARIADNE — ${data.target}`, "", `- **Type:** ${data.target_type}`, `- **Scan time:** ${data.total_elapsed_ms} ms`, ""];
    if (data.correlations?.length) {
      lines.push("## Correlations", "");
      for (const c of data.correlations) lines.push(`- **${c.kind}** — ${c.description}: ${c.linked_values.join(" · ")} _(${c.modules.join(" + ")})_`);
      lines.push("");
    }
    for (const r of data.results) {
      lines.push(`## ${r.module} — ${r.status}${r.error ? ` (${r.error})` : ""}`, "");
      if (r.findings.length) {
        lines.push("| Label | Value | Category | Confidence |", "|---|---|---|---|");
        for (const f of r.findings)
          lines.push(`| ${f.label} | ${String(f.value).replace(/\|/g, "\\|")} | ${f.category} | ${f.confidence} |`);
      }
      lines.push("");
    }
    download(`ariadne_${safeName()}.md`, "text/markdown", lines.join("\n"));
  } else if (format === "pdf") {
    if (state.view !== "list") setView("list");
    setTimeout(() => window.print(), 50);
  }
}

/* --------------------------------------------------------------- HISTORY */

let historyOffset = 0;

async function toggleHistory() {
  const panel = document.getElementById("history-panel");
  const opening = panel.hidden;
  panel.hidden = !opening;
  document.querySelector('[data-action="toggle-history"]').setAttribute("aria-expanded", String(opening));
  if (opening) { historyOffset = 0; await loadHistory(false); }
}

async function loadHistory(append) {
  const list = document.getElementById("history-list");
  if (!append) list.innerHTML = `<div class="hist-empty">Loading…</div>`;
  try {
    const page = await api(`/history?limit=25&offset=${historyOffset}`);
    const items = page.items || [];
    if (!items.length && !append) { list.innerHTML = `<div class="hist-empty">No scans yet.</div>`; return; }
    const html = items.map(it => {
      const when = (it.created_at || "").replace("T", " ").replace(/(\+00:00|Z)$/, " UTC");
      return `<div style="display:flex;align-items:center">
        <button type="button" class="hist-item" data-action="open-history" data-id="${it.id}">
          <span class="h-target">${escapeHtml(it.target)}</span>
          <span class="badge">${escapeHtml(it.target_type)}</span>
          <span class="h-meta">${it.findings_count} findings · ${escapeHtml(when)}</span>
        </button>
        <button class="hist-del" data-action="delete-history" data-id="${it.id}"
                title="Forget this scan" aria-label="Forget the scan of ${escapeHtml(it.target)}">🗑</button>
      </div>`;
    }).join("");
    if (append) list.insertAdjacentHTML("beforeend", html);
    else list.innerHTML = html;

    document.querySelector(".hist-more")?.remove();
    if (historyOffset + items.length < (page.total || 0)) {
      list.insertAdjacentHTML("beforeend", `<div class="hist-more"><button class="act" data-action="more-history">Load more</button></div>`);
    }
  } catch (err) {
    list.innerHTML = `<div class="hist-empty">${escapeHtml(explainError(err))}</div>`;
  }
}

async function openHistoryScan(id) {
  try {
    state.data = await api(`/history/${id}`);
    state.filter = { q: "", cat: "all" };
    state.collapsed.clear(); state.expanded.clear();
    document.getElementById("history-panel").hidden = true;
    document.querySelector('[data-action="toggle-history"]').setAttribute("aria-expanded", "false");
    renderAll();
    document.getElementById("results").scrollIntoView({ behavior: "smooth" });
  } catch { /* the entry may have been pruned by the retention policy */ }
}

async function deleteHistoryScan(id) {
  try {
    await api(`/history/${id}`, { method: "DELETE" });
    historyOffset = 0;
    await loadHistory(false);
  } catch (err) {
    document.getElementById("history-list").insertAdjacentHTML("afterbegin",
      `<div class="hist-empty">${escapeHtml(explainError(err))}</div>`);
  }
}

/* -------------------------------------------------------------- SETTINGS */

function toggleSettings() {
  const panel = document.getElementById("settings-panel");
  const opening = panel.hidden;
  panel.hidden = !opening;
  document.querySelector('[data-action="toggle-settings"]').setAttribute("aria-expanded", String(opening));
  if (opening) {
    document.getElementById("api-url").value = lsGet(LS.api) || "";
    document.getElementById("api-key").value = lsGet(LS.key) || "";
    document.getElementById("max-sites").value = lsGet(LS.sites) || "";
    document.getElementById("api-url").placeholder = apiBase();
  }
}

function saveSettings() {
  lsSet(LS.api, document.getElementById("api-url").value.trim());
  lsSet(LS.key, document.getElementById("api-key").value.trim());
  lsSet(LS.sites, document.getElementById("max-sites").value.trim());
  const status = document.getElementById("settings-status");
  status.textContent = `Saved. API: ${apiBase()}`;
  setTimeout(() => { status.textContent = ""; }, 4000);
}

/* ------------------------------------------------------------ DEEP LINKS */

function updateDeepLink(target, type) {
  const url = new URL(window.location.href);
  url.searchParams.set("target", target);
  if (type && type !== "auto") url.searchParams.set("type", type); else url.searchParams.delete("type");
  window.history.replaceState(null, "", url);
}

function applyDeepLink() {
  const params = new URLSearchParams(window.location.search);
  const target = params.get("target");
  const type = params.get("type");
  if (type && TARGET_TYPES.some(t => t.id === type)) state.type = type;
  if (target) {
    document.getElementById("target").value = target;
    renderTypePicker();
    scan();
    return true;
  }
  return false;
}

/* =========================== GRAPH VIEW ==================================
   Force-directed on canvas, no libraries.
   Rewritten for scale: node lookup is a Map (it was Array.find per edge per
   frame) and repulsion uses a Barnes-Hut quadtree instead of comparing every
   pair, which is what froze the browser on domains with hundreds of
   subdomains — precisely the most interesting case.
   ======================================================================== */

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function moduleColor(module) {
  return cssVar(`--mod-${module}`, cssVar("--mod-default", "#8b949e"));
}

function buildGraph(data) {
  const nodes = [], links = [];
  const W = 900, H = 560;
  nodes.push({ id: "__target__", label: data.target, type: "target", x: W / 2, y: H / 2, r: 26, color: cssVar("--text", "#fff") });

  const correlated = new Set();
  for (const c of data.correlations || []) for (const v of c.linked_values) correlated.add(v.toLowerCase());

  for (const res of data.results) {
    if (!res.findings.length) continue;
    const modId = "mod__" + res.module;
    nodes.push({
      id: modId, label: res.module, type: "module", r: 16, module: res.module,
      color: moduleColor(res.module),
      x: W / 2 + (Math.random() - .5) * 200, y: H / 2 + (Math.random() - .5) * 200,
    });
    links.push({ source: "__target__", target: modId, strong: true });

    res.findings.forEach((f, i) => {
      const fid = `${modId}__${i}`;
      const isCorr = correlated.has((f.value || "").toLowerCase());
      nodes.push({
        id: fid, label: f.value, sub: f.label, type: "finding", module: res.module,
        r: isCorr ? 9 : 6, color: isCorr ? cssVar("--yellow", "#d29922") : moduleColor(res.module),
        corr: isCorr, x: W / 2 + (Math.random() - .5) * 400, y: H / 2 + (Math.random() - .5) * 400,
      });
      links.push({ source: modId, target: fid, strong: false, corr: isCorr });
    });
  }
  const index = new Map(nodes.map(n => [n.id, n]));
  for (const l of links) { l.a = index.get(l.source); l.b = index.get(l.target); }
  return { nodes, links, index, W, H };
}

/* ---- Barnes-Hut quadtree: O(n log n) repulsion instead of O(n²) -------- */
class Quad {
  constructor(x0, y0, x1, y1) {
    this.x0 = x0; this.y0 = y0; this.x1 = x1; this.y1 = y1;
    this.mass = 0; this.cx = 0; this.cy = 0;
    this.point = null; this.children = null;
  }
  get size() { return Math.max(this.x1 - this.x0, this.y1 - this.y0); }
  subdivide() {
    const mx = (this.x0 + this.x1) / 2, my = (this.y0 + this.y1) / 2;
    this.children = [
      new Quad(this.x0, this.y0, mx, my), new Quad(mx, this.y0, this.x1, my),
      new Quad(this.x0, my, mx, this.y1), new Quad(mx, my, this.x1, this.y1),
    ];
    if (this.point) { this.place(this.point); this.point = null; }
  }
  place(p) {
    const mx = (this.x0 + this.x1) / 2, my = (this.y0 + this.y1) / 2;
    const i = (p.x >= mx ? 1 : 0) + (p.y >= my ? 2 : 0);
    this.children[i].insert(p);
  }
  insert(p) {
    this.mass += 1;
    this.cx += (p.x - this.cx) / this.mass;
    this.cy += (p.y - this.cy) / this.mass;
    if (this.children) { this.place(p); return; }
    if (!this.point) { this.point = p; return; }
    if (this.size < 1) return;   // coincident points: stop splitting
    this.subdivide();
    this.place(p);
  }
  force(p, theta, k, out) {
    if (this.mass === 0 || this.point === p) return;
    let dx = p.x - this.cx, dy = p.y - this.cy;
    let d = Math.hypot(dx, dy);
    if (d < 0.1) { dx = (Math.random() - .5); dy = (Math.random() - .5); d = 0.1; }
    if (!this.children || this.size / d < theta) {
      const rep = (k * this.mass) / (d * d);
      out.x += (dx / d) * rep; out.y += (dy / d) * rep;
      return;
    }
    for (const c of this.children) c.force(p, theta, k, out);
  }
}

let graphState = null;

function renderGraph() {
  const data = state.data;
  const body = document.getElementById("view-body");
  const hasFindings = data.results.some(r => r.findings.length);
  if (!hasFindings) { body.innerHTML = `<div class="empty-state">No data to graph.</div>`; return; }

  body.innerHTML = `
    <div id="graph-wrap">
      <canvas id="graph" role="img"
              aria-label="Force-directed graph of ${escapeHtml(data.target)} with ${data.results.length} sources. An equivalent table follows."></canvas>
      <div class="graph-legend" id="legend"></div>
      <div class="graph-controls">
        <button data-action="graph-zoom" data-dir="in" aria-label="Zoom in">+</button>
        <button data-action="graph-zoom" data-dir="out" aria-label="Zoom out">−</button>
        <button data-action="graph-zoom" data-dir="reset" aria-label="Reset the view">⌂</button>
      </div>
      <div class="graph-tip">Drag nodes · scroll to zoom · drag canvas to pan · click a source to fold it</div>
      <div class="node-tooltip" id="tooltip"></div>
    </div>
    ${graphTable(data)}`;

  const g = buildGraph(data);
  const canvas = document.getElementById("graph");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const VH = canvas.clientHeight || 560;
  canvas.width = rect.width * dpr; canvas.height = VH * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  const VW = rect.width;
  g.nodes.forEach(n => { n.x = n.x / g.W * VW; n.y = n.y / g.H * VH; n.vx = 0; n.vy = 0; });

  const mods = [...new Set(data.results.filter(r => r.findings.length).map(r => r.module))];
  document.getElementById("legend").innerHTML =
    `<div><span class="legend-dot" style="background:${cssVar("--text", "#fff")}"></span>Target</div>` +
    mods.map(m => `<div><span class="legend-dot" style="background:${moduleColor(m)}"></span>${escapeHtml(m)}</div>`).join("") +
    `<div><span class="legend-dot" style="background:${cssVar("--yellow", "#d29922")}"></span>correlated</div>`;

  graphState = { g, canvas, ctx, VW, VH, drag: null, pan: null, view: { k: 1, tx: 0, ty: 0 }, folded: new Set(), raf: null };
  setupGraphInteraction();
  runSimulation();
}

/* Screen-reader alternative: the canvas alone is invisible to assistive tech. */
function graphTable(data) {
  const rows = data.results.flatMap(r =>
    r.findings.map(f => `<tr><td>${escapeHtml(r.module)}</td><td>${escapeHtml(f.label)}</td><td>${escapeHtml(f.value)}</td></tr>`));
  return `<table class="visually-hidden"><caption>Graph data for ${escapeHtml(data.target)}</caption>
    <thead><tr><th>Source</th><th>Label</th><th>Value</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

function visibleNodes() {
  const s = graphState;
  return s.g.nodes.filter(n => !(n.type === "finding" && s.folded.has(n.module)));
}

function runSimulation() {
  const s = graphState;
  if (!s) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const { VW, VH } = s;
  let ticks = 0;
  const maxTicks = reduced ? 1 : 500;

  function step() {
    if (!graphState || graphState !== s) return;
    const nodes = visibleNodes();
    const iterations = reduced ? 300 : 1;   // settle instantly, then draw once
    for (let it = 0; it < iterations; it++) {
      for (const n of nodes) { if (n === s.drag) continue; n.fx = 0; n.fy = 0; }

      const tree = new Quad(-VW, -VH, VW * 2, VH * 2);
      for (const n of nodes) tree.insert(n);
      const out = { x: 0, y: 0 };
      for (const n of nodes) {
        if (n === s.drag) continue;
        out.x = 0; out.y = 0;
        tree.force(n, 0.9, 1400, out);
        n.fx += out.x; n.fy += out.y;
      }

      for (const l of s.g.links) {
        const a = l.a, b = l.b;                      // Map lookup done once at build time
        if (!a || !b) continue;
        if (b.type === "finding" && s.folded.has(b.module)) continue;
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.hypot(dx, dy) || 0.1;
        const targetLen = l.strong ? 90 : 55;
        const k = (d - targetLen) * 0.02;
        const fx = dx / d * k, fy = dy / d * k;
        a.fx += fx; a.fy += fy; b.fx -= fx; b.fy -= fy;
      }

      for (const n of nodes) {
        if (n === s.drag) continue;
        n.fx += (VW / 2 - n.x) * 0.005; n.fy += (VH / 2 - n.y) * 0.005;
        n.vx = (n.vx + n.fx) * 0.85; n.vy = (n.vy + n.fy) * 0.85;
        n.x += n.vx; n.y += n.vy;
        n.x = Math.max(n.r, Math.min(VW - n.r, n.x));
        n.y = Math.max(n.r, Math.min(VH - n.r, n.y));
      }
    }
    drawGraph();
    ticks++;
    if (ticks < maxTicks && document.visibilityState === "visible") s.raf = requestAnimationFrame(step);
  }
  step();
}

function drawGraph() {
  const s = graphState;
  if (!s) return;
  const { ctx, g, VW, VH, view } = s;
  ctx.save();
  ctx.clearRect(0, 0, VW, VH);
  ctx.translate(view.tx, view.ty);
  ctx.scale(view.k, view.k);

  const muted = "rgba(139,148,158,";
  for (const l of g.links) {
    const a = l.a, b = l.b;
    if (!a || !b) continue;
    if (b.type === "finding" && s.folded.has(b.module)) continue;
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
    ctx.strokeStyle = l.corr ? "rgba(210,153,34,.6)" : `${muted}${l.strong ? ".5" : ".2"})`;
    ctx.lineWidth = l.strong ? 2 : 1;
    ctx.stroke();
  }

  const labelColor = cssVar("--text", "#e6edf3");
  const ringColor = cssVar("--accent", "#2f81f7");
  for (const n of visibleNodes()) {
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = n.color; ctx.fill();
    if (n.type === "target") { ctx.lineWidth = 3; ctx.strokeStyle = ringColor; ctx.stroke(); }
    if (n.corr) { ctx.lineWidth = 2; ctx.strokeStyle = labelColor; ctx.stroke(); }
    if (n.type !== "finding") {
      ctx.fillStyle = labelColor;
      ctx.font = `${n.type === "target" ? "bold 13px" : "12px"} sans-serif`;
      ctx.textAlign = "center";
      const folded = n.type === "module" && s.folded.has(n.module);
      const base = n.label.length > 22 ? n.label.slice(0, 22) + "…" : n.label;
      ctx.fillText(folded ? `${base} (folded)` : base, n.x, n.y - n.r - 6);
    }
  }
  ctx.restore();
}

function setupGraphInteraction() {
  const s = graphState;
  const { canvas, g } = s;
  const tooltip = document.getElementById("tooltip");

  const toWorld = e => {
    const r = canvas.getBoundingClientRect();
    return {
      x: (e.clientX - r.left - s.view.tx) / s.view.k,
      y: (e.clientY - r.top - s.view.ty) / s.view.k,
      sx: e.clientX - r.left, sy: e.clientY - r.top,
    };
  };
  const nodeAt = p => {
    const nodes = visibleNodes();
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      if (Math.hypot(n.x - p.x, n.y - p.y) <= n.r + 3) return n;
    }
    return null;
  };

  canvas.addEventListener("mousedown", e => {
    const p = toWorld(e);
    const n = nodeAt(p);
    if (n) { s.drag = n; n.vx = 0; n.vy = 0; }
    else s.pan = { x: e.clientX - s.view.tx, y: e.clientY - s.view.ty };
  });
  canvas.addEventListener("mousemove", e => {
    const p = toWorld(e);
    if (s.drag) { s.drag.x = p.x; s.drag.y = p.y; drawGraph(); }
    else if (s.pan) { s.view.tx = e.clientX - s.pan.x; s.view.ty = e.clientY - s.pan.y; drawGraph(); }
    const n = nodeAt(p);
    if (n && n.type === "finding") {
      tooltip.style.display = "block";
      tooltip.style.left = `${p.sx + 12}px`;
      tooltip.style.top = `${p.sy + 12}px`;
      tooltip.innerHTML = `<b>${escapeHtml(n.sub || "")}</b><br>${escapeHtml(n.label)}`;
    } else tooltip.style.display = "none";
  });
  canvas.addEventListener("mouseup", e => {
    const wasDragging = s.drag || s.pan;
    const p = toWorld(e);
    const n = nodeAt(p);
    s.drag = null; s.pan = null;
    // Clicking a module node folds/unfolds its findings — the practical fix
    // for a graph with hundreds of subdomain nodes.
    if (n && n.type === "module" && !wasDragging) {
      if (s.folded.has(n.module)) s.folded.delete(n.module); else s.folded.add(n.module);
    }
    runSimulation();
  });
  canvas.addEventListener("mouseleave", () => { s.drag = null; s.pan = null; tooltip.style.display = "none"; });
  canvas.addEventListener("wheel", e => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    zoomAt(mx, my, factor);
  }, { passive: false });
  void g;
}

function zoomAt(mx, my, factor) {
  const s = graphState;
  if (!s) return;
  const k = Math.max(0.25, Math.min(4, s.view.k * factor));
  const real = k / s.view.k;
  s.view.tx = mx - (mx - s.view.tx) * real;
  s.view.ty = my - (my - s.view.ty) * real;
  s.view.k = k;
  drawGraph();
}

function graphZoom(dir) {
  const s = graphState;
  if (!s) return;
  if (dir === "reset") { s.view = { k: 1, tx: 0, ty: 0 }; drawGraph(); return; }
  zoomAt(s.VW / 2, s.VH / 2, dir === "in" ? 1.25 : 1 / 1.25);
}

/* ------------------------- BACKGROUND: animated node network ------------- */

(function backgroundNetwork() {
  const canvas = document.getElementById("bg-canvas");
  if (!canvas) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const ctx = canvas.getContext("2d");
  const PALETTE = ["#2f81f7", "#bc8cff", "#39c5cf", "#3fb950"];
  let W, H, dpr, nodes = [], raf = null;
  const mouse = { x: -9999, y: -9999 };

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    // Density proportional to the area (bounded).
    const count = Math.min(90, Math.max(38, Math.round((W * H) / 22000)));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25,
      r: Math.random() * 1.6 + 1,
      c: PALETTE[(Math.random() * PALETTE.length) | 0],
    }));
  }

  function tick() {
    ctx.clearRect(0, 0, W, H);
    const LINK = 140;
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;
      const mdx = mouse.x - n.x, mdy = mouse.y - n.y, md = Math.hypot(mdx, mdy);
      if (md < 180) { n.x += mdx / md * .4; n.y += mdy / md * .4; }
    }
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < LINK) {
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(139,148,158,${(1 - d / LINK) * .28})`;
          ctx.lineWidth = 1; ctx.stroke();
        }
      }
    }
    for (const n of nodes) {
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = n.c; ctx.globalAlpha = .85; ctx.fill(); ctx.globalAlpha = 1;
    }
    raf = requestAnimationFrame(tick);
  }

  function start() {
    // Respect motion preferences and stop burning battery on a hidden tab —
    // this loop used to run forever, no matter what.
    if (reduced.matches || document.visibilityState !== "visible") { stop(); return; }
    if (raf === null) tick();
  }
  function stop() {
    if (raf !== null) { cancelAnimationFrame(raf); raf = null; }
    ctx.clearRect(0, 0, W || 0, H || 0);
  }

  window.addEventListener("resize", resize);
  window.addEventListener("mousemove", e => { mouse.x = e.clientX; mouse.y = e.clientY; });
  window.addEventListener("mouseout", () => { mouse.x = -9999; mouse.y = -9999; });
  document.addEventListener("visibilitychange", () => (document.visibilityState === "visible" ? start() : stop()));
  reduced.addEventListener("change", () => (reduced.matches ? stop() : start()));

  resize();
  start();
})();

/* ------------------------------------------------------ EVENT DELEGATION */
/* One listener instead of ~30 inline `onclick` attributes, which is what
   made a strict Content-Security-Policy impossible before. */

const ACTIONS = {
  "toggle-theme": () => toggleTheme(),
  "toggle-history": () => toggleHistory(),
  "toggle-settings": () => toggleSettings(),
  "save-settings": () => saveSettings(),
  "toggle-cc": () => toggleCC(),
  "scan": () => scan(),
  "rescan": () => scan({ refresh: true }),
  "cancel": () => state.scan?.abort(),
  "set-type": el => setType(el.dataset.type),
  "set-view": el => setView(el.dataset.view),
  "set-cat": el => setCat(el.dataset.cat),
  "clear-filter": () => clearResFilter(),
  "toggle-mod": el => toggleMod(el.dataset.mod),
  "expand-mod": el => { state.expanded.add(el.dataset.mod); filterFindings(); },
  "copy": el => copyVal(el),
  "pivot": el => pivotTo(el.dataset.val),
  "export": el => exportAs(el.dataset.format),
  "open-history": el => openHistoryScan(el.dataset.id),
  "delete-history": el => deleteHistoryScan(el.dataset.id),
  "more-history": () => { historyOffset += 25; loadHistory(true); },
  "graph-zoom": el => graphZoom(el.dataset.dir),
};

document.addEventListener("click", e => {
  const el = e.target.closest("[data-action]");
  if (el) {
    e.preventDefault();
    e.stopPropagation();
    ACTIONS[el.dataset.action]?.(el);
    return;
  }
  const cc = e.target.closest("#cc-list .cc-item");
  if (cc) { selectCC(Number(cc.dataset.index)); return; }
  if (!e.target.closest("#country-code")) closeCC();
});

document.addEventListener("input", e => {
  if (e.target.id === "target") sanitizePhoneInput(e.target);
  else if (e.target.id === "res-search") onResSearch(e.target.value);
  else if (e.target.id === "cc-search") filterCC(e.target.value);
});

document.addEventListener("keydown", e => {
  if (e.target.id === "target" && e.key === "Enter") { scan(); return; }
  if (document.getElementById("country-code")?.classList.contains("open")) { onCCKeydown(e); return; }
  // "/" focuses the results filter, Escape clears it.
  if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(e.target.tagName)) {
    const box = document.getElementById("res-search");
    if (box) { e.preventDefault(); box.focus(); box.select(); }
  } else if (e.key === "Escape" && e.target.id === "res-search") {
    e.target.value = ""; onResSearch("");
  }
});

/* ------------------------------------------------------------------ INIT */

applyTheme(lsGet(LS.theme) || "dark");
state.type = lsGet(LS.type) || "auto";
populateCountryCodes();
renderTypePicker();

if (!applyDeepLink()) {
  const last = lsGet(LS.target);
  if (last) document.getElementById("target").value = last;
}
