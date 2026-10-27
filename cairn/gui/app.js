/* Cairn dashboard — local, token-authenticated, no external dependencies. */
(() => {
  "use strict";

  const TOKEN = typeof window.CAIRN_TOKEN === "string" ? window.CAIRN_TOKEN : "";
  const VERSION = window.CAIRN_VERSION || "dev";
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEV_COLOR = {
    critical: "var(--red)",
    high: "var(--amber)",
    medium: "var(--yellow)",
    low: "var(--teal)",
    info: "var(--blue)",
  };
  const STATUS_TONE = {
    active: "teal",
    completed: "teal",
    running: "amber",
    queued: "blue",
    cancelling: "amber",
    cancelled: "red",
    failed: "red",
    interrupted: "red",
    revoked: "red",
    expired: "amber",
    allow: "teal",
    deny: "red",
    error: "red",
    open: "blue",
    confirmed: "teal",
    false_positive: "red",
    accepted_risk: "amber",
    duplicate: "red",
    uncertain: "amber",
  };
  const VERDICTS = [
    ["confirmed", "Confirmed", "teal"],
    ["false_positive", "False positive", "danger"],
    ["accepted_risk", "Accepted risk", "ghost"],
    ["uncertain", "Uncertain", "ghost"],
    ["duplicate", "Duplicate", "ghost"],
  ];

  const ICONS = {
    overview:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
    engagements:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h16M4 17h10"/><circle cx="18" cy="17" r="3"/></svg>',
    findings:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 2.6 19.2A1 1 0 0 0 3.5 21h17a1 1 0 0 0 .9-1.8Z"/><path d="M12 9v5"/><circle cx="12" cy="17.3" r=".6" fill="currentColor"/></svg>',
    learning:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 18 8.2 9l4 5.5L15 10l6 8"/><path d="M3 21h18"/><circle cx="8.2" cy="9" r="1.2"/><circle cx="15" cy="10" r="1.2"/></svg>',
    audit:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6l1 3h3v15H5V6h3Z"/><path d="m9 13 2 2 4-4"/></svg>',
    plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M20 15.2A8.5 8.5 0 0 1 8.8 4 8.5 8.5 0 1 0 20 15.2Z"/></svg>',
    close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="m6 6 12 12M18 6 6 18"/></svg>',
    shield:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 6v5.5c0 4.6 3 8.1 7.5 9.5 4.5-1.4 7.5-4.9 7.5-9.5V6Z"/><path d="m9 12 2 2 4-4"/></svg>',
    refresh:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 1 0-2.3 6.3"/><path d="M20 4v7h-7"/></svg>',
    download:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M4 21h16"/></svg>',
    arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
    scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/><circle cx="12" cy="12" r="3"/></svg>',
  };

  const state = {
    engagements: [],
    overall: null,
    selectedId: lsGet("cairn.engagement"),
    overview: null,
    route: "overview",
    lastPageHash: "#/findings",
    filters: { severity: "", status: "", band: "", q: "" },
    pollTimer: null,
    runData: null,
    runAfter: 0,
    drawerId: null,
    navSeq: 0,
    theme: lsGet("cairn.theme") || "dark",
    analyst: lsGet("cairn.analyst") || "local-analyst",
  };

  // ------------------------------------------------------------------ helpers
  function $(selector, root = document) {
    return root.querySelector(selector);
  }

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
    });
  }

  function lsGet(key) {
    try {
      return localStorage.getItem(key);
    } catch (_error) {
      return null;
    }
  }

  function lsSet(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (_error) {
      /* private mode */
    }
  }

  function number(value) {
    const n = Number(value || 0);
    return n.toLocaleString();
  }

  function pct(value, digits = 1) {
    const n = Number(value || 0) * 100;
    return `${n.toFixed(digits)}%`;
  }

  function shortHash(value, size = 12) {
    const text = String(value || "");
    return text.length > size ? `${text.slice(0, size)}…` : text || "—";
  }

  function pretty(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch (_error) {
      return String(value);
    }
  }

  function dt(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString(undefined, {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function clock(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(11, 19);
    return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function until(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    const ms = date.getTime() - Date.now();
    if (ms <= 0) return "expired";
    const hours = Math.floor(ms / 3600000);
    if (hours < 48) return `${hours}h`;
    return `${Math.ceil(hours / 24)}d`;
  }

  function isExpired(engagement) {
    if (!engagement || !engagement.expires_at) return false;
    const date = new Date(engagement.expires_at);
    return !Number.isNaN(date.getTime()) && date.getTime() <= Date.now();
  }

  function isRunActive(status) {
    return ["queued", "running", "cancelling"].includes(status);
  }

  function statusChip(status, label) {
    const tone = STATUS_TONE[status] || "";
    return `<span class="chip ${tone}"><span class="dot"></span>${esc(label || status || "unknown")}</span>`;
  }

  function bandChip(band) {
    const tone = band === "high" ? "teal" : band === "medium" ? "amber" : "red";
    return `<span class="chip ${tone}">${esc(band || "low")}</span>`;
  }

  function severityChip(severity) {
    const safe = SEVERITIES.includes(severity) ? severity : "info";
    return `<span class="sev ${safe}">${esc(safe)}</span>`;
  }

  function confBar(value) {
    const clamped = Math.max(0, Math.min(1, Number(value || 0)));
    return `<div class="confbar"><div class="track"><i style="width:${(clamped * 100).toFixed(1)}%"></i></div><b>${(clamped * 100).toFixed(0)}%</b></div>`;
  }

  function findingRow(finding, confidenceOverride) {
    const confidence = confidenceOverride == null ? finding.confidence : confidenceOverride;
    const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "info";
    const rejected = finding.status === "false_positive";
    const band =
      confidence >= 0.85 ? "high" : confidence >= 0.6 ? "medium" : "low";
    return `<div class="finding-row ${rejected ? "rejected" : ""}" data-finding-id="${esc(finding.id)}" tabindex="0" role="button" aria-label="${esc(finding.title)}">
      ${severityChip(severity)}
      <div><div class="title" title="${esc(finding.title)}">${esc(finding.title)}</div>
        <div class="detector">${esc(finding.detector)} · ${esc(finding.status || "open")}</div></div>
      <div class="asset" title="${esc(finding.asset_value || "—")}">${esc(finding.asset_value || "—")}</div>
      <div title="${rejected ? "Model score at detection; an analyst marked this observation as a false positive." : "Calibrated probability that the observation is valid."}">${confBar(confidence)}</div>
      <div class="right">${rejected ? '<span class="chip red">rejected</span>' : bandChip(band)}</div>
    </div>`;
  }

  function findingList(findings, emptyText, confidenceKey) {
    if (!findings || !findings.length) {
      return `<div class="empty" style="padding:36px 20px"><p class="muted">${esc(emptyText)}</p></div>`;
    }
    return `<div class="finding-list">${findings.map((f) => findingRow(f, confidenceKey ? f[confidenceKey] : undefined)).join("")}</div>`;
  }

  function verifyBits(tuple) {
    const valid = Array.isArray(tuple) ? Boolean(tuple[0]) : Boolean(tuple);
    const count = Array.isArray(tuple) ? tuple[1] : 0;
    const failure = Array.isArray(tuple) ? tuple[2] : null;
    return { valid, count: Number(count || 0), failure };
  }

  function statusForEngagement(engagement) {
    if (!engagement) return "unknown";
    if (engagement.status === "active" && isExpired(engagement)) return "expired";
    return engagement.status || "unknown";
  }

  function scopeChips(scope, limit = 12) {
    if (!scope || !scope.length) return '<span class="muted">No scope rules</span>';
    const shown = scope.slice(0, limit);
    const chips = shown.map((rule) => {
      const sub = rule.include_subdomains ? " +*" : "";
      const mode = rule.mode === "exclude" ? "red" : "teal";
      return `<span class="chip ${mode}" title="${esc(rule.mode)} ${esc(rule.kind)}">${esc(rule.kind)}:${esc(rule.value)}${esc(sub)}</span>`;
    });
    if (scope.length > limit) chips.push(`<span class="chip">+${scope.length - limit} more</span>`);
    return chips.join("");
  }

  // ---------------------------------------------------------------------- API
  async function api(path, options = {}) {
    const headers = { "X-Cairn-Token": TOKEN, ...(options.headers || {}) };
    const init = { method: options.method || "GET", headers, credentials: "same-origin" };
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    const response = await fetch(path, init);
    const type = response.headers.get("content-type") || "";
    let payload = null;
    if (type.includes("application/json")) {
      payload = await response.json().catch(() => null);
    } else {
      payload = await response.text().catch(() => "");
    }
    if (!response.ok) {
      let detail =
        payload && payload.detail
          ? payload.detail
          : typeof payload === "string" && payload.trim()
            ? payload
            : `Request failed (${response.status})`;
      if (Array.isArray(detail)) {
        detail = detail.map((item) => item.msg || item.message || JSON.stringify(item)).join("; ");
      }
      if (typeof detail === "object") detail = pretty(detail);
      throw new Error(String(detail));
    }
    return payload;
  }

  async function refreshEngagements() {
    const data = await api("/api/engagements");
    state.engagements = data.engagements || [];
    state.overall = data.overall || null;
    if (!state.engagements.some((item) => item.id === state.selectedId)) {
      state.selectedId = state.engagements.length ? state.engagements[0].id : null;
      if (state.selectedId) lsSet("cairn.engagement", state.selectedId);
    }
    updateEngagementSelect();
    updateNavCounts();
  }

  function selectedEngagement() {
    return state.engagements.find((item) => item.id === state.selectedId) || null;
  }

  function selectEngagement(id) {
    if (state.selectedId !== id) {
      state.selectedId = id;
      lsSet("cairn.engagement", id || "");
      state.filters = { severity: "", status: "", band: "", q: "" };
      state.overview = null;
    }
    updateEngagementSelect();
    updateNavCounts();
  }

  // -------------------------------------------------------------------- shell
  function renderShell() {
    const app = $("#app");
    app.innerHTML = `
      <aside class="sidebar">
        <a class="brand" href="#/overview" aria-label="Cairn overview">
          <svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 5 37 18 24 31 11 18Z" fill="var(--teal)"/><path d="M24 19 35 30 24 41 13 30Z" fill="var(--amber)" opacity=".9"/></svg>
          <div><div class="brand-name">CAIRN</div><div class="brand-sub">evidence-first surface intel</div></div>
        </a>
        <div class="side-section">
          <div class="side-label">Workspace</div>
          <nav class="nav" aria-label="Primary">
            <a href="#/overview" data-nav="overview">${ICONS.overview}<span>Overview</span><span class="nav-count" id="nav-count-findings"></span></a>
            <a href="#/engagements" data-nav="engagements">${ICONS.engagements}<span>Engagements</span><span class="nav-count" id="nav-count-engagements"></span></a>
            <a href="#/findings" data-nav="findings">${ICONS.findings}<span>Findings</span></a>
            <a href="#/learning" data-nav="learning">${ICONS.learning}<span>Learning</span></a>
            <a href="#/audit" data-nav="audit">${ICONS.audit}<span>Audit trail</span></a>
          </nav>
        </div>
        <div class="sidefoot">
          <div class="safety">${ICONS.shield}<p>Loopback-only UI with a per-process token. Every probe is checked against the expiring scope manifest.</p></div>
          <div class="side-meta"><span>v${esc(VERSION)}</span><span>LOCAL ONLY</span></div>
        </div>
      </aside>
      <div class="main">
        <header class="topbar">
          <span class="crumb" id="crumb">Surface / Overview</span>
          <div class="engagement-switch"><select id="eng-select" aria-label="Selected engagement"></select></div>
          <button class="btn primary small" id="scan-btn" type="button">${ICONS.scan}<span>New scan</span></button>
          <button class="icon-btn" id="theme-btn" type="button" aria-label="Toggle theme" title="Toggle theme">${ICONS.sun}</button>
        </header>
        <div class="content" id="view"></div>
      </div>`;
    applyTheme(state.theme);
    $("#scan-btn").addEventListener("click", openScanModal);
    $("#theme-btn").addEventListener("click", () => {
      applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("#eng-select").addEventListener("change", (event) => {
      const id = event.target.value;
      if (!id) return;
      selectEngagement(id);
      closeDrawer({ silent: true });
      state.overview = null;
      location.hash = "#/overview";
      if (location.hash === "#/overview" && state.route === "overview") route();
    });
    updateEngagementSelect();
  }

  function applyTheme(theme) {
    const next = theme === "light" ? "light" : "dark";
    state.theme = next;
    document.documentElement.dataset.theme = next;
    lsSet("cairn.theme", next);
    const button = $("#theme-btn");
    if (button) {
      button.innerHTML = next === "dark" ? ICONS.sun : ICONS.moon;
      button.setAttribute("aria-label", next === "dark" ? "Switch to light theme" : "Switch to dark theme");
    }
  }

  function updateEngagementSelect() {
    const select = $("#eng-select");
    if (!select) return;
    if (!state.engagements.length) {
      select.innerHTML = '<option value="">No engagement</option>';
      select.disabled = true;
      const scan = $("#scan-btn");
      if (scan) scan.disabled = true;
      return;
    }
    select.disabled = false;
    select.innerHTML = state.engagements
      .map((item) => {
        const suffix = item.client ? ` · ${item.client}` : "";
        return `<option value="${esc(item.id)}"${item.id === state.selectedId ? " selected" : ""}>${esc(item.name + suffix)}</option>`;
      })
      .join("");
    const engagement = selectedEngagement();
    const scan = $("#scan-btn");
    if (scan) {
      const usable = Boolean(engagement && engagement.status === "active" && !isExpired(engagement));
      scan.disabled = !usable;
      scan.title = usable
        ? "Start a scope-gated scan"
        : !engagement
          ? "Create an engagement first"
          : "Engagement is not active or has expired";
    }
  }

  function updateNavCounts() {
    const engagement = selectedEngagement();
    const findings = $("#nav-count-findings");
    if (findings) findings.textContent = engagement ? String(engagement.open_findings || "") : "";
    const engagements = $("#nav-count-engagements");
    if (engagements) engagements.textContent = state.engagements.length ? String(state.engagements.length) : "";
  }

  function syncShell(routeName) {
    const navKey = routeName === "finding" ? "findings" : routeName;
    document.querySelectorAll("[data-nav]").forEach((link) => {
      link.classList.toggle("active", link.dataset.nav === navKey);
    });
    const crumbs = {
      overview: "Surface / Overview",
      engagements: "Workspace / Engagements",
      findings: "Surface / Findings",
      learning: "Model / Learning",
      audit: "Evidence / Audit trail",
      run: "Run / Live assessment",
      finding: "Surface / Finding",
    };
    const crumb = $("#crumb");
    if (crumb) crumb.textContent = crumbs[routeName] || "Surface / Overview";
    updateNavCounts();
  }

  function hideBoot() {
    const boot = $("#boot");
    const app = $("#app");
    if (app) app.hidden = false;
    if (!boot) return;
    boot.classList.add("done");
    setTimeout(() => boot.remove(), 340);
  }

  function showLoading(label) {
    $("#view").innerHTML = `<div class="panel pad" style="margin-top:20px"><div class="sub">${esc(label)}</div><div class="progress" style="margin-top:12px"><i style="width:36%"></i></div></div>`;
  }

  function showError(error) {
    const message = error && error.message ? error.message : String(error);
    $("#view").innerHTML = `<div class="empty">
      <div class="mark">${ICONS.findings}</div>
      <h2>That view could not load</h2>
      <p>${esc(message)}</p>
      <button class="btn primary" type="button" data-action="retry">${ICONS.refresh}Retry</button>
    </div>`;
  }

  // -------------------------------------------------------------------- modals
  function openModal(markup, onMount) {
    const root = $("#modal-root");
    root.innerHTML = `<div class="overlay" data-action="close-modal"></div><div class="modal">${markup}</div>`;
    const modal = root.querySelector(".modal-shell") || root.querySelector(".modal");
    if (modal) {
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-modal", "true");
    }
    if (onMount) onMount(root);
    const focusable = root.querySelector("input, select, textarea, button");
    if (focusable) setTimeout(() => focusable.focus(), 30);
    return root;
  }

  function closeModal() {
    $("#modal-root").innerHTML = "";
  }

  function modalShell({ eyebrow, title, body, footer, size }) {
    return `<div class="modal-shell" style="${size ? `width:min(${size},96vw)` : ""}">
      <div class="modal-head">
        <div><div class="eyebrow">${esc(eyebrow || "Cairn")}</div><h2>${esc(title)}</h2></div>
        <button class="icon-btn close" type="button" data-action="close-modal" aria-label="Close">${ICONS.close}</button>
      </div>
      <div class="modal-body">${body}</div>
      <div class="modal-foot">${footer || ""}</div>
    </div>`;
  }

  function openConfirm({ title, message, confirmLabel, danger, onConfirm }) {
    openModal(
      modalShell({
        eyebrow: "Confirm action",
        title,
        body: `<div class="note ${danger ? "red" : ""}">${esc(message)}</div>`,
        footer: `<button class="btn ghost" type="button" data-action="close-modal">Cancel</button>
          <button class="btn ${danger ? "danger" : "primary"}" id="confirm-action" type="button">${esc(confirmLabel || "Confirm")}</button>`,
      }),
      (root) => {
        $("#confirm-action", root).addEventListener("click", async (event) => {
          const button = event.currentTarget;
          button.disabled = true;
          try {
            await onConfirm();
            closeModal();
          } catch (error) {
            toast(error.message, "bad");
            button.disabled = false;
          }
        });
      },
    );
  }

  function scopeRow(index) {
    return `<div class="scope-row" data-row="${index}">
      <select class="select" data-field="kind" aria-label="Scope kind">
        <option value="domain">domain</option><option value="ip">ip</option>
        <option value="cidr">cidr</option><option value="url">url</option>
      </select>
      <input class="input" data-field="value" placeholder="example.com" aria-label="Scope value" autocomplete="off">
      <label class="check wild" style="font-size:10.5px"><input type="checkbox" data-field="wild"> subdomains</label>
      <button class="remove" type="button" data-remove-row aria-label="Remove scope rule">×</button>
    </div>`;
  }

  function openEngagementModal() {
    openModal(
      modalShell({
        eyebrow: "New engagement",
        title: "Define the authorized surface",
        body: `<form id="engagement-form" autocomplete="off">
          <div class="note">Cairn refuses to run without an explicit, expiring, hashed scope manifest. Confirm you have permission before the first probe.</div>
          <div class="form-grid" style="margin-top:16px">
            <div class="field"><label for="eng-name">Engagement name</label><input class="input" id="eng-name" required minlength="2" maxlength="120" placeholder="Q4 external assessment"></div>
            <div class="field"><label for="eng-client">Client</label><input class="input" id="eng-client" maxlength="120" placeholder="Acme Corp (or self)"></div>
            <div class="field"><label for="eng-authorized">Authorized by</label><input class="input" id="eng-authorized" required minlength="2" maxlength="160" placeholder="Security lead, ticket owner"></div>
            <div class="field"><label for="eng-ref">Authorization reference</label><input class="input" id="eng-ref" required minlength="3" maxlength="240" placeholder="SOW-2026-014 / TICKET-5521"></div>
            <div class="field"><label for="eng-expires">Expires in (hours)</label><input class="input" id="eng-expires" type="number" min="1" max="4320" value="24"></div>
            <div class="field"><label for="eng-max-hosts">Max hosts</label><input class="input" id="eng-max-hosts" type="number" min="1" max="4096" value="256"></div>
          </div>
          <fieldset style="margin-top:18px">
            <legend>Scope rules</legend>
            <div id="scope-rows">${scopeRow(0)}</div>
            <button class="btn small" type="button" id="add-scope" style="margin-top:8px">${ICONS.plus}Add rule</button>
            <div class="hint" style="margin-top:6px">Domain rules cover the apex unless "subdomains" is checked. Exclude rules can be added through the CLI.</div>
          </fieldset>
          <fieldset style="margin-top:18px">
            <legend>Probe ceilings</legend>
            <div class="form-grid">
              <div class="field"><label for="eng-ports">TCP ports</label><input class="input" id="eng-ports" placeholder="blank = top ports, or 80,443,8000-8100"><div class="hint">Port ranges are capped at 4,097 entries per range.</div></div>
              <div class="field"><label for="eng-timeout">Timeout (seconds)</label><input class="input" id="eng-timeout" type="number" min="1" max="30" step="0.5" value="8"></div>
              <div class="field"><label for="eng-http-rate">HTTP rate / second / host</label><input class="input" id="eng-http-rate" type="number" min="0.1" max="50" step="0.5" value="4"></div>
              <div class="field"><label for="eng-port-rate">Port rate / second / host</label><input class="input" id="eng-port-rate" type="number" min="1" max="1000" value="250"></div>
            </div>
            <label class="check" style="margin-top:10px"><input type="checkbox" id="eng-full-ports"> Authorize all 65,535 TCP ports <span class="faint">(slower, noisier)</span></label>
          </fieldset>
          <div class="field" style="margin-top:18px"><label for="eng-notes">Notes</label><textarea class="textarea" id="eng-notes" maxlength="4000" placeholder="Rules of engagement, contacts, exclusions, timing constraints"></textarea></div>
          <label class="check" style="margin-top:16px"><input type="checkbox" id="eng-confirm"> I confirm written authorization for the scope above and understand that Cairn performs only non-exploitative reconnaissance.</label>
          <div class="note red" id="form-error" style="display:none;margin-top:12px"></div>
        </form>`,
        footer: `<button class="btn ghost" type="button" data-action="close-modal">Cancel</button>
          <button class="btn primary" type="button" id="create-engagement">Create engagement</button>`,
      }),
      (root) => {
        let index = 1;
        $("#add-scope", root).addEventListener("click", () => {
          $("#scope-rows", root).insertAdjacentHTML("beforeend", scopeRow(index++));
        });
        $("#scope-rows", root).addEventListener("click", (event) => {
          const remove = event.target.closest("[data-remove-row]");
          if (remove) {
            const rows = root.querySelectorAll(".scope-row");
            if (rows.length > 1) remove.closest(".scope-row").remove();
          }
        });
        const submit = async () => {
          const errorBox = $("#form-error", root);
          errorBox.style.display = "none";
          if (!$("#eng-confirm", root).checked) {
            errorBox.textContent = "Explicit authorization confirmation is required.";
            errorBox.style.display = "block";
            return;
          }
          const scope = [];
          for (const row of root.querySelectorAll(".scope-row")) {
            const value = $("[data-field='value']", row).value.trim();
            if (!value) continue;
            scope.push({
              kind: $("[data-field='kind']", row).value,
              value,
              mode: "include",
              include_subdomains: $("[data-field='wild']", row).checked,
            });
          }
          if (!scope.length) {
            errorBox.textContent = "Add at least one scope rule.";
            errorBox.style.display = "block";
            return;
          }
          const body = {
            name: $("#eng-name", root).value.trim(),
            client: $("#eng-client", root).value.trim(),
            authorized_by: $("#eng-authorized", root).value.trim(),
            authorization_ref: $("#eng-ref", root).value.trim(),
            expires_hours: Number($("#eng-expires", root).value || 24),
            notes: $("#eng-notes", root).value,
            scope,
            ports: $("#eng-full-ports", root).checked ? "" : $("#eng-ports", root).value.trim(),
            full_ports: $("#eng-full-ports", root).checked,
            http_rate: Number($("#eng-http-rate", root).value || 4),
            port_rate: Number($("#eng-port-rate", root).value || 250),
            max_hosts: Number($("#eng-max-hosts", root).value || 256),
            timeout: Number($("#eng-timeout", root).value || 8),
            confirm_authorized: true,
          };
          if (!body.name || !body.authorized_by || !body.authorization_ref) {
            errorBox.textContent = "Name, authorizer, and authorization reference are required.";
            errorBox.style.display = "block";
            return;
          }
          const button = $("#create-engagement", root);
          button.disabled = true;
          button.textContent = "Creating…";
          try {
            const created = await api("/api/engagements", { method: "POST", body });
            await refreshEngagements();
            selectEngagement(created.id);
            closeModal();
            toast("Engagement created. The manifest is hashed and audited.", "good");
            state.overview = null;
            location.hash = "#/overview";
            if (state.route === "overview") await route();
          } catch (error) {
            errorBox.textContent = error.message;
            errorBox.style.display = "block";
            button.disabled = false;
            button.textContent = "Create engagement";
          }
        };
        $("#create-engagement", root).addEventListener("click", submit);
        $("#engagement-form", root).addEventListener("submit", (event) => {
          event.preventDefault();
          submit();
        });
      },
    );
  }

  function openScanModal() {
    const engagement = selectedEngagement();
    if (!engagement) {
      toast("Create an engagement before starting a scan.", "bad");
      return;
    }
    if (statusForEngagement(engagement) !== "active") {
      toast("This engagement is not active or has expired.", "bad");
      return;
    }
    openModal(
      modalShell({
        eyebrow: "Scope-gated scan",
        title: `Assess ${engagement.name}`,
        body: `<form id="run-form">
          <div class="note teal">Every connection is re-checked against the manifest. Passive mode sends no packets to target services; standard and deep add TCP, TLS, and HTTP reconnaissance.</div>
          <div class="form-grid" style="margin-top:16px">
            <div class="field"><label for="run-mode">Mode</label>
              <select class="select" id="run-mode">
                <option value="standard" selected>standard — DNS, ports, TLS, HTTP, content</option>
                <option value="passive">passive — DNS and third-party OSINT only</option>
                <option value="deep">deep — full authorized port and content budget</option>
              </select>
            </div>
            <div class="field"><label>Signals</label>
              <label class="check"><input type="checkbox" id="run-online" checked> Certificate Transparency and RDAP lookups</label>
              <label class="check"><input type="checkbox" id="run-active-dns" checked> Active subdomain wordlist discovery</label>
            </div>
          </div>
          <div class="kv" style="margin-top:16px">
            <div><dt>Scope</dt><dd>${esc(engagement.scope.length)} rule(s)</dd></div>
            <div><dt>Port budget</dt><dd>${engagement.limits && engagement.limits.full_ports ? "all 65,535" : `${number(engagement.limits && engagement.limits.allowed_ports ? engagement.limits.allowed_ports.length : 0)} ports`}</dd></div>
            <div><dt>Expires</dt><dd>${esc(until(engagement.expires_at))}</dd></div>
            <div><dt>Manifest</dt><dd class="hash">${esc(shortHash(engagement.manifest_hash, 16))}</dd></div>
          </div>
          <div class="note" id="run-mode-note" style="margin-top:14px">Standard mode uses the top-port budget and HTTP content discovery.</div>
        </form>`,
        footer: `<button class="btn ghost" type="button" data-action="close-modal">Cancel</button>
          <button class="btn primary" type="button" id="start-run">${ICONS.scan}Start scan</button>`,
      }),
      (root) => {
        const mode = $("#run-mode", root);
        const activeDns = $("#run-active-dns", root);
        const note = $("#run-mode-note", root);
        const sync = () => {
          const passive = mode.value === "passive";
          activeDns.disabled = passive;
          if (passive) activeDns.checked = false;
          note.textContent = passive
            ? "Passive mode performs DNS and third-party intelligence only. No TCP, TLS, or HTTP probes are sent to the target."
            : mode.value === "deep"
              ? "Deep mode uses the full authorized port list and expands content discovery within the manifest ceilings."
              : "Standard mode uses the top-port budget and HTTP content discovery.";
        };
        mode.addEventListener("change", sync);
        sync();
        const start = async () => {
          const button = $("#start-run", root);
          button.disabled = true;
          button.textContent = "Starting…";
          try {
            const run = await api(`/api/engagements/${engagement.id}/runs`, {
              method: "POST",
              body: {
                mode: mode.value,
                online_intel: $("#run-online", root).checked,
                active_dns: activeDns.checked,
              },
            });
            closeModal();
            toast(`Run ${run.id} queued.`, "good");
            state.overview = null;
            location.hash = `#/run/${run.id}`;
            if (state.route === "run" && state.runData && state.runData.run.id === run.id) {
              await route();
            }
          } catch (error) {
            toast(error.message, "bad");
            button.disabled = false;
            button.textContent = "Start scan";
          }
        };
        $("#start-run", root).addEventListener("click", start);
        $("#run-form", root).addEventListener("submit", (event) => {
          event.preventDefault();
          start();
        });
      },
    );
  }

  // ------------------------------------------------------------------- router
  async function route() {
    const seq = ++state.navSeq;
    stopPolling();
    const parsed = parseHash();
    if (["overview", "engagements", "findings", "learning", "audit", "run", "finding"].includes(parsed.name) === false) {
      location.hash = "#/overview";
      return;
    }
    state.route = parsed.name;
    syncShell(parsed.name);
    if (parsed.name !== "finding") {
      closeDrawer({ silent: true });
      state.lastPageHash = `#/${parsed.name}${parsed.id ? `/${parsed.id}` : ""}`;
    }

    try {
      if (parsed.name === "overview") await renderOverview(seq);
      else if (parsed.name === "engagements") await renderEngagements(seq);
      else if (parsed.name === "findings") await renderFindings(seq);
      else if (parsed.name === "learning") await renderLearning(seq);
      else if (parsed.name === "audit") await renderAudit(seq);
      else if (parsed.name === "run") await renderRun(parsed.id, seq);
      else if (parsed.name === "finding") await renderFindingRoute(parsed.id, seq);
    } catch (error) {
      if (seq === state.navSeq) showError(error);
    }
  }

  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    const parts = raw.split("/").filter(Boolean);
    return { name: parts[0] || "overview", id: parts[1] || "" };
  }

  // ----------------------------------------------------------------- overview
  function onboarding() {
    const overall = state.overall || {};
    return `<div class="page-head">
      <div><div class="eyebrow">Evidence-first reconnaissance</div><h1>Point Cairn at a surface you are allowed to test.</h1>
      <p class="lede">A local attack-surface workspace built around explicit authorization, hashed evidence, and calibrated confidence. No exploitation. No authentication attempts. No hidden telemetry.</p></div>
    </div>
    <div class="hero">
      <div class="hero-main">
        <div class="eyebrow">First contact</div>
        <h1>Evidence before assumptions.</h1>
        <p class="lede">Create an expiring scope manifest, run a non-destructive assessment, then review every finding with its evidence and a confidence score you can audit.</p>
        <div class="pill-row"><span class="chip teal">Explicit scope</span><span class="chip amber">Calibrated confidence</span><span class="chip blue">Hash-chained audit</span><span class="chip">Loopback only</span></div>
        <div style="margin-top:20px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="button" data-action="new-engagement">${ICONS.plus}Create your first engagement</button><a class="btn ghost" href="#/learning">See the learning model</a></div>
      </div>
      <div class="hero-side">
        <div style="font:600 9px/1 var(--mono);letter-spacing:.16em;color:var(--faint)">THE CONTRACT</div>
        <div><b style="font:400 22px/1.1 var(--serif)">01 · Authorize</b><div class="sub">Name the authorizer and reference. Set an expiry. The manifest is hashed.</div></div>
        <div><b style="font:400 22px/1.1 var(--serif)">02 · Observe</b><div class="sub">DNS, OSINT, TCP, TLS, and HTTP — each probe re-checked against scope.</div></div>
        <div><b style="font:400 22px/1.1 var(--serif)">03 · Calibrate</b><div class="sub">Analyst verdicts train a challenger; it replaces the champion only when Brier score improves.</div></div>
      </div>
    </div>
    <div class="grid metrics" style="margin-top:14px">
      <div class="panel metric"><div class="label">Engagements</div><div class="value">${number(overall.engagements)}</div><div class="foot">explicit scope manifests</div></div>
      <div class="panel metric"><div class="label">Findings</div><div class="value">${number(overall.findings)}</div><div class="foot">across all engagements</div></div>
      <div class="panel metric"><div class="label">Evidence records</div><div class="value">${number(overall.evidence)}</div><div class="foot">redacted and hash-chained</div></div>
      <div class="panel metric"><div class="label">Runs</div><div class="value">${number(overall.runs)}</div><div class="foot">scope-gated assessments</div></div>
    </div>
    <div class="grid two" style="margin-top:14px">
      <div class="panel pad"><h3 class="card-title">What Cairn does</h3><p class="sub" style="margin:8px 0 0">DNS and certificate-transparency discovery, connect-scanned services, TLS capture, technology fingerprinting, bounded content discovery, and non-exploitative detectors for exposed artifacts and misconfiguration.</p></div>
      <div class="panel pad"><h3 class="card-title">What Cairn refuses to do</h3><p class="sub" style="margin:8px 0 0">No exploitation, credential attacks, mutation of target state, public API binding, or scans outside an unexpired manifest. Findings are observations, not proof of exploitability.</p></div>
    </div>`;
  }

  async function renderOverview(seq) {
    const engagement = selectedEngagement();
    if (!engagement) {
      $("#view").innerHTML = onboarding();
      return;
    }
    showLoading("Loading engagement surface…");
    const summary = await api(`/api/engagements/${engagement.id}`);
    if (seq !== state.navSeq) return;
    state.overview = summary;
    const lastRun = summary.last_run;
    if (lastRun && isRunActive(lastRun.status)) {
      /* The overview remains a snapshot; the run page is the live view. */
    }
    const activeRun = summary.runs.find((run) => isRunActive(run.status));
    const e = summary.engagement;
    const sev = summary.severity || {};
    const bands = summary.bands || {};
    const totalSeverity = SEVERITIES.reduce((sum, key) => sum + Number(sev[key] || 0), 0);
    const openFindings = totalSeverity;
    const evidence = verifyBits(summary.verify && summary.verify.evidence);
    const audit = verifyBits(summary.verify && summary.verify.audit);
    const coverage = lastRun ? Number(lastRun.coverage || 0) : 0;
    const risk = (sev.critical || 0) + (sev.high || 0);
    const assetCount = summary.assets.length;
    const counts = summary.asset_counts || {};
    const recent = summary.findings.slice(0, 6);
    const scope = e.scope || [];
    const limits = e.limits || {};
    const delta = summary.delta;
    const lastStatus = lastRun ? lastRun.status : "never";

    $("#view").innerHTML = `
      <div class="page-head">
        <div>
          <div class="eyebrow">${statusForEngagement(e)} engagement · ${esc(e.client || "internal")}</div>
          <h1>${esc(e.name)}</h1>
          <p class="lede">${esc(e.notes || "An evidence-first view of the authorized attack surface. Confidence is a calibrated probability, not a severity score.")}</p>
        </div>
        <div class="head-actions">
          <button class="btn primary" type="button" data-action="new-scan" ${statusForEngagement(e) !== "active" ? "disabled" : ""}>${ICONS.scan}Start scan</button>
          <a class="btn ghost" href="#/findings">${ICONS.findings}Findings</a>
          <button class="btn danger small" type="button" data-action="revoke-engagement" data-id="${esc(e.id)}" data-name="${esc(e.name)}" ${e.status !== "active" ? "disabled" : ""}>Revoke</button>
        </div>
      </div>
      ${activeRun ? `<div class="run-banner"><span class="pulse"></span><div><b>${esc(activeRun.mode)} run in progress</b><div class="sub">${esc(activeRun.id)} · queued ${esc(dt(activeRun.created_at))}</div></div><a class="btn small" href="#/run/${esc(activeRun.id)}">${ICONS.arrow}Open live run</a></div>` : ""}
      <div class="hero">
        <div class="hero-main">
          <div class="eyebrow">Hash-sealed scope · ${esc(e.authorization_ref)}</div>
          <h1>${openFindings} open finding${openFindings === 1 ? "" : "s"} across ${assetCount} asset${assetCount === 1 ? "" : "s"}.</h1>
          <p class="lede">${lastRun ? `Last ${esc(lastRun.mode)} run ${esc(lastRun.status)} ${esc(dt(lastRun.finished_at || lastRun.started_at || lastRun.created_at))}. Coverage is measured against planned probes, not a guarantee of safety.` : "No scan has run against this manifest yet. Start with passive or standard mode and review the evidence."}</p>
          <div class="hero-meta">
            <span>authorized by <b>${esc(e.authorized_by)}</b></span>
            <span>expires <b>${esc(until(e.expires_at))}</b></span>
            <span>manifest <b class="mono">${esc(shortHash(e.manifest_hash, 14))}</b></span>
          </div>
          <div class="scope-inline" style="margin-top:15px">${scopeChips(scope, 6)}</div>
        </div>
        <div class="hero-side">
          <div class="coverage-ring">
            ${coverageRing(coverage)}
            <div class="ringtext"><b>${coverage ? pct(coverage, 0) : "—"}</b><span>last run coverage</span></div>
          </div>
          <div class="divider" style="margin:2px 0;background:var(--line)"></div>
          <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">${statusChip(lastRun ? lastStatus : "", lastRun ? lastStatus : "not run yet")}<span class="sub">${lastRun ? esc(lastRun.id) : "manifest ready"}</span></div>
          ${delta ? `<div class="delta"><div><b>${number(delta.new)}</b><span>new</span></div><div><b>${number(delta.resolved)}</b><span>resolved</span></div><div><b>${number(delta.persistent)}</b><span>persistent</span></div></div>` : ""}
        </div>
      </div>
      <div class="grid metrics" style="margin-top:14px">
        <div class="panel metric"><div class="label">Open findings</div><div class="value">${number(openFindings)}</div><div class="foot">${number(summary.feedback.false_positive || 0)} false positive verdict(s)</div></div>
        <div class="panel metric ${risk ? "alert" : "good"}"><div class="label">Critical + high</div><div class="value">${number(risk)}</div><div class="foot">${number(sev.critical || 0)} critical · ${number(sev.high || 0)} high</div></div>
        <div class="panel metric"><div class="label">Assets</div><div class="value">${number(assetCount)}</div><div class="foot">${number(counts.domain || 0)} domains · ${number(counts.service || 0)} services</div></div>
        <div class="panel metric ${bands.high ? "good" : ""}"><div class="label">High confidence</div><div class="value">${number(bands.high || 0)}</div><div class="foot">≥ 85% calibrated probability</div></div>
        <div class="panel metric"><div class="label">Evidence</div><div class="value">${number(evidence.count)}</div><div class="foot">${evidence.valid ? "chain verified" : "chain check failed"}</div></div>
        <div class="panel metric ${audit.valid ? "good" : "alert"}"><div class="label">Audit events</div><div class="value">${number(audit.count)}</div><div class="foot">${audit.valid ? "hash chain intact" : "verification failed"}</div></div>
      </div>
      <div class="grid main-side" style="margin-top:14px">
        <div>
          <div class="panel">
            <div class="panel-head"><h3 class="card-title">Severity &amp; confidence</h3><span class="sub">${number(totalSeverity)} active finding(s)</span></div>
            <div class="panel-body" style="display:grid;grid-template-columns:auto minmax(0,1fr);gap:24px;align-items:center">
              ${severityDonut(sev, totalSeverity)}
              <div>
                <div class="why-list">${severityRows(sev, totalSeverity)}</div>
                <div class="divider"></div>
                <div class="why-list">${bandRows(bands)}</div>
              </div>
            </div>
          </div>
          <div class="panel" style="margin-top:14px">
            <div class="panel-head"><h3 class="card-title">Recent findings</h3><a class="sub" href="#/findings" style="text-decoration:none">View all ${ICONS.arrow}</a></div>
            ${findingList(recent, "No findings yet. Run a scan to populate the evidence graph.")}
          </div>
          <div class="panel" style="margin-top:14px">
            <div class="panel-head"><h3 class="card-title">Assessment runs</h3><span class="sub">${summary.runs.length} recent</span></div>
            ${runsTable(summary.runs)}
          </div>
        </div>
        <div>
          <div class="panel">
            <div class="panel-head"><h3 class="card-title">Scope contract</h3>${statusChip(statusForEngagement(e), statusForEngagement(e))}</div>
            <div class="panel-body">
              <dl class="kv">
                <div><dt>Authorized by</dt><dd>${esc(e.authorized_by)}</dd></div>
                <div><dt>Reference</dt><dd>${esc(e.authorization_ref)}</dd></div>
                <div><dt>Window</dt><dd>${esc(dt(e.starts_at))} → ${esc(dt(e.expires_at))}</dd></div>
                <div><dt>Limits</dt><dd>${number((limits.allowed_ports || []).length)} ports · ${esc(limits.http_rate || 4)} req/s · ${esc(limits.timeout || 8)}s</dd></div>
              </dl>
              <div class="scope-inline" style="margin-top:12px">${scopeChips(scope, 8)}</div>
              <div class="hash" style="margin-top:13px">manifest ${esc(e.manifest_hash || "")}</div>
            </div>
          </div>
          <div class="panel" style="margin-top:14px">
            <div class="panel-head"><h3 class="card-title">Integrity</h3><span class="sub">independent chains</span></div>
            <div class="panel-body">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><span class="sub">Audit events</span><span class="chip ${audit.valid ? "teal" : "red"}">${audit.valid ? "verified" : "failed"}</span></div>
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:7px"><span class="sub">Evidence records</span><span class="chip ${evidence.valid ? "teal" : "red"}">${evidence.valid ? "verified" : "failed"}</span></div>
              <div class="note ${audit.valid && evidence.valid ? "teal" : "red"}" style="margin-top:12px">${audit.valid && evidence.valid ? `Both SHA-256 hash chains verify across ${number(audit.count)} audit events and ${number(evidence.count)} evidence records.` : `Chain verification failed${audit.failure || evidence.failure ? ` at ${esc(audit.failure || evidence.failure)}` : ""}. Investigate before trusting this dataset.`}</div>
              <a class="btn small ghost" style="margin-top:12px" href="#/audit">Open audit trail</a>
            </div>
          </div>
          <div class="panel" style="margin-top:14px">
            <div class="panel-head"><h3 class="card-title">Asset inventory</h3><span class="sub">${number(assetCount)} total</span></div>
            <div class="panel-body"><div class="pill-row">${Object.entries(counts).length ? Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([kind, n]) => `<span class="chip">${esc(kind)} <b>${number(n)}</b></span>`).join("") : '<span class="sub">No assets yet.</span>'}</div></div>
          </div>
        </div>
      </div>`;
  }

  // -------------------------------------------------------------- engagements
  async function renderEngagements(seq) {
    const data = await api("/api/engagements");
    if (seq !== state.navSeq) return;
    state.engagements = data.engagements || [];
    state.overall = data.overall || null;
    updateEngagementSelect();
    updateNavCounts();
    const overall = data.overall || {};
    const rows = state.engagements
      .map((e) => {
        const stateLabel = statusForEngagement(e);
        return `<tr>
          <td><div style="font-weight:600">${esc(e.name)}${e.id === state.selectedId ? ' <span class="chip amber">current</span>' : ""}</div><div class="faint" style="font-size:10.5px">${esc(e.client || "no client")} · ${esc(e.id)}</div></td>
          <td>${statusChip(stateLabel, stateLabel)}</td>
          <td><div class="scope-inline">${scopeChips(e.scope, 2)}</div></td>
          <td class="mono">${esc(e.authorized_by)}<div class="faint">${esc(e.authorization_ref)}</div></td>
          <td class="num">${number(e.run_count)}</td>
          <td class="num">${number(e.open_findings)}</td>
          <td class="nowrap">${esc(until(e.expires_at))}</td>
          <td class="right nowrap"><button class="btn small" type="button" data-select-engagement="${esc(e.id)}">Open</button>
            <button class="btn small danger" type="button" data-action="revoke-engagement" data-id="${esc(e.id)}" data-name="${esc(e.name)}" ${e.status !== "active" ? "disabled" : ""}>Revoke</button></td>
        </tr>`;
      })
      .join("");
    $("#view").innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Authorization ledger</div><h1>Engagements</h1><p class="lede">Each engagement is a bounded permission slip: scope rules, probe ceilings, an expiry, and a manifest hash recorded in the audit chain.</p></div>
        <div class="head-actions"><button class="btn primary" type="button" data-action="new-engagement">${ICONS.plus}New engagement</button></div>
      </div>
      <div class="grid metrics">
        <div class="panel metric"><div class="label">Engagements</div><div class="value">${number(overall.engagements)}</div><div class="foot">all time</div></div>
        <div class="panel metric"><div class="label">Findings</div><div class="value">${number(overall.findings)}</div><div class="foot">evidence-backed</div></div>
        <div class="panel metric"><div class="label">Evidence</div><div class="value">${number(overall.evidence)}</div><div class="foot">hash-chained records</div></div>
        <div class="panel metric"><div class="label">Runs</div><div class="value">${number(overall.runs)}</div><div class="foot">queued or completed</div></div>
      </div>
      <div class="panel" style="margin-top:14px">
        <div class="panel-head"><h3 class="card-title">All engagements</h3><span class="sub">${state.engagements.length} manifest(s)</span></div>
        ${state.engagements.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Engagement</th><th>Status</th><th>Scope</th><th>Authorized by</th><th class="num">Runs</th><th class="num">Open</th><th>Expires</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty"><h2>No engagements yet</h2><p>Create your first expiring scope manifest to start an assessment.</p><button class="btn primary" type="button" data-action="new-engagement">${ICONS.plus}Create engagement</button></div>`}
      </div>
      <div class="note teal" style="margin-top:14px"><b>Scope is a contract, not a suggestion.</b> Revoking an engagement stops its active runs and disables new probes immediately. The manifest and audit history remain for accountability.</div>`;
    document.querySelectorAll("[data-select-engagement]").forEach((button) => {
      button.addEventListener("click", async () => {
        selectEngagement(button.dataset.selectEngagement);
        state.overview = null;
        location.hash = "#/overview";
        if (state.route === "overview") await route();
      });
    });
  }

  // ----------------------------------------------------------------- findings
  async function renderFindings(seq) {
    const engagement = selectedEngagement();
    if (!engagement) {
      $("#view").innerHTML = onboarding();
      return;
    }
    showLoading("Querying the finding index…");
    const data = await loadFindings();
    if (seq !== state.navSeq) return;
    $("#view").innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Evidence graph · ${esc(engagement.name)}</div><h1>Findings</h1><p class="lede">Every row carries a calibrated probability that the observation is valid. Open a finding to inspect the evidence, the model's explanation, and record an analyst verdict.</p></div>
        <div class="head-actions"><button class="btn primary" type="button" data-action="new-scan">${ICONS.scan}New scan</button></div>
      </div>
      <div class="filters">
        <select class="select" id="filter-severity" aria-label="Minimum severity">
          <option value="">All severities</option>
          ${SEVERITIES.map((s) => `<option value="${s}"${state.filters.severity === s ? " selected" : ""}>${s} and above</option>`).join("")}
        </select>
        <select class="select" id="filter-status" aria-label="Finding status">
          <option value="">Any status</option>
          ${["open", "confirmed", "false_positive", "accepted_risk", "duplicate"].map((s) => `<option value="${s}"${state.filters.status === s ? " selected" : ""}>${s.replace("_", " ")}</option>`).join("")}
        </select>
        <select class="select" id="filter-band" aria-label="Confidence band">
          <option value="">Any confidence</option>
          ${["high", "medium", "low"].map((b) => `<option value="${b}"${state.filters.band === b ? " selected" : ""}>${b} confidence</option>`).join("")}
        </select>
        <input class="input search" id="filter-q" placeholder="Search title, detector, or asset…" value="${esc(state.filters.q)}" aria-label="Search findings">
        <button class="btn small ghost" type="button" id="clear-filters">Clear</button>
        <span class="spacer"></span><span class="result-count" id="findings-count">${data.findings.length} result(s)</span>
      </div>
      <div class="panel" id="findings-panel">${findingsBody(data.findings)}</div>`;
    const reflow = async () => {
      const result = await loadFindings();
      const panel = $("#findings-panel");
      if (panel) panel.innerHTML = findingsBody(result.findings);
      const count = $("#findings-count");
      if (count) count.textContent = `${result.findings.length} result(s)`;
    };
    $("#filter-severity").addEventListener("change", (event) => {
      state.filters.severity = event.target.value;
      reflow().catch((error) => toast(error.message, "bad"));
    });
    $("#filter-status").addEventListener("change", (event) => {
      state.filters.status = event.target.value;
      reflow().catch((error) => toast(error.message, "bad"));
    });
    $("#filter-band").addEventListener("change", (event) => {
      state.filters.band = event.target.value;
      reflow().catch((error) => toast(error.message, "bad"));
    });
    let timer = null;
    $("#filter-q").addEventListener("input", (event) => {
      state.filters.q = event.target.value;
      clearTimeout(timer);
      timer = setTimeout(() => reflow().catch((error) => toast(error.message, "bad")), 260);
    });
    $("#clear-filters").addEventListener("click", () => {
      state.filters = { severity: "", status: "", band: "", q: "" };
      renderFindings(++state.navSeq).catch((error) => showError(error));
    });
  }

  async function loadFindings() {
    const engagement = selectedEngagement();
    if (!engagement) return { findings: [] };
    const params = new URLSearchParams();
    if (state.filters.severity) params.set("min_severity", state.filters.severity);
    if (state.filters.status) params.set("status", state.filters.status);
    if (state.filters.band) params.set("band", state.filters.band);
    if (state.filters.q.trim()) params.set("q", state.filters.q.trim());
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return api(`/api/engagements/${engagement.id}/findings${suffix}`);
  }

  function findingsBody(findings) {
    if (!findings || !findings.length) {
      return `<div class="empty"><div class="mark">${ICONS.findings}</div><h2>No matching findings</h2><p>Try widening the filters, or run a standard scan to map more of the authorized surface.</p><button class="btn" type="button" data-action="new-scan">${ICONS.scan}Run a scan</button></div>`;
    }
    return `<div class="panel-head"><h3 class="card-title">${number(findings.length)} finding(s)</h3><span class="sub">sorted by severity, confidence, then recency</span></div>${findingList(findings, "No findings.")}`;
  }

  // ----------------------------------------------------------------- learning
  async function renderLearning(seq) {
    const engagement = selectedEngagement();
    showLoading("Reading the calibration ledger…");
    const data = await api(`/api/learning${engagement ? `?engagement_id=${encodeURIComponent(engagement.id)}` : ""}`);
    if (seq !== state.navSeq) return;
    const champion = data.champion;
    const models = data.models || [];
    const latest = models.length ? models[0] : null;
    const challenger = latest && (!champion || latest.id !== champion.id) ? latest : null;
    const displayModel = champion || latest;
    const metrics = displayModel ? displayModel.metrics || {} : {};
    const challengerMetrics = challenger ? challenger.metrics || {} : {};
    const thresholds = data.thresholds || {};
    const gate = challenger ? [
      {
        ok: Number(challengerMetrics.n_eval || 0) >= Number(thresholds.min_eval || 30),
        label: `${number(challengerMetrics.n_eval || 0)} / ${number(thresholds.min_eval || 30)} held-out human labels`,
      },
      {
        ok: Number(challengerMetrics.brier_calibrated ?? challengerMetrics.brier ?? 1)
          < Number(challengerMetrics.baseline_brier || 1) - Number(thresholds.baseline_margin || 0.002),
        label: `Brier ${Number(challengerMetrics.brier_calibrated ?? challengerMetrics.brier ?? 0).toFixed(3)} beats baseline ${Number(challengerMetrics.baseline_brier || 0).toFixed(3)}`,
      },
      {
        ok: Number(challengerMetrics.ece ?? 1) <= Number(thresholds.max_ece || 0.15),
        label: `ECE ${Number(challengerMetrics.ece ?? 0).toFixed(3)} within ${Number(thresholds.max_ece || 0.15).toFixed(2)} calibration gate`,
      },
      ...(champion ? [{
        ok: Number(challengerMetrics.brier_calibrated ?? challengerMetrics.brier ?? 1)
          < Number((champion.metrics || {}).brier_calibrated ?? (champion.metrics || {}).brier ?? 1)
            - Number(thresholds.promotion_improvement || 0.005),
        label: `Beats champion #${champion.id} by ${Number(thresholds.promotion_improvement || 0.005)} Brier`,
      }] : []),
    ] : [];
    const calibrationRegressed = Boolean(challenger) && (
      Number(challengerMetrics.brier_calibrated ?? challengerMetrics.brier ?? 0)
        > Number(challengerMetrics.baseline_brier || 0) + 0.01
      || Number(challengerMetrics.ece ?? 0) > Number(thresholds.max_ece || 0.15)
    );
    const counts = data.feedback_counts || {};
    const labels = data.human_labels || 0;
    const target = data.next_promotion_at || 30;
    const progress = Math.min(100, (labels / Math.max(1, target)) * 100);
    const bins = metrics.calibration_bins || [];
    const detectors = data.detectors || [];
    const paths = data.paths || [];
    const probes = data.probes || [];
    const queue = data.active_learning || [];

    $("#view").innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Continuous calibration</div><h1>Confidence, earned.</h1><p class="lede">Confidence is a probability that a finding is valid — not a severity. Analyst verdicts train a challenger, but promotion is gated on held-out human labels, Brier improvement, and calibration error. A model that only looks good on training loss never reaches the champion seat.</p></div>
        <div class="head-actions"><button class="btn primary" type="button" data-action="retrain">${ICONS.learning}Train challenger</button></div>
      </div>
      ${displayModel ? `<div class="grid metrics">
        <div class="panel metric"><div class="label">Brier score</div><div class="value">${Number(metrics.brier != null ? metrics.brier : 0).toFixed(3)}</div><div class="foot">calibrated · baseline ${Number(metrics.baseline_brier || 0).toFixed(3)} · raw ${Number(metrics.brier_uncalibrated != null ? metrics.brier_uncalibrated : metrics.brier || 0).toFixed(3)}</div></div>
        <div class="panel metric"><div class="label">Calibration error</div><div class="value">${Number(metrics.ece || 0).toFixed(3)}</div><div class="foot">ECE on ${number(metrics.n_eval)} human label(s) · raw ${Number(metrics.ece_uncalibrated || 0).toFixed(3)}</div></div>
        <div class="panel metric"><div class="label">Accuracy</div><div class="value">${pct(metrics.accuracy || 0, 0)}</div><div class="foot">precision ${pct(metrics.precision || 0, 0)} · recall ${pct(metrics.recall || 0, 0)}</div></div>
        <div class="panel metric"><div class="label">${champion ? "Champion labels" : "Evaluation labels"}</div><div class="value">${number(displayModel.n_labels)}</div><div class="foot">model #${esc(displayModel.id)} · ${esc(displayModel.status)}</div></div>
      </div>` : `<div class="panel pad" style="margin-bottom:14px"><div class="eyebrow">Heuristic baseline</div><h2 class="section" style="margin-top:0">No champion yet — and that is honest.</h2><p class="sub" style="max-width:740px;margin:0">Cairn is scoring with a transparent, fixed-weight model. It will not promote a learned champion until there are enough analyst verdicts, both classes are represented, and a challenger beats the baseline Brier score. Weak labels never enter the evaluation set.</p></div>`}
      ${challenger ? `<div class="note ${calibrationRegressed ? "red" : ""}" style="margin-bottom:14px">
        <b>Challenger #${esc(challenger.id)} ${challengerMetrics.promoted ? "won promotion" : champion ? `did not replace champion #${esc(champion.id)}` : "did not replace the heuristic baseline"}.</b>
        ${calibrationRegressed ? "Its calibration regressed on held-out labels, so the incumbent stays active." : "Its held-out results are shown in full rather than hidden behind a training score."}
        The deployed score is ${esc(challengerMetrics.calibration_method || "out-of-fold evaluated")}; evaluation used ${number(challengerMetrics.n_eval || 0)} human label(s).
        <div class="gate-list">${gate.map((item) => `<div class="gate-row ${item.ok ? "ok" : "no"}"><span class="gate-mark">${item.ok ? "✓" : "×"}</span><span>${esc(item.label)}</span></div>`).join("")}</div>
      </div>` : ""}
      <div class="grid main-side" style="margin-top:14px">
        <div class="panel cal-card">
          <div class="panel-head" style="padding:0;border:0;margin-bottom:14px"><h3 class="card-title">Reliability diagram</h3><span class="sub">${displayModel ? `${esc(displayModel.status)} #${esc(displayModel.id)} · out-of-fold` : "predicted vs. observed · human labels"}</span></div>
          ${bins.length ? calibrationChart(bins) : `<div class="empty" style="padding:34px 10px"><p class="muted">A calibration curve appears after a challenger is trained. Until then, review the active-learning queue below.</p></div>`}
          ${bins.length ? `<div class="legend" style="margin-top:10px"><span><i style="background:var(--teal)"></i>deployed score</span><span><i style="background:var(--faint)"></i>perfect calibration</span><span><i style="background:var(--amber)"></i>evaluation bins</span></div>` : ""}
          ${bins.length ? `<div class="sub" style="margin-top:9px">${metrics.calibration_active ? "Each human label is scored by a calibrator fitted without that label." : `Identity calibration is active until ${number(thresholds.min_isotonic || 30)} human labels; isotonic regression would overfit this sample.`}</div>` : ""}
        </div>
        <div>
          <div class="panel">
            <div class="panel-head"><h3 class="card-title">Feedback ledger</h3><span class="sub">${number(labels)} training label(s)</span></div>
            <div class="panel-body">
              <div class="kv">
                <div><dt>Confirmed</dt><dd>${number(counts.confirmed || 0)}</dd></div>
                <div><dt>False positive</dt><dd>${number(counts.false_positive || 0)}</dd></div>
                <div><dt>Accepted risk</dt><dd>${number(counts.accepted_risk || 0)}</dd></div>
                <div><dt>Other verdicts</dt><dd>${number((counts.uncertain || 0) + (counts.duplicate || 0))}</dd></div>
              </div>
              <div style="margin-top:14px"><div style="display:flex;justify-content:space-between" class="sub"><span>Progress to next evaluation</span><span>${number(labels)} / ${number(target)}</span></div><div class="progress" style="margin-top:6px"><i style="width:${progress.toFixed(1)}%"></i></div></div>
              <div class="note" style="margin-top:12px">${displayModel ? `Promotion requires ${number(thresholds.min_eval || 30)} held-out human labels, a calibrated Brier score ${Number(thresholds.baseline_margin || 0.002).toFixed(3)} below baseline, ECE at most ${Number(thresholds.max_ece || 0.15).toFixed(2)}, and a ${Number(thresholds.promotion_improvement || 0.005).toFixed(3)} margin over the champion.${champion ? ` Champion #${esc(champion.id)} was trained on ${number(champion.n_labels)} human labels.` : " No champion is active yet; the heuristic baseline remains in force."}` : "Add analyst verdicts to findings. Both confirmed and false-positive examples are required before training."}</div>
            </div>
          </div>
          <div class="panel" style="margin-top:14px">
            <div class="panel-head"><h3 class="card-title">Champion lineage</h3><span class="sub">${models.length} model(s)</span></div>
            ${models.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Model</th><th>Status</th><th class="num">Labels</th><th class="num">Brier</th><th class="num">ECE</th><th>Created</th></tr></thead><tbody>${models.map((m) => { const modelMetrics = m.metrics || {}; const brier = modelMetrics.brier_calibrated != null ? modelMetrics.brier_calibrated : modelMetrics.brier; return `<tr><td class="mono">#${esc(m.id)}</td><td>${statusChip(m.status, m.status)}</td><td class="num">${number(m.n_labels)}</td><td class="num">${brier != null ? Number(brier).toFixed(3) : "—"}</td><td class="num">${modelMetrics.ece != null ? Number(modelMetrics.ece).toFixed(3) : "—"}</td><td class="nowrap">${esc(dt(m.created_at))}</td></tr>`; }).join("")}</tbody></table></div><div class="sub" style="padding:10px 14px 0">Metrics are recorded at training time. Older challengers may predate the current leave-one-out calibration protocol.</div>` : '<div class="empty" style="padding:26px"><p class="sub">No models trained yet. The heuristic remains the champion.</p></div>'}
          </div>
        </div>
      </div>
      <div class="grid two" style="margin-top:14px">
        <div class="panel">
          <div class="panel-head"><h3 class="card-title">Active learning queue</h3><span class="sub">0.30 – 0.70 confidence</span></div>
          ${queue.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Finding</th><th>Confidence</th><th></th></tr></thead><tbody>${queue.map((item) => `<tr><td><a href="#/finding/${esc(item.id)}" style="font-weight:600">${esc(item.title)}</a><div class="faint" style="font-size:10px">${esc(item.detector)} · ${esc(item.asset_value || "—")}</div></td><td style="min-width:120px">${confBar(item.confidence)}</td><td class="right nowrap"><button class="btn small teal" type="button" data-action="quick-feedback" data-finding="${esc(item.id)}" data-verdict="confirmed">Confirm</button> <button class="btn small danger" type="button" data-action="quick-feedback" data-finding="${esc(item.id)}" data-verdict="false_positive">Reject</button></td></tr>`).join("")}</tbody></table></div>` : '<div class="empty" style="padding:30px"><p class="sub">The uncertain band is empty. More labeled findings may surface candidates.</p></div>'}
        </div>
        <div class="panel">
          <div class="panel-head"><h3 class="card-title">Detector reliability</h3><span class="sub">from analyst feedback</span></div>
          ${detectors.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Detector</th><th class="num">Labels</th><th class="num">Confirmed</th><th>Smoothed rate</th></tr></thead><tbody>${detectors.map((d) => `<tr><td class="mono">${esc(d.detector)}</td><td class="num">${number(d.labels)}</td><td class="num">${number(d.confirmed)}</td><td style="min-width:120px">${confBar(d.rate)}</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty" style="padding:30px"><p class="sub">No labeled detectors yet. Reliability estimates appear after analyst verdicts.</p></div>'}
        </div>
      </div>
      <div class="grid two" style="margin-top:14px">
        <div class="panel">
          <div class="panel-head"><h3 class="card-title">Adaptive content paths</h3><span class="sub">Thompson-sampled yield</span></div>
          ${paths.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Path</th><th class="num">Trials</th><th class="num">Hits</th><th class="num">Yield</th></tr></thead><tbody>${paths.slice(0, 14).map((p) => `<tr><td class="mono">${esc(p.path)}</td><td class="num">${number(p.trials)}</td><td class="num">${number(p.successes)}</td><td class="num">${pct((p.successes || 0) / Math.max(1, p.trials || 1), 0)}</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty" style="padding:30px"><p class="sub">Content path statistics accumulate after scans.</p></div>'}
        </div>
        <div class="panel">
          <div class="panel-head"><h3 class="card-title">Detector probes</h3><span class="sub">reward history</span></div>
          ${probes.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Probe</th><th class="num">Trials</th><th class="num">Success</th><th class="num">Reward</th></tr></thead><tbody>${probes.slice(0, 14).map((p) => `<tr><td class="mono">${esc(p.key)}<div class="faint">${esc(p.kind)}</div></td><td class="num">${number(p.trials)}</td><td class="num">${number(p.successes)}</td><td class="num">${Number(p.reward || 0).toFixed(1)}</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty" style="padding:30px"><p class="sub">No probe outcomes recorded yet.</p></div>'}
        </div>
      </div>
      <div class="note teal" style="margin-top:14px"><b>How to read this:</b> Brier score measures probability accuracy; ECE measures calibration error. A model can be accurate and still poorly calibrated. Champion promotion is gated on held-out human labels, not on training loss.</div>`;
  }

  // -------------------------------------------------------------------- audit
  async function renderAudit(seq) {
    const engagement = selectedEngagement();
    if (!engagement) {
      $("#view").innerHTML = onboarding();
      return;
    }
    showLoading("Verifying hash chains…");
    const data = await api(`/api/audit?engagement_id=${encodeURIComponent(engagement.id)}`);
    if (seq !== state.navSeq) return;
    const verification = data.verification || {};
    const events = data.events || [];
    const auditOk = Boolean(verification.audit_valid);
    const evidenceOk = Boolean(verification.evidence_valid);
    $("#view").innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Tamper-evident record · ${esc(engagement.name)}</div><h1>Audit trail</h1><p class="lede">Every authorization decision, scope check, run transition, and analyst verdict is appended to a SHA-256 hash chain. Evidence records form a second, independent chain.</p></div>
        <div class="head-actions"><button class="btn" type="button" data-action="refresh-audit">${ICONS.refresh}Verify again</button></div>
      </div>
      <div class="grid two">
        <div class="panel pad">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px"><div><div class="eyebrow">Audit chain</div><h2 class="section" style="margin:0">${auditOk ? "Intact" : "Verification failed"}</h2></div><span class="chip ${auditOk ? "teal" : "red"}">${auditOk ? "verified" : "failed"}</span></div>
          <p class="sub" style="margin:10px 0 0">${number(verification.audit_events)} events. ${auditOk ? "Every prev_hash and digest recomputes correctly." : `First mismatch at event ${esc(verification.audit_failure_id)}.`}</p>
        </div>
        <div class="panel pad">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px"><div><div class="eyebrow">Evidence chain</div><h2 class="section" style="margin:0">${evidenceOk ? "Intact" : "Verification failed"}</h2></div><span class="chip ${evidenceOk ? "teal" : "red"}">${evidenceOk ? "verified" : "failed"}</span></div>
          <p class="sub" style="margin:10px 0 0">${number(verification.evidence_records)} records. ${evidenceOk ? "Excerpts and content hashes are chained in collection order." : `First mismatch at record ${esc(verification.evidence_failure_id)}.`}</p>
        </div>
      </div>
      <div class="panel" style="margin-top:14px">
        <div class="panel-head"><h3 class="card-title">Event log</h3><span class="sub">newest first · ${number(events.length)} shown</span></div>
        ${events.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Decision</th><th>Target</th><th>Chain</th></tr></thead><tbody>${events.map((event) => `<tr>
          <td class="nowrap mono">${esc(dt(event.ts))}</td>
          <td class="mono">${esc(event.actor)}</td>
          <td><span style="font-weight:600">${esc(event.action)}</span>${event.details && Object.keys(event.details).length ? `<details style="margin-top:3px"><summary class="faint" style="cursor:pointer;font-size:10px">details</summary><pre style="white-space:pre-wrap;font-size:10px;color:var(--muted);margin:5px 0 0;max-width:420px">${esc(pretty(event.details))}</pre></details>` : ""}</td>
          <td>${statusChip(event.decision, event.decision || "—")}</td>
          <td class="mono" style="max-width:240px;word-break:break-all">${esc(event.target || "—")}</td>
          <td class="hash">${esc(shortHash(event.hash, 10))}<div class="faint">prev ${esc(shortHash(event.prev_hash, 8))}</div></td>
        </tr>`).join("")}</tbody></table></div>` : '<div class="empty" style="padding:34px"><p class="sub">No audit events for this engagement.</p></div>'}
      </div>
      <div class="note ${auditOk && evidenceOk ? "teal" : "red"}" style="margin-top:14px">${auditOk && evidenceOk ? "<b>Integrity check passed.</b> This does not prove the observations are correct; it proves the record has not changed since collection." : "<b>Do not trust this record.</b> A hash-chain mismatch indicates database tampering, corruption, or an interrupted write. Preserve the database and investigate before relying on any finding."}</div>`;
  }

  // ---------------------------------------------------------------------- run
  async function renderRun(runId, seq) {
    if (!runId) {
      location.hash = "#/overview";
      return;
    }
    showLoading("Loading run…");
    const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
    if (seq !== state.navSeq) return;
    const run = data.run;
    const events = data.events || [];
    state.runData = { run, events, findings: data.findings || [] };
    state.runAfter = events.reduce((max, event) => Math.max(max, Number(event.id || 0)), 0);
    const engagement = run.engagement || {};
    if (run.engagement_id !== state.selectedId) {
      selectEngagement(run.engagement_id);
    }
    $("#view").innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Run · ${esc(run.id)}</div><h1>${esc(engagement.name || "Assessment")}</h1><p class="lede">${esc(run.mode)} mode · ${esc(run.config && run.config.source ? run.config.source : "local")} source · queued ${esc(dt(run.created_at))}. The event log streams below while the run is active.</p></div>
        <div class="head-actions">
          <a class="btn ghost" href="#/overview">${ICONS.overview}Overview</a>
          <button class="btn small" type="button" data-action="download-report" data-run="${esc(run.id)}" data-format="html">${ICONS.download}HTML</button>
          <button class="btn small" type="button" data-action="download-report" data-run="${esc(run.id)}" data-format="md">${ICONS.download}MD</button>
          <button class="btn small" type="button" data-action="download-report" data-run="${esc(run.id)}" data-format="json">${ICONS.download}JSON</button>
          <button class="btn danger small" id="cancel-run" type="button" data-action="cancel-run" data-run="${esc(run.id)}" ${isRunActive(run.status) ? "" : "disabled"}>Cancel run</button>
        </div>
      </div>
      <div id="run-banner-slot">${runBanner(run)}</div>
      <div class="grid metrics" id="run-metrics">${runMetrics(run)}</div>
      <div class="grid main-side" style="margin-top:14px">
        <div>
          <div class="panel">
            <div class="panel-head"><h3 class="card-title">Findings from this run</h3><span class="sub" id="run-findings-count">${number((data.findings || []).length)}</span></div>
            <div id="run-findings">${runFindings(data.findings || [])}</div>
          </div>
          <div class="panel" style="margin-top:14px">
            <div class="panel-head"><h3 class="card-title">Event stream</h3><span class="sub" id="run-event-count">${number(events.length)} events</span></div>
            <div class="panel-body" id="run-timeline">${timeline(events)}</div>
          </div>
        </div>
        <div>
          <div class="panel"><div class="panel-head"><h3 class="card-title">Coverage</h3><span class="sub">planned probes</span></div><div class="panel-body" id="run-coverage">${coveragePanel(run)}</div></div>
          <div class="panel" style="margin-top:14px"><div class="panel-head"><h3 class="card-title">Run configuration</h3></div><div class="panel-body" id="run-config">${runConfigPanel(run)}</div></div>
        </div>
      </div>`;
    if (isRunActive(run.status)) startRunPolling(run.id);
  }

  function runBanner(run) {
    if (!isRunActive(run.status)) return "";
    return `<div class="run-banner"><span class="pulse"></span><div><b>${esc(run.status)} · ${esc(run.mode)} mode</b><div class="sub">The engine is working inside the manifest. Events stream every couple of seconds.</div></div><span class="chip amber">live</span></div>`;
  }

  function runMetrics(run) {
    const stats = run.stats || {};
    const coverage = Number(run.coverage || (stats.coverage && stats.coverage.score) || 0);
    const newFindings = stats.findings_new != null ? stats.findings_new : (state.runData && state.runData.findings ? state.runData.findings.length : 0);
    return `
      <div class="panel metric"><div class="label">Coverage</div><div class="value">${coverage ? pct(coverage, 0) : "—"}</div><div class="foot">weighted planned probes</div></div>
      <div class="panel metric"><div class="label">New findings</div><div class="value">${number(newFindings)}</div><div class="foot">${number(stats.findings_updated || 0)} updated</div></div>
      <div class="panel metric"><div class="label">Evidence</div><div class="value">${number(stats.evidence || 0)}</div><div class="foot">redacted records</div></div>
      <div class="panel metric"><div class="label">Asset records</div><div class="value">${number(stats.assets || 0)}</div><div class="foot">upserted during this run</div></div>
      <div class="panel metric"><div class="label">Open ports</div><div class="value">${number(stats.open_ports || 0)}</div><div class="foot">${number(stats.web_targets || 0)} web target(s)</div></div>
      <div class="panel metric"><div class="label">Duration</div><div class="value">${stats.duration_s != null ? `${Number(stats.duration_s).toFixed(1)}<small>s</small>` : "—"}</div><div class="foot">${number(stats.http_requests || 0)} HTTP requests</div></div>`;
  }

  function runFindings(findings) {
    return findingList(findings, "No findings recorded for this run yet.", "run_confidence");
  }

  function timeline(events) {
    if (!events || !events.length) return '<p class="sub">Waiting for the first event…</p>';
    return `<div class="timeline">${events.map((event) => `<div class="timeline-item ${event.level === "error" ? "error" : event.level === "warning" ? "warning" : ""}">
      <span class="time">${esc(clock(event.ts))}</span><span class="node"></span>
      <span class="msg"><span class="faint" style="text-transform:uppercase;font:600 8.5px var(--mono);letter-spacing:.08em">${esc(event.kind)}</span><br>${esc(event.message)}</span>
    </div>`).join("")}</div>`;
  }

  function coveragePanel(run) {
    const coverage = (run.stats && run.stats.coverage) || {};
    const categories = coverage.categories || {};
    const warnings = coverage.warnings || [];
    const rows = Object.entries(categories).map(([name, item]) => `<div class="why-row"><span>${esc(name)}</span><div class="track"><i style="width:${Math.max(0, Math.min(100, Number(item.percent || 0)))}%"></i></div><b>${esc(item.percent)}%</b></div>`).join("");
    return `<div class="coverage-ring" style="margin-bottom:14px">${coverageRing(Number(coverage.score || run.coverage || 0))}<div class="ringtext"><b>${coverage.score != null ? pct(coverage.score, 0) : "—"}</b><span>weighted coverage</span></div></div>
      ${rows ? `<div class="why-list">${rows}</div>` : '<p class="sub">Coverage details appear as probes complete.</p>'}
      ${warnings.length ? `<details style="margin-top:12px"><summary class="faint" style="cursor:pointer;font-size:10.5px">${warnings.length} coverage note(s)</summary><div class="note" style="margin-top:7px;font-size:10.5px">${warnings.slice(0, 8).map((w) => esc(w)).join("<br>")}</div></details>` : ""}
      <div class="sub" style="margin-top:12px">${esc(coverage.interpretation || "Coverage is the weighted success of planned probes, not proof that untested paths are safe.")}</div>`;
  }

  function runConfigPanel(run) {
    const engagement = run.engagement || {};
    const config = run.config || {};
    const limits = engagement.limits || {};
    return `<dl class="kv">
      <div><dt>Status</dt><dd>${statusChip(run.status, run.status)}</dd></div>
      <div><dt>Mode</dt><dd>${esc(run.mode)}</dd></div>
      <div><dt>Online intel</dt><dd>${config.online_intel ? "enabled" : "disabled"}</dd></div>
      <div><dt>Active DNS</dt><dd>${config.active_dns ? "enabled" : "disabled"}</dd></div>
      <div><dt>Port budget</dt><dd>${limits.full_ports ? "all 65,535" : `${number((limits.allowed_ports || []).length)} allowed`}</dd></div>
      <div><dt>Scope</dt><dd>${number((engagement.scope || []).length)} rule(s)</dd></div>
      <div><dt>Started</dt><dd>${esc(dt(run.started_at))}</dd></div>
      <div><dt>Finished</dt><dd>${esc(dt(run.finished_at))}</dd></div>
    </dl>
    ${run.error ? `<div class="note red" style="margin-top:12px">${esc(run.error)}</div>` : ""}
    <div class="hash" style="margin-top:12px">manifest ${esc(shortHash(engagement.manifest_hash, 24))}</div>`;
  }

  function startRunPolling(runId) {
    stopPolling();
    state.pollTimer = setInterval(async () => {
      if (state.route !== "run" || !state.runData || state.runData.run.id !== runId) {
        stopPolling();
        return;
      }
      try {
        const data = await api(`/api/runs/${encodeURIComponent(runId)}?after=${state.runAfter}`);
        if (!state.runData || state.runData.run.id !== runId) return;
        state.runData.run = data.run;
        state.runData.findings = data.findings || [];
        if (data.events && data.events.length) {
          state.runData.events.push(...data.events);
          state.runAfter = state.runData.events.reduce((max, event) => Math.max(max, Number(event.id || 0)), state.runAfter);
        }
        updateRunLive();
        if (!isRunActive(data.run.status)) {
          stopPolling();
          refreshEngagements().catch(() => {});
          toast(`Run ${data.run.status}.`, data.run.status === "completed" ? "good" : "bad");
        }
      } catch (error) {
        stopPolling();
        toast(error.message, "bad");
      }
    }, 2200);
  }

  function updateRunLive() {
    const data = state.runData;
    if (!data) return;
    const run = data.run;
    const metrics = $("#run-metrics");
    if (metrics) metrics.innerHTML = runMetrics(run);
    const findings = $("#run-findings");
    if (findings) findings.innerHTML = runFindings(data.findings || []);
    const findingsCount = $("#run-findings-count");
    if (findingsCount) findingsCount.textContent = number((data.findings || []).length);
    const coverage = $("#run-coverage");
    if (coverage) coverage.innerHTML = coveragePanel(run);
    const config = $("#run-config");
    if (config) config.innerHTML = runConfigPanel(run);
    const timelineBox = $("#run-timeline");
    if (timelineBox) timelineBox.innerHTML = timeline(data.events || []);
    const eventCount = $("#run-event-count");
    if (eventCount) eventCount.textContent = `${number((data.events || []).length)} events`;
    const banner = $("#run-banner-slot");
    if (banner) banner.innerHTML = runBanner(run);
    const cancel = $("#cancel-run");
    if (cancel) cancel.disabled = !isRunActive(run.status) || run.status === "cancelling";
  }

  // ------------------------------------------------------------- finding route
  async function renderFindingRoute(findingId, seq) {
    if (!findingId) {
      location.hash = "#/findings";
      return;
    }
    const finding = await api(`/api/findings/${encodeURIComponent(findingId)}`);
    if (seq !== state.navSeq) return;
    if (finding.engagement_id !== state.selectedId) {
      selectEngagement(finding.engagement_id);
    }
    await renderFindings(seq);
    if (seq !== state.navSeq) return;
    syncShell("finding");
    mountDrawer(finding);
  }

  // ------------------------------------------------------------------- drawer
  function closeDrawer(options = {}) {
    const root = $("#drawer-root");
    const wasOpen = Boolean(state.drawerId);
    state.drawerId = null;
    if (root) root.innerHTML = "";
    document.body.style.overflow = "";
    if (!options.silent && wasOpen && location.hash.startsWith("#/finding/")) {
      const target = state.lastPageHash.startsWith("#/finding") ? "#/findings" : state.lastPageHash || "#/findings";
      if (location.hash === target) route();
      else location.hash = target;
    }
  }

  async function mountDrawer(finding) {
    state.drawerId = finding.id;
    const root = $("#drawer-root");
    root.innerHTML = `<div class="overlay" data-action="close-drawer"></div><aside class="drawer" id="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <div class="drawer-head">
        <div>${severityChip(finding.severity)}<h2 id="drawer-title">${esc(finding.title)}</h2><div class="sub mono">${esc(finding.detector)} · ${esc(finding.asset_value || "unknown asset")}</div></div>
        <button class="icon-btn close" type="button" data-action="close-drawer" aria-label="Close finding">${ICONS.close}</button>
      </div>
      <div class="drawer-body">${drawerBody(finding)}</div>
      <div class="drawer-foot"><span class="sub" style="margin-right:auto">Verdicts train the local calibration model.</span><button class="btn ghost" type="button" data-action="close-drawer">Close</button></div>
    </aside>`;
    document.body.style.overflow = "hidden";
    const close = root.querySelector("[data-action='close-drawer']");
    if (close) setTimeout(() => close.focus(), 40);
  }

  function drawerBody(finding) {
    const evidence = finding.evidence || [];
    const runs = finding.runs || [];
    const feedback = finding.feedback || [];
    const explain = finding.explain || [];
    const confidence = Number(finding.confidence || 0);
    const status = finding.status || "open";
    return `
      <div class="drawer-block" style="margin-top:0">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">${statusChip(status, status)}<span class="chip">${esc(finding.category)}</span><span class="chip">${number(finding.occurrences)} occurrence(s)</span></div>
      </div>
      <div class="drawer-block">
        <h3>Confidence · ${pct(confidence)}</h3>
        ${confBar(confidence)}
        <div style="display:flex;gap:7px;margin-top:8px;flex-wrap:wrap">${bandChip(finding.confidence_band)}<span class="chip">model ${esc(finding.model_version == null ? "heuristic" : `#${finding.model_version}`)}</span></div>
        <p class="sub" style="margin-top:8px">Calibrated probability that this finding is valid. It is separate from severity.</p>
      </div>
      <div class="drawer-block">
        <h3>Why this score</h3>
        <div class="why-list">${explain.length ? explain.map((item) => `<div class="why-row" title="feature value ${esc(item.value)} · contribution ${esc(item.contribution)}"><span>${esc(item.label)}</span><div class="track"><i style="width:${Math.round(Math.max(0, Math.min(1, Number(item.value || 0))) * 100)}%"></i></div><b style="color:${Number(item.contribution) >= 0 ? "var(--teal)" : "var(--red)"}">${Number(item.contribution) >= 0 ? "+" : ""}${Number(item.contribution || 0).toFixed(2)}</b></div>`).join("") : '<p class="sub">No explanation recorded.</p>'}</div>
      </div>
      <div class="drawer-block"><h3>Description</h3><p>${esc(finding.description)}</p></div>
      <div class="drawer-block"><h3>Remediation</h3><p>${esc(finding.remediation)}</p></div>
      <div class="drawer-block">
        <h3>Evidence · ${number(evidence.length)} record(s)</h3>
        ${evidence.length ? evidence.map((item) => `<details class="evidence-item"><summary>${esc(item.kind)} · ${esc(item.source)} · ${esc(item.locator)}</summary><pre>${esc(item.excerpt)}</pre><div class="hash" style="padding:8px 12px;background:var(--panel-2)">content sha256 ${esc(item.content_sha256)}<br>collected ${esc(dt(item.collected_at))} · chain ${esc(shortHash(item.hash, 20))}</div></details>`).join("") : '<p class="sub">No evidence attached. Treat this finding as unverified.</p>'}
      </div>
      <div class="drawer-block">
        <h3>Timeline</h3>
        <dl class="kv"><div><dt>First seen</dt><dd>${esc(dt(finding.first_seen))}</dd></div><div><dt>Last seen</dt><dd>${esc(dt(finding.last_seen))}</dd></div><div><dt>Asset</dt><dd>${esc(finding.asset_value || "—")}</dd></div><div><dt>Fingerprint</dt><dd class="hash">${esc(shortHash(finding.fingerprint, 16))}</dd></div></dl>
      </div>
      <div class="drawer-block">
        <h3>Run history</h3>
        ${runs.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Run</th><th>Confidence</th><th>Observed</th></tr></thead><tbody>${runs.map((run) => `<tr><td><a class="mono" href="#/run/${esc(run.run_id)}">${esc(shortHash(run.run_id, 14))}</a></td><td style="min-width:110px">${confBar(run.confidence)}</td><td class="nowrap">${esc(dt(run.observed_at))}</td></tr>`).join("")}</tbody></table></div>` : '<p class="sub">No run history.</p>'}
      </div>
      <div class="drawer-block">
        <details class="evidence-item"><summary>Feature vector</summary><pre>${esc(pretty(finding.features))}</pre></details>
      </div>
      <div class="drawer-block">
        <h3>Analyst verdict</h3>
        <div class="feedback-grid">${VERDICTS.map(([value, label, tone]) => `<button class="btn ${tone}" type="button" data-action="feedback" data-verdict="${value}">${esc(label)}</button>`).join("")}</div>
        <div class="field" style="margin-top:10px"><label for="feedback-note">Note (optional)</label><textarea class="textarea" id="feedback-note" maxlength="4000" placeholder="What did you verify? Include a safe reference, not secrets."></textarea></div>
        <div class="field" style="margin-top:8px"><label for="feedback-analyst">Analyst</label><input class="input" id="feedback-analyst" maxlength="120" value="${esc(state.analyst)}"></div>
      </div>
      <div class="drawer-block">
        <h3>Feedback history</h3>
        ${feedback.length ? `<div class="feedback-history">${feedback.map((item) => `<div><span class="mono">${esc(dt(item.created_at))}</span><span>${statusChip(item.verdict, item.verdict)}</span><span>${esc(item.analyst)}${item.note ? ` — ${esc(item.note)}` : ""}</span></div>`).join("")}</div>` : '<p class="sub">No verdict yet. The active-learning queue flags uncertain findings like this one.</p>'}
      </div>`;
  }

  // ------------------------------------------------------------------ feedback
  async function submitFeedback(findingId, verdict, button) {
    const noteEl = $("#feedback-note");
    const analystEl = $("#feedback-analyst");
    const note = noteEl ? noteEl.value.trim() : "";
    const analyst = (analystEl && analystEl.value.trim()) || state.analyst || "local-analyst";
    if (analyst) {
      state.analyst = analyst;
      lsSet("cairn.analyst", analyst);
    }
    const buttons = document.querySelectorAll("[data-action='feedback'], [data-action='quick-feedback']");
    buttons.forEach((item) => {
      item.disabled = true;
    });
    try {
      const result = await api(`/api/findings/${encodeURIComponent(findingId)}/feedback`, {
        method: "POST",
        body: { verdict, analyst, note },
      });
      let message = "Analyst verdict recorded.";
      if (result && result.learning) {
        const learning = result.learning;
        if (learning.promoted) message = "Verdict recorded. A challenger won and is now the champion.";
        else if (learning.status === "challenger") message = "Verdict recorded. Challenger evaluated; champion retained.";
        else if (learning.status === "insufficient") message = "Verdict recorded. Waiting for enough labels to train.";
        else message = `Verdict recorded · learning ${learning.status || "updated"}.`;
      }
      toast(message, "good");
      if (state.drawerId === findingId) {
        const updated = await api(`/api/findings/${encodeURIComponent(findingId)}`);
        if (state.drawerId === findingId) await mountDrawer(updated);
      }
      if (state.route === "learning" && state.drawerId !== findingId) {
        await renderLearning(++state.navSeq);
      }
    } catch (error) {
      toast(error.message, "bad");
      buttons.forEach((item) => {
        item.disabled = false;
      });
      if (button) button.disabled = false;
    }
  }

  // --------------------------------------------------------------- engagement
  async function revokeEngagement(id, name) {
    openConfirm({
      title: `Revoke ${name || "engagement"}?`,
      message:
        "This stops active runs at the next scope check and blocks new scans immediately. The manifest, findings, evidence, and audit history remain immutable for accountability.",
      confirmLabel: "Revoke engagement",
      danger: true,
      onConfirm: async () => {
        await api(`/api/engagements/${encodeURIComponent(id)}/revoke`, { method: "POST" });
        await refreshEngagements();
        state.overview = null;
        toast("Engagement revoked. New probes are blocked.", "good");
        location.hash = "#/overview";
        if (state.route === "overview") await route();
      },
    });
  }

  // -------------------------------------------------------------- downloads etc.
  async function downloadReport(runId, format, button) {
    if (button) button.disabled = true;
    try {
      const response = await fetch(`/api/report/${encodeURIComponent(runId)}?format=${encodeURIComponent(format)}`, {
        headers: { "X-Cairn-Token": TOKEN },
        credentials: "same-origin",
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || `Report failed (${response.status})`);
      }
      const blob = await response.blob();
      const link = document.createElement("a");
      const url = URL.createObjectURL(blob);
      link.href = url;
      link.download = `cairn-${runId}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
      toast(`${format.toUpperCase()} report downloaded.`, "good");
    } catch (error) {
      toast(error.message, "bad");
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function cancelRun(runId, button) {
    if (button) button.disabled = true;
    try {
      await api(`/api/runs/${encodeURIComponent(runId)}/cancel`, { method: "POST" });
      toast("Cancellation requested. The engine stops at the next check.", "good");
      if (state.runData && state.runData.run.id === runId) {
        state.runData.run.status = "cancelling";
        updateRunLive();
      }
    } catch (error) {
      toast(error.message, "bad");
      if (button) button.disabled = false;
    }
  }

  async function retrainModel(button) {
    if (button) button.disabled = true;
    try {
      const result = await api("/api/learning/retrain", { method: "POST", body: { include_weak: true } });
      if (result.status === "champion") {
        toast(`Champion promoted: model #${result.model_id}, Brier ${Number((result.metrics || {}).brier || 0).toFixed(3)}.`, "good");
      } else if (result.status === "challenger") {
        toast("Challenger trained but did not beat the champion. Existing model retained.", "good");
      } else {
        toast(result.reason || "Not enough labels to train yet.", "bad");
      }
      await renderLearning(++state.navSeq);
    } catch (error) {
      toast(error.message, "bad");
      if (button) button.disabled = false;
    }
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  // -------------------------------------------------------------------- charts
  function coverageRing(score) {
    const value = Math.max(0, Math.min(1, Number(score || 0)));
    const radius = 30;
    const circumference = 2 * Math.PI * radius;
    const dash = circumference * value;
    return `<div class="donut" style="width:78px;height:78px"><svg width="78" height="78" viewBox="0 0 78 78" aria-hidden="true">
      <circle cx="39" cy="39" r="${radius}" fill="none" stroke="var(--panel-3)" stroke-width="7"/>
      <circle cx="39" cy="39" r="${radius}" fill="none" stroke="var(--teal)" stroke-width="7" stroke-linecap="round" stroke-dasharray="${dash.toFixed(2)} ${(circumference - dash).toFixed(2)}" transform="rotate(-90 39 39)"/>
    </svg><div class="donut-label" style="font-size:8px">COVERED</div></div>`;
  }

  function severityDonut(counts, total) {
    const radius = 34;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const segments = SEVERITIES.map((severity) => {
      const count = Number(counts[severity] || 0);
      if (!count || !total) return "";
      const length = (count / total) * circumference;
      const circle = `<circle cx="40" cy="40" r="${radius}" fill="none" stroke="${SEV_COLOR[severity]}" stroke-width="9" stroke-dasharray="${length.toFixed(2)} ${(circumference - length).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}"><title>${severity}: ${count}</title></circle>`;
      offset += length;
      return circle;
    }).join("");
    return `<div class="donut" style="width:112px;height:112px"><svg width="112" height="112" viewBox="0 0 80 80">${segments || `<circle cx="40" cy="40" r="${radius}" fill="none" stroke="var(--panel-3)" stroke-width="9"/>`}</svg><div class="donut-label"><b>${number(total)}</b>ACTIVE</div></div>`;
  }

  function severityRows(counts, total) {
    return SEVERITIES.map((severity) => {
      const count = Number(counts[severity] || 0);
      const width = total ? (count / total) * 100 : 0;
      return `<div class="why-row"><span style="text-transform:capitalize">${severity}</span><div class="track"><i style="width:${width.toFixed(1)}%;background:${SEV_COLOR[severity]}"></i></div><b>${number(count)}</b></div>`;
    }).join("");
  }

  function bandRows(bands) {
    const total = (bands.high || 0) + (bands.medium || 0) + (bands.low || 0);
    const colors = { high: "var(--teal)", medium: "var(--amber)", low: "var(--red)" };
    return ["high", "medium", "low"].map((band) => {
      const count = Number(bands[band] || 0);
      const width = total ? (count / total) * 100 : 0;
      return `<div class="why-row"><span style="text-transform:capitalize">${band} confidence</span><div class="track"><i style="width:${width.toFixed(1)}%;background:${colors[band]}"></i></div><b>${number(count)}</b></div>`;
    }).join("");
  }

  function calibrationChart(bins) {
    const width = 520;
    const height = 260;
    const pad = { left: 42, right: 16, top: 16, bottom: 34 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;
    const x = (value) => pad.left + value * plotW;
    const y = (value) => pad.top + (1 - value) * plotH;
    const usable = bins.filter((bin) => bin.confidence != null && bin.accuracy != null && bin.n);
    const points = usable.map((bin) => [Number(bin.confidence), Number(bin.accuracy), Number(bin.n)]);
    const path = points.length ? `M ${points.map(([cx, cy]) => `${x(cx).toFixed(1)} ${y(cy).toFixed(1)}`).join(" L ")}` : "";
    const grid = [0, 0.25, 0.5, 0.75, 1].map((tick) => `
      <line class="gridline" x1="${x(0)}" y1="${y(tick)}" x2="${x(1)}" y2="${y(tick)}"/>
      <line class="gridline" x1="${x(tick)}" y1="${y(0)}" x2="${x(tick)}" y2="${y(1)}"/>
      <text x="${x(tick)}" y="${height - 12}" text-anchor="middle">${tick.toFixed(2)}</text>
      <text x="${pad.left - 8}" y="${y(tick) + 3}" text-anchor="end">${tick.toFixed(2)}</text>`).join("");
    return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Calibration reliability diagram">
      ${grid}
      <line class="diag" x1="${x(0)}" y1="${y(0)}" x2="${x(1)}" y2="${y(1)}"/>
      <line class="axis" x1="${x(0)}" y1="${y(0)}" x2="${x(1)}" y2="${y(0)}"/>
      <line class="axis" x1="${x(0)}" y1="${y(0)}" x2="${x(0)}" y2="${y(1)}"/>
      ${path ? `<path class="cal-line" d="${path}"/>` : ""}
      ${points.map(([cx, cy, n]) => `<circle class="cal-dot" cx="${x(cx).toFixed(1)}" cy="${y(cy).toFixed(1)}" r="${Math.max(3.2, Math.min(6, 2 + Math.log2(n + 1)))}"><title>predicted ${(cx * 100).toFixed(0)}% · observed ${(cy * 100).toFixed(0)}% · n=${n}</title></circle>`).join("")}
      <text x="${pad.left + plotW / 2}" y="${height - 1}" text-anchor="middle">predicted probability</text>
      <text x="12" y="${pad.top + plotH / 2}" text-anchor="middle" transform="rotate(-90 12 ${pad.top + plotH / 2})">observed frequency</text>
    </svg>`;
  }

  function runsTable(runs) {
    if (!runs || !runs.length) {
      return '<div class="empty" style="padding:36px 20px"><p class="sub">No runs yet. Start a scan to establish a baseline.</p></div>';
    }
    return `<div class="table-wrap"><table class="data"><thead><tr><th>Run</th><th>Mode</th><th>Status</th><th class="num">Coverage</th><th class="num">New</th><th>Started</th><th></th></tr></thead><tbody>${runs.slice(0, 8).map((run) => `<tr>
      <td class="mono"><a href="#/run/${esc(run.id)}">${esc(shortHash(run.id, 14))}</a></td>
      <td>${esc(run.mode)}</td><td>${statusChip(run.status, run.status)}</td>
      <td class="num">${pct(run.coverage || 0, 1)}</td>
      <td class="num">${number((run.stats || {}).findings_new || 0)}</td>
      <td class="nowrap">${esc(dt(run.started_at || run.created_at))}</td>
      <td class="right"><a class="btn small ghost" href="#/run/${esc(run.id)}">Open</a></td>
    </tr>`).join("")}</tbody></table></div>`;
  }

  // -------------------------------------------------------------------- toast
  function toast(message, kind) {
    const root = $("#toast-root");
    if (!root) return;
    const item = document.createElement("div");
    item.className = `toast ${kind === "bad" ? "bad" : "good"}`;
    item.textContent = message;
    root.appendChild(item);
    setTimeout(() => {
      item.style.opacity = "0";
      item.style.transform = "translateY(6px)";
      item.style.transition = "opacity .2s, transform .2s";
      setTimeout(() => item.remove(), 220);
    }, 5200);
  }

  // -------------------------------------------------------------------- global
  function bindGlobal() {
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      if ($("#modal-root").children.length) closeModal();
      else if (state.drawerId) closeDrawer();
    });

    document.addEventListener("click", (event) => {
      const row = event.target.closest("[data-finding-id]");
      if (row && !event.target.closest("button, a")) {
        location.hash = `#/finding/${row.dataset.findingId}`;
        return;
      }

      const actionEl = event.target.closest("[data-action]");
      if (!actionEl) return;
      const action = actionEl.dataset.action;
      if (action === "close-modal") closeModal();
      else if (action === "close-drawer") closeDrawer();
      else if (action === "new-engagement") openEngagementModal();
      else if (action === "new-scan") openScanModal();
      else if (action === "retry") route();
      else if (action === "refresh-audit") renderAudit(++state.navSeq).catch((error) => showError(error));
      else if (action === "retrain") retrainModel(actionEl);
      else if (action === "revoke-engagement") revokeEngagement(actionEl.dataset.id, actionEl.dataset.name);
      else if (action === "cancel-run") cancelRun(actionEl.dataset.run, actionEl);
      else if (action === "download-report") downloadReport(actionEl.dataset.run, actionEl.dataset.format, actionEl);
      else if (action === "feedback") submitFeedback(state.drawerId, actionEl.dataset.verdict, actionEl);
      else if (action === "quick-feedback") submitFeedback(actionEl.dataset.finding, actionEl.dataset.verdict, actionEl);
      else if (action === "back") history.back();
    });
  }

  // ---------------------------------------------------------------------- boot
  async function boot() {
    applyTheme(state.theme);
    renderShell();
    bindGlobal();
    window.addEventListener("hashchange", () => {
      route().catch((error) => showError(error));
    });
    try {
      await refreshEngagements();
    } catch (error) {
      showError(error);
      hideBoot();
      return;
    }
    await route();
    hideBoot();
    if (!TOKEN) {
      toast("No API token was injected. Restart with `cairn serve`.", "bad");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      boot().catch((error) => {
        showError(error);
        hideBoot();
      });
    });
  } else {
    boot().catch((error) => {
      showError(error);
      hideBoot();
    });
  }
})();
