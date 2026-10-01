// ============================================================
// Gateway Mode (AI Guard Demo Kit web console)
// Pages: connect, preflight, configure, install, demo, diagnostics
// (detected by .gateway-page[data-step]). Talks to /gateway/api/*.
// Every value from the server is rendered with textContent / DOM APIs.
// Secrets typed into the page are sent once and cleared from the inputs.
// The server rewords the engine's CLI fix steps for the console and adds
// machine-readable `actions` to errors (and `web_action` to preflight checks):
// they are rendered as buttons here, never as commands to type.
// ============================================================

import { getDetectorLabel, setLoading, showNotification } from "../shared/utils.js";
import { renderStagePipeline } from "../shared/pipeline.js";

const STEP_ORDER = ["connect", "preflight", "configure", "install", "demo"];
const POLL_MS = 1000;
const PROVIDER_LABELS = { openai: "OpenAI", anthropic: "Anthropic", gemini: "Google Gemini", azure: "Azure OpenAI" };
const COMPONENT_LABELS = {
  mgmt: "Management API", lakera: "Lakera", probe: "Demo traffic", engine: "Engine", preflight: "Preflight",
  plan: "Plan", approval: "Approval", correlate: "Log match", diagnose: "Diagnosis", session: "Session",
  web: "Web console", gateways: "Gateways", scene: "Scenes", report: "Report", tls: "TLS",
};

let root = null;
let apiBase = "/gateway/api/";
let status = null;
// Page-level handlers for action buttons (the Preflight page opens its HTTPS fix card).
const pageHooks = {};

// ------------------------------------------------------------------ DOM helpers

function el(tag, opts = {}, ...children) {
  const node = document.createElement(tag);
  if (opts.cls) node.className = opts.cls;
  if (opts.text != null) node.textContent = String(opts.text);
  if (opts.attrs) Object.keys(opts.attrs).forEach((k) => { if (opts.attrs[k] != null) node.setAttribute(k, String(opts.attrs[k])); });
  if (opts.on) Object.keys(opts.on).forEach((k) => node.addEventListener(k, opts.on[k]));
  children.flat().forEach((c) => { if (c == null || c === false) return; node.append(c instanceof Node ? c : document.createTextNode(String(c))); });
  return node;
}
const $ = (sel, scope = document) => scope.querySelector(sel);
const gw = (name) => (root ? root.querySelector(`[data-gw="${name}"]`) : null);
const setText = (node, text) => { if (node) node.textContent = text == null ? "" : String(text); };
const show = (node, on = true) => { if (node) node.hidden = !on; };
const clear = (node) => { if (node) node.replaceChildren(); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const providerLabel = (p) => PROVIDER_LABELS[p] || (p ? String(p) : "the provider");
const fmtMs = (ms) => (ms == null ? "" : ms >= 1000 ? (ms / 1000).toFixed(1) + " s" : ms + " ms");
const pageUrl = (step) => apiBase.replace(/api\/$/, "") + step;

function pill(text, tone = "neutral", extra = "") {
  return el("span", { cls: `gw-pill ${tone} ${extra}`.trim(), text });
}
function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? String(iso) : d.toLocaleTimeString();
}
function linkDisabled(a, disabled) {
  if (!a) return;
  a.classList.toggle("is-disabled", !!disabled);
  a.setAttribute("aria-disabled", disabled ? "true" : "false");
  if (disabled) a.setAttribute("tabindex", "-1"); else a.removeAttribute("tabindex");
}

// ------------------------------------------------------------------ API

class ApiError extends Error {
  constructor(status, data) {
    const err = data && typeof data.error === "object" && data.error ? data.error
      : { what: (data && (data.message || data.error)) || `Request failed (HTTP ${status})` };
    super(err.what || "Request failed");
    this.status = status;
    this.detail = err;
  }
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body || {});
  }
  let resp;
  try {
    resp = await fetch(apiBase + path, opts);
  } catch (e) {
    throw new ApiError(0, { error: {
      what: "The console server did not answer", why: "The request did not reach this web app.",
      fix: ["Check that the app is still running, then reload the page"], state: "Nothing was changed." } });
  }
  let data = null;
  try { data = await resp.json(); } catch (e) { data = null; }
  if (resp.status === 401) {
    window.location.assign((root && root.dataset.login) || "/login");
    throw new ApiError(401, data || {});
  }
  if (!resp.ok || !data || data.ok === false) throw new ApiError(resp.status, data || {});
  return data;
}

async function refreshStatus() {
  status = await api("GET", "status");
  updateSidebar(status);
  return status;
}

// Poll a job every second until it finishes; onUpdate(job) after each poll.
async function pollJob(id, onUpdate) {
  let failures = 0;
  for (;;) {
    let job = null;
    try {
      job = await api("GET", "jobs/" + encodeURIComponent(id));
      failures = 0;
    } catch (e) {
      failures += 1;
      if (e.status === 404 || failures >= 5) throw e;
    }
    if (job) {
      try { onUpdate && onUpdate(job); } catch (e) { console.error(e); }
      if (job.status !== "running") return job;
    }
    await sleep(POLL_MS);
  }
}

// ------------------------------------------------------------------ components

function normalizeError(e) {
  if (!e) return { what: "Something went wrong" };
  if (e instanceof ApiError) return e.detail || { what: e.message };
  if (e instanceof Error) return { what: e.message || "Something went wrong" };
  if (typeof e === "string") return { what: e };
  return e;
}

// The five-field error block: What failed / Server said / Why / Fix / State + Details,
// then one button per err.actions item (rollback, HTTPS Inspection fix, outbound CA...).
function errorBlock(errLike, { tone = "bad", label = "Failed", actions = true, onAction = null } = {}) {
  const err = normalizeError(errLike);
  const box = el("div", { cls: `gw-error ${tone === "warn" ? "warn" : ""}`, attrs: { role: "alert" } });
  box.append(el("div", { cls: "gw-error-head" },
    el("span", { cls: `gw-label ${tone}`, text: label }),
    el("strong", { text: err.what || "Something went wrong" })));
  const dl = el("dl", { cls: "gw-error-grid" });
  const row = (term, value, cls) => {
    if (value == null || value === "" || (Array.isArray(value) && !value.length)) return;
    dl.append(el("dt", { text: term }));
    const dd = el("dd", { cls: cls || "" });
    if (Array.isArray(value)) {
      const ol = el("ol");
      value.forEach((v) => ol.append(el("li", { text: v })));
      dd.append(ol);
    } else {
      dd.textContent = String(value);
    }
    dl.append(dd);
  };
  row("What failed", err.what);
  row("Server said", err.server_said, "gw-said");
  row("Why", err.why);
  row("Fix", Array.isArray(err.fix) ? err.fix : err.fix ? [err.fix] : []);
  row("State", err.state);
  box.append(dl);
  if (actions && Array.isArray(err.actions) && err.actions.length) {
    const out = el("div", { cls: "gw-action-out" });
    const bar = el("div", { cls: "gw-actions" });
    err.actions.forEach((a) => { const b = actionButton(a, out, onAction); if (b) bar.append(b); });
    if (bar.childElementCount) box.append(bar, out);
  }
  if (err.log_line != null || err.log_path) {
    const parts = [];
    if (err.log_line != null) parts.push("log line " + err.log_line);
    if (err.log_path) parts.push(err.log_path);
    box.append(el("div", { cls: "gw-error-details", text: "Details: " + parts.join(" · ") }));
  }
  return box;
}

// ------------------------------------------------------------------ action buttons

// Roll back a point: the first click arms the button, the second runs the rollback job.
async function runRollback(rid, btn, out, { install = true, onDone = null } = {}) {
  if (btn && btn.dataset.armed !== "1") {
    btn.dataset.armed = "1";
    setText(btn, `Confirm roll back ${rid}`);
    return null;
  }
  if (btn) btn.disabled = true;
  clear(out);
  let done = false;
  try {
    const data = await api("POST", "rollback", { rollback_id: rid, install });
    const list = el("ol", { cls: "gw-steplist" });
    if (out) out.replaceChildren(list);
    const job = await pollJob(data.job.id, (j) => renderSteps(list, j.steps));
    done = job.status === "done";
    if (done) showNotification(`Rolled back ${rid}`, "success");
    else if (out) out.append(errorBlock(job.error, { actions: false }));
    return job;
  } catch (e) {
    if (out) out.replaceChildren(errorBlock(e, { actions: false }));
    return null;
  } finally {
    if (btn) {
      btn.dataset.armed = "";
      btn.disabled = done;
      setText(btn, done ? `Rolled back ${rid}` : `Roll back ${rid}`);
    }
    try { await refreshStatus(); } catch (e) { /* keep the page */ }
    if (onDone) onDone();
  }
}

// Read the gateway's outbound CA from the management server and trust it for the
// prompts this server sends (manual upload stays available on Preflight).
async function exportOutboundCa(btn, out, onDone) {
  clear(out);
  if (btn) setLoading(true, btn);
  try {
    const data = await api("POST", "outbound-ca", { from_management: true });
    const cert = data.certificate || {};
    showNotification(`Outbound CA ${cert.name || ""} trusted for the demo traffic`.replace(/\s+/g, " "), "success");
    if (out) out.replaceChildren(callout("ok", "Outbound CA trusted for the demo traffic",
      el("span", { text: [cert.name, cert["issued-by"] && `issued by ${cert["issued-by"]}`, cert["valid-to"] && `valid to ${cert["valid-to"]}`].filter(Boolean).join(" · ") })));
    if (onDone) onDone(data);
    return data;
  } catch (e) {
    if (out) out.replaceChildren(errorBlock(e, { actions: false, label: "Export outbound CA" }));
    return null;
  } finally {
    if (btn) setLoading(false, btn);
  }
}

function goHttpsFix(addRule) {
  if (pageHooks.httpsFix) { pageHooks.httpsFix(addRule); return; }
  window.location.assign(pageUrl("preflight") + "?fix=" + (addRule ? "https-rule" : "https"));
}

function actionButton(a, out, onDone) {
  if (!a || !a.id) return null;
  const btn = (cls, text, onClick) => {
    const b = el("button", { cls, attrs: { type: "button" } }, el("span", { cls: "btn-text", text }), el("div", { cls: "loader hidden" }));
    b.addEventListener("click", () => onClick(b));
    return b;
  };
  switch (a.id) {
    case "rollback":
      if (!a.rollback_id) return null;
      return el("button", { cls: "danger-btn", attrs: { type: "button", "data-action": "rollback" }, text: a.label || `Roll back ${a.rollback_id}`,
        on: { click: (ev) => runRollback(a.rollback_id, ev.currentTarget, out, { onDone }) } });
    case "https_fix":
      return btn("btn-gradient", a.label || "Turn on for me", () => goHttpsFix(false));
    case "https_rule":
      return btn("btn-gradient", a.label || "Add the Inspect rule for me", () => goHttpsFix(true));
    case "outbound_ca":
      return btn("secondary-btn", a.label || "Export outbound CA", (b) => exportOutboundCa(b, out, onDone));
    case "discard":
      return btn("secondary-btn", a.label || "Discard unpublished changes", async (b) => {
        setLoading(true, b);
        try {
          const data = await api("POST", "discard", {});
          showNotification(data.discarded ? "Unpublished changes discarded" : "Nothing to discard", "success");
          if (onDone) onDone(data);
        } catch (e) { if (out) out.replaceChildren(errorBlock(e, { actions: false })); } finally { setLoading(false, b); }
      });
    case "configure":
    case "connect":
      return el("a", { cls: "secondary-btn gw-btn-link", attrs: { href: pageUrl(a.id) }, text: a.label || "Open" });
    default:
      return null;
  }
}
function renderError(container, e, opts) {
  if (!container) return;
  container.replaceChildren(errorBlock(e, opts));
}
function callout(tone, title, ...body) {
  return el("div", { cls: `gw-callout ${tone}`, attrs: { role: tone === "bad" ? "alert" : "status" } },
    title ? el("strong", { text: title }) : null, ...body);
}
function warningsList(container, warnings) {
  clear(container);
  (warnings || []).forEach((w) => container.append(callout("warn", null, el("span", { text: w }))));
}

const STEP_ICON = {
  done: ["✓", "ok"], pass: ["✓", "ok"], ok: ["✓", "ok"],
  failed: ["✗", "bad"], fail: ["✗", "bad"], error: ["✗", "bad"],
  warning: ["!", "warn"], warn: ["!", "warn"],
  running: ["▸", "run"], manual: ["!", "manual"],
  skipped: ["–", ""], skip: ["–", ""], pending: ["", ""],
};

// Job step list. steps: [{id, title, status, pct, message}]
function renderSteps(container, steps, { numbered = true } = {}) {
  if (!container) return;
  clear(container);
  (steps || []).forEach((s, i) => {
    const [sym, tone] = STEP_ICON[s.status] || ["", ""];
    const icon = el("span", { cls: `gw-si ${tone}`, text: sym || (numbered ? String(i + 1) : ""), attrs: { "aria-hidden": "true" } });
    const body = el("div", { cls: "gw-step-body" }, el("strong", { text: s.title || s.id }));
    const meta = [];
    if (s.status === "manual") meta.push("You do this");
    if (s.message) meta.push(s.message);
    if (meta.length) body.append(el("span", { text: meta.join(" · ") }));
    if (s.status === "running" && s.pct != null) {
      body.append(el("div", { cls: "progress-bar-bg" }, el("div", { cls: "progress-bar-fill", attrs: { style: `width:${Math.max(0, Math.min(100, s.pct))}%` } })));
    }
    const li = el("li", { attrs: { "data-status": s.status || "pending" } }, icon, body);
    li.append(el("span", { cls: "gw-sr-only", text: s.status || "pending" }));
    container.append(li);
  });
}
function setBar(bar, pct) {
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, Number(pct) || 0))}%`;
}
function elapsedTimer(node) {
  const t0 = Date.now();
  const tick = () => {
    const s = Math.floor((Date.now() - t0) / 1000);
    setText(node, `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")} elapsed`);
  };
  tick();
  const id = setInterval(tick, 1000);
  return () => clearInterval(id);
}

const ACTION_SYM = { add: ["+", "add"], update: ["~", "update"], publish: ["→", ""], install: ["→", ""], script: ["▸", "manual"], manual: ["!", "manual"], none: ["=", ""], delete: ["−", "delete"] };

function stepSubline(s) {
  const bits = [];
  if (s.action === "manual") {
    bits.push("You do this" + (s.manual_steps && s.manual_steps.length ? ": " + s.manual_steps.join(" ") : ""));
  } else if (s.action === "none") {
    bits.push("already in place, no change");
  } else if (s.command) {
    bits.push(s.command);
  }
  if (s.action === "update" && s.kind === "add") bits.push("updates the object AI Guard created earlier");
  else if (s.action === "update") bits.push("changes an existing object");
  return bits.join(" · ");
}

// Compact plan list (Configure aside, HTTPS fix).
function renderPlanList(container, plan) {
  clear(container);
  const list = el("div", { cls: "gw-plan-list" });
  (plan.steps || []).forEach((s) => {
    const [sym, cls] = ACTION_SYM[s.action] || ["•", ""];
    list.append(el("div", { cls: "gw-plan-item" },
      el("span", { cls: `gw-plan-sym ${cls}`, text: sym, attrs: { "aria-hidden": "true" } }),
      el("div", { cls: "gw-plan-text" }, el("strong", { text: s.describe || s.id }), el("span", { text: stepSubline(s) }))));
  });
  container.append(list);
  container.append(el("p", { cls: "gw-muted gw-mono", text: `Plan ${plan.plan_id}` }));
}

function apiCallsDetails(plan) {
  const calls = plan.api_calls || [];
  const det = el("details", { cls: "gw-apicalls" }, el("summary", { text: `Show all ${calls.length} API calls` }));
  calls.forEach((c) => {
    det.append(el("div", { cls: "gw-apicall" },
      el("div", { cls: "gw-apicall-title", text: `POST /web_api/${c.command}` }),
      el("pre", { cls: "gw-pre", text: JSON.stringify(c.payload || {}, null, 2) })));
  });
  if (!calls.length) det.append(el("p", { cls: "gw-muted", text: "No API calls: every step is manual or already in place." }));
  return det;
}

function changeTable(plan) {
  const tbody = el("tbody");
  (plan.steps || []).forEach((s) => {
    const kind = s.action === "manual" ? "manual" : s.action === "none" ? "none" : s.kind === "script" ? "script" : s.action;
    const label = { add: "Add", update: "Update", publish: "Publish", install: "Install", script: "Script", manual: "You do this", none: "No change", delete: "Delete" }[kind] || kind;
    tbody.append(el("tr", {},
      el("td", {}, el("span", { cls: `gw-badge ${kind}`, text: label })),
      el("td", { text: s.describe || s.id }),
      el("td", { cls: "gw-muted", text: stepSubline(s) })));
  });
  return el("div", { cls: "table-container gw-table-wrap" },
    el("table", { cls: "gw-table gw-change-table" },
      el("thead", {}, el("tr", {}, el("th", { text: "Change" }), el("th", { text: "Object" }), el("th", { text: "Details" }))),
      tbody));
}

function planCounts(plan) {
  const steps = plan.steps || [];
  return {
    objects: steps.filter((s) => s.action === "add" || s.action === "update").length,
    install: steps.some((s) => s.kind === "install"),
    script: steps.some((s) => s.kind === "script" && s.action !== "manual"),
  };
}

// Approval panel: the button enables only with the checkbox ticked AND "APPROVE" typed.
function approvalPanel(container, plan, { onApprove, onError, buttonText = "Approve and install", sentence } = {}) {
  clear(container);
  const id = "gw-ack-" + Math.random().toString(36).slice(2, 8);
  const c = planCounts(plan);
  const where = plan.domain ? `domain ${plan.domain}` : plan.server || "the management server";
  const text = sentence || (`I understand this publishes ${c.objects} object${c.objects === 1 ? "" : "s"} in ${where}` +
    (c.install ? ` and installs Threat Prevention policy on ${plan.gateway}` : "") +
    (c.script ? `, and runs a one-time script on ${plan.gateway}` : "") + ".");
  const ack = el("input", { attrs: { type: "checkbox", id } });
  const typed = el("input", { cls: "input-field", attrs: { id: id + "-typed", autocomplete: "off", spellcheck: "false", maxlength: "16", placeholder: "APPROVE" } });
  const btn = el("button", { cls: "btn-gradient", attrs: { type: "button", disabled: "" } },
    el("span", { cls: "btn-text", text: buttonText }), el("div", { cls: "loader hidden" }));
  const meta = el("div", { cls: "gw-approval-meta" }, pill(`plan ${plan.plan_id}`, "neutral", "small gw-mono"));
  const sync = () => { btn.disabled = !(ack.checked && typed.value.trim() === "APPROVE"); };
  ack.addEventListener("change", sync);
  typed.addEventListener("input", sync);
  btn.addEventListener("click", async () => {
    if (btn.disabled) return;
    setLoading(true, btn);
    try {
      await onApprove({ plan_id: plan.plan_id, typed: typed.value.trim(), acknowledge: ack.checked });
      ack.disabled = true; typed.disabled = true;
    } catch (e) {
      setLoading(false, btn);
      sync();
      if (onError) onError(e); else console.error(e);
    }
  });
  container.append(el("div", { cls: "gw-approval" },
    el("label", { cls: "gw-check", attrs: { for: id } }, ack, el("span", { text })),
    el("div", { cls: "input-group" }, el("label", { cls: "input-label", attrs: { for: id + "-typed" }, text: "Type APPROVE to continue" }), typed),
    el("div", { cls: "gw-actions" }, btn), meta));
  return { button: btn, done: () => { setLoading(false, btn); btn.disabled = true; } };
}

// ------------------------------------------------------------------ sidebar

function updateSidebar(st) {
  if (!root || !st) return;
  const reached = Math.max(0, STEP_ORDER.indexOf(st.step || "connect"));
  const pfBlocked = !!(st.preflight && !st.preflight.ok);
  root.querySelectorAll(".gw-step").forEach((a) => {
    const id = a.dataset.stepLink;
    const idx = STEP_ORDER.indexOf(id);
    const attention = id === "preflight" && pfBlocked;
    const done = idx >= 0 && idx < reached && !attention;
    a.classList.toggle("done", done);
    a.classList.toggle("attention", attention);
    const state = a.querySelector(".gw-step-state");
    if (state) {
      setText(state, attention ? "!" : done ? "✓" : "");
      if (attention) state.setAttribute("title", "Blocking preflight items"); else state.removeAttribute("title");
    }
  });
  const conn = st.connection || {};
  const sideText = st.connected
    ? `${conn.server || "server"}${conn.domain ? " › " + conn.domain : ""}${st.gateway ? " · " + st.gateway.name : ""}`
    : "Not connected";
  setText(gw("side-conn-text"), sideText);
  const logPath = st.log_path || (st.web && st.web.log_path);
  setText(gw("log-path"), logPath || "Created when you connect");
}

function needConnection(container, st, { gateway = true } = {}) {
  if (st.connected && (!gateway || st.gateway)) return false;
  clear(container);
  container.append(callout("warn", st.connected ? "Pick a gateway first" : "Connect first",
    el("span", { text: st.connected ? "Preflight, the plan and the demo work on one gateway." : "Sign in to the management server and pick the gateway your demo traffic goes through." }),
    el("a", { text: "Go to Connect", attrs: { href: pageUrl("connect") } })));
  return true;
}

// ================================================================== Connect

// Connection dict with the MDS "System Data" pseudo-domain treated as "no domain"
// (the server already does this; kept here for older status payloads).
function connView(c) {
  const conn = Object.assign({}, c || {});
  if (isSystemData(conn.domain)) { conn.domain = null; conn.system_data = true; }
  return conn;
}

function initConnect(st) {
  const form = $("#gw-connect-form");
  const domainGroup = gw("domain-group");
  const connectBtn = $("#gw-connect-btn");
  const disconnectBtn = $("#gw-disconnect-btn");
  const preflightBtn = $("#gw-run-preflight");
  const segBtns = [...root.querySelectorAll(".gw-seg-btn")];
  let serverType = "SMS";
  let selected = null;

  const setType = (t) => {
    serverType = t === "MDS" ? "MDS" : "SMS";
    segBtns.forEach((b) => {
      const on = b.dataset.serverType === serverType;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    show(domainGroup, serverType === "MDS");
  };
  segBtns.forEach((b) => b.addEventListener("click", () => setType(b.dataset.serverType)));

  const authValue = () => (root.querySelector('input[name="gw-auth"]:checked') || {}).value || "api-key";
  const syncAuth = () => {
    const a = authValue();
    root.querySelectorAll("[data-auth]").forEach((n) => show(n, n.dataset.auth === a));
  };
  root.querySelectorAll('input[name="gw-auth"]').forEach((r) => r.addEventListener("change", syncAuth));

  const caFile = $("#gw-ca-file");
  const caText = $("#gw-ca-pem");
  caFile.addEventListener("change", () => {
    const f = caFile.files && caFile.files[0];
    if (!f) return;
    if (f.size > 64 * 1024) { showNotification("The certificate file is larger than 64 KB", "error"); caFile.value = ""; return; }
    const reader = new FileReader();
    reader.onload = () => { caText.value = String(reader.result || ""); };
    reader.onerror = () => showNotification("Could not read the file", "error");
    reader.readAsText(f);
  });

  const renderConnection = (s, info) => {
    const conn = connView(s.connection);
    const p = gw("conn-pill");
    if (s.connected) {
      p.className = "gw-pill ok";
      setText(p, `● Connected${info && info.ms != null ? " · " + info.ms + " ms" : ""}`);
      const bits = [conn.server_type === "MDS" ? "Multi-Domain Server" : conn.server_type === "SMS" ? "Security Management Server" : "Management server"];
      if (conn.release) bits.push(conn.release);
      if (conn.api_version) bits.push("API " + conn.api_version);
      if (conn.domain) bits.push("domain " + conn.domain);
      else if (conn.system_data) bits.push("System Data (no domain yet)");
      if (conn.read_only) bits.push("read-only login");
      const line = gw("connect-result");
      line.className = "gw-result-line ok";
      setText(line, "✓ " + bits.join(" · ") + (conn.fingerprint_sha1 ? ` · certificate SHA-1 ${conn.fingerprint_sha1}` : ""));
      setText(connectBtn.querySelector(".btn-text"), "Reconnect");
      show(disconnectBtn, true);
      setText(gw("needs-ip"), conn.local_ip ? ` (${conn.local_ip})` : "");
      if (conn.server) $("#gw-server").value = conn.server;
      if (conn.port) $("#gw-port").value = conn.port;
      if (conn.server_type === "MDS" || conn.server_type === "SMS") setType(conn.server_type);
      // "System Data" is where an MDS login without a domain lands, not a domain to reuse.
      $("#gw-domain").value = conn.domain || "";
      if (conn.user && conn.auth === "password") {
        const r = root.querySelector('input[name="gw-auth"][value="password"]');
        if (r) { r.checked = true; syncAuth(); }
        $("#gw-user").value = conn.user;
      }
    } else {
      p.className = "gw-pill";
      setText(p, "Not connected");
      setText(gw("connect-result"), "");
      setText(connectBtn.querySelector(".btn-text"), "Connect");
      show(disconnectBtn, false);
    }
    show(gw("ca-clear-row"), !!(s.web && s.web.mgmt_ca));
    if (info && Array.isArray(info.domains)) {
      const dl = $("#gw-domain-list");
      clear(dl);
      info.domains.forEach((d) => dl.append(el("option", { attrs: { value: d } })));
    }
    renderGateways(s);
  };

  const renderGateways = (s) => {
    const card = gw("gateways-card");
    const body = gw("gateways-body");
    const gws = s.gateways || [];
    show(card, !!s.connected);
    if (!s.connected) return;
    const conn = connView(s.connection);
    setText(gw("gateways-title"), conn.domain ? `Gateways in ${conn.domain}` : "Gateways");
    clear(body);
    if (!gws.length) {
      body.append(el("tr", {}, el("td", { attrs: { colspan: "7" }, cls: "gw-muted",
        text: conn.server_type === "MDS" && !conn.domain ? "Pick a domain above to list its gateways." : "No gateways or clusters were found on this server." })));
    }
    selected = (s.gateway && s.gateway.name) || selected || (gws[0] && gws[0].name) || null;
    gws.forEach((g) => {
      const radio = el("input", { attrs: { type: "radio", name: "gw-pick", value: g.name, "aria-label": `Select ${g.name}` } });
      radio.checked = g.name === selected;
      const ai = g.ai_security === true ? pill("On", "ok", "small") : g.ai_security === false ? pill("Off", "warn", "small") : pill("Checked in preflight", "neutral", "small");
      const https = g.https_inspection === true ? pill("On", "ok", "small") : g.https_inspection === false ? pill("Off · will be flagged", "warn", "small") : pill("Checked in preflight", "neutral", "small");
      const tr = el("tr", { cls: g.name === selected ? "selected" : "" },
        el("td", {}, radio),
        el("td", {}, el("strong", { text: g.name }), g.is_cluster ? el("span", { cls: "gw-sub", text: " (cluster)" }) : null),
        el("td", { cls: "gw-mono", text: g.ipv4 || "" }),
        el("td", { text: g.release || g.version || "unknown" }),
        el("td", { text: g.policy_package || "" }),
        el("td", {}, ai), el("td", {}, https));
      const pick = () => {
        selected = g.name;
        body.querySelectorAll("tr").forEach((r) => r.classList.remove("selected"));
        tr.classList.add("selected");
        radio.checked = true;
        syncPreflightBtn();
      };
      tr.addEventListener("click", pick);
      radio.addEventListener("change", pick);
      body.append(tr);
    });
    syncPreflightBtn();
  };

  const syncPreflightBtn = () => {
    preflightBtn.disabled = !selected;
    setText(preflightBtn.querySelector(".btn-text"), selected ? `Run preflight on ${selected}` : "Run preflight");
  };

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clear(gw("connect-error"));
    clear(gw("connect-warnings"));
    const auth = authValue();
    const apiKeyInput = $("#gw-api-key");
    const passwordInput = $("#gw-password");
    const typed = $("#gw-domain").value.trim();
    const domain = isSystemData(typed) ? "" : typed;
    const conn = connView(status && status.connection);
    const secretTyped = auth === "api-key" ? apiKeyInput.value.trim() : passwordInput.value;
    setLoading(true, connectBtn);
    try {
      let data;
      if (status && status.connected && conn.server_type === "MDS" && domain && domain !== conn.domain && !secretTyped) {
        // Same login, another domain (no new login: avoids the login rate limit).
        data = await api("POST", "domain", { domain });
        status = data.status;
        updateSidebar(status);
        renderConnection(status, data.connect);
        if (data.discover_error) renderError(gw("connect-error"), data.discover_error, { tone: "warn", label: "Gateways" });
        showNotification(`Switched to domain ${domain}`, "success");
        return;
      }
      const body = {
        server: $("#gw-server").value.trim(), port: $("#gw-port").value.trim() || "443",
        server_type: serverType, domain: serverType === "MDS" ? domain : "", auth,
        server_name: $("#gw-server-name").value.trim(),
      };
      const localIp = $("#gw-local-ip") ? $("#gw-local-ip").value.trim() : "";
      if (localIp) body.local_ip = localIp;
      if (auth === "api-key") body.api_key = apiKeyInput.value.trim();
      else { body.user = $("#gw-user").value.trim(); body.password = passwordInput.value; }
      const pem = caText.value.trim();
      if (pem) body.ca_pem = pem;
      else if ($("#gw-ca-clear").checked) body.clear_ca = true;
      data = await api("POST", "connect", body);
      apiKeyInput.value = "";
      passwordInput.value = "";
      caText.value = "";
      caFile.value = "";
      $("#gw-ca-clear").checked = false;
      status = data;
      updateSidebar(status);
      renderConnection(status, data.connect);
      warningsList(gw("connect-warnings"), data.warnings);
      if (data.discover_error) renderError(gw("connect-error"), data.discover_error, { tone: "warn", label: "Gateways" });
    } catch (e) {
      renderError(gw("connect-error"), e);
      try { status = await refreshStatus(); renderConnection(status); } catch (e2) { /* keep the error visible */ }
    } finally {
      setLoading(false, connectBtn);
    }
  });

  disconnectBtn.addEventListener("click", async () => {
    clear(gw("connect-error"));
    try {
      const data = await api("POST", "disconnect", {});
      status = data.status;
      updateSidebar(status);
      renderConnection(status);
      showNotification("Disconnected. The keys were forgotten.", "success");
    } catch (e) {
      renderError(gw("connect-error"), e);
    }
  });

  preflightBtn.addEventListener("click", async () => {
    if (!selected) return;
    clear(gw("gateway-error"));
    setLoading(true, preflightBtn);
    try {
      await api("POST", "gateway", { name: selected });
      window.location.assign(pageUrl("preflight") + "?run=1");
    } catch (e) {
      setLoading(false, preflightBtn);
      renderError(gw("gateway-error"), e);
    }
  });

  setType("SMS");
  syncAuth();
  renderConnection(st);
}

// ================================================================== Preflight

function checkIcon(c) {
  if (c.status === "pass") return ["✓", "ok"];
  if (c.status === "fail") return ["✗", "bad"];
  if (c.status === "warn") return ["!", "warn"];
  return ["○", "muted"];
}

function evidenceList(evidence, skip = []) {
  const keys = Object.keys(evidence || {}).filter((k) => !skip.includes(k));
  if (!keys.length) return null;
  const dl = el("dl", { cls: "gw-evidence" });
  keys.forEach((k) => dl.append(el("dt", { text: k.replace(/[_-]/g, " ") }), el("dd", { text: evidence[k] })));
  return dl;
}
// Server text quoted verbatim (e.g. the Install Policy verification messages).
function saidBlock(said, title = "Server said") {
  if (!said) return null;
  return el("div", { cls: "gw-said-wrap" },
    el("span", { cls: "gw-eyebrow", text: title }),
    el("pre", { cls: "gw-pre gw-said-block", text: String(said) }));
}
const checkSaid = (c) => (c && (c.server_said || (c.evidence && c.evidence.server_said))) || null;

// The "last policy install" check, shown on its own at the top of Preflight, Diagnostics
// and (when it failed) the demo: a partial install leaves the gateway on an older policy.
function installCheckCard(c, { onRecheck = null, compact = false } = {}) {
  const tone = c.status === "fail" ? "bad" : c.status === "warn" ? "warn" : c.status === "pass" ? "ok" : "";
  const label = { fail: "Not fully installed", warn: "Check this", pass: "Installed", skip: "Not checked" }[c.status] || c.status;
  const id = "gw-install-" + Math.random().toString(36).slice(2, 8);
  const card = el("section", { cls: `gw-card gw-install-card ${tone}`, attrs: { "aria-labelledby": id, "data-check": c.id, "data-status": c.status } });
  card.append(el("div", { cls: "gw-card-head" },
    el("span", { cls: `gw-label ${tone || "neutral"}`, text: label }),
    el("h2", { cls: "gw-h2 gw-grow", attrs: { id }, text: c.title || "Last policy installation on the gateway" })));
  card.append(el("p", { cls: "gw-issue-detail", text: c.detail }));
  const said = checkSaid(c);
  if (said) card.append(saidBlock(said, "Install Policy details (server said)"));
  if (!compact || c.status !== "pass") {
    const ev = evidenceList(c.evidence, ["server_said"]);
    if (ev) card.append(ev);
  }
  if (c.status !== "pass" && c.fix && c.fix.length) card.append(el("span", { cls: "gw-eyebrow", text: "How to fix it" }), fixList(c.fix));
  if (onRecheck) {
    card.append(el("div", { cls: "gw-actions" },
      el("button", { cls: "secondary-btn gw-small-btn", attrs: { type: "button" }, text: "Check again", on: { click: () => onRecheck() } })));
  }
  return card;
}
const findCheck = (report, id) => ((report && report.checks) || []).find((c) => c.id === id) || null;
const isSystemData = (d) => typeof d === "string" && /^\s*system data\s*$/i.test(d);

function fixList(fix) {
  if (!fix || !fix.length) return null;
  const ol = el("ol", { cls: "gw-fixlist" });
  fix.forEach((f) => ol.append(el("li", { text: f })));
  return ol;
}

function promptPath(st, check, report) {
  const gwName = (report && report.gateway) || (st.gateway && st.gateway.name) || "the gateway";
  const host = (check.evidence && (check.evidence.host || check.evidence.probe_host)) || "api.openai.com";
  const ip = (report && report.local_ip) || (st.preflight && st.preflight.local_ip) || st.local_ip || "IP unknown";
  return el("div", { cls: "gw-path" },
    el("span", { cls: "gw-eyebrow", text: "What the prompt path looks like now" }),
    el("div", { cls: "gw-path-row" },
      el("div", { cls: "gw-path-node" }, el("strong", { text: "This server" }), el("span", { text: ip })),
      el("span", { cls: "gw-path-arrow", text: "→", attrs: { "aria-hidden": "true" } }),
      el("div", { cls: "gw-path-node bad" }, el("strong", { text: gwName }), el("span", { text: "sees encrypted bytes" })),
      el("span", { cls: "gw-path-arrow", text: "→", attrs: { "aria-hidden": "true" } }),
      el("div", { cls: "gw-path-node" }, el("strong", { text: host }), el("span", { text: "reads the prompt" }))));
}

function initPreflight(st) {
  const runBtn = $("#gw-pf-run");
  const progressCard = gw("pf-progress");
  const continueLink = $("#gw-pf-continue");
  const anyway = $("#gw-pf-anyway");
  const query = new URLSearchParams(window.location.search);
  const wantFix = query.get("fix");
  let running = false;
  let pfPackage = "";

  const badge = gw("pf-badge");
  if (st.gateway) {
    const g = st.gateway;
    setText(badge, `Step 2 of 6 · ${g.name}${g.release || g.version ? " · " + (g.release || g.version) : ""}`);
  }

  const renderCounters = (r) => {
    const box = gw("pf-counters");
    clear(box);
    if (!r) return;
    box.append(pill(`${r.passed} passed`, "ok"));
    if (r.failed_blocking) box.append(pill(`${r.failed_blocking} blocking`, "bad"));
    if (r.warnings) box.append(pill(`${r.warnings} warning${r.warnings === 1 ? "" : "s"}`, "warn"));
  };

  const outboundCaPanel = () => {
    const ta = el("textarea", { cls: "input-field gw-mono", attrs: { rows: "4", spellcheck: "false", placeholder: "-----BEGIN CERTIFICATE-----", "aria-label": "Outbound CA certificate (PEM)" } });
    const file = el("input", { cls: "gw-file", attrs: { type: "file", accept: ".pem,.crt,.cer,text/plain", "aria-label": "Choose the outbound CA file" } });
    const out = el("div");
    const fromMgmt = el("button", { cls: "btn-gradient", attrs: { type: "button", "data-action": "outbound_ca" } }, el("span", { cls: "btn-text", text: "Export outbound CA" }), el("div", { cls: "loader hidden" }));
    fromMgmt.addEventListener("click", () => exportOutboundCa(fromMgmt, out, () => {
      showNotification("Running the checks again.", "info");
      startPreflight();
    }));
    const btn = el("button", { cls: "secondary-btn", attrs: { type: "button" } }, el("span", { cls: "btn-text", text: "Trust the pasted CA" }), el("div", { cls: "loader hidden" }));
    file.addEventListener("change", () => {
      const f = file.files && file.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = () => { ta.value = String(reader.result || ""); };
      reader.readAsText(f);
    });
    btn.addEventListener("click", async () => {
      clear(out);
      setLoading(true, btn);
      try {
        await api("POST", "outbound-ca", { ca_pem: ta.value });
        ta.value = "";
        showNotification("Outbound CA saved for this session. Running the checks again.", "success");
        startPreflight();
      } catch (e) {
        renderError(out, e);
      } finally {
        setLoading(false, btn);
      }
    });
    return el("div", { cls: "gw-stack gw-ca-panel" },
      el("p", { cls: "gw-help", text: "Export outbound CA reads the gateway's outbound CA (public certificate only) from the management server and trusts it for the prompts this server sends. It is deleted when you disconnect and does not change this computer's trust store." }),
      el("div", { cls: "gw-actions" }, fromMgmt),
      el("p", { cls: "gw-help", text: "Or export it yourself: SmartConsole > the gateway > HTTPS Inspection > Step 2: Export Certificate (or Security Policies > HTTPS Inspection > Outbound Policy > Outbound Certificates), save it as PEM (Base-64) and paste it here." }),
      file, ta, el("div", { cls: "gw-actions" }, btn), out);
  };

  // The package check failed: let the user name the package and check again with it.
  const packagePanel = (c) => {
    const id = "gw-pf-package-" + Math.random().toString(36).slice(2, 6);
    const input = el("input", { cls: "input-field", attrs: { id, maxlength: "128", spellcheck: "false", autocomplete: "off", placeholder: "Standard" } });
    const ev = (c.evidence && (c.evidence.packages || c.evidence.package)) || "";
    input.value = pfPackage || "";
    const go = el("button", { cls: "secondary-btn", attrs: { type: "button" }, text: "Check again with this package" });
    go.addEventListener("click", () => { pfPackage = input.value.trim(); startPreflight(); });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go.click(); } });
    return el("div", { cls: "gw-stack" },
      el("div", { cls: "input-group" }, el("label", { cls: "input-label", attrs: { for: id }, text: "Policy package" }), input),
      ev ? el("p", { cls: "gw-help", text: `On the server: ${ev}` }) : null,
      el("div", { cls: "gw-actions" }, go),
      el("p", { cls: "gw-help", text: "Configure uses the same package when you build the plan (Policy package field)." }));
  };

  const renderIssue = (c, tone, report) => {
    const card = el("section", { cls: `gw-card ${tone}` });
    card.append(el("div", { cls: "gw-card-head" },
      el("span", { cls: `gw-label ${tone}`, text: tone === "bad" ? "Blocking" : "Warning" }),
      el("h2", { cls: "gw-h2 gw-grow", text: c.title })));
    const main = el("div", { cls: "gw-issue-main" }, el("p", { cls: "gw-issue-detail", text: c.detail }));
    const ev = evidenceList(c.evidence);
    if (ev) main.append(ev);
    const said = checkSaid(c);
    if (said) main.append(saidBlock(said));
    const actions = el("div", { cls: "gw-actions" });
    const wa = c.web_action || (c.fixable === "https-inspection" ? { id: "https_fix" } : c.fixable === "https-rule" ? { id: "https_rule" } : null);
    if (wa && wa.id === "https_fix") {
      actions.append(el("button", { cls: "btn-gradient", attrs: { type: "button", "data-action": "https_fix" }, text: "Turn on for me (asks for approval)", on: { click: () => openHttpsFix(false) } }));
    } else if (wa && wa.id === "https_rule") {
      actions.append(el("button", { cls: "btn-gradient", attrs: { type: "button", "data-action": "https_rule" }, text: "Add the Inspect rule for me (asks for approval)", on: { click: () => openHttpsFix(true) } }));
    }
    actions.append(el("button", { cls: "secondary-btn", attrs: { type: "button" }, text: "Check again", on: { click: () => startPreflight() } }));
    main.append(actions);
    const side = el("div", { cls: "gw-issue-main" });
    if (c.id === "https_gw" || (c.id === "tls_path" && c.status === "fail")) side.append(promptPath(status || st, c, report));
    if (c.fix && c.fix.length) side.append(el("span", { cls: "gw-eyebrow", text: "How to fix it" }), fixList(c.fix));
    if ((wa && wa.id === "outbound_ca") || (c.id === "tls_path" && c.status === "warn")) side.append(outboundCaPanel());
    if (c.id === "package" && c.status === "fail") side.append(packagePanel(c));
    card.append(el("div", { cls: "gw-issue" }, main, side));
    return card;
  };

  const renderReport = (r) => {
    renderCounters(r);
    const blocking = gw("pf-blocking");
    const warnings = gw("pf-warnings");
    const passed = gw("pf-passed");
    clear(blocking); clear(warnings); clear(passed);
    // The last policy install goes first, on its own: if Access Control did not install,
    // the gateway still enforces an older policy and nothing on screen is live.
    const install = gw("pf-install");
    clear(install);
    const li = findCheck(r, "last_install");
    if (li && install) install.append(installCheckCard(li, { onRecheck: () => startPreflight(), compact: true }));
    const checks = (r.checks || []).filter((c) => c.id !== "last_install");
    checks.filter((c) => c.status === "fail" && c.blocking).forEach((c) => blocking.append(renderIssue(c, "bad", r)));
    checks.filter((c) => (c.status === "warn" && c.id !== "workforce_ai") || (c.status === "fail" && !c.blocking)).forEach((c) => warnings.append(renderIssue(c, "warn", r)));
    const rest = checks.filter((c) => c.status === "pass" || c.status === "skip" || (c.id === "workforce_ai" && c.status === "warn"));
    rest.forEach((c) => {
      const [sym, tone] = c.id === "workforce_ai" ? ["i", "muted"] : checkIcon(c);
      passed.append(el("div", { cls: "gw-checkrow" },
        el("span", { cls: `gw-tick ${tone}`, text: sym, attrs: { "aria-label": c.status } }),
        el("span", { cls: "gw-cr-title", text: c.title }),
        el("span", { cls: "gw-cr-detail", text: c.detail })));
    });
    show(gw("pf-passed-card"), rest.length > 0);
    linkDisabled(continueLink, !r.ok);
    show(anyway, !r.ok);
    setText(gw("pf-footer-text"), r.ok
      ? `All blocking checks passed (${r.summary || ""}). Checked ${fmtTime(r.created_at)}.`
      : "Fix the blocking item to continue. You can also continue anyway, but no prompt will be blocked.");
  };

  const showProgress = (job) => {
    show(progressCard, true);
    renderSteps(gw("pf-steps"), job.steps);
    setBar(gw("pf-bar"), job.progress);
  };

  const followJob = async (jobId) => {
    running = true;
    runBtn.disabled = true;
    const stop = elapsedTimer(gw("pf-elapsed"));
    try {
      const job = await pollJob(jobId, showProgress);
      if (job.status === "done") {
        show(progressCard, false);
        renderReport(job.result.preflight);
      } else {
        renderError(gw("pf-error"), job.error);
      }
    } catch (e) {
      renderError(gw("pf-error"), e);
    } finally {
      stop();
      running = false;
      runBtn.disabled = false;
      setLoading(false, runBtn);
      refreshStatus().catch(() => {});
    }
  };

  const startPreflight = async () => {
    if (running) return;
    clear(gw("pf-error"));
    setLoading(true, runBtn);
    try {
      const data = await api("POST", "preflight", pfPackage ? { package: pfPackage } : {});
      await followJob(data.job.id);
    } catch (e) {
      setLoading(false, runBtn);
      renderError(gw("pf-error"), e);
    }
  };

  // ---- HTTPS Inspection fix (plan -> approval -> apply job -> preflight again)
  const fixCard = gw("pf-fix");
  const fixRule = $("#gw-pf-fix-rule");
  const openHttpsFix = async (addRule) => {
    if (addRule === true || addRule === false) fixRule.checked = addRule;
    show(fixCard, true);
    fixCard.scrollIntoView({ behavior: "smooth", block: "start" });
    clear(gw("pf-fix-error")); clear(gw("pf-fix-progress")); clear(gw("pf-fix-approval"));
    const planBox = gw("pf-fix-plan");
    planBox.replaceChildren(el("p", { cls: "gw-muted", text: "Building the plan (read-only)..." }));
    try {
      const data = await api("POST", "plan", { template: "https-inspection", add_rule: fixRule.checked });
      const plan = data.plan;
      renderPlanList(planBox, plan);
      planBox.append(apiCallsDetails(plan));
      approvalPanel(gw("pf-fix-approval"), plan, {
        buttonText: "Approve and turn on",
        sentence: `I understand this turns on HTTPS Inspection on ${plan.gateway}, publishes the change and installs policy.`,
        onApprove: async (body) => {
          const res = await api("POST", "apply", body);
          const list = el("ol", { cls: "gw-steplist" });
          gw("pf-fix-progress").replaceChildren(list);
          const job = await pollJob(res.job.id, (j) => renderSteps(list, j.steps));
          if (job.status === "done") {
            showNotification("HTTPS Inspection is on. Running the checks again.", "success");
            show(fixCard, false);
            startPreflight();
          } else {
            renderError(gw("pf-fix-error"), job.error);
          }
        },
        onError: (e) => renderError(gw("pf-fix-error"), e),
      });
    } catch (e) {
      clear(planBox);
      renderError(gw("pf-fix-error"), e);
    }
  };
  fixRule.addEventListener("change", () => { if (!fixCard.hidden) openHttpsFix(); });
  pageHooks.httpsFix = (addRule) => openHttpsFix(addRule);

  runBtn.addEventListener("click", () => startPreflight());
  if (needConnection(gw("pf-notice"), st)) {
    runBtn.disabled = true;
    return;
  }
  if (wantFix === "https" || wantFix === "https-rule") {
    window.history.replaceState(null, "", window.location.pathname);
    openHttpsFix(wantFix === "https-rule");
  }
  const job = st.job;
  if (job && job.kind === "preflight" && job.status === "running") {
    showProgress(job);
    followJob(job.id);
  } else if (job && job.kind === "apply" && job.status === "running" && job.label === "HTTPS fix") {
    show(fixCard, true);
    const list = el("ol", { cls: "gw-steplist" });
    gw("pf-fix-progress").replaceChildren(list);
    pollJob(job.id, (j) => renderSteps(list, j.steps)).then((j) => {
      if (j.status === "done") startPreflight(); else renderError(gw("pf-fix-error"), j.error);
    }).catch((e) => renderError(gw("pf-fix-error"), e));
  } else if (st.preflight && !query.has("run")) {
    renderReport(st.preflight);
  } else {
    if (window.location.search) window.history.replaceState(null, "", window.location.pathname);
    startPreflight();
  }
}

// ================================================================== Configure

function initConfigure(st) {
  const buildBtn = $("#gw-plan-build");
  const reviewLink = $("#gw-plan-review");
  const checkBtn = $("#gw-key-check");
  const scope = $("#gw-scope");
  const scopeObj = $("#gw-scope-object");
  const keyInput = $("#gw-lakera-key");
  const projectInput = $("#gw-project-id");
  const keyGroup = gw("key-input-group");
  let planFresh = false;
  let keyState = st.lakera || {};

  if (needConnection(gw("cfg-notice"), st)) { buildBtn.disabled = true; }
  else if (st.preflight && !st.preflight.ok) {
    gw("cfg-notice").replaceChildren(callout("warn", "Preflight has blocking items",
      el("span", { text: "You can build and install the policy, but the demo will probably not block anything until they are fixed." }),
      el("a", { text: "Back to Preflight", attrs: { href: pageUrl("preflight") } })));
  }
  if (st.gateway) {
    const pkg = st.gateway.policy_package;
    setText(gw("cfg-badge"), `Step 3 of 6 · ${st.gateway.name}${pkg ? " · package " + pkg : ""}`);
    if (pkg) $("#gw-package").placeholder = `From the gateway: ${pkg}`;
  }
  const ip = (st.preflight && st.preflight.local_ip) || st.local_ip;
  if (ip) scope.options[0].textContent = `This server only (${ip})`;

  const keySource = () => (root.querySelector('input[name="gw-key-source"]:checked') || { value: "new" }).value;
  const syncKeySource = () => { if (keyGroup && root.querySelector('input[name="gw-key-source"]')) show(keyGroup, keySource() === "new"); };
  root.querySelectorAll('input[name="gw-key-source"]').forEach((r) => r.addEventListener("change", () => { syncKeySource(); markStale(); }));
  syncKeySource();
  const syncScope = () => show(gw("scope-object-group"), scope.value === "object");
  scope.addEventListener("change", syncScope);

  // Restore the options of the plan built earlier in this session.
  const prev = (st.plan && st.plan.template === "ai-agent-security" && st.plan.options) || null;
  if (prev) {
    if (prev.profile_name) $("#gw-profile-name").value = prev.profile_name;
    if (prev.rule_name) $("#gw-rule-name").value = prev.rule_name;
    if (prev.track) $("#gw-track").value = prev.track;
    if (prev.scope && prev.scope !== "client" && prev.scope !== "any") { scope.value = "object"; scopeObj.value = prev.scope; }
    else if (prev.scope) scope.value = prev.scope;
    $("#gw-moderation").checked = !!prev.moderation;
    $("#gw-install").checked = prev.install !== false;
    if (prev.package) $("#gw-package").value = prev.package;
  }
  syncScope();
  if (keyState.project_id && !projectInput.value) projectInput.value = keyState.project_id;

  const wf = st.preflight && (st.preflight.checks || []).find((c) => c.id === "workforce_ai");
  if (wf) {
    const p = gw("wf-state");
    p.className = "gw-pill " + (wf.status === "pass" ? "ok" : "neutral");
    setText(p, wf.status === "pass" ? "On for this gateway" : wf.status === "warn" ? "Off for this gateway" : "Unknown");
  }

  const renderKeyState = (k) => {
    const line = gw("key-result");
    if (!k || !k.masked_key) { setText(line, ""); return; }
    line.className = "gw-result-line " + (k.validated ? "ok" : "warn");
    const by = k.validated_by === "management" ? "validated by the management server" : k.validated_by === "lakera" ? "accepted by Lakera" : "not validated yet";
    setText(line, `${k.validated ? "✓" : "!"} Key ${k.masked_key} · project ${k.project_id || "?"} · ${by}${k.message ? " · " + k.message : ""}`);
    warningsList(gw("key-warnings"), k.warnings);
  };
  renderKeyState(keyState);

  const markStale = () => {
    if (!planFresh) return;
    planFresh = false;
    linkDisabled(reviewLink, true);
    gw("plan-warnings").replaceChildren(callout("info", null, el("span", { text: "Options changed: build the plan again before you approve it." })));
  };
  root.querySelectorAll(".gw-main input, .gw-main select").forEach((n) => {
    if (n.id === "gw-lakera-key" || n.id === "gw-project-id") return;
    n.addEventListener("change", markStale);
  });

  const setKey = async () => {
    clear(gw("key-error"));
    const body = { project_id: projectInput.value.trim() };
    if (root.querySelector('input[name="gw-key-source"]') && keySource() === "saved") body.use_saved = true;
    else body.api_key = keyInput.value.trim();
    const data = await api("POST", "lakera", body);
    keyInput.value = "";
    keyState = data.lakera;
    renderKeyState(keyState);
    if (data.plan_cleared) {
      // The plan held the previous key / project: it must be built (and reviewed) again.
      planFresh = false;
      clear(gw("plan-list"));
      linkDisabled(reviewLink, true);
      gw("plan-warnings").replaceChildren(callout("info", null, el("span", { text: "The key or project changed: the plan built with the previous one was discarded. Build the plan again." })));
    }
    return keyState;
  };

  const keyNeeded = () => {
    if (!keyState || !keyState.masked_key) return true;
    if (keyInput.value.trim()) return true;
    if (projectInput.value.trim() && projectInput.value.trim() !== keyState.project_id) return true;
    return false;
  };

  checkBtn.addEventListener("click", async () => {
    setLoading(true, checkBtn);
    try { await setKey(); markStale(); } catch (e) { renderError(gw("key-error"), e); } finally { setLoading(false, checkBtn); }
  });

  const renderPlan = (plan) => {
    renderPlanList(gw("plan-list"), plan);
    gw("plan-list").append(apiCallsDetails(plan));
    warningsList(gw("plan-warnings"), plan.warnings);
    setText(gw("plan-where"), plan.domain ? `${plan.server} › ${plan.domain}` : plan.server || "");
    planFresh = true;
    linkDisabled(reviewLink, false);
  };
  if (st.plan && st.plan.template === "ai-agent-security") renderPlan(st.plan);

  buildBtn.addEventListener("click", async () => {
    clear(gw("plan-error"));
    setLoading(true, buildBtn);
    try {
      if (keyNeeded()) {
        try { await setKey(); } catch (e) { renderError(gw("key-error"), e); throw e; }
      }
      const scopeVal = scope.value === "object" ? scopeObj.value.trim() : scope.value;
      if (scope.value === "object" && !scopeVal) throw new ApiError(400, { error: { what: "Enter the name of the network object for the protected scope", state: "Nothing was changed." } });
      const options = {
        profile_name: $("#gw-profile-name").value.trim(), rule_name: $("#gw-rule-name").value.trim(),
        scope: scopeVal, track: $("#gw-track").value, moderation: $("#gw-moderation").checked,
        install: $("#gw-install").checked, package: $("#gw-package").value.trim(),
        lakera_project_id: projectInput.value.trim(),
      };
      const data = await api("POST", "plan", { options });
      renderPlan(data.plan);
      refreshStatus().catch(() => {});
    } catch (e) {
      if (!(e instanceof ApiError && e.detail && gw("key-error").childElementCount)) renderError(gw("plan-error"), e);
      linkDisabled(reviewLink, true);
    } finally {
      setLoading(false, buildBtn);
    }
  });
}

// ================================================================== Install

// {"access": "installed" | "not installed" | "unknown", "threat_prevention": ...}
function installStatusText(st) {
  if (!st || typeof st !== "object") return "";
  const names = { access: "Access Control", threat_prevention: "Threat Prevention" };
  return Object.keys(st).map((k) => `${names[k] || k}: ${st[k]}`).join(" · ");
}

function initInstall(st) {
  const plan = st.plan;
  const demoLink = $("#gw-inst-demo");
  const steps = gw("inst-steps");
  let stopTimer = null;

  const renderResult = (job) => {
    const res = (job.result && (job.result.apply || job.result.rollback)) || {};
    const box = gw("inst-result");
    clear(box);
    if (job.status === "done") {
      const lines = [];
      if (res.approved_by) lines.push(`Approved by ${res.approved_by} · ${fmtTime(res.approved_at)}`);
      if (res.rollback_id) lines.push(`Rollback point ${res.rollback_id} saved`);
      if (res.message && !res.partial) lines.push(res.message);
      const parts = installStatusText(res.install_status);
      if (parts) lines.push(parts);
      box.append(callout("ok", res.installed ? "Published and installed" : res.published ? "Published" : "Done", ...lines.map((l) => el("span", { text: l }))));
      // Installed, but an optional step (e.g. content moderation) needs you: warnings with
      // their fix and buttons, not a failure.
      const notices = (res.notices || []).slice();
      if (res.error) notices.push(res.error);
      notices.forEach((n) => box.append(errorBlock(n, { tone: "warn", label: "Still to do" })));
      const said = notices.map((n) => String(n.what || "").replace(/\.$/, "")).filter(Boolean);
      (res.warnings || []).filter((w) => !said.some((t) => String(w).startsWith(t)))
        .forEach((w) => box.append(callout("warn", null, el("span", { text: w }))));
      const enf = res.enforcement;
      if (enf) {
        if (enf.confirmed) box.append(callout("ok", "Enforcement confirmed", el("span", { text: "The test prompt was blocked by the gateway." })));
        else if (enf.error) box.append(errorBlock(enf.error, { tone: "warn", label: "Enforcement check" }));
        else {
          const ol = el("ol", { cls: "gw-fixlist" });
          (enf.diagnosis || []).forEach((d) => ol.append(el("li", { text: d })));
          box.append(callout("warn", `Enforcement not confirmed (${(enf.result && enf.result.verdict) || "no block"})`, ol));
        }
      }
      linkDisabled(demoLink, false);
    } else if (job.status === "failed") {
      const err = job.error || {};
      renderError(gw("inst-error"), err, { onAction: () => refreshStatus().then(renderRollbacks).catch(() => {}) });
      const parts = installStatusText(res.install_status);
      if (parts) box.append(callout("warn", "Policy on the gateway", el("span", { text: parts })));
      const offered = (err.actions || []).some((a) => a.id === "rollback" && a.rollback_id === res.rollback_id);
      if (res.rollback_id && !offered) {
        const rb = el("button", { cls: "danger-btn", attrs: { type: "button" }, text: `Roll back ${res.rollback_id}` });
        rb.addEventListener("click", () => startRollback(res.rollback_id, rb));
        box.append(el("div", { cls: "gw-actions" }, rb));
      }
      if (err.code === "web.plan_mismatch") {
        // The plan was built again from what the server holds now: review that one.
        box.append(el("div", { cls: "gw-actions" },
          el("button", { cls: "btn-gradient", attrs: { type: "button" }, text: "Review the new plan", on: { click: () => window.location.reload() } })));
      }
    }
  };

  const follow = async (jobId) => {
    show(gw("inst-bar-wrap"), true);
    stopTimer = elapsedTimer(gw("inst-elapsed"));
    try {
      const job = await pollJob(jobId, (j) => { renderSteps(steps, j.steps); setBar(gw("inst-bar"), j.progress); });
      renderResult(job);
      return job;
    } finally {
      if (stopTimer) stopTimer();
      refreshStatus().then(renderRollbacks).catch(() => {});
    }
  };

  // ---- rollback points
  const startRollback = (rid, btn) => {
    clear(gw("rb-error"));
    return runRollback(rid, btn, gw("rb-progress"), {
      install: $("#gw-rb-install").checked,
      onDone: () => renderRollbacks(status),
    });
  };
  const renderRollbacks = (s) => {
    const points = (s && s.rollbacks) || [];
    show(gw("rb-card"), points.length > 0 && !!s.connected);
    const box = gw("rb-list");
    clear(box);
    const rows = el("div", { cls: "gw-checkrows" });
    points.slice().reverse().forEach((p) => {
      const done = p.status === "rolled-back" || p.status === "discarded";
      const doneLabel = p.status === "discarded" ? "Nothing to undo" : "Rolled back";
      // "publish-unknown": the publish may or may not have completed (lost connection,
      // or the console shut down mid-apply). Still undoable.
      const statusText = p.status === "publish-unknown"
        ? "publish result unknown: check SmartConsole, roll back if the changes are there"
        : (p.status || "");
      const btn = el("button", { cls: "secondary-btn gw-small-btn", attrs: { type: "button" }, text: done ? doneLabel : `Roll back ${p.id}` });
      btn.disabled = done;
      btn.addEventListener("click", () => startRollback(p.id, btn));
      rows.append(el("div", { cls: "gw-checkrow" },
        el("span", { cls: `gw-tick ${done ? "muted" : "ok"}`, text: done ? "○" : "●" }),
        el("span", { cls: "gw-cr-title" }, `${p.id} · ${p.gateway || ""}`, el("span", { cls: "gw-cr-detail", text: `  ${fmtTime(p.created_at)} · ${statusText}` })),
        el("span", { cls: "gw-cr-detail" }, p.summary || "", " ", btn)));
    });
    box.append(rows);
  };
  renderRollbacks(st);

  if (needConnection(gw("inst-notice"), st)) return;
  if (!plan) {
    gw("inst-notice").replaceChildren(callout("warn", "There is no plan yet",
      el("span", { text: "Build the plan on Configure, then come back to approve it." }),
      el("a", { text: "Go to Configure", attrs: { href: pageUrl("configure") } })));
    clear(gw("inst-plan"));
    return;
  }
  const pid = gw("plan-id-pill");
  setText(pid, `plan ${plan.plan_id}`);
  show(pid, true);
  const planBox = gw("inst-plan");
  planBox.replaceChildren(changeTable(plan), apiCallsDetails(plan));
  warningsList(gw("inst-warnings"), plan.warnings);

  const job = st.job;
  const la = st.last_apply || {};
  const samePlan = la.plan_id === plan.plan_id && la.kind !== "rollback";
  const applied = samePlan && (la.ok || la.installed);
  // An approved plan runs once (the engine refuses it again): after a failed install, a
  // rollback or a partial run, offer a new plan instead of an approval that cannot work.
  const published = !!((st.web && st.web.plan_applied) || plan.published || plan.applied);
  // Only the latest apply job of THIS plan belongs on this page.
  const jobPlan = job && job.result && job.result.apply && job.result.apply.plan_id;
  const ownJob = job && job.kind === "apply" && jobPlan === plan.plan_id;
  if (job && job.kind === "apply" && job.status === "running") {
    gw("inst-approval").replaceChildren(callout("info", "Approved", el("span", { text: "The change is running. Its progress is shown here." })));
    follow(job.id);
    return;
  }
  if (applied) {
    gw("inst-approval").replaceChildren(callout("ok", "This plan was applied",
      el("span", { text: "Build a new plan on Configure to change anything, or roll back below." })));
    if (ownJob) { renderSteps(steps, job.steps); renderResult(job); }
    linkDisabled(demoLink, false);
    return;
  }
  if (ownJob && job.status === "failed") { renderSteps(steps, job.steps); renderResult(job); }
  if (published) {
    gw("inst-approval").replaceChildren(callout("warn", "This plan already ran",
      el("span", { text: la.kind === "rollback" ? "It was rolled back since. To install the demo policy again, build a new plan on Configure and approve that one."
        : "Its changes were published, so it cannot run again. Fix the cause shown under Progress, then build a new plan on Configure (it updates the objects that exist now), or roll back below." }),
      el("a", { text: "Build a new plan on Configure", attrs: { href: pageUrl("configure") } })));
    return;
  }

  const panel = approvalPanel(gw("inst-approval"), plan, {
    onApprove: async (body) => {
      clear(gw("inst-error"));
      clear(gw("inst-result"));
      let data;
      data = await api("POST", "apply", body);
      panel.done();
      await follow(data.job.id);
    },
    onError: (e) => renderError(gw("inst-error"), e),
  });
}

// ================================================================== Demo

function verdictClass(v) {
  return { BLOCKED: "blocked", ALLOWED: "allowed", UNKNOWN: "unknown", ERROR: "error" }[v] || "unknown";
}
function categoryLabel(cat) {
  return cat ? getDetectorLabel(cat) : "";
}

function initDemo(st) {
  let scenes = [];
  let providers = [];
  let current = null;
  let currentResult = null;
  let selectedPromptId = "custom";
  const results = new Map();
  (st.results || []).forEach((r) => results.set(r.id, r));
  const sendBtn = $("#gw-send");
  const runBtn = $("#gw-scene-run");
  const textArea = $("#gw-prompt-text");
  const providerSel = $("#gw-provider");
  const expectSel = $("#gw-expect");
  const gwName = (st.gateway && st.gateway.name) || "the gateway";
  setText(gw("send-label"), st.gateway ? `Send through ${gwName}` : "Send through the gateway");

  const notice = gw("demo-notice");
  if (!st.connected) {
    notice.replaceChildren(callout("info", "Not connected to the management server",
      el("span", { text: "Prompts still go through the network path of this server, but AI Guard cannot look up the gateway logs." }),
      el("a", { text: "Connect", attrs: { href: pageUrl("connect") } })));
  } else if (st.step !== "demo") {
    notice.replaceChildren(callout("warn", "The demo policy is not installed yet",
      el("span", { text: "Prompts are sent anyway, but expect them to go through until the plan is approved and installed." }),
      el("a", { text: "Approve and install", attrs: { href: pageUrl("install") } })));
  }
  // Before any demo run: a last install that did not fully succeed means the gateway may
  // be enforcing an older policy than the one on screen.
  const li = findCheck(st.preflight, "last_install");
  if (li && (li.status === "fail" || li.status === "warn")) {
    notice.append(installCheckCard(li, { compact: true }),
      el("p", { cls: "gw-help" }, el("a", { text: "Check it again on Preflight", attrs: { href: pageUrl("preflight") + "?run=1" } })));
  }

  const renderCounters = (summary) => {
    const box = gw("demo-counters");
    clear(box);
    if (!summary || !summary.total) return;
    box.append(pill(`${summary.blocked || 0} blocked`, "bad"), pill(`${summary.allowed || 0} allowed`, "ok"));
    const un = (summary.unexpected || []).length;
    box.append(pill(`${un} unexpected`, un ? "warn" : "neutral"));
  };
  renderCounters(st.summary);

  const renderHistory = () => {
    const ol = gw("history");
    clear(ol);
    const list = [...results.values()].reverse();
    if (!list.length) { ol.append(el("li", { cls: "gw-muted", text: "No prompts sent yet." })); return; }
    list.forEach((r) => {
      const meta = r.verdict === "BLOCKED"
        ? [categoryLabel(r.category) || "blocked", r.confidence_label].filter(Boolean).join(" · ")
        : r.verdict === "ALLOWED" ? `no finding · ${fmtMs(r.ms)}` : r.evidence || r.reason || r.verdict;
      const li = el("li", { cls: r.matched ? "" : "unexpected" },
        el("span", { cls: `gw-verdict small ${verdictClass(r.verdict)}`, text: r.verdict }),
        el("button", { cls: "gw-hist-prompt", attrs: { type: "button", title: "Show this result" }, text: r.prompt, on: { click: () => renderResult(r) } }),
        el("span", { cls: "gw-hist-meta", text: r.matched ? meta : `unexpected · ${meta}` }));
      ol.append(li);
    });
  };

  const renderResult = (r) => {
    if (!r) return;
    currentResult = r;
    const card = gw("result-card");
    show(card, true);
    const v = r.verdict;
    const prov = providerLabel(r.provider);
    const vb = gw("result-verdict");
    vb.className = `gw-verdict ${verdictClass(v)}`;
    setText(vb, v);
    setText(gw("result-by"), v === "BLOCKED" ? `by Check Point · ${gwName} · ${fmtMs(r.ms)}`
      : v === "ALLOWED" ? `reached ${prov} · ${fmtMs(r.ms)}` : v === "UNKNOWN" ? `no conclusive reply · ${fmtMs(r.ms)}` : "not sent");
    const mp = gw("result-match");
    mp.className = `gw-pill ${r.matched ? "ok" : "warn"}`;
    setText(mp, r.matched ? "As expected" : `Unexpected (expected ${r.expect === "allow" ? "allow" : "block"})`);
    const cat = categoryLabel(r.category);
    setText(gw("result-headline"),
      v === "BLOCKED" ? `${cat ? cat + " was" : "This prompt was"} stopped at the gateway before it reached ${prov}`
        : v === "ALLOWED" ? (r.expect === "allow" ? `Everyday work goes through: the prompt reached ${prov}` : `The prompt reached ${prov}`)
        : v === "UNKNOWN" ? "No conclusive answer from the network" : "The prompt could not be sent");
    setText(gw("result-prompt"), r.prompt);

    const facts = gw("result-facts");
    clear(facts);
    const fact = (k, val) => facts.append(el("div", { cls: "gw-fact" }, el("span", { text: k }), el("strong", { text: val || "—" })));
    fact("Category", cat || (v === "BLOCKED" ? "not reported" : "no finding"));
    fact("Confidence", r.confidence_label || (r.confidence != null ? String(r.confidence) : ""));
    fact("Engine", v === "BLOCKED" ? "AI Agent Security" : "");
    fact("Category from", r.category_source === "gateway log" ? "Gateway log" : r.category_source === "lakera" ? "Lakera" : "");
    const lm = r.log_match;
    if (lm && lm.rule) fact("Rule", lm.rule);

    // Client -> Quantum Gateway -> LLM
    const blocked = v === "BLOCKED";
    const stages = [
      { id: "client", kind: "user", name: "Client", role: r.local_ip || "this server", status: "ok", badge: "prompt" },
      { id: "gateway", kind: "gateway", name: "Quantum Gateway", role: gwName, status: blocked ? "block" : v === "ALLOWED" ? "pass" : v === "ERROR" ? "error" : "unknown" },
      { id: "llm", kind: "llm", name: prov, role: r.model || r.host || "model", status: v === "ALLOWED" ? "run" : "skip" },
    ];
    const verdict = blocked ? { tone: "bad", title: "Blocked at the gateway", desc: `${prov} never received this prompt.` }
      : v === "ALLOWED" ? { tone: r.matched ? "ok" : "warn", title: "Delivered", desc: `The gateway let the prompt through to ${prov}.` }
      : { tone: "warn", title: v === "ERROR" ? "Not sent" : "Not conclusive", desc: r.reason || r.evidence || "" };
    renderStagePipeline(gw("result-pipeline"), stages, verdict);

    // What the user saw
    setText(gw("saw-title"), blocked ? (r.content_type && r.content_type.includes("html") ? "Check Point block page" : `Blocked: ${r.evidence || "by the network"}`)
      : v === "ALLOWED" ? `The ${prov} answer${r.http_status ? " (HTTP " + r.http_status + ")" : ""}` : r.evidence || r.reason || v);
    const saw = gw("saw-kv");
    clear(saw);
    const kv = (box, k, val) => { if (val == null || val === "") return; box.append(el("dt", { text: k }), el("dd", { text: val })); };
    kv(saw, "HTTP status", r.http_status);
    kv(saw, "Content type", r.content_type);
    kv(saw, "Evidence", r.evidence);
    kv(saw, "Redirect", r.location);
    kv(saw, "Certificate", r.inspected === true ? `inspected (issuer ${r.issuer || "gateway CA"})` : r.inspected === false ? `not inspected (issuer ${r.issuer || "public CA"})` : r.issuer);
    if (r.dummy_key) kv(saw, "Provider key", "placeholder (none saved in Settings)");
    const snip = gw("saw-snippet");
    setText(snip, r.snippet || "");
    show(snip, !!r.snippet);

    // Proof in SmartConsole
    const proof = gw("proof-kv");
    clear(proof);
    if (lm) {
      setText(gw("proof-title"), `Log found · action ${lm.action || "?"}${lm.blade ? " · " + lm.blade : ""}`);
      kv(proof, "Time", lm.time); kv(proof, "Action", lm.action); kv(proof, "Blade", lm.blade);
      kv(proof, "Rule", lm.rule); kv(proof, "Protection", lm.protection); kv(proof, "Category", lm.category);
      kv(proof, "Log id", lm.log_id);
    } else {
      setText(gw("proof-title"), status && status.connected ? "No log found yet" : "Not checked (not connected)");
      kv(proof, "Note", status && status.connected ? "Logs can take up to a minute to appear. Check again in a moment." : "Connect to the management server to look up the gateway log.");
    }
    setText(gw("proof-filter"), r.local_ip ? `SmartConsole > Logs & Events, filter: src:${r.local_ip}` : "");
    show($("#gw-correlate"), !!(status && status.connected));

    const diag = gw("result-diagnosis");
    clear(diag);
    if (r.diagnosis && r.diagnosis.length) {
      const ol = el("ol", { cls: "gw-fixlist" });
      r.diagnosis.forEach((d) => ol.append(el("li", { text: d })));
      diag.append(callout("warn", "Why this was not the expected result", ol));
    }
    if (r.error && v === "ERROR") diag.append(errorBlock(r.error));
  };

  const addResults = (list, summary) => {
    (list || []).forEach((r) => results.set(r.id, r));
    renderHistory();
    if (summary) renderCounters(summary);
  };

  // TLS handshake towards the provider (no prompt): is this traffic inspected?
  let tlsSeq = 0;
  const checkTls = async () => {
    const line = gw("tls-line");
    const out = gw("tls-out");
    if (!line || !providerSel.value) return;
    const seq = ++tlsSeq;
    clear(out);
    line.className = "gw-result-line";
    setText(line, `Checking the TLS path to ${providerLabel(providerSel.value)}...`);
    try {
      const data = await api("POST", "tls-check", { provider: providerSel.value });
      if (seq !== tlsSeq) return;
      const t = data.tls || {};
      const host = t.host || providerLabel(data.provider);
      if (t.status === "inspected") {
        line.className = "gw-result-line ok";
        setText(line, `✓ ${host}: inspected by the gateway (certificate issued by ${t.issuer || t.issuer_cn || "the outbound CA"})`);
      } else if (t.status === "untrusted") {
        line.className = "gw-result-line warn";
        setText(line, `! ${host}: re-signed by the gateway, but this server does not trust its outbound CA yet`);
        out.append(el("div", { cls: "gw-actions" }, actionButton({ id: "outbound_ca", label: "Export outbound CA" }, out, () => checkTls())));
      } else if (t.status === "not_inspected") {
        line.className = "gw-result-line warn";
        setText(line, `! ${host}: not inspected (issuer ${t.issuer || "a public CA"}): the gateway cannot read the prompts`);
        out.append(el("a", { text: "See Preflight", attrs: { href: pageUrl("preflight") } }));
      } else {
        line.className = "gw-result-line warn";
        setText(line, `! ${host}: ${(t.error && t.error.what) || t.connect_error || "the TLS handshake failed"}`);
      }
    } catch (e) {
      if (seq !== tlsSeq) return;
      line.className = "gw-result-line warn";
      setText(line, `! TLS check: ${normalizeError(e).what}`);
    }
  };

  const fillProviders = () => {
    clear(providerSel);
    providers.forEach((p) => providerSel.append(el("option", { attrs: { value: p.name }, text: `${p.label} · ${p.model}${p.key === "saved" ? "" : " (no key saved)"}` })));
    const sync = () => {
      const p = providers.find((x) => x.name === providerSel.value);
      setText(gw("key-hint"), p && p.key !== "saved"
        ? `No ${p.label} key is saved in Settings: AI Guard sends a placeholder key. The gateway still inspects the prompt; a prompt that goes through gets the provider's "invalid key" answer.`
        : "");
    };
    providerSel.addEventListener("change", () => { sync(); checkTls(); });
    sync();
  };

  const selectScene = (scene) => {
    current = scene;
    root.querySelectorAll(".gw-scene").forEach((b) => b.classList.toggle("active", b.dataset.scene === scene.id));
    show(gw("scene-panel"), true);
    setText(gw("scene-number"), `Scene ${scene.number}`);
    setText(gw("scene-title"), scene.title);
    setText(gw("demo-badge"), `Step 5 of 6 · Scene ${scene.number}`);
    setText(gw("demo-title"), scene.title);
    setText(gw("scene-say"), scene.say || "");
    setText(gw("scene-after"), scene.after || "");
    show(gw("scene-after-wrap"), !!scene.after);
    setText(gw("scene-note"), scene.note || "");
    show(gw("scene-note"), !!scene.note);
    show(runBtn, (scene.prompts || []).length > 0);
    show(gw("scene-steps"), false);
    clear(gw("scene-error"));
    const warn = gw("scene-warning");
    clear(warn);
    const moderationOn = !!(status && ((status.web && status.web.moderation_on) || status.moderation_enabled));
    if (scene.requires === "moderation" && !moderationOn) {
      warn.append(callout("warn", "Content moderation is not on in this session",
        el("span", { text: "Turn it on in Configure (it is applied after approval), or these prompts will probably go through." })));
    }
    const chips = gw("prompt-chips");
    clear(chips);
    (scene.prompts || []).forEach((p) => {
      chips.append(el("button", { cls: "gw-chip", attrs: { type: "button", title: p.note || p.category || "" }, on: { click: () => {
        textArea.value = p.text; expectSel.value = p.expect === "allow" ? "allow" : "block"; selectedPromptId = p.id; textArea.focus();
      } } }, p.text.length > 60 ? p.text.slice(0, 57) + "..." : p.text, " ", el("span", { cls: "gw-chip-exp", text: p.expect })));
    });
    if (!(scene.prompts || []).length) {
      chips.append(el("span", { cls: "gw-muted", text: "Type your own prompt below and choose what you expect." }));
      textArea.focus();
    }
    if (window.location.hash !== "#" + scene.id) window.history.replaceState(null, "", "#" + scene.id);
  };

  const renderSceneList = () => {
    const ol = gw("scene-list");
    clear(ol);
    scenes.forEach((s) => {
      const b = el("button", { cls: "gw-scene", attrs: { type: "button", "data-scene": s.id } },
        el("span", { cls: "gw-scene-no", text: s.number }),
        el("span", { cls: "gw-scene-text" }, el("span", { text: s.title }),
          el("small", { text: s.prompts && s.prompts.length ? `${s.prompts.length} prompt${s.prompts.length === 1 ? "" : "s"}` : "your own prompt" })));
      b.addEventListener("click", () => selectScene(s));
      ol.append(el("li", {}, b));
    });
  };

  textArea.addEventListener("input", () => { selectedPromptId = "custom"; });

  sendBtn.addEventListener("click", async () => {
    clear(gw("send-error"));
    const text = textArea.value;
    if (!text.trim()) { renderError(gw("send-error"), { what: "Type a prompt first", state: "Nothing was sent." }); return; }
    setLoading(true, sendBtn);
    try {
      const data = await api("POST", "prompt", { text, provider: providerSel.value, expect: expectSel.value, prompt_id: selectedPromptId });
      addResults([data.result], data.summary);
      renderResult(data.result);
      (data.warnings || []).forEach((w) => showNotification(w, "warning"));
    } catch (e) {
      renderError(gw("send-error"), e);
    } finally {
      setLoading(false, sendBtn);
    }
  });

  const followScene = async (jobId) => {
    const list = gw("scene-steps");
    show(list, true);
    runBtn.disabled = true;
    try {
      const job = await pollJob(jobId, (j) => renderSteps(list, j.steps));
      if (job.status === "done") {
        const out = job.result.results || [];
        addResults(out, job.result.summary);
        const show1 = out.find((r) => r.verdict === "BLOCKED") || out[out.length - 1];
        renderResult(show1);
      } else {
        renderError(gw("scene-error"), job.error);
      }
    } catch (e) {
      renderError(gw("scene-error"), e);
    } finally {
      runBtn.disabled = false;
      setLoading(false, runBtn);
    }
  };

  runBtn.addEventListener("click", async () => {
    if (!current) return;
    clear(gw("scene-error"));
    setLoading(true, runBtn);
    try {
      const data = await api("POST", "scene", { scene_id: current.id, provider: providerSel.value });
      await followScene(data.job.id);
    } catch (e) {
      setLoading(false, runBtn);
      renderError(gw("scene-error"), e);
    }
  });

  const corrBtn = $("#gw-correlate");
  corrBtn.addEventListener("click", async () => {
    setLoading(true, corrBtn);
    try {
      const data = await api("POST", "correlate", {});
      addResults(data.results, data.summary);
      if (currentResult && results.has(currentResult.id)) renderResult(results.get(currentResult.id));
      if (data.correlate_error) gw("result-diagnosis").append(errorBlock(data.correlate_error, { tone: "warn", label: "Gateway logs" }));
    } catch (e) {
      renderError(gw("result-diagnosis"), e);
    } finally {
      setLoading(false, corrBtn);
    }
  });

  renderHistory();
  const last = [...results.values()].pop();
  if (last) renderResult(last);

  api("GET", "scenes").then((data) => {
    scenes = data.scenes || [];
    providers = data.providers || [];
    fillProviders();
    renderSceneList();
    const fromHash = scenes.find((s) => "#" + s.id === window.location.hash);
    if (scenes.length) selectScene(fromHash || scenes[0]);
    const job = st.job;
    if (job && job.kind === "scene" && job.status === "running") followScene(job.id);
    else checkTls();
  }).catch((e) => renderError(gw("demo-notice"), e));
  const tlsBtn = $("#gw-tls-check");
  if (tlsBtn) tlsBtn.addEventListener("click", () => checkTls());
}

// ================================================================== Diagnostics

function initDiagnostics(st) {
  const view = gw("log-view");
  const filters = { level: "", component: "" };
  let timer = null;

  // The last policy install, first: a partial install (Access Control failed, Threat
  // Prevention succeeded) leaves the gateway on an older policy without saying so.
  const li = findCheck(st.preflight, "last_install");
  const installBox = gw("diag-install");
  if (installBox) {
    clear(installBox);
    if (li) installBox.append(installCheckCard(li, { compact: true }));
    else if (st.connected) installBox.append(callout("info", "Last policy installation: not checked yet",
      el("span", { text: "Preflight reads the last installation on the gateway (both Access Control and Threat Prevention must succeed)." }),
      el("a", { text: "Run preflight", attrs: { href: pageUrl("preflight") + "?run=1" } })));
  }

  const lastErr = (st.web && st.web.last_error) || (st.job && st.job.status === "failed" ? st.job.error : null);
  const errBox = gw("diag-error");
  const actions = gw("diag-actions");
  if (lastErr) {
    renderError(errBox, lastErr, { onAction: () => load() });
    const la = st.last_apply;
    const offered = (lastErr.actions || []).some((a) => a.id === "rollback" && la && a.rollback_id === la.rollback_id);
    if (st.connected && la && la.rollback_id && !la.ok && la.kind !== "rollback" && !offered) {
      const rb = el("button", { cls: "danger-btn", attrs: { type: "button" }, text: `Roll back ${la.rollback_id}` });
      rb.addEventListener("click", () => runRollback(la.rollback_id, rb, gw("diag-action-progress"), { onDone: () => load() }));
      actions.append(rb);
    }
    const code = String(lastErr.code || "") + " " + String(lastErr.type || "");
    const target = /connect|tls|login|TlsTrust|Connect/.test(code) ? ["connect", "Back to Connect"]
      : /preflight/.test(code) ? ["preflight", "Back to Preflight"]
      : /lakera/.test(code) ? ["configure", "Back to Configure"]
      : /plan|approv|apply|install|publish|script/.test(code) ? ["install", "Back to Approve and install"]
      : /scene|probe/.test(code) ? ["demo", "Back to the demo"] : null;
    if (target) actions.append(el("a", { cls: "secondary-btn gw-btn-link", attrs: { href: pageUrl(target[0]) }, text: target[1] }));
  }

  const fieldText = (fields) => Object.keys(fields || {}).map((k) => {
    const v = fields[k];
    if (v == null) return null;
    return `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`;
  }).filter(Boolean).join(" ");

  const renderLines = (records) => {
    clear(view);
    if (!records.length) { view.append(el("div", { cls: "gw-muted", text: "No log lines match." })); return; }
    records.forEach((r) => {
      const lvl = String(r.level || "").toUpperCase();
      const time = typeof r.ts === "string" && r.ts.length >= 19 ? r.ts.slice(11, 23) : String(r.ts || "");
      const msg = [r.msg, fieldText(r.fields)].filter(Boolean).join("  ");
      view.append(el("div", { cls: `gw-log-line ${lvl}`, attrs: { title: r.line != null ? `log line ${r.line}` : "" } },
        el("span", { cls: "t", text: time }), el("span", { cls: `gw-lvl ${lvl}`, text: lvl }),
        el("span", { cls: "c", text: r.component || "" }), el("span", { cls: "m", text: msg })));
    });
    view.scrollTop = view.scrollHeight;
  };

  const renderComponents = (components) => {
    const bar = gw("component-filters");
    clear(bar);
    const mk = (value, label) => {
      const b = el("button", { cls: "gw-filter" + (filters.component === value ? " active" : ""), attrs: { type: "button", "data-component": value }, text: label });
      b.addEventListener("click", () => { filters.component = value; load(); });
      return b;
    };
    bar.append(mk("", "All parts"));
    (components || []).forEach((c) => bar.append(mk(c, COMPONENT_LABELS[c] || c)));
  };

  const load = async () => {
    try {
      const params = new URLSearchParams({ n: "500" });
      if (filters.level) params.set("level", filters.level);
      if (filters.component) params.set("component", filters.component);
      const data = await api("GET", "log?" + params.toString());
      renderLines(data.records || []);
      renderComponents(data.components);
      ["ERROR", "WARN", "HINT"].forEach((l) => setText(gw("count-" + l), data.counts && data.counts[l] ? data.counts[l] : ""));
      setText(gw("diag-log-path"), data.log_path ? `${data.live ? "" : "(closed session) "}${data.log_path}` : "No log yet: it starts when you connect.");
    } catch (e) {
      renderError(view, e);
    }
  };

  gw("level-filters").querySelectorAll(".gw-filter").forEach((b) => b.addEventListener("click", () => {
    filters.level = b.dataset.level || "";
    gw("level-filters").querySelectorAll(".gw-filter").forEach((x) => x.classList.toggle("active", x === b));
    load();
  }));
  $("#gw-log-refresh").addEventListener("click", load);

  const follow = $("#gw-log-follow");
  const tick = async () => {
    if (!follow.checked) return;
    try {
      const s = await refreshStatus();
      if (s.job && s.job.status === "running") load();
    } catch (e) { /* keep the last view */ }
  };
  timer = setInterval(tick, 2000);
  window.addEventListener("pagehide", () => clearInterval(timer));

  $("#gw-report-save").addEventListener("click", async () => {
    try {
      const data = await api("GET", "report");
      if (!data.report) { showNotification("Nothing to report yet: connect and run the demo first.", "info"); return; }
      const blob = new Blob([JSON.stringify(data.report, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `aiguard-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    } catch (e) {
      showNotification(normalizeError(e).what, "error");
    }
  });

  load();
}

// ================================================================== entry

const PAGES = {
  connect: initConnect, preflight: initPreflight, configure: initConfigure,
  install: initInstall, demo: initDemo, diagnostics: initDiagnostics,
};

export async function initGateway() {
  root = document.querySelector(".gateway-page");
  if (!root) return;
  apiBase = root.dataset.api || "/gateway/api/";
  const step = root.dataset.step || "connect";
  const init = Object.prototype.hasOwnProperty.call(PAGES, step) ? PAGES[step] : null;
  let st;
  try {
    st = await refreshStatus();
  } catch (e) {
    const main = root.querySelector(".gw-main");
    if (main) main.prepend(errorBlock(e));
    return;
  }
  if (init) init(st);
}
