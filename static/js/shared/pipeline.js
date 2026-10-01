// ============================================================
// Guard pipeline visualization (shared): hero explainer + live result flow.
// All text (stage names, roles, badges, verdicts) is set with textContent.
// Icons are built from static shape lists (no innerHTML).
// ============================================================

import { createSvg } from "./utils.js";

const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

export const ICON = Object.freeze({
  user: [["circle", { cx: 12, cy: 8, r: 4 }], ["path", { d: "M4 21c0-4 4-6 8-6s8 2 8 6" }]],
  guard: [["path", { d: "M12 3l7 3v5c0 4.4-3 7.9-7 9-4-1.1-7-4.6-7-9V6z" }]],
  llm: [["rect", { x: 4, y: 4, width: 16, height: 16, rx: 4 }], ["path", { d: "M9 9h6M9 13h6" }]],
  // Security gateway: a firewall brick wall.
  gateway: [
    ["rect", { x: 3, y: 5, width: 18, height: 14, rx: 2 }],
    ["path", { d: "M3 9.7h18M3 14.3h18M9 5v4.7M15 5v4.7M6 9.7v4.6M12 9.7v4.6M18 9.7v4.6M9 14.3V19M15 14.3V19" }],
  ],
});
const VERDICT_ICON = Object.freeze({
  ok: [["path", { d: "M5 13l4 4L19 7" }]],
  bad: [["path", { d: "M18 6L6 18M6 6l12 12" }]],
  warn: [["path", { d: "M12 6v8" }], ["path", { d: "M12 18h.01" }]],
});
const BADGE = {
  pass: "✓ passed", block: "✗ blocked", run: "✓ generated", skip: "— skipped", ok: "✓ received",
  idle: "idle", prompt: "prompt", error: "✗ error", detect: "! detected", unknown: "? unknown",
};
const badgeCls = (s) =>
  s === "pass" || s === "run" || s === "ok" ? "ok"
    : s === "block" || s === "error" ? "bad"
    : s === "detect" || s === "unknown" ? "warn"
    : s === "skip" ? "" : "wait";
// 'guard' and 'gateway' use the brand gradient chip.
const chipKind = (kind) => (kind === "guard" || kind === "gateway" ? "brand" : kind === "llm" ? "llm" : "user");
const iconFor = (kind) => (own(ICON, kind) ? ICON[kind] : ICON.user);
// Stages whose status stops the packet (the rest of the pipe is dimmed).
const isStop = (status) => status === "block" || status === "error";

const findNode = (root, id) =>
  [...root.querySelectorAll(".gp-node")].find((n) => n.dataset.n === String(id)) || null;
const findBadge = (root, id) =>
  [...root.querySelectorAll(".gp-badge")].find((b) => b.dataset.b === String(id)) || null;

// Build the pipe DOM from a stage spec (any count; CSS supports 2-6 nodes).
// Stages: [{id, kind:'user'|'guard'|'gateway'|'llm', name, role, status, badge}]
export function buildPipe(stages) {
  const pipe = document.createElement("div");
  const n = stages.length;
  pipe.className = "gp-pipe" + (n >= 2 && n <= 6 && n !== 5 ? " gp-pipe--n" + n : "");
  stages.forEach((st, i) => {
    const node = document.createElement("div");
    node.className = "gp-node";
    node.dataset.n = String(st.id);

    const chip = document.createElement("div");
    chip.className = "gp-chip " + chipKind(st.kind);
    chip.appendChild(createSvg(iconFor(st.kind)));

    const name = document.createElement("div");
    name.className = "gp-name";
    name.textContent = st.name == null ? "" : String(st.name);

    const role = document.createElement("div");
    role.className = "gp-role";
    role.textContent = st.role == null ? "" : String(st.role);

    const badge = document.createElement("span");
    badge.className = "gp-badge";
    badge.dataset.b = String(st.id);

    node.append(chip, name, role, badge);
    pipe.appendChild(node);
    if (i < stages.length - 1) {
      const link = document.createElement("div");
      link.className = "gp-link";
      link.dataset.l = String(i);
      const fill = document.createElement("div");
      fill.className = "gp-fill";
      const packet = document.createElement("div");
      packet.className = "gp-packet";
      link.append(fill, packet);
      pipe.appendChild(link);
    }
  });
  return pipe;
}

function applyBadge(root, id, status) {
  const b = findBadge(root, id);
  if (!b) return;
  b.className = "gp-badge " + badgeCls(status);
  b.textContent = own(BADGE, status) ? BADGE[status] : String(status == null ? "" : status);
}

// Animate the packet through the pipe, applying per-stage statuses in order and
// stopping at the first stage whose status is "block" (or "error").
export function animate(root, stages, timers) {
  const links = [...root.querySelectorAll(".gp-link")];
  const ping = (id) => {
    const el = findNode(root, id);
    if (!el) return;
    el.classList.add("pinged");
    timers.push(setTimeout(() => el.classList.remove("pinged"), 400));
  };
  const flow = (li, cb, blocked) => {
    const l = links[li];
    if (!l) return cb && cb();
    const p = l.querySelector(".gp-packet");
    p.style.transition = "none"; p.style.left = "0"; p.style.opacity = 1;
    requestAnimationFrame(() => { p.style.transition = "left .55s ease"; p.style.left = "calc(100% - 12px)"; });
    l.classList.add("done"); if (blocked) l.classList.add("blocked");
    timers.push(setTimeout(() => { p.style.opacity = 0; cb && cb(); }, 580));
  };
  let i = 0;
  const step = () => {
    if (i >= stages.length) return;
    const st = stages[i];
    ping(st.id);
    applyBadge(root, st.id, st.badge || st.status);
    if (isStop(st.status)) {
      const node = findNode(root, st.id);
      if (node) node.classList.add("blocked");
      if (links[i - 1]) links[i - 1].classList.add("blocked");
      for (let j = i + 1; j < stages.length; j++) {
        const later = findNode(root, stages[j].id);
        if (later) later.classList.add("dim");
        applyBadge(root, stages[j].id, stages[j].badge || "skip");
      }
      return;
    }
    i++;
    if (i < stages.length) timers.push(setTimeout(() => flow(i - 1, step, false), 240));
  };
  timers.push(setTimeout(step, 260));
}

// Append verdict text. `desc` is plain text, or an array of parts where a part
// is a string or {b: "bold text"} (rendered as <b> with textContent).
function appendRich(el, desc) {
  if (Array.isArray(desc)) {
    desc.forEach((part) => {
      if (part && typeof part === "object") {
        const b = document.createElement("b");
        b.textContent = part.b == null ? "" : String(part.b);
        el.appendChild(b);
      } else {
        el.appendChild(document.createTextNode(part == null ? "" : String(part)));
      }
    });
  } else {
    el.textContent = desc == null ? "" : String(desc);
  }
}

// Verdict box: v = {tone: 'ok'|'bad'|'warn', title, desc}. Text only.
export function renderVerdict(root, v) {
  const tone = v && (v.tone === "bad" || v.tone === "warn") ? v.tone : "ok";
  let el = root.querySelector(".gp-verdict");
  if (!el) { el = document.createElement("div"); root.appendChild(el); }
  el.className = "gp-verdict " + tone;

  const vic = document.createElement("div");
  vic.className = "gp-vic";
  vic.appendChild(createSvg(VERDICT_ICON[tone]));

  const body = document.createElement("div");
  const title = document.createElement("p");
  title.className = "gp-vt";
  title.textContent = v && v.title != null ? String(v.title) : "";
  const desc = document.createElement("p");
  desc.className = "gp-vd";
  appendRich(desc, v ? v.desc : "");
  body.append(title, desc);

  el.replaceChildren(vic, body);
}

// Make non-skipped nodes clickable (mouse and keyboard).
function wireNodeClicks(pipe, stages, onNodeClick) {
  if (!onNodeClick) return;
  pipe.querySelectorAll(".gp-node").forEach((node) => {
    const id = node.dataset.n;
    const st = stages.find((s) => String(s.id) === id);
    if (st && st.status !== "skip") {
      node.style.cursor = "pointer";
      node.setAttribute("role", "button");
      node.tabIndex = 0;
      node.addEventListener("click", () => onNodeClick(st.id));
      node.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onNodeClick(st.id); }
      });
    }
  });
}

// ---- Hero explainer (interactive scenarios) --------------------------------
const HERO_STAGES = [
  { id: "user", kind: "user", name: "User", role: "sends prompt" },
  { id: "inbound", kind: "guard", name: "Inbound guard", role: "scans the prompt" },
  { id: "llm", kind: "llm", name: "LLM", role: "generates reply" },
  { id: "outbound", kind: "guard", name: "Outbound guard", role: "scans the reply" },
  { id: "deliver", kind: "user", name: "User", role: "receives reply" },
];
const SCENARIOS = {
  safe: { label: "Safe prompt", st: { user: "prompt", inbound: "pass", llm: "run", outbound: "pass", deliver: "ok" },
    v: { tone: "ok", title: "Delivered safely", desc: "Both scans passed. The user gets a normal answer — Guard stayed out of the way." } },
  inject: { label: "Prompt injection", st: { user: "prompt", inbound: "block", llm: "skip", outbound: "skip", deliver: "block" },
    v: { tone: "bad", title: "Blocked at the door", desc: ["Guard flagged ", { b: "prompt injection" }, " on the way in. The model never sees it. ", { b: "Without Guard," }, " this reaches the LLM and can override its instructions."] } },
  leak: { label: "Sensitive data leak", st: { user: "prompt", inbound: "pass", llm: "run", outbound: "block", deliver: "block" },
    v: { tone: "bad", title: "Leak caught on the way out", desc: ["The prompt looked fine, but the reply contained ", { b: "sensitive data" }, ". Guard blocked the response before the user saw it."] } },
};

export function initHeroPipeline(root) {
  if (!root) return;
  let timers = [];
  const bar = document.createElement("div");
  bar.className = "gp-scenarios";
  Object.keys(SCENARIOS).forEach((k, idx) => {
    const b = document.createElement("button");
    b.className = "gp-scn" + (idx === 0 ? " active" : "");
    b.dataset.s = k;
    const dot = document.createElement("span");
    dot.className = "gp-dot";
    b.append(dot, document.createTextNode(SCENARIOS[k].label));
    bar.appendChild(b);
  });
  const stageEls = HERO_STAGES.map((s) => ({ ...s }));
  const pipe = buildPipe(stageEls);
  const gp = document.createElement("div");
  gp.className = "gp";
  gp.append(bar, pipe);
  root.appendChild(gp);

  const run = (key) => {
    timers.forEach(clearTimeout); timers = [];
    gp.querySelectorAll(".gp-node").forEach((n) => n.classList.remove("dim", "blocked", "pinged"));
    gp.querySelectorAll(".gp-link").forEach((l) => { l.classList.remove("done", "blocked"); const p = l.querySelector(".gp-packet"); p.style.transition = "none"; p.style.left = "0"; p.style.opacity = 0; });
    gp.querySelectorAll(".gp-badge").forEach((b) => { b.className = "gp-badge"; b.textContent = "idle"; });
    const sc = SCENARIOS[key];
    const stages = HERO_STAGES.map((s) => ({ ...s, status: sc.st[s.id], badge: sc.st[s.id] }));
    animate(gp, stages, timers);
    timers.push(setTimeout(() => renderVerdict(gp, sc.v), stages.length * 850));
  };
  bar.addEventListener("click", (e) => {
    const b = e.target.closest(".gp-scn"); if (!b || !own(SCENARIOS, b.dataset.s)) return;
    bar.querySelectorAll(".gp-scn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active"); run(b.dataset.s);
  });
  run("safe");
}

// ---- Generic stage pipeline (e.g. Client -> Gateway -> LLM) ----------------
const rootTimers = new WeakMap();

/**
 * Render an animated pipeline for any stage list into `root` (its previous
 * content is replaced; pass null to only build it).
 * @param {HTMLElement|null} root
 * @param {Array<{id, kind:'user'|'guard'|'gateway'|'llm', name, role, status, badge}>} stages
 *   status: pass|block|run|skip|ok|prompt|error|detect|unknown; "block"/"error" stop the packet.
 * @param {{tone:'ok'|'bad'|'warn', title:string, desc:string|Array}|null} verdict  shown after the animation (text only)
 * @param {(id:string)=>void} [onNodeClick] called for non-skipped nodes
 * @returns {HTMLDivElement} the .gp element; gp.stop() cancels pending animation timers
 */
export function renderStagePipeline(root, stages, verdict, onNodeClick) {
  const list = Array.isArray(stages) ? stages.map((s) => ({ ...s, badge: s.badge || s.status })) : [];
  if (root && rootTimers.has(root)) rootTimers.get(root).forEach(clearTimeout);
  const timers = [];
  const gp = document.createElement("div");
  gp.className = "gp";
  const pipe = buildPipe(list);
  gp.appendChild(pipe);
  animate(gp, list, timers);
  if (verdict) timers.push(setTimeout(() => renderVerdict(gp, verdict), list.length * 820));
  wireNodeClicks(pipe, list, onNodeClick);
  gp.stop = () => timers.forEach(clearTimeout);
  if (root) {
    rootTimers.set(root, timers);
    root.replaceChildren(gp);
  }
  return gp;
}

// ---- Live result flow (driven by real scan data) --------------------------
export function scanToStages(data, useInbound, useOutbound) {
  const inboundBlocked = data.guardrails_result && data.guardrails_result.flagged;
  const outboundBlocked = data.guardrails_outbound_result && data.guardrails_outbound_result.flagged;
  // A requested scan that produced no result but reported an error failed:
  // show it as an error, never as "passed". /api/analyze reports an inbound
  // failure in guardrails_error and an outbound one in guardrails_outbound_error
  // (502, the model's reply withheld, so openai_response is null). Older stored
  // rows put either failure in guardrails_error.
  const scanError = !!data.guardrails_error;
  const inboundFailed = useInbound && scanError && !data.guardrails_result;
  const outboundReported = !!data.guardrails_outbound_error && !data.guardrails_outbound_result
    && !inboundBlocked && !inboundFailed;
  // The model ran when it answered, or when its reply was withheld unscanned.
  const llmRan = !inboundBlocked && !inboundFailed && (!!data.openai_response || outboundReported);
  const outboundFailed = outboundReported
    || (useOutbound && scanError && llmRan && !data.guardrails_outbound_result);
  const outboundScanned = useOutbound || outboundFailed;
  let provider = "OpenAI";
  if (data.model_provider === "azure") provider = "Azure";
  else if (data.model_provider === "gemini") provider = "Gemini";
  else if (data.model_provider === "anthropic") provider = "Claude";
  else if (data.model_provider === "ollama") provider = "Ollama";

  const stages = [
    { id: "user", kind: "user", name: "User", role: "prompt", status: "ok", badge: "prompt" },
    { id: "inbound", kind: "guard", name: "Inbound guard", role: "scans the prompt",
      status: useInbound ? (inboundFailed ? "error" : inboundBlocked ? "block" : "pass") : "skip" },
    { id: "llm", kind: "llm", name: provider, role: data.model_name || "model",
      status: inboundBlocked ? "skip" : (llmRan ? "run" : "skip") },
    { id: "outbound", kind: "guard", name: "Outbound guard", role: "scans the reply",
      status: !llmRan ? "skip" : (outboundScanned ? (outboundFailed ? "error" : outboundBlocked ? "block" : "pass") : "skip") },
    { id: "deliver", kind: "user", name: "User", role: "receives reply",
      status: inboundBlocked || outboundBlocked || outboundReported ? "block" : (llmRan ? "ok" : "skip") },
  ];
  stages.forEach((s) => { if (!s.badge) s.badge = s.status; });

  let v;
  if (useInbound && inboundBlocked) v = { tone: "bad", title: "Threat blocked inbound", desc: "Guard flagged the prompt before it reached the model." };
  else if (inboundFailed) v = { tone: "warn", title: "Inbound scan failed", desc: "The prompt could not be scanned, so it was not sent to the model." };
  else if (useOutbound && outboundBlocked) v = { tone: "bad", title: "Threat blocked outbound", desc: "Guard flagged the model's reply before it reached the user." };
  else if (outboundFailed) v = { tone: "warn", title: "Outbound scan failed", desc: outboundReported
    ? "The model's reply could not be scanned, so it was withheld."
    : "The model's reply could not be scanned." };
  else if (llmRan) v = { tone: "ok", title: "Delivered safely", desc: "The request passed the enabled scans." };
  else v = { tone: "ok", title: "No response generated", desc: "Nothing was delivered." };
  return { stages, verdict: v };
}

export function renderScanPipeline(data, useInbound, useOutbound, onNodeClick) {
  const { stages, verdict } = scanToStages(data, useInbound, useOutbound);
  const gp = document.createElement("div");
  gp.className = "gp";
  const pipe = buildPipe(stages);
  gp.appendChild(pipe);
  const timers = [];
  animate(gp, stages, timers);
  timers.push(setTimeout(() => renderVerdict(gp, verdict), stages.length * 820));
  wireNodeClicks(pipe, stages, onNodeClick);
  return gp;
}

// Indeterminate "scanning…" pipeline shown while /api/analyze is in flight.
export function renderScanningPipeline({ useInbound, useOutbound, provider, model }) {
  const prov = provider === "azure" ? "Azure" : provider === "gemini" ? "Gemini" : provider === "anthropic" ? "Claude" : provider === "ollama" ? "Ollama" : "OpenAI";
  const stages = [
    { id: "user", kind: "user", name: "User", role: "prompt", badge: "sent" },
    { id: "inbound", kind: "guard", name: "Inbound guard", role: "scans the prompt", badge: useInbound ? "scanning…" : "skipped" },
    { id: "llm", kind: "llm", name: prov, role: model || "model", badge: "waiting" },
    { id: "outbound", kind: "guard", name: "Outbound guard", role: "scans the reply", badge: useOutbound ? "scanning…" : "skipped" },
    { id: "deliver", kind: "user", name: "User", role: "receives reply", badge: "waiting" },
  ];
  const gp = document.createElement("div");
  gp.className = "gp gp-scanning";
  gp.appendChild(buildPipe(stages));
  stages.forEach((s) => {
    const b = findBadge(gp, s.id);
    if (b) { b.className = "gp-badge wait"; b.textContent = s.badge; }
  });
  gp.querySelectorAll(".gp-link .gp-fill").forEach((f) => (f.style.width = "60%"));
  return gp;
}
