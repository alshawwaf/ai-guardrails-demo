// ============================================================
// Guard pipeline visualization (shared): hero explainer + live result flow.
// ============================================================

const ICON = {
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
  guard: '<path d="M12 3l7 3v5c0 4.4-3 7.9-7 9-4-1.1-7-4.6-7-9V6z"/>',
  llm: '<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M9 9h6M9 13h6"/>',
};
const BADGE = { pass: "✓ passed", block: "✗ blocked", run: "✓ generated", skip: "— skipped", ok: "✓ received", idle: "idle", prompt: "prompt" };
const badgeCls = (s) => (s === "pass" || s === "run" || s === "ok" ? "ok" : s === "block" ? "bad" : s === "skip" ? "" : "wait");
const chipKind = (kind) => (kind === "guard" ? "brand" : kind === "llm" ? "llm" : "user");
// Escape dynamic fields (e.g. model_name from the scan) before innerHTML.
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Build the pipe DOM from a 5-stage spec. Stages: [{kind,name,role,status,badge}]
export function buildPipe(stages) {
  const pipe = document.createElement("div");
  pipe.className = "gp-pipe";
  stages.forEach((st, i) => {
    const node = document.createElement("div");
    node.className = "gp-node";
    node.dataset.n = st.id;
    node.innerHTML =
      `<div class="gp-chip ${chipKind(st.kind)}"><svg viewBox="0 0 24 24">${ICON[st.kind]}</svg></div>` +
      `<div class="gp-name">${esc(st.name)}</div>` +
      `<div class="gp-role">${esc(st.role)}</div>` +
      `<span class="gp-badge" data-b="${esc(st.id)}"></span>`;
    pipe.appendChild(node);
    if (i < stages.length - 1) {
      const link = document.createElement("div");
      link.className = "gp-link";
      link.dataset.l = i;
      link.innerHTML = '<div class="gp-fill"></div><div class="gp-packet"></div>';
      pipe.appendChild(link);
    }
  });
  return pipe;
}

function applyBadge(root, id, status) {
  const b = root.querySelector('[data-b="' + id + '"]');
  if (!b) return;
  b.className = "gp-badge " + badgeCls(status);
  b.textContent = BADGE[status] || status;
}

// Animate the packet through the pipe, applying per-stage statuses in order and
// stopping at the first stage whose status is "block".
function animate(root, stages, timers) {
  const links = [...root.querySelectorAll(".gp-link")];
  const ping = (id) => {
    const el = root.querySelector('.gp-node[data-n="' + id + '"]');
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
    if (st.status === "block") {
      root.querySelector('.gp-node[data-n="' + st.id + '"]').classList.add("blocked");
      if (links[i - 1]) links[i - 1].classList.add("blocked");
      for (let j = i + 1; j < stages.length; j++) {
        root.querySelector('.gp-node[data-n="' + stages[j].id + '"]').classList.add("dim");
        applyBadge(root, stages[j].id, stages[j].badge || "skip");
      }
      return;
    }
    i++;
    if (i < stages.length) timers.push(setTimeout(() => flow(i - 1, step, false), 240));
  };
  timers.push(setTimeout(step, 260));
}

function renderVerdict(root, v) {
  let el = root.querySelector(".gp-verdict");
  if (!el) { el = document.createElement("div"); el.className = "gp-verdict"; root.appendChild(el); }
  el.className = "gp-verdict " + (v.tone || "ok");
  const icon = v.tone === "bad" ? '<path d="M18 6L6 18M6 6l12 12"/>' : '<path d="M5 13l4 4L19 7"/>';
  el.innerHTML = `<div class="gp-vic"><svg viewBox="0 0 24 24">${icon}</svg></div>` +
    `<div><p class="gp-vt">${v.title}</p><p class="gp-vd">${v.desc}</p></div>`;
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
    v: { tone: "bad", title: "Blocked at the door", desc: "Guard flagged <b>prompt injection</b> on the way in. The model never sees it. <b>Without Guard,</b> this reaches the LLM and can override its instructions." } },
  leak: { label: "Sensitive data leak", st: { user: "prompt", inbound: "pass", llm: "run", outbound: "block", deliver: "block" },
    v: { tone: "bad", title: "Leak caught on the way out", desc: "The prompt looked fine, but the reply contained <b>sensitive data</b>. Guard blocked the response before the user saw it." } },
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
    b.innerHTML = '<span class="gp-dot"></span>' + SCENARIOS[k].label;
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
    const b = e.target.closest(".gp-scn"); if (!b) return;
    bar.querySelectorAll(".gp-scn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active"); run(b.dataset.s);
  });
  run("safe");
}

// ---- Live result flow (driven by real scan data) --------------------------
export function scanToStages(data, useInbound, useOutbound) {
  const inboundBlocked = data.guardrails_result && data.guardrails_result.flagged;
  const outboundBlocked = data.guardrails_outbound_result && data.guardrails_outbound_result.flagged;
  const llmRan = !inboundBlocked && !!data.openai_response;
  let provider = "OpenAI";
  if (data.model_provider === "azure") provider = "Azure";
  else if (data.model_provider === "gemini") provider = "Gemini";
  else if (data.model_provider === "ollama") provider = "Ollama";

  const st = (status) => status;
  const stages = [
    { id: "user", kind: "user", name: "User", role: "prompt", status: "ok", badge: "prompt" },
    { id: "inbound", kind: "guard", name: "Inbound guard", role: "scans the prompt",
      status: useInbound ? (inboundBlocked ? "block" : "pass") : "skip" },
    { id: "llm", kind: "llm", name: provider, role: data.model_name || "model",
      status: inboundBlocked ? "skip" : (llmRan ? "run" : "skip") },
    { id: "outbound", kind: "guard", name: "Outbound guard", role: "scans the reply",
      status: !llmRan ? "skip" : (useOutbound ? (outboundBlocked ? "block" : "pass") : "skip") },
    { id: "deliver", kind: "user", name: "User", role: "receives reply",
      status: inboundBlocked || outboundBlocked ? "block" : (llmRan ? "ok" : "skip") },
  ];
  stages.forEach((s) => { if (!s.badge) s.badge = s.status; });

  let v;
  if (useInbound && inboundBlocked) v = { tone: "bad", title: "Threat blocked inbound", desc: "Guard flagged the prompt before it reached the model." };
  else if (useOutbound && outboundBlocked) v = { tone: "bad", title: "Threat blocked outbound", desc: "Guard flagged the model's reply before it reached the user." };
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
  if (onNodeClick) {
    pipe.querySelectorAll(".gp-node").forEach((node) => {
      const id = node.dataset.n;
      const st = stages.find((s) => s.id === id);
      if (st && st.status !== "skip") {
        node.style.cursor = "pointer";
        node.addEventListener("click", () => onNodeClick(id));
      }
    });
  }
  return gp;
}

// Indeterminate "scanning…" pipeline shown while /api/analyze is in flight.
export function renderScanningPipeline({ useInbound, useOutbound, provider, model }) {
  const prov = provider === "azure" ? "Azure" : provider === "gemini" ? "Gemini" : provider === "ollama" ? "Ollama" : "OpenAI";
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
    const b = gp.querySelector('[data-b="' + s.id + '"]');
    if (b) { b.className = "gp-badge wait"; b.textContent = s.badge; }
  });
  gp.querySelectorAll(".gp-link .gp-fill").forEach((f) => (f.style.width = "60%"));
  return gp;
}
