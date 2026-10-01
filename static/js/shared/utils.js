// ============================================
// Shared Utilities
// ============================================

const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/**
 * Escape a value for safe interpolation into HTML text or a quoted attribute.
 * Escapes & < > " ' and backtick. null/undefined become "".
 * Prefer textContent / DOM construction; use this only where a string of
 * markup is unavoidable.
 * @param {*} value
 * @returns {string}
 */
export function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>"'`]/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "`": "&#96;",
  }[c]));
}

// ---- Detector (attack vector) labels and colours ---------------------------
// Fixed palette: every colour that can reach a style property comes from here,
// never from data. Keys are normalized detector names (see normalizeKey).
const PALETTE = Object.freeze({
  crime: "#ef4444", // red
  violence: "#dc2626", // dark red
  weapons: "#f97316", // orange
  hate: "#fb923c", // light orange
  profanity: "#fbbf24", // amber
  sexual: "#facc15", // yellow
  self_harm: "#f43f5e", // rose
  custom: "#d946ef", // fuchsia
  moderated_content: "#f59e0b", // amber (whole category)
  prompt_attack: "#a855f7", // purple
  jailbreak: "#8b5cf6", // violet (legacy v1 name)
  pii: "#06b6d4", // cyan
  address: "#0891b2", // dark cyan
  email: "#22d3ee", // light cyan
  phone_number: "#0ea5e9", // sky blue
  credit_card: "#3b82f6", // blue
  us_social_security_number: "#2563eb", // dark blue
  name: "#14b8a6", // teal
  ip_address: "#10b981", // green
  iban_code: "#059669", // emerald
  unknown_links: "#eab308", // gold
  default: "#64748b", // slate gray (unknown types)
});

const MODERATION_LABELS = Object.freeze({
  crime: "Crime",
  hate: "Hate",
  profanity: "Profanity",
  sexual: "Sexual",
  violence: "Violence",
  weapons: "Weapons",
  self_harm: "Self-harm",
  custom: "Custom",
});

const PII_LABELS = Object.freeze({
  name: "name",
  phone_number: "phone number",
  email: "email",
  ip_address: "IP address",
  address: "address",
  credit_card: "credit card",
  iban_code: "IBAN",
  us_social_security_number: "US SSN",
  custom: "custom",
});

const OTHER_LABELS = Object.freeze({
  prompt_attack: "Prompt attack",
  unknown_links: "Unknown links",
  jailbreak: "Jailbreak",
  pii: "PII",
  moderated_content: "Moderated content",
});

// "Self-Harm", "self harm", "self-harm" -> "self_harm"
const normalizeKey = (s) => s.trim().toLowerCase().replace(/[\s-]+/g, "_");

/**
 * Resolve a detector type to a display label and a palette colour.
 * Accepts full Lakera types ("moderated_content/hate", "pii/credit_card",
 * "moderated_content/self-harm" or "self_harm", "prompt_attack", "unknown_links")
 * and the short names older rows store ("hate", "credit_card").
 * Unknown types keep their raw string as label and get the neutral colour.
 * @param {string} detectorType
 * @returns {{type: string, label: string, color: string, known: boolean}}
 */
export function getDetectorInfo(detectorType) {
  const raw = detectorType == null ? "" : String(detectorType);
  const norm = normalizeKey(raw);
  const slash = norm.lastIndexOf("/");
  const group = slash >= 0 ? norm.slice(0, slash) : "";
  const sub = slash >= 0 ? norm.slice(slash + 1) : norm;
  const color = (key) => (own(PALETTE, key) ? PALETTE[key] : PALETTE.default);
  const out = (label, key) => ({ type: raw, label, color: color(key), known: true });

  if (group === "moderated_content" && own(MODERATION_LABELS, sub)) {
    return out(MODERATION_LABELS[sub], sub);
  }
  if (group === "pii" && sub) {
    const pretty = own(PII_LABELS, sub) ? PII_LABELS[sub] : sub.replace(/_/g, " ");
    return out("PII: " + pretty, own(PII_LABELS, sub) && sub !== "custom" ? sub : "pii");
  }
  if (!group && sub) {
    if (own(OTHER_LABELS, sub)) return out(OTHER_LABELS[sub], sub);
    if (own(MODERATION_LABELS, sub)) return out(MODERATION_LABELS[sub], sub);
    if (own(PII_LABELS, sub)) return out("PII: " + PII_LABELS[sub], sub);
  }
  return { type: raw, label: raw.trim() || "Unknown", color: PALETTE.default, known: false };
}

/**
 * Display label for a detector type (see getDetectorInfo).
 * @param {string} detectorType
 * @returns {string}
 */
export function getDetectorLabel(detectorType) {
  return getDetectorInfo(detectorType).label;
}

/**
 * Get color for a specific attack type. Always returns a colour from the fixed
 * palette (never the input), so it is safe to put into a style property.
 * @param {string} attackType - The type of attack (short or full detector type)
 * @returns {string} Hex color code
 */
export function getAttackColor(attackType) {
  return getDetectorInfo(attackType).color;
}

/**
 * Build a coloured badge element for a detector type. Text goes through
 * textContent; colours come from the fixed palette.
 * @param {string} detectorType
 * @param {string} className - e.g. "attack-badge", "vector-badge"
 * @returns {HTMLSpanElement}
 */
export function createDetectorBadge(detectorType, className = "attack-badge") {
  const info = getDetectorInfo(detectorType);
  const badge = document.createElement("span");
  badge.className = className;
  badge.textContent = info.label;
  if (info.type && info.label !== info.type) badge.title = info.type;
  badge.style.background = info.color + "20";
  badge.style.borderColor = info.color;
  badge.style.color = info.color;
  return badge;
}

// ---- Small DOM helpers ------------------------------------------------------
const SVG_NS = "http://www.w3.org/2000/svg";

/**
 * Build an SVG element from a static shape list, without innerHTML.
 * @param {Array<[string, Object]>} shapes - e.g. [["path", {d: "M5 13l4 4L19 7"}]]
 * @param {Object} attrs - attributes for the <svg> (viewBox defaults to 0 0 24 24)
 * @returns {SVGSVGElement}
 */
export function createSvg(shapes, attrs = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  const all = { viewBox: "0 0 24 24", ...attrs };
  Object.keys(all).forEach((k) => svg.setAttribute(k, String(all[k])));
  (shapes || []).forEach(([tag, a]) => {
    const el = document.createElementNS(SVG_NS, tag);
    Object.keys(a || {}).forEach((k) => el.setAttribute(k, String(a[k])));
    svg.appendChild(el);
  });
  return svg;
}

// ---- API calls ---------------------------------------------------------------

/** Thrown by apiFetch when the session has ended (HTTP 401); the page is leaving. */
export class SignInRequiredError extends Error {
  constructor() {
    super("Your session has ended. Sign in again.");
    this.name = "SignInRequiredError";
  }
}

let redirectingToLogin = false;

/** Send the browser to the sign-in page (once, however many calls fail). */
export function redirectToLogin() {
  if (redirectingToLogin) return;
  redirectingToLogin = true;
  window.location.assign("/login");
}

/**
 * fetch() for the app's own /api routes. Every route needs a signed-in session
 * and answers 401 {"error": "Sign in required"} once it has ended (signed out in
 * another tab, restart with a new session key). Then this redirects to /login
 * and throws SignInRequiredError, so callers never render the 401 body as data.
 * Any other status is returned as is: callers still check response.ok.
 */
export async function apiFetch(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    redirectToLogin();
    throw new SignInRequiredError();
  }
  return response;
}

/**
 * Set loading state on a button
 * @param {boolean} isLoading - Whether to show loading state
 * @param {HTMLElement} btn - The button element
 */
export function setLoading(isLoading, btn) {
  if (!btn) return;

  const btnText = btn.querySelector(".btn-text");
  const loader = btn.querySelector(".loader");

  if (isLoading) {
    btn.disabled = true;
    if (btnText) btnText.style.opacity = "0";
    if (loader) loader.classList.remove("hidden");
  } else {
    btn.disabled = false;
    if (btnText) btnText.style.opacity = "1";
    if (loader) loader.classList.add("hidden");
  }
}

const NOTIFICATION_TYPES = ["error", "success", "warning", "info"];

/**
 * Show a notification toast. The message is always rendered as text.
 * @param {string} message - The message to display
 * @param {string} type - 'error', 'success', 'warning' or 'info'
 */
export function showNotification(message, type = 'info') {
    const container = document.getElementById('notification-container') || createNotificationContainer();
    const kind = NOTIFICATION_TYPES.includes(type) ? type : 'info';

    const notification = document.createElement('div');
    notification.className = `notification ${kind}`;

    const content = document.createElement('div');
    content.className = 'notification-content';
    const icon = document.createElement('span');
    icon.className = 'notification-icon';
    icon.textContent = getIconForType(kind);
    const text = document.createElement('span');
    text.className = 'notification-message';
    text.textContent = message == null ? '' : String(message);
    content.append(icon, text);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'notification-close';
    closeBtn.type = 'button';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.textContent = '×';

    notification.append(content, closeBtn);
    container.appendChild(notification);

    // Animate in
    requestAnimationFrame(() => {
        notification.classList.add('show');
    });

    // Auto remove
    const timeout = setTimeout(() => {
        removeNotification(notification);
    }, 5000);

    // Close button
    closeBtn.addEventListener('click', () => {
        clearTimeout(timeout);
        removeNotification(notification);
    });
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notification-container';
    document.body.appendChild(container);
    return container;
}

function removeNotification(notification) {
    notification.classList.remove('show');
    notification.addEventListener('transitionend', () => {
        notification.remove();
    });
}

function getIconForType(type) {
    switch(type) {
        case 'error': return '❌';
        case 'success': return '✅';
        case 'warning': return '⚠️';
        default: return 'ℹ️';
    }
}
