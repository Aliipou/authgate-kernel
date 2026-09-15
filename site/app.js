// Loads the real compiled authgate_kernel.wasm (wasm-bindgen `web` target)
// and drives the live demo. No JS reimplementation of the kernel logic —
// every Permit/Deny below comes from the actual Rust `engine::verify()`.
// `verify_json_wasm` (the signed variant) calls std::time::SystemTime::now()
// internally to timestamp the signature, which panics on wasm32-unknown-unknown
// (no wall clock without JS interop the crate doesn't wire up yet — a real,
// confirmed-live gap, not a hypothetical one). `verify_json_unsigned` is the
// function this crate already ships for exactly this situation — see wasm.rs's
// own doc comment. Still the real kernel, just without a signature attached.
import init, { verify_json_unsigned } from "./pkg/authgate_kernel.js";
// kernel_pubkey_wasm() is intentionally not imported/called: it lazily
// generates an ed25519 keypair via OsRng on first use, which needs a working
// getrandom "js" backend. That's wired up for a real browser (Crypto.
// getRandomValues) but wasn't reliably reproducible in this sandbox's Node
// smoke test, so the demo doesn't depend on it — verify_json_unsigned never
// touches key generation at all.

const dot = document.getElementById("wasm-dot");
const status = document.getElementById("wasm-status");
const verifyBtn = document.getElementById("verify-btn");
const registryInput = document.getElementById("registry-input");
const actionInput = document.getElementById("action-input");
const resultEl = document.getElementById("result");

// Real scenario data, lifted directly from this repo's own
// examples/callgate_demo.py (_build()): alice owns sales-data and
// report-file, delegates read/write on those two to data-analyst-bot,
// system-config has no claim at all, rogue-bot has no owner.
const entity = (name, kind) => ({ name, kind });
const resource = (name, rtype, scope) => ({ name, rtype, scope, is_public: false, ifc_label: "", trust_domain: null });
const claim = (holderName, holderKind, resourceName, rtype, scope, rights) => ({
  holder: entity(holderName, holderKind),
  resource: resource(resourceName, rtype, scope),
  can_read: !!rights.read,
  can_write: !!rights.write,
  can_delegate: !!rights.delegate,
  confidence: 1.0,
  expires_at: null,
  trust_domain: null,
  delegation_depth: 0,
});

const REGISTRY = {
  claims: [
    claim("alice", "HUMAN", "sales-data", "DATASET", "/data/alice/sales/", { read: true, delegate: true }),
    claim("alice", "HUMAN", "report-file", "FILE", "/reports/alice/", { write: true, delegate: true }),
    claim("data-analyst-bot", "MACHINE", "sales-data", "DATASET", "/data/alice/sales/", { read: true }),
    claim("data-analyst-bot", "MACHINE", "report-file", "FILE", "/reports/alice/", { write: true }),
  ],
  machine_owners: [{ machine: entity("data-analyst-bot", "MACHINE"), owner: entity("alice", "HUMAN") }],
  trust_domains: [],
};

const baseAction = (overrides) => ({
  action_id: overrides.action_id ?? "demo-action",
  actor: overrides.actor,
  description: overrides.description ?? "",
  resources_read: overrides.resources_read ?? [],
  resources_write: overrides.resources_write ?? [],
  resources_delegate: [],
  governs_humans: [],
  argument: "",
  increases_machine_sovereignty: false,
  resists_human_correction: false,
  bypasses_verifier: false,
  weakens_verifier: false,
  disables_corrigibility: overrides.disables_corrigibility ?? false,
  machine_coalition_dominion: false,
  coerces: false,
  deceives: false,
  self_modification_weakens_verifier: false,
  machine_coalition_reduces_freedom: false,
  trust_domain: null,
  delegation_depth: 0,
});

const SCENARIOS = {
  "permit-direct": baseAction({
    action_id: "read-sales-direct",
    actor: entity("alice", "HUMAN"),
    resources_read: [resource("sales-data", "DATASET", "/data/alice/sales/")],
  }),
  "permit-delegated": baseAction({
    action_id: "read-sales-delegated",
    actor: entity("data-analyst-bot", "MACHINE"),
    resources_read: [resource("sales-data", "DATASET", "/data/alice/sales/")],
  }),
  "deny-no-claim": baseAction({
    action_id: "read-system-config",
    actor: entity("data-analyst-bot", "MACHINE"),
    resources_read: [resource("system-config", "FILE", "/etc/")],
  }),
  "deny-rogue": baseAction({
    action_id: "rogue-read-sales",
    actor: entity("rogue-bot", "MACHINE"),
    resources_read: [resource("sales-data", "DATASET", "/data/alice/sales/")],
  }),
  "deny-sovereignty": baseAction({
    action_id: "corrigibility-override",
    actor: entity("data-analyst-bot", "MACHINE"),
    resources_write: [resource("report-file", "FILE", "/reports/alice/")],
    disables_corrigibility: true,
  }),
};

function loadScenario(key) {
  registryInput.value = JSON.stringify(REGISTRY, null, 2);
  actionInput.value = JSON.stringify(SCENARIOS[key], null, 2);
}

document.querySelectorAll("button.scenario").forEach((btn) => {
  btn.addEventListener("click", () => loadScenario(btn.dataset.scenario));
});

function renderResult(r, pubkey) {
  const decisionClass = r.permitted ? "permit" : "deny";
  const decisionText = r.permitted ? "PERMIT" : "DENY";
  let html = `<div class="decision ${decisionClass}">${decisionText}</div>`;
  if (r.violations && r.violations.length) {
    html += `<ul class="violations">${r.violations.map((v) => `<li>${escapeHtml(v)}</li>`).join("")}</ul>`;
  }
  if (r.warnings && r.warnings.length) {
    html += `<ul class="warnings">${r.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`;
  }
  html += `<div class="result-meta">confidence=${r.confidence.toFixed(2)} · manipulation_score=${r.manipulation_score.toFixed(2)}`;
  if (r.signature) {
    html += `<br/>ed25519 signature: <span class="mono">${r.signature.slice(0, 32)}…</span> (verifying key: <span class="mono">${(r.signing_key || pubkey || "").slice(0, 16)}…</span>)`;
  } else {
    html += `<br/>unsigned — this build uses verify_json_unsigned() (SystemTime::now() isn't available on wasm32-unknown-unknown without JS clock interop the crate doesn't wire up yet)`;
  }
  html += `</div>`;
  resultEl.innerHTML = html;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

verifyBtn.addEventListener("click", () => {
  let registry, action;
  try {
    registry = JSON.parse(registryInput.value);
    action = JSON.parse(actionInput.value);
  } catch (e) {
    resultEl.innerHTML = `<div class="decision deny">JSON parse error</div><p>${escapeHtml(String(e))}</p>`;
    return;
  }
  try {
    const raw = verify_json_unsigned(JSON.stringify({ registry, action }));
    renderResult(JSON.parse(raw));
  } catch (e) {
    resultEl.innerHTML = `<div class="decision deny">Kernel error</div><p>${escapeHtml(String(e))}</p>`;
  }
});

(async function boot() {
  try {
    await init();
    dot.classList.add("ok");
    status.textContent = "Real kernel loaded (wasm-bindgen, compiled from this repo's authgate-kernel/src).";
    verifyBtn.disabled = false;
    loadScenario("permit-direct");
    window.__authgateVerify = (reg, act) => JSON.parse(verify_json_unsigned(JSON.stringify({ registry: reg, action: act })));
  } catch (e) {
    dot.classList.add("err");
    status.textContent = "Failed to load the compiled kernel: " + e;
  }
})();
