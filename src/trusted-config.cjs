// SPDX-License-Identifier: Apache-2.0
"use strict";

const KNOWN_TOP_LEVEL_KEYS = new Set([
  "epoch", "server", "safety", "temporal", "consensus", "convergence",
  "calibration", "linear", "budget",
]);

const KERNELS = [
  { key: "safety", name: "Safety", symbol: "S" },
  { key: "temporal", name: "Temporal", symbol: "T" },
  { key: "consensus", name: "Consensus", symbol: "C" },
  { key: "convergence", name: "Convergence", symbol: "V" },
  { key: "calibration", name: "Calibration", symbol: "K", experimental: true },
  { key: "linear", name: "Linear", symbol: "L" },
  { key: "budget", name: "Budget", symbol: "B" },
];

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function has(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function requireObject(value, where, errors) {
  if (!isObject(value)) {
    errors.push(`${where}: object required`);
    return false;
  }
  return true;
}

function requireString(value, where, errors) {
  if (typeof value !== "string") {
    errors.push(`${where}: string required`);
    return false;
  }
  return true;
}

function requireNat(value, where, errors) {
  if (!Number.isInteger(value) || value < 0) {
    errors.push(`${where}: non-negative integer required`);
    return false;
  }
  return true;
}

function requireStringArray(value, where, errors) {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    errors.push(`${where}: string array required`);
    return false;
  }
  return true;
}

// Mirrors Seal.JsonUtil.expectObjKeys (mcp-seal-dev Seal/PolicyBundle.lean): the
// verified parser hard-errors on unknown keys at section and entry level, so the
// signer must refuse to sign what the kernel will refuse to load.
function checkKeys(object, allowed, where, errors) {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key))
      errors.push(`${where}: unknown key ${JSON.stringify(key)} (kernel parsePolicyBundle rejects it; allowed: ${allowed.join(", ")})`);
  }
}

// Per-section `enabled` (PolicyBundle parseEnabled): optional boolean; default is
// true for temporal/consensus/convergence/linear/budget, false for calibration
// (EXPERIMENTAL, opt-in twice). Safety accepts no `enabled` key at all.
function validateEnabled(section, where, errors) {
  if (has(section, "enabled") && typeof section.enabled !== "boolean")
    errors.push(`${where}.enabled: boolean when present`);
}

function sectionEnabled(section, defaultValue) {
  return has(section, "enabled") ? section.enabled === true : defaultValue;
}

function validateMatch(match, where, errors) {
  if (!isObject(match) || typeof match.type !== "string") {
    errors.push(`${where}: match object with type required`);
    return;
  }
  if (match.type === "always") return;
  if (["equals", "starts_with"].includes(match.type)) {
    if (typeof match.arg !== "string" || !match.arg) errors.push(`${where}.arg: non-empty string required`);
    requireString(match.value, `${where}.value`, errors);
    return;
  }
  if (match.type === "contains_any_ci") {
    if (typeof match.arg !== "string" || !match.arg) errors.push(`${where}.arg: non-empty string required`);
    requireStringArray(match.needles, `${where}.needles`, errors);
    return;
  }
  if (["all", "any"].includes(match.type)) {
    if (!Array.isArray(match.matches) || match.matches.length === 0) {
      errors.push(`${where}.matches: non-empty match array required`);
      return;
    }
    match.matches.forEach((child, index) => validateMatch(child, `${where}.matches[${index}]`, errors));
    return;
  }
  errors.push(`${where}.type: unsupported match type ${JSON.stringify(match.type)}`);
}

function validateTarget(target, where, errors) {
  if (!Array.isArray(target)) {
    errors.push(`${where}: array required`);
    return;
  }
  target.forEach((part, index) => {
    const partWhere = `${where}[${index}]`;
    if (!isObject(part)) {
      errors.push(`${partWhere}: object required`);
      return;
    }
    const present = ["literal", "arg", "full_arguments"].filter((key) => has(part, key));
    if (present.length !== 1) {
      errors.push(`${partWhere}: exactly one literal, arg, or full_arguments:true required`);
      return;
    }
    if (present[0] === "literal") requireString(part.literal, `${partWhere}.literal`, errors);
    if (present[0] === "arg") requireString(part.arg, `${partWhere}.arg`, errors);
    if (present[0] === "full_arguments" && part.full_arguments !== true)
      errors.push(`${partWhere}.full_arguments: true required`);
  });
}

function validateSafety(config, errors) {
  const safety = config.safety;
  if (!requireObject(safety, "safety", errors)) return;
  // safetyShallowKeys: no `enabled` here — Safety is never off by design
  // (safety_always_registered); the kernel hard-errors on the key.
  checkKeys(safety, ["approval", "tools", "server"], "safety", errors);
  if (has(safety, "server") && typeof safety.server !== "string")
    errors.push("safety.server: string when present");
  if (typeof config.server === "string" && typeof safety.server === "string" && config.server !== safety.server)
    errors.push("server identity conflicts between trusted config and safety policy");

  const approval = safety.approval;
  if (requireObject(approval, "safety.approval", errors)) {
    // approvalKeys allowlist; replay_store is the host-layer replay-store pointer
    // (rust/src/main.rs replay_store_path_from_envelope: null, or an object with
    // a non-empty sqlite_path string — the kernel allowlists the key untyped).
    checkKeys(approval, ["control_file", "ttl_seconds", "replay_store"], "safety.approval", errors);
    requireString(approval.control_file, "safety.approval.control_file", errors);
    if (has(approval, "ttl_seconds")) requireNat(approval.ttl_seconds, "safety.approval.ttl_seconds", errors);
    if (has(approval, "replay_store") && approval.replay_store !== null) {
      if (!isObject(approval.replay_store)
          || typeof approval.replay_store.sqlite_path !== "string"
          || !approval.replay_store.sqlite_path)
        errors.push("safety.approval.replay_store: null or object with non-empty sqlite_path string required (host contract)");
    }
  }

  if (!Array.isArray(safety.tools)) {
    errors.push("safety.tools: array required");
    return;
  }
  safety.tools.forEach((rule, index) => {
    const where = `safety.tools[${index}]`;
    if (!requireObject(rule, where, errors)) return;
    if (typeof rule.name !== "string" || !rule.name) errors.push(`${where}.name: non-empty string required`);
    if (!["allow", "guard", "guarded", "deny"].includes(rule.mode))
      errors.push(`${where}.mode: allow|guard|guarded|deny required`);
    if (has(rule, "match")) validateMatch(rule.match, `${where}.match`, errors);
    if (has(rule, "target")) validateTarget(rule.target, `${where}.target`, errors);
    if (["guard", "guarded"].includes(rule.mode) && (!Array.isArray(rule.target) || rule.target.length === 0))
      errors.push(`${where}.target: non-empty array required for guarded rules`);
  });
}

function validateTemporal(section, errors) {
  if (!requireObject(section, "temporal", errors)) return;
  checkKeys(section, ["enabled", "policies"], "temporal", errors);
  validateEnabled(section, "temporal", errors);
  if (!Array.isArray(section.policies)) {
    errors.push("temporal.policies: array required");
    return;
  }
  section.policies.forEach((policy, index) => {
    const where = `temporal.policies[${index}]`;
    if (!requireObject(policy, where, errors)) return;
    checkKeys(policy, ["name", "type", "trigger", "forbidden"], where, errors);
    requireString(policy.name, `${where}.name`, errors);
    if (typeof policy.type !== "string") errors.push(`${where}.type: string required`);
    else if (policy.type !== "no_after") errors.push(`${where}.type: unsupported temporal policy type ${JSON.stringify(policy.type)}`);
    requireStringArray(policy.trigger, `${where}.trigger`, errors);
    requireStringArray(policy.forbidden, `${where}.forbidden`, errors);
  });
}

function validateConsensus(section, errors) {
  if (!requireObject(section, "consensus", errors)) return;
  checkKeys(section, ["enabled", "roster", "votes_file", "high_stakes"], "consensus", errors);
  validateEnabled(section, "consensus", errors);
  if (!Array.isArray(section.roster)) errors.push("consensus.roster: array of non-negative integers required");
  else section.roster.forEach((value, index) => requireNat(value, `consensus.roster[${index}]`, errors));
  requireString(section.votes_file, "consensus.votes_file", errors);
  requireStringArray(section.high_stakes, "consensus.high_stakes", errors);
}

function validateConvergence(section, errors) {
  if (!requireObject(section, "convergence", errors)) return;
  checkKeys(section, ["enabled", "tools"], "convergence", errors);
  validateEnabled(section, "convergence", errors);
  if (!Array.isArray(section.tools)) {
    errors.push("convergence.tools: array required");
    return;
  }
  section.tools.forEach((tool, index) => {
    const where = `convergence.tools[${index}]`;
    if (!requireObject(tool, where, errors)) return;
    checkKeys(tool, ["tool", "op_arg"], where, errors);
    requireString(tool.tool, `${where}.tool`, errors);
    requireString(tool.op_arg, `${where}.op_arg`, errors);
  });
}

function validateCalibration(section, errors) {
  if (!requireObject(section, "calibration", errors)) return;
  checkKeys(section, ["enabled", "delta_num", "delta_den", "min_samples", "records_file", "gated_tools"], "calibration", errors);
  validateEnabled(section, "calibration", errors);
  const numOk = requireNat(section.delta_num, "calibration.delta_num", errors);
  const denOk = requireNat(section.delta_den, "calibration.delta_den", errors);
  if (numOk && denOk && (section.delta_num === 0 || section.delta_den <= section.delta_num))
    errors.push("calibration delta must satisfy 0 < delta < 1");
  requireNat(section.min_samples, "calibration.min_samples", errors);
  requireString(section.records_file, "calibration.records_file", errors);
  requireStringArray(section.gated_tools, "calibration.gated_tools", errors);
}

function validateLinear(section, errors) {
  if (!requireObject(section, "linear", errors)) return;
  checkKeys(section, ["enabled", "grants_file", "tools"], "linear", errors);
  validateEnabled(section, "linear", errors);
  requireString(section.grants_file, "linear.grants_file", errors);
  if (!Array.isArray(section.tools)) {
    errors.push("linear.tools: array required");
    return;
  }
  section.tools.forEach((tool, index) => {
    const where = `linear.tools[${index}]`;
    if (!requireObject(tool, where, errors)) return;
    checkKeys(tool, ["tool", "cap_arg"], where, errors);
    requireString(tool.tool, `${where}.tool`, errors);
    requireString(tool.cap_arg, `${where}.cap_arg`, errors);
  });
}

function validateBudget(section, errors) {
  if (!requireObject(section, "budget", errors)) return;
  checkKeys(section, ["enabled", "budgets"], "budget", errors);
  validateEnabled(section, "budget", errors);
  if (!Array.isArray(section.budgets)) {
    errors.push("budget.budgets: array required");
    return;
  }
  section.budgets.forEach((budget, index) => {
    const where = `budget.budgets[${index}]`;
    if (!requireObject(budget, where, errors)) return;
    checkKeys(budget, ["name", "cap", "tools", "cost_arg"], where, errors);
    requireString(budget.name, `${where}.name`, errors);
    requireNat(budget.cap, `${where}.cap`, errors);
    requireStringArray(budget.tools, `${where}.tools`, errors);
    if (has(budget, "cost_arg")) requireString(budget.cost_arg, `${where}.cost_arg`, errors);
  });
}

function state(kernel, status, reason) {
  return { ...kernel, status, reason };
}

function analyzeParticipation(config) {
  const byKey = Object.fromEntries(KERNELS.map((kernel) => [kernel.key, kernel]));
  const states = [state(byKey.safety, "active", "required; gates every tool call")];

  // enabled:false collapse (PolicyBundle effective*): a disabled section maps to
  // absent before the host mapping — consensus/convergence/linear/budget go
  // unregistered; temporal stays REGISTERED but vacuous
  // (bundle_temporal_always_registered); calibration keeps its distinct
  // present-but-disabled state (calibration_registered_iff double gate).
  if (!has(config, "temporal")) states.push(state(byKey.temporal, "absent", "section absent; off"));
  else if (!sectionEnabled(config.temporal, true))
    states.push(state(byKey.temporal, "inactive", "enabled:false; kernel stays registered but with zero policies (vacuous by construction)"));
  else {
    const effective = config.temporal.policies.some((policy) => policy.trigger.length > 0 && policy.forbidden.length > 0);
    states.push(state(byKey.temporal, effective ? "active" : "inactive",
      effective ? `${config.temporal.policies.length} configured no_after policy/policies` : "VACUOUS: no policy has both trigger and forbidden tools; enforces nothing"));
  }

  if (!has(config, "consensus")) states.push(state(byKey.consensus, "absent", "section absent; off"));
  else if (!sectionEnabled(config.consensus, true))
    states.push(state(byKey.consensus, "inactive", "enabled:false; section collapses to absent — kernel unregistered"));
  else states.push(state(byKey.consensus, config.consensus.high_stakes.length ? "active" : "inactive",
    config.consensus.high_stakes.length ? `${config.consensus.high_stakes.length} high-stakes tool(s)` : "VACUOUS: high_stakes is empty; enforces nothing"));

  if (!has(config, "convergence")) states.push(state(byKey.convergence, "absent", "section absent; off"));
  else if (!sectionEnabled(config.convergence, true))
    states.push(state(byKey.convergence, "inactive", "enabled:false; section collapses to absent — kernel unregistered"));
  else states.push(state(byKey.convergence, config.convergence.tools.length ? "active" : "inactive",
    config.convergence.tools.length ? `${config.convergence.tools.length} replicated tool(s)` : "VACUOUS: tools is empty; enforces nothing"));

  if (!has(config, "calibration")) states.push(state(byKey.calibration, "absent", "section absent; off"));
  else {
    const enabled = sectionEnabled(config.calibration, false);
    const effective = enabled && config.calibration.gated_tools.length > 0;
    const reason = !enabled ? (has(config.calibration, "enabled")
        ? "enabled:false; explicitly inactive (present-but-disabled is a distinct pinned state)"
        : "enabled defaults to false (EXPERIMENTAL, opt-in twice); absent flag means off") :
      effective ? `${config.calibration.gated_tools.length} gated tool(s)` : "VACUOUS: gated_tools is empty; enforces nothing";
    states.push(state(byKey.calibration, effective ? "active" : "inactive", reason));
  }

  if (!has(config, "linear")) states.push(state(byKey.linear, "absent", "section absent; off"));
  else if (!sectionEnabled(config.linear, true))
    states.push(state(byKey.linear, "inactive", "enabled:false; section collapses to absent — kernel unregistered"));
  else states.push(state(byKey.linear, config.linear.tools.length ? "active" : "inactive",
    config.linear.tools.length ? `${config.linear.tools.length} linearly-gated tool(s)` : "VACUOUS: tools is empty; enforces nothing"));

  if (!has(config, "budget")) states.push(state(byKey.budget, "absent", "section absent; off"));
  else if (!sectionEnabled(config.budget, true))
    states.push(state(byKey.budget, "inactive", "enabled:false; section collapses to absent — kernel unregistered"));
  else {
    const covering = config.budget.budgets.reduce((count, budget) => count + budget.tools.length, 0);
    states.push(state(byKey.budget, covering ? "active" : "inactive",
      covering ? `${config.budget.budgets.length} budget(s), ${covering} covered tool entry/entries` : "VACUOUS: no budget covers a tool; enforces nothing"));
  }
  return {
    states,
    active: states.filter((entry) => entry.status === "active"),
    inactive: states.filter((entry) => entry.status === "inactive"),
    absent: states.filter((entry) => entry.status === "absent"),
  };
}

function kernelLabel(entry) {
  return `${entry.name} (${entry.symbol}${entry.experimental ? ", EXPERIMENTAL" : ""})`;
}

function formatParticipation(participation) {
  const lines = [
    "COMPOSED INVARIANT: a mediated ALLOW requires Safety and every configured kernel whose gate covers that call to allow; only ACTIVE kernels below can impose a non-vacuous constraint.",
  ];
  for (const [heading, entries] of [
    ["ACTIVE", participation.active],
    ["PRESENT-BUT-INACTIVE", participation.inactive],
    ["ABSENT/OFF", participation.absent],
  ]) {
    lines.push(`${heading} (${entries.length}):`);
    if (entries.length === 0) lines.push("  (none)");
    else entries.forEach((entry) => lines.push(`  ${kernelLabel(entry)} — ${entry.reason}`));
  }
  return lines;
}

function validateTrustedConfig(config) {
  const errors = [];
  if (!isObject(config)) return { ok: false, errors: ["policy must be an object"], participation: null };
  for (const key of Object.keys(config)) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key))
      errors.push(`UNKNOWN TOP-LEVEL KEY ${JSON.stringify(key)}: no TrustedConfig section matches it; the intended kernel would be silently off`);
  }
  if (!Number.isInteger(config.epoch) || config.epoch < 1) errors.push("epoch: integer >= 1 required");
  if (has(config, "server") && (typeof config.server !== "string" || !config.server))
    errors.push("server: non-empty string when present");
  validateSafety(config, errors);
  if (has(config, "temporal")) validateTemporal(config.temporal, errors);
  if (has(config, "consensus")) validateConsensus(config.consensus, errors);
  if (has(config, "convergence")) validateConvergence(config.convergence, errors);
  if (has(config, "calibration")) validateCalibration(config.calibration, errors);
  if (has(config, "linear")) validateLinear(config.linear, errors);
  if (has(config, "budget")) validateBudget(config.budget, errors);
  return {
    ok: errors.length === 0,
    errors,
    participation: errors.length === 0 ? analyzeParticipation(config) : null,
  };
}

module.exports = {
  KNOWN_TOP_LEVEL_KEYS,
  analyzeParticipation,
  formatParticipation,
  validateTrustedConfig,
};
