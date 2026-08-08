// SPDX-License-Identifier: Apache-2.0
"use strict";

const { scaffoldManifest } = require("./init.cjs");
const { validateTrustedConfig } = require("./trusted-config.cjs");

const RECIPE_ACTIVE = {
  "prod-db": ["S", "T", "B"],
  deploy: ["S", "C", "L"],
  "token-governor": ["S", "B"],
  mesh: ["S", "V"],
};

const SECTION_FOR = {
  S: "safety", T: "temporal", C: "consensus", V: "convergence",
  K: "calibration", L: "linear", B: "budget",
};

const ROLE_WORDS = {
  deploy: {
    semantic: ["deploy", "release", "rollout"],
    fallback: ["push", "publish", "create", "update", "write", "execute", "run"],
  },
  rollback: {
    semantic: ["rollback", "revert", "undo", "restore"],
    fallback: ["delete", "remove", "drop"],
  },
  token: {
    semantic: ["token", "llm", "model", "completion", "generate", "infer"],
    fallback: ["execute", "run", "write"],
  },
  payment: {
    semantic: ["payment", "pay", "charge", "transfer", "purchase", "billing", "invoice"],
    fallback: [],
  },
  shared: {
    semantic: ["shared", "store", "sync", "merge", "replicate"],
    fallback: ["update", "edit", "write", "push", "publish", "execute"],
  },
  publish: {
    semantic: ["publish"],
    fallback: ["push", "send", "create_or_update", "write", "execute"],
  },
};

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clone(value) {
  return structuredClone(value);
}

function recipeContext(manifest) {
  const policy = scaffoldManifest(manifest);
  const byName = new Map(manifest.tools.map((tool) => [tool.name, tool]));
  const guarded = policy.safety.tools
    .filter((rule) => rule.mode === "guard")
    .map((rule) => ({
      name: rule.name,
      text: `${rule.name} ${byName.get(rule.name)?.description || ""}`.toLowerCase(),
    }));
  if (guarded.length === 0)
    throw new Error("recipe requires at least one guarded real manifest tool; refusing to emit vacuous sections");
  return { manifest, policy, guarded, mappings: [], notices: [] };
}

function findByWords(candidates, words) {
  for (const word of words) {
    const found = candidates.find((candidate) => candidate.text.includes(word));
    if (found) return found;
  }
  return null;
}

function selectRole(context, role) {
  const words = ROLE_WORDS[role];
  const semantic = findByWords(context.guarded, words.semantic);
  const selected = semantic || findByWords(context.guarded, words.fallback) || context.guarded[0];
  const bestFit = semantic === null;
  const notice = bestFit
    ? `EDIT-ME: best-fit mapping: role '${role}' → tool '${selected.name}'. Review whether this recipe suits this server at all.`
    : `recipe mapping: role '${role}' → real manifest tool '${selected.name}'`;
  context.mappings.push({ role, tool: selected.name, bestFit, notice });
  if (bestFit) context.notices.push(notice);
  return selected.name;
}

function markSafetyRole(policy, toolName, role, notice) {
  const rule = policy.safety.tools.find((candidate) => candidate.name === toolName && candidate.mode === "guard");
  if (!rule) throw new Error(`recipe role ${role} did not resolve to a guarded Safety rule`);
  const label = `${role}: ${notice}`;
  rule._comment = rule._comment ? `${rule._comment}; ${label}` : label;
}

// The verified 28bb3ae7 parser (Seal.parsePolicyBundle) hard-errors on unknown
// keys at section and entry level, so `_comment` may no longer live inside kernel
// sections. The ONE kernel-tolerated in-file home for review markers is a safety
// rule's interior (rule-level strictness is a named follow-up); section notes are
// therefore stamped onto safety rules via noteOnSafetyRules below, and file paths
// keep their EDIT-ME placeholder VALUES (values are never key-policed).
function noteOnSafetyRules(policy, toolNames, label) {
  const names = new Set(toolNames);
  let stamped = false;
  for (const rule of policy.safety.tools) {
    if (!names.has(rule.name)) continue;
    rule._comment = rule._comment ? `${rule._comment}; ${label}` : label;
    stamped = true;
  }
  if (!stamped) {
    const rule = policy.safety.tools[0];
    if (rule) rule._comment = rule._comment ? `${rule._comment}; ${label}` : label;
  }
}

function temporalFor(toolNames) {
  return {
    section: {
      policies: [{
        name: "freeze-destructive-after-trigger",
        type: "no_after",
        trigger: [...toolNames],
        forbidden: [...toolNames],
      }],
    },
    note: "temporal: EDIT-ME: every mapped destructive tool currently triggers the freeze; narrow trigger if that is not intended.",
  };
}

function budgetFor(toolNames, { name, costArg } = {}) {
  const budget = {
    name: name || "guarded-calls",
    cap: 0,
    tools: [...toolNames],
  };
  let note = "budget: EDIT-ME: cap 0 is a fail-closed placeholder; set the intended limit before use.";
  if (costArg) {
    budget.cost_arg = costArg;
    note += ` EDIT-ME: verify cost_arg '${costArg}' against the real tool arguments.`;
  }
  return { section: { budgets: [budget] }, note };
}

function consensusFor(toolName, mappingNotice) {
  return {
    section: {
      roster: [],
      votes_file: "EDIT-ME/seal-votes.ndjson",
      high_stakes: [toolName],
    },
    note: `consensus: EDIT-ME: empty roster fails closed; configure real member IDs and votes_file. ${mappingNotice}`,
  };
}

function linearFor(toolName, mappingNotice) {
  return {
    section: {
      grants_file: "EDIT-ME/seal-grants.ndjson",
      tools: [{ tool: toolName, cap_arg: "capability.id" }],
    },
    note: `linear: EDIT-ME: configure a real grants_file before use; the placeholder fails closed. EDIT-ME: verify cap_arg against the real tool arguments. ${mappingNotice}`,
  };
}

function convergenceFor(toolName, mappingNotice) {
  return {
    section: {
      tools: [{ tool: toolName, op_arg: "operation.kind" }],
    },
    note: `convergence: EDIT-ME: verify op_arg against the real tool arguments. ${mappingNotice}`,
  };
}

function calibrationFor(toolName, mappingNotice) {
  return {
    section: {
      enabled: true,
      delta_num: 1,
      delta_den: 20,
      min_samples: 100,
      records_file: "EDIT-ME/seal-forecasts.ndjson",
      gated_tools: [toolName],
    },
    note: `calibration: EXPERIMENTAL. EDIT-ME: configure thresholds and records_file before use. ${mappingNotice}`,
  };
}

function referencedTools(policy) {
  const refs = [];
  for (const item of policy.temporal?.policies || []) refs.push(...item.trigger, ...item.forbidden);
  refs.push(...(policy.consensus?.high_stakes || []));
  for (const item of policy.convergence?.tools || []) refs.push(item.tool);
  refs.push(...(policy.calibration?.gated_tools || []));
  for (const item of policy.linear?.tools || []) refs.push(item.tool);
  for (const item of policy.budget?.budgets || []) refs.push(...item.tools);
  return refs;
}

function validateGenerated(policy, manifest, expectedActive, { allowCalibration = false } = {}) {
  const shape = validateTrustedConfig(policy);
  if (!shape.ok) throw new Error(`generated policy failed TrustedConfig validation: ${shape.errors.join("; ")}`);
  const actual = shape.participation.active.map((entry) => entry.symbol).sort();
  const expected = [...expectedActive].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    throw new Error(`generated ACTIVE set mismatch: got {${actual}}, expected {${expected}}`);
  if (shape.participation.inactive.length)
    throw new Error(`generated policy contains vacuous section(s): ${shape.participation.inactive.map((entry) => entry.symbol).join(", ")}`);
  if (!allowCalibration && Object.prototype.hasOwnProperty.call(policy, "calibration"))
    throw new Error("recipes must not emit experimental Calibration (K)");
  const names = new Set(manifest.tools.map((tool) => tool.name));
  const missing = referencedTools(policy).filter((name) => !names.has(name));
  if (missing.length) throw new Error(`generated kernel reference is not a real manifest tool: ${missing.join(", ")}`);
  return shape.participation;
}

function applyRecipe(manifest, recipeName) {
  if (!Object.prototype.hasOwnProperty.call(RECIPE_ACTIVE, recipeName))
    throw new Error(`unknown recipe ${JSON.stringify(recipeName)} (known: ${Object.keys(RECIPE_ACTIVE).join(", ")})`);
  const context = recipeContext(manifest);
  const policy = context.policy;
  const guardedNames = context.guarded.map((tool) => tool.name);

  if (recipeName === "prod-db") {
    const temporal = temporalFor(guardedNames);
    const budget = budgetFor(guardedNames, { name: "prod-db-destructive-calls" });
    policy.temporal = temporal.section;
    policy.budget = budget.section;
    noteOnSafetyRules(policy, guardedNames, temporal.note);
    noteOnSafetyRules(policy, guardedNames, budget.note);
  } else if (recipeName === "deploy") {
    const deploy = selectRole(context, "deploy");
    const rollback = selectRole(context, "rollback");
    const deployMapping = context.mappings.find((entry) => entry.role === "deploy");
    const rollbackMapping = context.mappings.find((entry) => entry.role === "rollback");
    markSafetyRole(policy, rollback, "rollback", rollbackMapping.notice);
    const consensus = consensusFor(deploy, deployMapping.notice);
    const linear = linearFor(deploy, deployMapping.notice);
    policy.consensus = consensus.section;
    policy.linear = linear.section;
    noteOnSafetyRules(policy, [deploy], consensus.note);
    noteOnSafetyRules(policy, [deploy], linear.note);
  } else if (recipeName === "token-governor") {
    const token = selectRole(context, "token");
    const payment = selectRole(context, "payment");
    const tokenMapping = context.mappings.find((entry) => entry.role === "token");
    const paymentMapping = context.mappings.find((entry) => entry.role === "payment");
    markSafetyRole(policy, payment, "payment", paymentMapping.notice);
    const budget = budgetFor([token], { name: "token-usage", costArg: "usage.tokens" });
    policy.budget = budget.section;
    noteOnSafetyRules(policy, [token], `${budget.note} ${tokenMapping.notice}`);
  } else if (recipeName === "mesh") {
    const shared = selectRole(context, "shared");
    const publish = selectRole(context, "publish");
    const sharedMapping = context.mappings.find((entry) => entry.role === "shared");
    const publishMapping = context.mappings.find((entry) => entry.role === "publish");
    markSafetyRole(policy, publish, "publish", publishMapping.notice);
    const convergence = convergenceFor(shared, sharedMapping.notice);
    policy.convergence = convergence.section;
    noteOnSafetyRules(policy, [shared], convergence.note);
  }

  const participation = validateGenerated(policy, manifest, RECIPE_ACTIVE[recipeName]);
  return { policy, participation, mappings: context.mappings, notices: context.notices };
}

function kernelFragment(context, symbol) {
  const guardedNames = context.guarded.map((tool) => tool.name);
  if (symbol === "S") return { section: clone(context.policy.safety), note: null, noteTools: [] };
  if (symbol === "T") return { ...temporalFor(guardedNames), noteTools: guardedNames };
  if (symbol === "B") return { ...budgetFor(guardedNames, { name: "guarded-call-budget" }), noteTools: guardedNames };
  if (symbol === "C" || symbol === "L") {
    const tool = selectRole(context, "deploy");
    const mapping = context.mappings.at(-1);
    const made = symbol === "C" ? consensusFor(tool, mapping.notice) : linearFor(tool, mapping.notice);
    return { ...made, noteTools: [tool] };
  }
  if (symbol === "V") {
    const tool = selectRole(context, "shared");
    return { ...convergenceFor(tool, context.mappings.at(-1).notice), noteTools: [tool] };
  }
  if (symbol === "K") {
    const tool = context.guarded[0].name;
    const notice = `EDIT-ME: best-fit mapping: role 'calibration-gated' → tool '${tool}'. Review whether this experimental kernel suits this server at all.`;
    context.notices.push(notice);
    return { ...calibrationFor(tool, notice), noteTools: [tool] };
  }
  throw new Error(`unknown kernel ${JSON.stringify(symbol)} (known: S, T, C, V, L, B; K requires --experimental)`);
}

function addKernelToPolicy(policy, manifest, symbol, { experimental = false } = {}) {
  if (!isObject(policy)) throw new Error("policy must be a JSON object");
  const normalized = String(symbol || "").toUpperCase();
  if (!SECTION_FOR[normalized])
    throw new Error(`unknown kernel ${JSON.stringify(symbol)} (known: S, T, C, V, L, B; K requires --experimental)`);
  if (normalized === "K" && !experimental)
    throw new Error("EXPERIMENTAL K REFUSED: rerun with --experimental only after reviewing its non-claims");
  const section = SECTION_FOR[normalized];
  if (Object.prototype.hasOwnProperty.call(policy, section))
    throw new Error(`${section} (${normalized}) is already present; refusing to overwrite existing policy edits`);
  if (typeof policy.server === "string" && policy.server !== manifest.server)
    throw new Error(`server identity mismatch: manifest=${manifest.server} policy=${policy.server}`);
  if (normalized !== "S") {
    const before = validateTrustedConfig(policy);
    if (!before.ok) throw new Error(`existing policy failed TrustedConfig validation: ${before.errors.join("; ")}`);
  }

  const context = recipeContext(manifest);
  const result = clone(policy);
  if (!Object.prototype.hasOwnProperty.call(result, "server")) result.server = manifest.server;
  const fragment = kernelFragment(context, normalized);
  result[section] = fragment.section;
  if (fragment.note) noteOnSafetyRules(result, fragment.noteTools, fragment.note);
  const shape = validateTrustedConfig(result);
  if (!shape.ok) throw new Error(`updated policy failed TrustedConfig validation: ${shape.errors.join("; ")}`);
  const newState = shape.participation.states.find((entry) => entry.symbol === normalized);
  if (!newState || newState.status !== "active")
    throw new Error(`added kernel ${normalized} is not effectively ACTIVE`);
  const names = new Set(manifest.tools.map((tool) => tool.name));
  const missing = referencedTools(result).filter((name) => !names.has(name));
  if (missing.length) throw new Error(`kernel reference is not a real manifest tool: ${missing.join(", ")}`);
  return { policy: result, participation: shape.participation, notices: context.notices, section };
}

module.exports = {
  RECIPE_ACTIVE,
  addKernelToPolicy,
  applyRecipe,
  referencedTools,
  validateGenerated,
};
