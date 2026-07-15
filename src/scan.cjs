// SPDX-License-Identifier: Apache-2.0
// `seal scan <tools.json> <policy.json>` — MCP policy coverage auditor.
// `seal scan diff <old-tools.json> <new-tools.json> <policy.json>`
//
// Answers the question every agent-platform buyer actually has: of the tools this
// server exposes, which can mutate state, which are guarded, which are denied, and
// which are UNCOVERED (effectful with no policy). Effect is read from MCP tool
// annotations when present, else inferred from a verb heuristic; unknown effect is
// treated as mutating (fail-safe). Exits non-zero if any mutating tool is uncovered,
// so it drops straight into CI.
const fs = require("fs");
const path = require("path");
const { formatParticipation, validateTrustedConfig } = require("./trusted-config.cjs");

const MUTATING_VERBS = /\b(write|delete|remove|drop|send|pay|transfer|execute|exec|run|create|insert|update|patch|put|post|issue|revoke|mint|grant|set|modify|destroy|purge|deploy|publish|approve|move|rename)\b/i;
const READONLY_VERBS = /\b(read|get|list|query|search|fetch|show|view|describe|inspect|status|count)\b/i;

function readJson(p) { return JSON.parse(fs.readFileSync(p, "utf8")); }
function toolList(doc) { return Array.isArray(doc) ? doc : (doc.tools || []); }

function isV2Policy(policy) {
  return policy && policy.safety && Array.isArray(policy.safety.tools);
}

function v2RulesFor(name, policy) {
  return (policy.safety.tools || []).filter((rule) => rule && rule.name === name);
}

function v2CatchAllMode(name, policy) {
  const modes = v2RulesFor(name, policy)
    .filter((rule) => !rule.match || rule.match.type === "always")
    .map((rule) => rule.mode === "guarded" ? "guard" : rule.mode);
  if (modes.includes("deny")) return "deny";
  if (modes.includes("guard")) return "guard";
  if (modes.includes("allow")) return "allow";
  return null;
}

function v2ConditionalModes(name, policy) {
  return v2RulesFor(name, policy)
    .filter((rule) => rule.match && rule.match.type !== "always")
    .map((rule) => rule.mode === "guarded" ? "guard" : rule.mode);
}

// mutating | readonly  — annotations win, then policy-declared effect, then heuristic.
function effectOf(tool, rule) {
  const a = tool.annotations || {};
  if (a.readOnlyHint === true) return "readonly";
  if (a.destructiveHint === true || a.idempotentHint === false) return "mutating";
  if (rule && rule.effect) return rule.effect;
  const text = `${tool.name} ${tool.description || ""}`;
  if (MUTATING_VERBS.test(text)) return "mutating";
  if (READONLY_VERBS.test(text)) return "readonly";
  return "mutating"; // unknown => fail-safe: must be covered
}

// exact match wins; else longest matching "prefix.*" glob.
function ruleFor(name, rules) {
  if (rules[name]) return rules[name];
  let best = null, bestLen = -1;
  for (const key of Object.keys(rules)) {
    if (key.endsWith("*") && name.startsWith(key.slice(0, -1)) && key.length > bestLen) {
      best = rules[key]; bestLen = key.length;
    }
  }
  return best;
}

function classify(tool, policy) {
  if (isV2Policy(policy)) {
    const effect = effectOf(tool, null);
    const guard = v2CatchAllMode(tool.name, policy);
    if (!guard) {
      const conditional = v2ConditionalModes(tool.name, policy);
      if (conditional.includes("guard")) return { bucket: "guarded", effect, guard: "guard (conditional; no-match denies)" };
      if (conditional.includes("deny") && !conditional.includes("allow")) return { bucket: "denied", effect, guard: "deny (conditional; no-match denies)" };
      if (conditional.includes("allow")) return {
        bucket: effect === "mutating" ? "allowed-ungated" : "readonly",
        effect,
        guard: "allow (conditional; no-match denies)",
      };
      return { bucket: "uncovered", effect, guard: null };
    }
    if (guard === "deny") return { bucket: "denied", effect, guard };
    if (guard === "guard") return { bucket: "guarded", effect, guard };
    return { bucket: effect === "mutating" ? "allowed-ungated" : "readonly", effect, guard };
  }
  const rule = ruleFor(tool.name, policy.rules || {});
  const effect = effectOf(tool, rule);
  if (!rule) return { bucket: effect === "mutating" ? "uncovered" : "readonly", effect, guard: null };
  const guard = rule.guard || "allow";
  if (guard === "deny") return { bucket: "denied", effect, guard };
  if (guard === "allow") return { bucket: effect === "mutating" ? "allowed-ungated" : "readonly", effect, guard };
  return { bucket: "guarded", effect, guard };
}

function validateAndShowComposition(policy) {
  const shape = validateTrustedConfig(policy);
  if (!shape.ok) {
    console.log("FAIL  TRUSTED CONFIG INVALID:");
    for (const error of shape.errors) console.log(`  ${error}`);
    return null;
  }
  console.log("\nEFFECTIVE KERNEL PARTICIPATION (signed payload):");
  for (const line of formatParticipation(shape.participation)) console.log(`  ${line}`);
  return shape.participation;
}

function scan(toolsPath, policyPath) {
  const toolDoc = readJson(toolsPath);
  const tools = toolList(toolDoc);
  const policy = readJson(policyPath);
  if (!validateAndShowComposition(policy)) return false;
  const buckets = { guarded: [], denied: [], "allowed-ungated": [], uncovered: [], readonly: [] };
  for (const t of tools) {
    const c = classify(t, policy);
    buckets[c.bucket].push({ name: t.name, guard: c.guard, effect: c.effect });
  }
  const manifestNames = new Set(tools.map((tool) => tool.name));
  const orphanAllows = isV2Policy(policy)
    ? policy.safety.tools.filter((rule) => rule.mode === "allow" && !manifestNames.has(rule.name))
    : [];
  const serverMismatch = isV2Policy(policy) && typeof toolDoc.server === "string" &&
    typeof policy.server === "string" && toolDoc.server !== policy.server;
  const show = (label, arr, fmt = (x) => x.name) => {
    if (!arr.length) return;
    console.log(`\n${label} (${arr.length}):`);
    for (const x of arr) console.log(`  ${fmt(x)}`);
  };
  console.log(`seal scan  ${toolsPath}  x  ${policyPath}   (${tools.length} tools)`);
  show("GUARDED", buckets.guarded, (x) => `${x.name}  [${x.guard}]`);
  show("DENIED", buckets.denied);
  show("readonly (informational)", buckets.readonly, (x) => `${x.name}${x.guard ? `  [${x.guard}]` : ""}`);
  show("WARN  allowed but ungated (mutating, guard=allow)", buckets["allowed-ungated"]);
  show("FAIL  UNCOVERED tools", buckets.uncovered);
  show("FAIL  ORPHAN explicit ALLOW rules", orphanAllows, (rule) => rule.name);
  if (serverMismatch) console.log(`\nFAIL  server identity mismatch: manifest=${toolDoc.server} policy=${policy.server}`);
  const nUncovered = buckets.uncovered.length, nWarn = buckets["allowed-ungated"].length;
  const failed = nUncovered > 0 || nWarn > 0 || orphanAllows.length > 0 || serverMismatch;
  console.log(`\n  ${failed ? "FAIL" : "PASS"}  ${nUncovered} uncovered, ${nWarn} ungated, ` +
    `${buckets.guarded.length} guarded, ${buckets.denied.length} denied, ${buckets.readonly.length} read-only`);
  if (isV2Policy(policy)) {
    // The warrant reads its provenance from the pin so this line can never
    // drift from what is actually checked: JS↔pin runs on every kit test
    // run (test/scan-pin.test.cjs); Lean↔pin runs in mcp-seal-dev CI (the
    // scan-bridge step). If the pin is unreadable, claim NOTHING.
    try {
      const pin = JSON.parse(fs.readFileSync(
        path.resolve(__dirname, "../fixtures/scan-lean-oracle.json"), "utf8"));
      console.log(`  warrant: JS scan agrees with the pinned Lean scan_oracle verdicts (scan_pass_sound; mcp-seal-dev @${pin.provenance.commit.slice(0, 12)}, ${pin.provenance.generated}) over corpus C — JS↔pin checked on every kit test run, Lean↔pin checked in mcp-seal-dev CI; differential evidence, not universal verification; annotations + manifest completeness remain assumptions.`);
    } catch {
      console.log("  warrant: NONE — the pinned Lean scan-oracle output (fixtures/scan-lean-oracle.json) is unreadable, so no JS↔Lean binding is claimed. Regenerate it with `SCAN_LEAN_ROOT=<mcp-seal-dev> node scripts/scan_bridge.mjs --write-pin`.");
    }
  }
  return !failed;
}

function diff(oldPath, newPath, policyPath) {
  const oldNames = new Set(toolList(readJson(oldPath)).map((t) => t.name));
  const newTools = toolList(readJson(newPath));
  const policy = readJson(policyPath);
  if (!validateAndShowComposition(policy)) return false;
  const added = newTools.filter((t) => !oldNames.has(t.name));
  const removed = [...oldNames].filter((n) => !newTools.some((t) => t.name === n));
  console.log(`seal scan diff  ${oldPath} -> ${newPath}`);
  if (added.length) {
    console.log(`\nNEW since last scan (${added.length}):`);
    for (const t of added) {
      const c = classify(t, policy);
      console.log(`  ${t.name}  ->  ${c.bucket}${c.guard ? " [" + c.guard + "]" : ""}`);
    }
  }
  if (removed.length) console.log(`\nREMOVED (${removed.length}):\n  ${removed.join("\n  ")}`);
  const newUncovered = added.filter((t) => classify(t, policy).bucket === "uncovered");
  console.log(`\n  ${newUncovered.length ? "FAIL" : "PASS"}  ${added.length} new, ${removed.length} removed, ` +
    `${newUncovered.length} new-and-uncovered`);
  return newUncovered.length === 0;
}

module.exports = { scan, diff, classify, validateAndShowComposition };
