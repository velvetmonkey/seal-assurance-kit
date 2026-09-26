// SPDX-License-Identifier: Apache-2.0
"use strict";

const fs = require("node:fs");

const { atomicWrite } = require("./atomic-write.cjs");
const { scaffoldReason } = require("./tool-annotations.cjs");

const ALLOW_COMMENT = "unverified suggestion — server self-described readOnly";

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function defaultOutputPath(manifestPath) {
  if (manifestPath.endsWith(".tools.json"))
    return manifestPath.slice(0, -".tools.json".length) + ".policy.json";
  if (manifestPath.endsWith(".json"))
    return manifestPath.slice(0, -".json".length) + ".policy.json";
  return manifestPath + ".policy.json";
}

function scaffoldManifest(manifest) {
  if (!isObject(manifest)) throw new Error("manifest must be a JSON object");
  if (typeof manifest.server !== "string" || !manifest.server)
    throw new Error("manifest.server must be a non-empty string");
  if (!Array.isArray(manifest.tools)) throw new Error("manifest.tools must be an array");

  const names = new Set();
  manifest.tools.forEach((tool, index) => {
    if (!isObject(tool) || typeof tool.name !== "string" || !tool.name)
      throw new Error(`manifest.tools[${index}].name must be a non-empty string`);
    if (names.has(tool.name)) throw new Error(`duplicate tool name: ${tool.name}`);
    names.add(tool.name);
  });

  const tools = manifest.tools.map((tool) => {
    const reason = scaffoldReason(tool);
    const rule = {
      name: tool.name,
      mode: reason === "readonly" ? "allow" : "guard",
      target: [{ full_arguments: true }],
      _seal_scaffold: { reason },
    };
    if (rule.mode === "allow") rule._comment = ALLOW_COMMENT;
    return rule;
  });

  return {
    epoch: 1,
    server: manifest.server,
    safety: {
      approval: { ttl_seconds: 120, control_file: "seal-approvals.jsonl" },
      tools,
    },
  };
}

function initPolicy(manifestPath, { outputPath, recipe, force = false, allowEmpty = false } = {}) {
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")); }
  catch (error) { throw new Error(`cannot read manifest: ${error.message}`); }
  const generated = recipe
    ? require("./recipes.cjs").applyRecipe(manifest, recipe)
    : { policy: scaffoldManifest(manifest), participation: null, mappings: [], notices: [] };
  if (!recipe && manifest.tools.length === 0 && !allowEmpty)
    throw new Error(`refusing manifest ${manifestPath}: policy would gate no tool; use --allow-empty to request an empty policy`);
  const policy = generated.policy;
  const output = outputPath || defaultOutputPath(manifestPath);
  try {
    atomicWrite(output, JSON.stringify(policy, null, 2) + "\n", { mode: 0o600, force });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`refusing to overwrite ${output}; use --force to replace it`);
    throw error;
  }
  const unverifiedAllows = policy.safety.tools
    .filter((rule) => rule.mode === "allow")
    .map((rule) => rule.name);
  return { output, policy, unverifiedAllows, recipe, ...generated };
}

function addKernel(manifestPath, symbol, { policyPath, experimental = false } = {}) {
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")); }
  catch (error) { throw new Error(`cannot read manifest: ${error.message}`); }
  scaffoldManifest(manifest);
  const target = policyPath || defaultOutputPath(manifestPath);
  let policy;
  try { policy = JSON.parse(fs.readFileSync(target, "utf8")); }
  catch (error) { throw new Error(`cannot read existing policy ${target}: ${error.message}`); }
  const result = require("./recipes.cjs").addKernelToPolicy(policy, manifest, symbol, { experimental });
  atomicWrite(target, JSON.stringify(result.policy, null, 2) + "\n", { mode: 0o600, force: true });
  return { output: target, symbol: String(symbol).toUpperCase(), ...result };
}

module.exports = { ALLOW_COMMENT, addKernel, defaultOutputPath, initPolicy, scaffoldManifest };
