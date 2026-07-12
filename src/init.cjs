// SPDX-License-Identifier: Apache-2.0
"use strict";

const fs = require("node:fs");
const path = require("node:path");

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

function scaffoldReason(tool) {
  const annotations = isObject(tool.annotations) ? tool.annotations : {};
  if (annotations.readOnlyHint === true && annotations.destructiveHint === true) return "conflict";
  if (annotations.readOnlyHint === true) return "readonly";
  if (annotations.destructiveHint === true) return "destructive";
  return "unknown";
}

function scaffoldManifest(manifest) {
  if (!isObject(manifest)) throw new Error("manifest must be a JSON object");
  if (typeof manifest.server !== "string" || !manifest.server)
    throw new Error("manifest.server must be a non-empty string");
  if (!Array.isArray(manifest.tools)) throw new Error("manifest.tools must be an array");

  const tools = manifest.tools.map((tool, index) => {
    if (!isObject(tool) || typeof tool.name !== "string" || !tool.name)
      throw new Error(`manifest.tools[${index}].name must be a non-empty string`);
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

function initPolicy(manifestPath, { outputPath } = {}) {
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")); }
  catch (error) { throw new Error(`cannot read manifest: ${error.message}`); }
  const policy = scaffoldManifest(manifest);
  const output = outputPath || defaultOutputPath(manifestPath);
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, JSON.stringify(policy, null, 2) + "\n", { mode: 0o600 });
  const unverifiedAllows = policy.safety.tools
    .filter((rule) => rule.mode === "allow")
    .map((rule) => rule.name);
  return { output, policy, unverifiedAllows };
}

module.exports = { ALLOW_COMMENT, defaultOutputPath, initPolicy, scaffoldManifest };
