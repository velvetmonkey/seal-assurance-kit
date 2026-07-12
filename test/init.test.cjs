// SPDX-License-Identifier: Apache-2.0
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { ALLOW_COMMENT } = require("../src/init.cjs");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "seal");
const LEAN_ROOT = path.resolve(process.env.SEAL_SCAFFOLD_LEAN_ROOT || path.join(ROOT, "..", "mcp-seal-dev"));
const MANIFEST_ROOT = path.resolve(process.env.SEAL_MANIFEST_ROOT || path.join(ROOT, "..", "seal-host", "profiles", "manifests"));
const MANIFESTS = [
  "dbhub-0.23.0.tools.json",
  "filesystem-2026.7.10.tools.json",
  "github-mcp-v1.0.5.tools.json",
];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, 0, `${command} ${args.join(" ")} failed (${result.status}):\n${output}`);
  return output;
}

function leanString(value) { return JSON.stringify(value); }
function leanOption(value) {
  return value === undefined ? "none" : `some ${value === true ? "true" : "false"}`;
}

function leanProjection(manifest, work) {
  const rows = manifest.tools.map((tool) => {
    const annotations = tool.annotations || {};
    return `  { name := ${leanString(tool.name)}, readOnlyHint := ${leanOption(annotations.readOnlyHint)}, destructiveHint := ${leanOption(annotations.destructiveHint)} }`;
  }).join(",\n");
  const source = `import Seal.Scaffold

open Seal

private def manifest : Seal.Manifest := [
${rows}
]

private def modeText : ToolMode → String
  | .allow => "allow"
  | .guarded => "guard"
  | .deny => "deny"

private def targetText : List TargetPart → String
  | [.fullArguments] => "full_arguments"
  | [] => "none"
  | _ => "other"

def main : IO Unit := do
  let policy := Seal.scaffold ${leanString(manifest.server)} 120000 "seal-approvals.jsonl" manifest
  IO.println s!"META\\t{policy.serverIdentity}\\t{policy.approvalTtlMs}\\t{policy.approvalFile}"
  for rule in policy.tools do
    IO.println s!"TOOL\\t{rule.name}\\t{modeText rule.mode}\\t{targetText rule.target}"
`;
  const oracle = path.join(work, "ScaffoldOracle.lean");
  fs.writeFileSync(oracle, source);
  const output = run("lake", ["env", "lean", "--run", oracle], { cwd: LEAN_ROOT });
  const lines = output.trim().split("\n").filter((line) => line.startsWith("META\t") || line.startsWith("TOOL\t"));
  const meta = lines.find((line) => line.startsWith("META\t")).split("\t");
  return {
    server: meta[1],
    ttlMs: Number(meta[2]),
    approvalFile: meta[3],
    tools: lines.filter((line) => line.startsWith("TOOL\t")).map((line) => {
      const [, name, mode, target] = line.split("\t");
      return { name, mode, target };
    }),
  };
}

function jsProjection(policy) {
  return {
    server: policy.server,
    ttlMs: policy.safety.approval.ttl_seconds * 1000,
    approvalFile: policy.safety.approval.control_file,
    tools: policy.safety.tools.map((rule) => ({
      name: rule.name,
      mode: rule.mode,
      target: rule.target?.[0]?.full_arguments === true ? "full_arguments" : "none",
    })),
  };
}

for (const filename of MANIFESTS) {
  test(`${filename}: seal init is scan-clean, labelled, and JS ≡ Lean scaffold`, () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "seal-init-"));
    const source = path.join(MANIFEST_ROOT, filename);
    const copied = path.join(work, filename);
    fs.copyFileSync(source, copied);
    const initOutput = run(process.execPath, [CLI, "init", copied]);
    const policyPath = copied.replace(/\.tools\.json$/, ".policy.json");
    assert.match(initOutput, /unverified suggestion\(s\) — server self-described readOnly/);
    assert.equal(fs.existsSync(policyPath), true, "derived .policy.json was not written");

    const manifest = JSON.parse(fs.readFileSync(source, "utf8"));
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    assert.deepEqual(jsProjection(policy), leanProjection(manifest, work));
    assert.deepEqual(policy.safety.tools.map((rule) => rule.name), manifest.tools.map((tool) => tool.name));
    assert.equal(policy.safety.tools.some((rule) => rule.name.includes("*")), false);
    assert.equal(policy.safety.tools.some((rule) => rule.mode === "deny"), false);
    for (const rule of policy.safety.tools.filter((candidate) => candidate.mode === "allow"))
      assert.equal(rule._comment, ALLOW_COMMENT);

    const scanOutput = run(process.execPath, [CLI, "scan", source, policyPath]);
    assert.match(scanOutput, /PASS  0 uncovered, 0 ungated/);
    console.log(`PASS ${filename}: JS ≡ Lean; allow rows labelled; scan clean`);
  });
}
