// SPDX-License-Identifier: Apache-2.0
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { RECIPE_ACTIVE, referencedTools } = require("../src/recipes.cjs");
const { validateTrustedConfig } = require("../src/trusted-config.cjs");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "seal");
const MANIFEST_ROOT = path.join(__dirname, "fixtures", "manifests");
const MANIFESTS = [
  "dbhub-0.23.0.tools.json",
  "filesystem-2026.7.10.tools.json",
  "github-mcp-v1.0.5.tools.json",
];

function run(args, expected = 0) {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, expected, `${args.join(" ")} exited ${result.status}:\n${output}`);
  return output;
}

function activeSymbols(output) {
  const block = output.match(/ACTIVE \(\d+\):\n([\s\S]*?)\n\s*PRESENT-BUT-INACTIVE/);
  assert.ok(block, `ACTIVE block missing:\n${output}`);
  return [...block[1].matchAll(/\(([STCVKLB])(?:, EXPERIMENTAL)?\)/g)]
    .map((match) => match[1]).sort();
}

function assertGeneratedPolicy(policy, manifest, expected) {
  const shape = validateTrustedConfig(policy);
  assert.equal(shape.ok, true, shape.errors.join("; "));
  assert.deepEqual(shape.participation.active.map((entry) => entry.symbol).sort(), [...expected].sort());
  assert.deepEqual(shape.participation.inactive, []);
  assert.equal(Object.prototype.hasOwnProperty.call(policy, "calibration"), false, "recipe emitted K");
  const names = new Set(manifest.tools.map((tool) => tool.name));
  for (const name of referencedTools(policy)) assert.equal(names.has(name), true, `non-manifest kernel reference: ${name}`);
  assert.match(JSON.stringify(policy), /EDIT-ME/, "recipe omitted visible placeholders/review markers");
}

for (const [recipe, expected] of Object.entries(RECIPE_ACTIVE)) {
  for (const filename of MANIFESTS) {
    test(`${recipe} × ${filename}: non-vacuous, sign-ack/scan agree, K absent`, () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-recipe-"));
      const manifestPath = path.join(MANIFEST_ROOT, filename);
      const policyPath = path.join(dir, "policy.json");
      const keyPath = path.join(dir, "key");
      const signedPath = path.join(dir, "trusted.json");
      fs.writeFileSync(keyPath, "07".repeat(32));

      const init = run(["init", "--recipe", recipe, manifestPath, "--out", policyPath]);
      assert.match(init, new RegExp(`recipe ${recipe.replaceAll("-", "\\-")}  ACTIVE`));
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
      assertGeneratedPolicy(policy, manifest, expected);

      const sign = run(["policy", "sign", policyPath, "--key", keyPath, "--out", signedPath, "--yes"]);
      const scan = run(["scan", manifestPath, policyPath]);
      assert.deepEqual(activeSymbols(sign), [...expected].sort());
      assert.deepEqual(activeSymbols(scan), [...expected].sort());
      assert.match(sign, /PRESENT-BUT-INACTIVE \(0\)/);
      assert.match(scan, /PRESENT-BUT-INACTIVE \(0\)/);
      assert.match(scan, /PASS  0 uncovered, 0 ungated/);
      assert.equal(fs.existsSync(signedPath), true);

      for (const line of init.split("\n").filter((entry) => entry.includes("best-fit mapping")))
        assert.match(line, /Review whether this recipe suits this server at all/);
      if (recipe === "deploy" && filename.startsWith("dbhub"))
        assert.match(init, /best-fit mapping: role 'deploy' → tool 'execute_sql'.*Review whether this recipe suits this server at all/);
      console.log(`PASS ${recipe} × ${filename}: ACTIVE {${[...expected].sort()}}; no vacuity; K absent`);
    });
  }
}

test("add-kernel supports derived sibling and explicit --policy without overwriting sections", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-add-kernel-"));
  const source = path.join(MANIFEST_ROOT, MANIFESTS[0]);
  const manifest = path.join(dir, "dbhub.tools.json");
  fs.copyFileSync(source, manifest);
  run(["init", manifest]);
  const derived = path.join(dir, "dbhub.policy.json");
  run(["add-kernel", "B", manifest]);
  let shape = validateTrustedConfig(JSON.parse(fs.readFileSync(derived, "utf8")));
  assert.deepEqual(shape.participation.active.map((entry) => entry.symbol).sort(), ["B", "S"]);

  const custom = path.join(dir, "moved.json");
  run(["init", manifest, "--out", custom]);
  run(["add-kernel", "V", manifest, "--policy", custom]);
  const beforeDuplicate = fs.readFileSync(custom);
  const duplicate = run(["add-kernel", "V", manifest, "--policy", custom], 1);
  assert.match(duplicate, /refusing to overwrite existing policy edits/);
  assert.deepEqual(fs.readFileSync(custom), beforeDuplicate);
  shape = validateTrustedConfig(JSON.parse(beforeDuplicate));
  assert.deepEqual(shape.participation.active.map((entry) => entry.symbol).sort(), ["S", "V"]);
});

test("Calibration K is refused without --experimental and bytes stay unchanged", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-add-k-"));
  const manifest = path.join(MANIFEST_ROOT, MANIFESTS[0]);
  const policy = path.join(dir, "policy.json");
  run(["init", manifest, "--out", policy]);
  const before = fs.readFileSync(policy);
  const refused = run(["add-kernel", "K", manifest, "--policy", policy], 1);
  assert.match(refused, /EXPERIMENTAL K REFUSED/);
  assert.deepEqual(fs.readFileSync(policy), before);

  const accepted = run(["add-kernel", "K", manifest, "--policy", policy, "--experimental"]);
  assert.match(accepted, /CALIBRATION \(K\) IS EXPERIMENTAL/);
  const shape = validateTrustedConfig(JSON.parse(fs.readFileSync(policy, "utf8")));
  assert.equal(shape.ok, true, shape.errors.join("; "));
  assert.equal(shape.participation.active.some((entry) => entry.symbol === "K"), true);
  assert.deepEqual(shape.participation.inactive, []);
});
