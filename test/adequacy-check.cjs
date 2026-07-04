// SPDX-License-Identifier: Apache-2.0
// Regression tests for finite witness refinement, collisions, vacuous samples,
// and fail-closed missing monitor evidence.
const assert = require("assert");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const seal = path.join(root, "bin", "seal");

function run(args) {
  return spawnSync(process.execPath, [seal, ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

function includes(out, needle) {
  assert(out.includes(needle), `expected output to include ${JSON.stringify(needle)}\n--- output ---\n${out}`);
}

{
  const r = run(["adequacy", "check", "fixtures/adequacy-pass.json"]);
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  includes(r.stdout, "PASS  ADEQUATE over observed finite sample");
  includes(r.stdout, "scope: finite supplied sample only; PASS is not universal adequacy over all traces");
  includes(r.stdout, "certificate:");
}

{
  const r = run(["adequacy", "check", "fixtures/adequacy-fail.json"]);
  assert.strictEqual(r.status, 1, r.stdout + r.stderr);
  includes(r.stdout, "FAIL  monitor evidence does not refine labels over the observed finite sample");
  includes(r.stdout, "collision: deploy-staging vs deploy-prod");
  includes(r.stdout, "labels: \"allow\" vs \"block\"");
  includes(r.stdout, "shared evidence: risk_score=\"medium\", has_approval=true");
  includes(r.stdout, "missing distinguisher (heuristic): environment");
}

{
  const r = run(["adequacy", "find-collision", "fixtures/adequacy-fail.json"]);
  assert.strictEqual(r.status, 1, r.stdout + r.stderr);
  includes(r.stdout, "seal adequacy find-collision");
  includes(r.stdout, "collision: deploy-staging vs deploy-prod");
}

{
  const r = run(["adequacy", "check", "fixtures/adequacy-vacuous.json"]);
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  includes(r.stdout, "WARN  VACUOUS over observed finite sample");
  includes(r.stdout, "sample does not exercise a policy distinction");
}

{
  const r = run(["adequacy", "check", "fixtures/adequacy-malformed-missing-monitor.json"]);
  assert.strictEqual(r.status, 1, r.stdout + r.stderr);
  includes(r.stdout, "FAIL  malformed input: state \"missing\" evidence missing declared monitor \"has_approval\"");
}

console.log("ALL ADEQUACY CHECKS PASS");
