// SPDX-License-Identifier: Apache-2.0
// Regression tests for finite witness refinement, collisions, vacuous samples,
// and fail-closed missing monitor evidence.
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const os = require("os");
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

// Independent oracle: match the original bucket / i / j enumeration.
const generated = fs.mkdtempSync(path.join(os.tmpdir(), "seal-adequacy-"));
try {
  const doc = { monitors: ["m"], states: [] };
  for (const [bucket, labels] of [
    ["z", ["a", "a", "b", "c", "a", "b"]],
    ["a", ["c", "b", "b", "b", "a"]],
    ["m", ["b", "b", "a", "c", "c", "c", "c"]],
  ]) {
    for (const label of labels) {
      doc.states.push({ id: `s${doc.states.length}`, label, evidence: { m: bucket } });
    }
  }
  const file = path.join(generated, "uneven.json");
  fs.writeFileSync(file, JSON.stringify(doc));
  const buckets = new Map();
  for (const state of doc.states) {
    const key = state.evidence.m;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(state);
  }
  let bruteCount = 0;
  let first;
  let formulaCount = 0;
  for (const states of buckets.values()) {
    const counts = new Map();
    for (const state of states) counts.set(state.label, (counts.get(state.label) || 0) + 1);
    formulaCount += states.length * (states.length - 1) / 2;
    for (const n of counts.values()) formulaCount -= n * (n - 1) / 2;
    for (let i = 0; i < states.length; i++) {
      for (let j = i + 1; j < states.length; j++) {
        if (states[i].label !== states[j].label) {
          bruteCount++;
          if (!first) first = `  collision: ${states[i].id} vs ${states[j].id}`;
        }
      }
    }
  }
  assert.strictEqual(bruteCount, formulaCount, "generated count: independent formula");
  for (const mode of ["check", "find-collision"]) {
    const r = run(["adequacy", mode, file]);
    assert.strictEqual(r.status, 1, `generated count (${mode}): ${r.stderr}`);
    const count = r.stdout.match(/FAIL  (\d+) collision\(s\)/);
    assert(count, `generated count (${mode}): missing count`);
    assert.strictEqual(Number(count[1]), bruteCount, `generated count (${mode})`);
    const pairs = r.stdout.split("\n").filter((line) => line.startsWith("  collision:"));
    assert.strictEqual(pairs[0], first, `generated first pair (${mode})`);
    assert.strictEqual(pairs.length, mode === "check" ? bruteCount : 1, `generated displayed pairs (${mode})`);
  }
  console.log("PASS generated count and first pair (both modes)");

  const large = path.join(generated, "large.json");
  fs.writeFileSync(large, JSON.stringify({
    monitors: ["m"],
    states: Array.from({ length: 6000 }, (_, i) => ({ id: `s${i}`, label: i % 2, evidence: { m: 1 } })),
  }));
  const r = spawnSync(process.execPath, ["--max-old-space-size=128", seal, "adequacy", "find-collision", large], {
    cwd: root, encoding: "utf8", timeout: 30000,
  });
  assert.strictEqual(r.status, 1, `memory guard: status=${r.status} signal=${r.signal} error=${r.error} ${r.stderr}`);
  assert(r.stdout.includes("FAIL  9000000 collision(s)"), "memory guard: expected 9000000 collisions");
  console.log("PASS memory guard (6000 states, 128 MiB heap)");
} finally {
  fs.rmSync(generated, { recursive: true, force: true });
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
