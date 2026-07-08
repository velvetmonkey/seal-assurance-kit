#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Differential JS↔Lean adequacy bridge.
//
// Evidence over corpus C only: compare the shipping JS CLI against the Lean
// `decide` oracle anchored by witness_computable_iff_refines. This is not a
// universal proof of the JS implementation.

import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ATTENTION_LEAN_ROOT = process.env.ATTENTION_LEAN_ROOT;
if (!ATTENTION_LEAN_ROOT) {
  console.error("set ATTENTION_LEAN_ROOT to your attention-lean checkout (it must build `lake exe adequacy_oracle`)");
  console.error("example: ATTENTION_LEAN_ROOT=~/src/attention-lean npm run test:adequacy-bridge");
  process.exit(2);
}
const FIXTURES = [
  "fixtures/adequacy-pass.json",
  "fixtures/adequacy-vacuous.json",
  "fixtures/adequacy-fail.json",
  "fixtures/adequacy-malformed-missing-monitor.json",
  "fixtures/adequacy-numeric.json",
];

let failed = false;
const ok = (msg) => console.log(`  PASS  ${msg}`);
const fail = (msg) => { console.error(`  FAIL  ${msg}`); failed = true; };

function run(cmd, args, cwd) {
  return spawnSync(cmd, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
}

function verdictOf(output) {
  if (/FAIL\s+malformed|FAIL malformed|malformed input/i.test(output)) return "FAIL_MALFORMED";
  if (/\bWARN\b/.test(output)) return "WARN";
  if (/\bFAIL\b/.test(output)) return "FAIL";
  if (/\bPASS\b/.test(output)) return "PASS";
  return "UNKNOWN";
}

function collisionPairs(output) {
  const pairs = new Set();
  const re = /^\s*collision:\s+(.+?)\s+vs\s+(.+?)\s*$/gm;
  let m;
  while ((m = re.exec(output)) !== null) {
    const ids = [m[1], m[2]].sort();
    pairs.add(`${ids[0]}\u0000${ids[1]}`);
  }
  return pairs;
}

function sameSet(a, b) {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

function formatSet(s) {
  return [...s].map((x) => x.replace("\u0000", " vs ")).join(", ") || "<none>";
}

console.log("===============================================================");
console.log(" JS↔Lean adequacy bridge  (differential evidence over corpus C)");
console.log("===============================================================");
console.log(`kit: ${ROOT}`);
console.log(`attention-lean: ${ATTENTION_LEAN_ROOT}`);
console.log(`corpus C: ${FIXTURES.length} adequacy fixtures`);

for (const fixture of FIXTURES) {
  const path = join(ROOT, fixture);
  const js = run(process.execPath, ["bin/seal", "adequacy", "check", path], ROOT);
  const lean = run("lake", ["exe", "adequacy_oracle", path], ATTENTION_LEAN_ROOT);
  const jsOut = `${js.stdout || ""}${js.stderr || ""}`;
  const leanOut = `${lean.stdout || ""}${lean.stderr || ""}`;
  const jsVerdict = verdictOf(jsOut);
  const leanVerdict = verdictOf(leanOut);

  console.log(`\n${fixture}`);
  if (js.status !== lean.status) {
    fail(`exit diverged: JS=${js.status} Lean=${lean.status}`);
  }
  if (jsVerdict !== leanVerdict) {
    fail(`verdict diverged: JS=${jsVerdict} Lean=${leanVerdict}`);
  }
  if (jsVerdict === "FAIL" || leanVerdict === "FAIL") {
    const jsPairs = collisionPairs(jsOut);
    const leanPairs = collisionPairs(leanOut);
    if (!sameSet(jsPairs, leanPairs)) {
      fail(`collision set diverged: JS={${formatSet(jsPairs)}} Lean={${formatSet(leanPairs)}}`);
    }
  }
  if (js.status === lean.status && jsVerdict === leanVerdict &&
      (jsVerdict !== "FAIL" || sameSet(collisionPairs(jsOut), collisionPairs(leanOut)))) {
    ok(`${jsVerdict} exit=${js.status}`);
  }
}

console.log("\n===============================================================");
if (failed) {
  console.log(" ADEQUACY BRIDGE: FAIL — a divergence was detected.");
  process.exit(1);
}
console.log(" ADEQUACY BRIDGE: PASS");
console.log("   • JS CLI and Lean decide-oracle agree on corpus C");
console.log("   • evidence is finite-corpus differential checking, not JS formal verification");
