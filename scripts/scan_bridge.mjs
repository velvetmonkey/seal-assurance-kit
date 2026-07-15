#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Differential JS↔Lean scan bridge.
//
// Evidence over corpus C only: compare the shipping JS scanner with Lean
// `scanPass`, which is covered by `scan_pass_sound`. This is finite-corpus
// differential evidence, not universal verification of the JS implementation.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCAN_LEAN_ROOT = process.env.SCAN_LEAN_ROOT;
if (!SCAN_LEAN_ROOT) {
  console.error("set SCAN_LEAN_ROOT to your mcp-seal-dev checkout (it must build `lake exe scan_oracle`)");
  console.error("example: SCAN_LEAN_ROOT=../mcp-seal-dev node scripts/scan_bridge.mjs");
  process.exit(2);
}

const CORPUS_PATH = join(ROOT, "fixtures", "scan-corpus.json");
const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
const items = corpus.items;
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

function parseLeanResults(output) {
  const results = new Map();
  for (const line of output.split("\n")) {
    if (!line.startsWith("{")) continue;
    const row = JSON.parse(line);
    if (typeof row.name !== "string" || typeof row.scanPass !== "boolean")
      throw new Error(`malformed oracle row: ${line}`);
    if (results.has(row.name)) throw new Error(`duplicate oracle result: ${row.name}`);
    results.set(row.name, row.scanPass);
  }
  return results;
}

console.log("===============================================================");
console.log(" JS↔Lean scan bridge  (differential evidence over corpus C)");
console.log("===============================================================");
console.log(`kit: ${ROOT}`);
console.log(`mcp-seal-dev: ${resolve(SCAN_LEAN_ROOT)}`);
console.log(`corpus C: ${items.length} policy/manifest pairs`);

const lean = run("lake", ["exe", "scan_oracle", CORPUS_PATH], SCAN_LEAN_ROOT);
const leanOutput = `${lean.stdout || ""}${lean.stderr || ""}`;
if (lean.status !== 0) {
  console.error(leanOutput);
  console.error(`SCAN BRIDGE: FAIL — Lean oracle exited ${lean.status}`);
  process.exit(1);
}

let leanResults;
try {
  leanResults = parseLeanResults(leanOutput);
} catch (error) {
  console.error(`SCAN BRIDGE: FAIL — ${error.message}`);
  process.exit(1);
}
if (leanResults.size !== items.length) {
  console.error(`SCAN BRIDGE: FAIL — oracle returned ${leanResults.size}/${items.length} results`);
  process.exit(1);
}

// Pin leg: the checked-in fixtures/scan-lean-oracle.json is the shared
// intermediate of the two automated differential halves (kit CI: JS↔pin;
// mcp-seal-dev CI: this bridge, Lean↔pin). A live run that disagrees with
// the pin means the pin is STALE — regenerate with --write-pin, which also
// stamps provenance (mcp-seal-dev commit + date). Never edit the pin by hand.
const PIN_PATH = join(ROOT, "fixtures", "scan-lean-oracle.json");
if (process.argv.includes("--write-pin")) {
  const commit = run("git", ["rev-parse", "HEAD"], SCAN_LEAN_ROOT).stdout.trim();
  const toolchain = readFileSync(join(resolve(SCAN_LEAN_ROOT), "lean-toolchain"), "utf8").trim();
  const pin = {
    provenance: {
      repo: "velvetmonkey/mcp-seal-dev",
      commit,
      toolchain,
      generated: new Date().toISOString().slice(0, 10),
      command: "lake exe scan_oracle <kit>/fixtures/scan-corpus.json",
      note: "Pinned output of the Lean scan oracle (scanPass, covered by scan_pass_sound) over corpus C. Regenerate ONLY via `SCAN_LEAN_ROOT=<mcp-seal-dev> node scripts/scan_bridge.mjs --write-pin`. Guards: test/scan-pin.test.cjs (JS vs pin, every kit test run), the scan-bridge step in mcp-seal-dev CI (Lean vs pin, every mcp-seal-dev run), and the bridge's pin-freshness assertion on any manual run.",
    },
    rows: items.map((item) => ({ name: item.name, scanPass: leanResults.get(item.name) })),
  };
  writeFileSync(PIN_PATH, JSON.stringify(pin, null, 2) + "\n");
  console.log(`pin written: ${PIN_PATH} (mcp-seal-dev @ ${commit.slice(0, 12)})`);
} else {
  let pin;
  try {
    pin = JSON.parse(readFileSync(PIN_PATH, "utf8"));
  } catch (error) {
    fail(`pin unreadable (${error.message}) — regenerate with --write-pin`);
  }
  if (pin) {
    const pinned = new Map(pin.rows.map((r) => [r.name, r.scanPass]));
    for (const item of items) {
      if (pinned.get(item.name) !== leanResults.get(item.name))
        fail(`${item.name}: pin=${pinned.get(item.name)} live Lean=${leanResults.get(item.name)} — pin STALE; regenerate with --write-pin`);
    }
    if (pin.rows.length !== items.length)
      fail(`pin covers ${pin.rows.length}/${items.length} corpus items — pin STALE; regenerate with --write-pin`);
  }
}

const work = mkdtempSync(join(tmpdir(), "seal-scan-bridge-"));
try {
  for (const item of items) {
    const manifestPath = join(work, `${item.name}.tools.json`);
    const policyPath = join(work, `${item.name}.policy.json`);
    writeFileSync(manifestPath, JSON.stringify(item.manifest, null, 2) + "\n");
    writeFileSync(policyPath, JSON.stringify(item.policy, null, 2) + "\n");

    const js = run(process.execPath, ["bin/seal", "scan", manifestPath, policyPath], ROOT);
    const jsOutput = `${js.stdout || ""}${js.stderr || ""}`;
    const finalVerdict = jsOutput.match(/^\s*(PASS|FAIL)\s+\d+ uncovered,/m)?.[1];
    const jsVerdict = finalVerdict === "PASS" ? true : finalVerdict === "FAIL" ? false : null;
    const leanVerdict = leanResults.get(item.name);

    if (js.status !== (jsVerdict ? 0 : 1))
      fail(`${item.name}: JS exit=${js.status}, verdict=${String(jsVerdict)}`);
    if (jsVerdict === null)
      fail(`${item.name}: JS emitted no final scan verdict`);
    if (leanVerdict === undefined)
      fail(`${item.name}: Lean oracle emitted no result`);
    if (jsVerdict !== leanVerdict || leanVerdict !== item.expected)
      fail(`${item.name}: JS=${jsVerdict} Lean=${leanVerdict} expected=${item.expected}`);
    else
      ok(`${item.name}: JS=${jsVerdict} Lean=${leanVerdict} expected=${item.expected}`);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log("\n===============================================================");
if (failed) {
  console.log(" SCAN BRIDGE: FAIL — a divergence was detected.");
  process.exit(1);
}
console.log(` SCAN BRIDGE: PASS ${items.length}/${items.length}`);
console.log("   • JS scanner, Lean scanPass, and expected verdict agree on corpus C");
console.log("   • evidence is finite-corpus differential checking, not universal verification");
