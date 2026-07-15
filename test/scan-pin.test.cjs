// SPDX-License-Identifier: Apache-2.0
// Always-on half of the scan differential: JS scan verdict vs the PINNED
// Lean scan_oracle output vs the corpus's expected verdict, for every item
// of corpus C. No Lean toolchain needed — that is the point: this leg runs
// on every `npm test`, in kit CI, forever. The other half (live Lean vs the
// same pin) runs in mcp-seal-dev CI and via the SCAN_LEAN_ROOT bridge.
// Together they are the full differential; the checked-in pin is the shared
// intermediate. Before this test the differential NEVER ran in automation
// while scan.cjs asserted the binding to every user.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { scanVerdict } = require("../scripts/scan-verdict.cjs");

const ROOT = path.resolve(__dirname, "..");
const corpus = JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures/scan-corpus.json"), "utf8"));
const pin = JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures/scan-lean-oracle.json"), "utf8"));

test("pin carries well-formed provenance", () => {
  const p = pin.provenance;
  assert.equal(p.repo, "velvetmonkey/mcp-seal-dev");
  assert.match(p.commit, /^[0-9a-f]{40}$/);
  assert.match(p.toolchain, /^leanprover\/lean4:v/);
  assert.match(p.generated, /^\d{4}-\d{2}-\d{2}$/);
});

test("pin covers exactly the corpus items, no more, no less", () => {
  const corpusNames = corpus.items.map((i) => i.name).sort();
  const pinNames = pin.rows.map((r) => r.name).sort();
  assert.deepEqual(pinNames, corpusNames);
});

test("JS scan agrees with the pinned Lean oracle AND the expected verdict on every corpus item", () => {
  const pinned = new Map(pin.rows.map((r) => [r.name, r.scanPass]));
  for (const item of corpus.items) {
    const { verdict, exitOk, output } = scanVerdict(item);
    assert.notEqual(verdict, null, `${item.name}: no final scan verdict\n${output}`);
    assert.ok(exitOk, `${item.name}: exit code disagrees with verdict`);
    assert.equal(verdict, pinned.get(item.name),
      `${item.name}: JS=${verdict} pin=${pinned.get(item.name)} — JS and pinned Lean oracle DISAGREE`);
    assert.equal(verdict, item.expected,
      `${item.name}: JS=${verdict} expected=${item.expected}`);
  }
});
