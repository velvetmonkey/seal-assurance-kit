// SPDX-License-Identifier: Apache-2.0
// Profile self-check (docs/VERIFY-PROFILES.md): this repo's verifier copy
// declares VERIFY_PROFILE = "P-REF", and its behaviour on the local fixtures
// matches the P-REF row of the spec table (test/corpus/verify-profiles.json).
// This is the CI-enforceable half of the profile teeth: the fleet
// differentials (manual, fleet-root) check cross-repo agreement; this checks
// that THIS copy is on its own declared profile using only local files.
//
// If a leg here goes red, the copy is OFF ITS DECLARED PROFILE. That is a
// finding to report — not a test to re-green by editing the declaration or
// the spec table (VERIFY-PROFILES.md §8).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const KIT_ROOT = path.resolve(__dirname, "..");
const verifier = require(path.join(KIT_ROOT, "src", "verify.cjs"));
const SPEC = JSON.parse(fs.readFileSync(
  path.join(__dirname, "corpus", "verify-profiles.json"), "utf8"));

// Run verify() with console captured; return { ok, output }.
async function runVerify(file) {
  const buf = [];
  const ol = console.log, oe = console.error;
  console.log = (...a) => buf.push(a.join(" "));
  console.error = (...a) => buf.push(a.join(" "));
  let ok;
  try { ok = await verifier.verify(file); }
  finally { console.log = ol; console.error = oe; }
  return { ok, output: buf.join("\n") };
}

function tmpMutated(baseName, mutate) {
  const r = JSON.parse(fs.readFileSync(path.join(KIT_ROOT, "fixtures", baseName), "utf8"));
  mutate(r);
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "kit-profile-"));
  const file = path.join(dir, baseName);
  fs.writeFileSync(file, JSON.stringify(r, null, 2) + "\n");
  return file;
}

test("declaration: VERIFY_PROFILE is P-REF, grammar-extractable, and matches the spec roster", () => {
  assert.equal(verifier.VERIFY_PROFILE, "P-REF");
  assert.equal(SPEC.roster.kit.profile, "P-REF");
  assert.equal(SPEC.roster.kit.declaration, "src/verify.cjs");
  // The fleet tools extract declarations by regex, not by import — the
  // declaration must satisfy the spec grammar in the declared file.
  const src = fs.readFileSync(path.join(KIT_ROOT, "src", "verify.cjs"), "utf8");
  const m = src.match(new RegExp(SPEC.declaration_regex));
  assert.ok(m, "VERIFY_PROFILE declaration not extractable by the spec regex");
  assert.equal(m[1], "P-REF");
});

test("spec mirror: the JSON table and the prose doc agree on version and profiles", () => {
  const doc = fs.readFileSync(path.join(KIT_ROOT, "docs", "VERIFY-PROFILES.md"), "utf8");
  assert.match(doc, new RegExp(`^Version ${SPEC.version} `, "m"),
    "docs/VERIFY-PROFILES.md version line != verify-profiles.json version — bump both together");
  for (const p of Object.keys(SPEC.profiles)) {
    assert.ok(doc.includes(p), `profile ${p} in the JSON mirror but not the doc`);
  }
  for (const [repo, row] of Object.entries(SPEC.roster)) {
    assert.ok(SPEC.profiles[row.profile], `roster ${repo} names unknown profile ${row.profile}`);
  }
});

test("P-REF behaviour: a config-less mediated receipt VERIFIES (the profile-distinguishing row)", async () => {
  // fixtures/receipt-allow.json is config-less by design (the
  // signed-config-known-gap): P-REF accepts it; every P-ENFORCE copy fails it.
  const r = await runVerify(path.join(KIT_ROOT, "fixtures", "receipt-allow.json"));
  assert.equal(r.ok, true, "P-REF must verify its own producer's config-less receipt");
  assert.match(r.output, /PASS {2}VERIFIED/);
});

test("P-REF behaviour: the §11.1 fixture is REDUCED — distinct label, never the success banner", async () => {
  const r = await runVerify(path.join(KIT_ROOT, "fixtures", "receipt-unparseable.json"));
  assert.equal(r.ok, false, "reduced scope is not a pass (U4)");
  assert.match(r.output, /REDUCED SCOPE \(authorised-unparseable\)/);
  assert.doesNotMatch(r.output, /PASS {2}VERIFIED/);
});

test("P-REF behaviour: binding tamper fails closed (U3)", async () => {
  const file = tmpMutated("receipt-allow.json", (r) => {
    // Flip the bound argument value: the re-derived canonical request no
    // longer matches the receipt's hashes; re-derivation must FAIL.
    r.arguments = { ...r.arguments, tampered: true };
  });
  const r = await runVerify(file);
  assert.equal(r.ok, false, "tampered arguments must never verify");
  assert.doesNotMatch(r.output, /PASS {2}VERIFIED/);
});
