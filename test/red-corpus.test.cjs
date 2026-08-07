// SPDX-License-Identifier: Apache-2.0
//
// ======================= RED adversarial corpus — kit half =====================
// ARIA Part B / B1+B2+B4. Drives the corpus manifest (test/corpus/red-corpus.json)
// against THIS repo's shipped receipt validator (kernel/receipt-format.js — the
// exact copy bin/seal verify routes through, via src/verify.cjs). Every entry is
// a vector a defence must REFUSE; if a defence line ever disappears its test goes
// RED loudly instead of quietly passing.
//
// Scope split (deliberate, not a silent skip):
//   - This file asserts the KIT copy's verdict for every js-validator vector, so
//     the kit's own CI regresses on kit drift.
//   - Six-copy agreement across the fleet is asserted in fleet-copy-differential.cjs
//     (fails loud if a sibling repo is absent). That is a FLEET-ROOT tool: it needs
//     all six repos side by side and the five siblings are PRIVATE, so it canNOT
//     run in this repo's `npm test` and it is NOT run by CI. It is MANUAL:
//     `npm run test:fleet-differential` on a box holding the whole fleet.
//     A green CI run on this repo therefore says NOTHING about six-copy
//     agreement. Do not read it as if it does.
//   - rust-host / verify-action vectors are asserted in their own suites; here they
//     appear in the printed B4 table with an executed_in pointer, never a skip.
//
// Run:  node --test test/red-corpus.test.cjs
// ==============================================================================
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = JSON.parse(fs.readFileSync(path.join(__dirname, "corpus", "red-corpus.json"), "utf8"));

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", name), "utf8"));
}

// Build the receipt input for a vector: inline literal, or a base fixture with a
// shallow `set` mutation. Anything else (a `description`-only vector) is asserted
// in another surface's suite and returns null here.
function buildInput(vector) {
  if (vector.inline) return structuredClone(vector.inline);
  if (vector.base_fixture) {
    const r = loadFixture(vector.base_fixture);
    if (vector.mutate && vector.mutate.set) Object.assign(r, structuredClone(vector.mutate.set));
    return r;
  }
  return null;
}

// The kit's shipped validator — the one bin/seal verify actually uses.
let validateReceipt;
test.before(async () => {
  const F = await import("file://" + path.join(ROOT, "kernel", "receipt-format.js"));
  validateReceipt = F.validateReceipt;
});

const byId = Object.fromEntries(MANIFEST.vectors.map((v) => [v.id, v]));

// ---- js-validator vectors: assert the KIT copy refuses (or characterizes) ----

test("copy-drift: authority_trusted (verifier-only field) is REJECTED", () => {
  const v = byId["copy-drift-authority-trusted"];
  const out = validateReceipt(buildInput(v.vector));
  assert.equal(out.ok, false, "kit must reject a receipt carrying authority_trusted");
  assert.ok(
    out.errors.some((e) => e.includes(v.expected_refusal.error_substring)),
    `expected error substring ${JSON.stringify(v.expected_refusal.error_substring)}; got ${JSON.stringify(out.errors)}`
  );
});

// Named so a reader CANNOT mistake a green run for fleet consistency. This is a
// characterization of a known, intentional, fail-CLOSED divergence: the kit's
// producer emits no signed_config, so the kit validator (correctly, for its own
// output) does not require it — while the five downstream copies do. If the kit
// ever starts emitting signed_config, or its validator starts requiring it, this
// flips RED and forces the decision back into the open.
test("KNOWN_GAP_kit_producer_omits_signed_config (characterization, NOT verified-consistent)", () => {
  const v = byId["signed-config-known-gap"];
  const out = validateReceipt(buildInput(v.vector));
  assert.equal(
    out.ok, true,
    "KNOWN GAP: the kit validator currently ACCEPTS its own mediated receipt (no signed_config). " +
    "If this is now false, the kit gained signed_config — update the fix decision and the manifest, do not just re-green."
  );
});

test("serde §11.1: unparseable receipt smuggling structured fields is REJECTED", () => {
  const v = byId["serde-unparseable-fabrication"];
  const out = validateReceipt(buildInput(v.vector));
  assert.equal(out.ok, false, "kit must reject a parse-error receipt that also carries tool/arguments");
  assert.ok(
    out.errors.some((e) => e.includes(v.expected_refusal.error_substring)),
    `expected ${JSON.stringify(v.expected_refusal.error_substring)}; got ${JSON.stringify(out.errors)}`
  );
});

test("hard-split: legacy Schema K receipt is REJECTED (not coerced)", () => {
  const v = byId["schema-k-hard-split"];
  const out = validateReceipt(buildInput(v.vector));
  assert.equal(out.ok, false);
  assert.ok(
    out.errors.some((e) => e.includes(v.expected_refusal.error_substring)),
    `expected ${JSON.stringify(v.expected_refusal.error_substring)}; got ${JSON.stringify(out.errors)}`
  );
});

test("version discriminator: unrecognized receipt shape is REJECTED", () => {
  const v = byId["no-version-discriminator"];
  const out = validateReceipt(buildInput(v.vector));
  assert.equal(out.ok, false);
  assert.ok(
    out.errors.some((e) => e.includes(v.expected_refusal.error_substring)),
    `expected ${JSON.stringify(v.expected_refusal.error_substring)}; got ${JSON.stringify(out.errors)}`
  );
});

test("authorization-decision discriminator selects the complete v2 validation path", () => {
  const current = loadFixture("receipt-allow.json");
  delete current.seal_receipt;
  current.record_type = "seal.authorization-decision";
  current.record_version = 2;
  assert.deepEqual(validateReceipt(current), { ok: true, version: "v2", errors: [], document_checked: false });

  current.canonical_request_sha256 = "not-hex";
  const refused = validateReceipt(current);
  assert.equal(refused.ok, false);
  assert.ok(refused.errors.some((e) => e.includes("canonical_request_sha256")));
});

test("conflicting version-discriminator families are refused before classification", () => {
  const current = loadFixture("receipt-allow.json");
  current.record_type = "seal.authorization-decision";
  current.record_version = 2;
  const refused = validateReceipt(current);
  assert.equal(refused.ok, false);
  assert.equal(refused.version, null);
  assert.match(refused.errors.join("; "), /conflicting version discriminators: seal_receipt \+ record_type\/record_version/);
});

test("received document with a duplicated discriminator is refused before JSON.parse can collapse it", () => {
  const current = loadFixture("receipt-allow.json");
  const document = JSON.stringify(current).replace(
    '"seal_receipt":"v2"', '"seal_receipt":"v2","seal_receipt":"v2"');
  const refused = validateReceipt(document);
  assert.equal(refused.ok, false);
  assert.equal(refused.document_checked, true);
  assert.match(refused.errors.join("; "), /version discriminator "seal_receipt" occurs 2 times/);
});

// ---- B4: proof-catchable table, emitted as a build artefact ----
test("B4 proof-catchable table (artefact)", () => {
  const rows = MANIFEST.vectors.map((v) => ({
    id: v.id,
    proof_catchable: v.proof_catchable.verdict,
    executed_in: v.executed_in,
  }));
  const w = Math.max(...rows.map((r) => r.id.length));
  console.log("\n  RED corpus — B4 proof-catchable tag (Track-1 proof / Track-2 red-team boundary)");
  console.log("  " + "-".repeat(w + 46));
  for (const r of rows) {
    console.log(`  ${r.id.padEnd(w)}  ${String(r.proof_catchable).padEnd(6)}  ${r.executed_in}`);
  }
  console.log("  " + "-".repeat(w + 46));
  const jsCaught = rows.filter((r) => r.proof_catchable === "NO").length;
  console.log(`  ${jsCaught}/${rows.length} vectors NO proof could have caught — they live below the proof line ` +
              `(host, channel, parser boundary, verifier). That is what the red team is for.\n`);
  // The tag is data, not a pass/fail gate; assert only that every entry carries one.
  for (const v of MANIFEST.vectors) {
    assert.ok(["NO", "PARTLY", "YES"].includes(v.proof_catchable.verdict),
      `vector ${v.id} missing a proof_catchable verdict`);
  }
});

// ---- No silent skips: name the entries executed in other surfaces' suites ----
test("cross-surface vectors are executed elsewhere (explicit pointers, not skips)", () => {
  const elsewhere = MANIFEST.vectors.filter((v) =>
    !v.surfaces.some((s) => s.startsWith("js-validator") || s.startsWith("kit-verify")));
  console.log("\n  Executed in other surfaces' suites (asserted there, referenced here):");
  for (const v of elsewhere) console.log(`    ${v.id.padEnd(28)} -> ${v.executed_in}`);
  // Say the quiet part in every run's log, CI included: this suite does NOT
  // cover six-copy agreement, and the thing that does is manual. A reader who
  // sees this file go green must not infer the fleet is consistent.
  console.log("\n  NOT COVERED HERE (manual): six-copy agreement across the fleet.");
  console.log("    -> npm run test:fleet-differential   (needs all six repos side by side;");
  console.log("       the five siblings are PRIVATE, so no CI runner can do it. Run it in a frisk.)\n");
  assert.ok(elsewhere.length >= 1, "expected at least one cross-surface vector documented");
});
