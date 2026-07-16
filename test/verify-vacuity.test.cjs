// SPDX-License-Identifier: Apache-2.0
//
// Vacuity pin for src/verify.cjs `report()` (RED corpus B2-b).
//
// `report()` folds the verdict with `checks.every((c) => c.pass)`. `[].every`
// is `true`, so an EMPTY check list would print "PASS  VERIFIED" and return
// true — a verifier that vouches for a receipt it never checked. This is a
// LATENT hazard, not a live defect: every one of the five `report()` call
// sites in verify.cjs adds at least one check before calling it (schema at
// the top, then the mediated/bypass/grants/unparseable/parseable paths), so
// an empty list is unreachable through `verify()` today. This test pins the
// INVARIANT directly at `report()` so a future refactor that reaches it with
// an empty list fails closed instead of fabricating a pass.
const test = require("node:test");
const assert = require("node:assert/strict");
const { report } = require("../src/verify.cjs");

// A minimal receipt shape `report()` reads for its header line only.
const receipt = { verdict: "ALLOW", kernel_identity: { wasm_sha256: "0".repeat(64) } };

test("report() over ZERO checks does not vouch (vacuous-truth guard)", () => {
  const out = report([], receipt, "fixtures/nonexistent.json");
  assert.equal(
    out, false,
    "report([]) must be false: an empty check list is not a verified receipt. " +
    "If this is true, the `checks.length > 0` guard was removed and [].every()==true " +
    "now lets the verifier vouch for a receipt it never checked."
  );
});

test("report() still passes when every present check passes", () => {
  const out = report([{ name: "x", pass: true, detail: "" }], receipt, "fixtures/nonexistent.json");
  assert.equal(out, true, "a single passing check must still verify");
});

test("report() fails when any present check fails", () => {
  const out = report(
    [{ name: "x", pass: true }, { name: "y", pass: false }],
    receipt,
    "fixtures/nonexistent.json"
  );
  assert.equal(out, false, "one failing check must fail the receipt");
});
