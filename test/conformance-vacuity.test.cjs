// SPDX-License-Identifier: Apache-2.0
//
// Vacuity pin for src/test.cjs `test()` conformance oracle (RED corpus B2-b).
//
// The oracle folds `allGood = allGood && pass` over CORPUS and prints
// "PASS  CONFORMANT (N/N traces)". With N === 0 the loop never runs, allGood
// stays true, and the oracle reports CONFORMANT over zero traces — a green it
// never earned. LATENT, not live: CORPUS (kernel/corpus.js) is a static,
// non-empty list. This pins the invariant so emptying the corpus fails closed.
const test = require("node:test");
const assert = require("node:assert/strict");
const { test: conformance } = require("../src/test.cjs");

test("conformance oracle over an EMPTY corpus is NON-CONFORMANT (not vacuously green)", async () => {
  const out = await conformance("L0", []);
  assert.equal(
    out, false,
    "an empty corpus must report NON-CONFORMANT: zero traces run proves nothing. " +
    "If this is true, the `CORPUS.length === 0` guard was removed and the fold " +
    "over [] returns a spurious CONFORMANT."
  );
});
