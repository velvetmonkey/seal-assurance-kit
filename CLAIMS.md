# Claims

Honest boundaries. What this kit does and does not assert.

## `seal verify` claims

- The kernel binary that produced the receipt is **byte-identical** to the one named in
  the receipt AND to the pinned audited build (`sha256`).
- Re-running that **same** kernel with the receipt's own policy and call reproduces the
  claimed verdict and the verbatim emitted decision bytes.
- The canonical request the receipt hashes matches its stated `canonical_request_sha256`.

If all pass, the receipt is a faithful, reproducible record of what the kernel decided
for that call under that policy.

## `seal verify` does NOT claim

- That the **policy is correct** for your risk. it verifies the decision matches the
  policy, not that the policy is what you wanted.
- That the enforcement path is tight (a correct decision can still be bypassed downstream
  by route mutation, missing credential binding, etc.). That is `seal test` / a PEP's job.
- Anything about the Lean proofs of the kernel. `asserted_provenance` in the receipt is a
  **labelled assertion** of the source's proof hygiene, NOT verified here and NOT part of
  any hash.

## Kernel

The verifier re-derives through the vendored public seal kernel (`kernel/wasm/seal.wasm`,
Apache-2.0, from `seal-check`). Pinned sha256 is checked on every run; a mismatch fails
verification loudly rather than silently trusting a swapped binary.

## `seal adequacy` claims

- For the finite state sample supplied in `labels.json`, the declared monitor
  evidence refines the supplied labels iff no same-evidence/different-label
  collision is found.
- A collision is a negative certificate: no monitor-based policy over those
  monitors can be correct on that sample.
- Missing declared monitor evidence is malformed input and fails closed.
- The JS command is differentially checked against the Lean decision procedure
  (`decide` of the witness-adequacy predicate, anchored by
  `AttentionLean.WitnessTheory.witness_computable_iff_refines`) over corpus C via
  `scripts/adequacy_bridge.mjs`. Collisions are characterized by
  `witness_separation_fails_of_char`.

## `seal adequacy` does NOT claim

- Universal adequacy over all possible traces. `PASS` means no collision in the
  observed finite sample you fed it.
- That the labels are the right policy for your risk. It checks whether monitors
  separate the labels, not whether the labels are correct.
- That the sample is complete or representative.
- That the JS implementation is formally verified. Lean proves the predicate; JS
  runs the finite decision procedure.
- That a one-label sample is meaningful evidence. The command emits `WARN` when
  refinement is vacuous because the sample does not exercise any policy distinction.
