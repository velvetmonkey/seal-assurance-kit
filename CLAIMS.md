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
