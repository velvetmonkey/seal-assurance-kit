# Claims

Honest boundaries. What this kit does and does not assert.

## `seal verify` claims

- The kernel binary supplied to the verifier is **byte-identical** to the hash named in
  the receipt and to the supplied pinned hash (`sha256`); this verifier does not audit that pinned build.
- Re-running that **same** kernel with the receipt's own policy and call reproduces the
  claimed verdict and the verbatim emitted decision bytes.
- The canonical request the receipt hashes matches its stated `canonical_request_sha256`.
- For a receipt carrying `principal`, `PASS VERIFIED` additionally means the
  valid `signed_config` signer matches the operator config-signing key supplied
  independently with `--expected-config-pubkey`. A valid self-signature alone
  has a ceiling of `REDUCED SCOPE`.

If all pass, the receipt is a faithful, reproducible record of what the kernel decided
for that call under that policy.

For shipped Seal spine-v2 receipts, `seal verify --receipt-pubkey <64-hex>`
instead checks the producer's `replay` commitments, the Ed25519 signature over
the independently serialized unsigned body, and a fresh kernel replay. The
receipt does not carry a public key, so the key is necessarily caller-supplied.

## `seal verify` does NOT claim

- That the **policy is correct** for your risk. it verifies the decision matches the
  policy, not that the policy is what you wanted.
- That the enforcement path is tight (a correct decision can still be bypassed downstream
  by route mutation, missing credential binding, etc.). That is `seal test` / a PEP's job.
- Anything about the Lean proofs of the kernel. `asserted_provenance` in the receipt is a
  **labelled assertion** of the source's proof hygiene, NOT verified here and NOT part of
  any hash.
- Principal-envelope replay or PrincipalBudget ordered-trace replay. Those
  verifier hooks remain TODOs pending the frozen Fix B signed-message contract.

## Principal receipt export residual (C3)

A principal-bearing receipt carries reusable credential material. It is an
**audit artifact**, not a capability, and it is **not safe to publish**. Store
and transmit it as credential-bearing evidence with access controls appropriate
to the principal and the protected request.

Today the principal envelope binds only `nonce`, `issuedAt`, and the judged
request line. It does not bind the operator config authority. This interim
verifier therefore requires an independently pinned config-signing key before
it will print `PASS VERIFIED` for a principal attribution. The envelope-level
config-authority binding and exact-line replay land separately via Fix B.

## Kernel

The verifier re-derives through the vendored seal kernel (`kernel/wasm/seal.wasm`,
Apache-2.0, from the public `seal-check`). Pinned sha256 is checked on every run; a mismatch fails
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
- The same refinement question, asked of receipt/approval FIELD SETS ("do these
  fields carry enough information to identify the exact effect?"), is exercised
  by the private sufficiency analyzer `witness-check` (internal repo,
  `velvetmonkey/witness-check`): it found the concrete collision proving the
  pre-v2 approval surface insufficient, and that receipt-schema-v2's
  `args_hash` closes it. Internal tooling; referenced publicly by capability
  only.

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
