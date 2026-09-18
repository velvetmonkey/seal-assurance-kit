# Deployment: install to first PASS/FAIL

The shortest honest path from a clean machine to a verdict you can act on. Every step below is
rerunnable; nothing depends on trusting this document.

## Prerequisites — all of them

- **Node.js 22** (the CI-tested version; ≥18 generally works). No npm dependencies — the kit is
  zero-dependency by design; `npm install` is not required.
- **Access.** The Seal fleet is public; cloning these repositories does not require special evaluator access.
- Nothing else. No API keys, no network calls at verify time: `seal verify` re-derives decisions
  locally against the vendored, hash-pinned kernel.

## 1. Install

```sh
# cwd: wherever you run this — it creates and enters seal-assurance-kit/
git clone https://github.com/velvetmonkey/seal-assurance-kit
cd seal-assurance-kit
node bin/seal --version
```

## 2. First PASS — verify a known-good receipt

```sh
# cwd: seal-assurance-kit/ (from step 1)
node bin/seal verify fixtures/receipt-block.json
# ...per-check PASS lines, then:
# PASS  VERIFIED          → exit 0
```

For this parseable mediated kit/host receipt, the kit checked the receipt's schema, confirmed the local kernel binary
matches both the receipt's claimed kernel and the audited pin, re-derived the canonical request
line and its SHA-256, resolved the policy grants to approval targets, re-ran the decision, and
compared the emitted decision bytes byte-for-byte modulo the kernel request commitment.

For a shipped Seal spine-v2 receipt, supply `--receipt-pubkey <64-lowercase-hex>`.
That path checks the worker schema, action/verdict consistency, the arguments and
config SHA-256 commitments in `replay`, the unsigned body's Ed25519 signature,
the local kernel against the supplied pin, and replays the verdict and reason.
Spine-v2 carries no kernel hash, canonical request hash, or emitted bytes to compare.

For a principal-bearing receipt, provision the operator config-signing key
independently (never copy it from the receipt):

```sh
# <your-receipt>.json: a principal-bearing receipt from your own seal-host deployment
# (none is shipped here — principal receipts carry credential material);
# SEAL_CONFIG_PUBKEY: your operator config-signing public key, 64 lowercase hex.
# cwd: seal-assurance-kit/
node bin/seal verify <your-receipt>.json \
  --expected-config-pubkey "$SEAL_CONFIG_PUBKEY"
```

No pin or a non-matching pin yields `REDUCED SCOPE` (exit 4), not `PASS
VERIFIED` and not a hard failure. A malformed or invalid config signature still
fails with exit 1. Principal receipts carry reusable credential material and
are not safe to publish; see [../CLAIMS.md](../CLAIMS.md).

## 3. First FAIL — prove the tool can say no

```sh
# cwd: seal-assurance-kit/
node bin/seal verify fixtures/receipt-bypass.json
# FAIL  NOT MEDIATED (bypass receipt)   → exit 1
node bin/seal scan fixtures/tools.json fixtures/policy-v2.json
# FAIL, exit 1 — the sample policy deliberately leaves three mutating tools uncovered.
```

A tool that cannot fail is theatre. These two failures are the kit doing its job; wire the same
commands into CI so an uncovered tool or an unverifiable receipt fails your build (exit codes:
0 pass · 1 fail · 2 usage · 3 internal · 4 reduced scope). For GitHub Actions, `seal-verify-action` runs a
sha256-pinned, downstream-stricter fork of the `seal verify` closure as a ready-made CI gate
(it additionally requires a valid `signed_config`; see seal-verify-action/VENDORED.md).

## 3b. Compare two receipts

```sh
# cwd: seal-assurance-kit/
node bin/seal receipt-diff fixtures/receipt-allow.json fixtures/receipt-block.json
# AUTHORIZATION-SURFACE DRIFT (...)   → exit 1: these receipts do not authorize the same thing
```

`receipt-diff` classifies every field-level difference as authorization-surface vs minor,
after checking each receipt's stored hashes against its own arguments. It reports change; it
does not re-verify a seal.

## 4. Full suite

```sh
# cwd: seal-assurance-kit/
npm test          # verify + fixture-drift + bypass-expect-fail + format + adequacy
                  # leaves the working tree untouched (CI enforces this)
```

Steps 1-4 are the kit's own basic journey: install, a real PASS, a real FAIL,
a receipt comparison, and the full suite — all against fixtures shipped in
this repository, no other checkout required.

## 5. Deploying the boundary itself

The kit *checks* boundaries; it does not run one. The deployable gateway is
[`seal-host`](https://github.com/velvetmonkey/seal-host) (public): a Rust MCP host that requires
a **signed** policy config and an approval channel at startup, and routes every guarded call
through the proven kernel. Start from `seal-host/README.md` ("Verify in five minutes") and
`seal-host/docs/ARCHITECTURE.md`. Honest scope for what deployment gets you — and does not —
is one table away: the family
[claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/archive/CLAIMS-MATRIX.md)
(historical) and [What Seal is NOT](WHAT-SEAL-IS-NOT.md).
