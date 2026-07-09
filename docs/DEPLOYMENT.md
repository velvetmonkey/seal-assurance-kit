# Deployment: install to first PASS/FAIL

The shortest honest path from a clean machine to a verdict you can act on. Every step below is
rerunnable; nothing depends on trusting this document.

## Prerequisites — all of them

- **Node.js 22** (the CI-tested version; ≥18 generally works). No npm dependencies — the kit is
  zero-dependency by design; `npm install` is not required.
- **Access.** The Seal family is currently private; cloning works only for authorised evaluators.
- For the live demo (optional, recommended): **Docker with `docker compose`**.
- Nothing else. No API keys, no network calls at verify time: `seal verify` re-derives decisions
  locally against the vendored, hash-pinned kernel.

## 1. Install

```sh
git clone https://github.com/velvetmonkey/seal-assurance-kit
cd seal-assurance-kit
node bin/seal --version
```

## 2. First PASS — verify a known-good receipt

```sh
node bin/seal verify fixtures/receipt-block.json
# ...per-check PASS lines, then:
# PASS  VERIFIED          → exit 0
```

What just happened: the kit checked the receipt's schema, confirmed the local kernel binary
matches both the receipt's claimed kernel and the audited pin, re-derived the canonical request
line and its SHA-256, resolved the policy grants to approval targets, re-ran the decision, and
compared the emitted decision bytes byte-for-byte.

## 3. First FAIL — prove the tool can say no

```sh
node bin/seal verify fixtures/receipt-bypass.json
# FAIL  NOT MEDIATED (bypass receipt)   → exit 1
node bin/seal scan fixtures/tools.json fixtures/policy.json
# FAIL, exit 1 — the sample policy deliberately leaves three mutating tools uncovered.
```

A tool that cannot fail is theatre. These two failures are the kit doing its job; wire the same
commands into CI so an uncovered tool or an unverifiable receipt fails your build (exit codes:
0 pass · 1 fail · 2 usage · 3 internal).

## 4. Full suite

```sh
npm test          # verify + fixture-drift + bypass-expect-fail + format + adequacy
                  # leaves the working tree untouched (CI enforces this)
```

## 5. A real receipt, end to end (optional, ~5 minutes)

```sh
git clone https://github.com/velvetmonkey/seal-live-demo && cd seal-live-demo
bash scripts/run_local.sh        # real containers; ends "ASSERT OK: 15/15"
```

The run leaves receipts in `evidence/receipts.jsonl` (each line's `.receipt`-bearing phases are
also bundled into `pwa/bundle.json`). Extract one and hand it back to the kit:

```sh
node bin/seal verify <path-to-extracted-receipt.json>
```

The same receipt also replays in the browser: serve `seal-live-demo/pwa/` statically and watch
the wasm kernel re-derive it, or open it in `seal-check`.

## 6. Deploying the boundary itself

The kit *checks* boundaries; it does not run one. The deployable gateway is
[`seal-host`](https://github.com/velvetmonkey/seal-host) (private): a Rust MCP host that requires
a **signed** policy config and an approval channel at startup, and routes every guarded call
through the proven kernel. Start from `seal-host/README.md` ("Verify in five minutes") and
`seal-host/docs/ARCHITECTURE.md`. Honest scope for what deployment gets you — and does not —
is one table away: the family
[claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) and
[What Seal is NOT](WHAT-SEAL-IS-NOT.md).
