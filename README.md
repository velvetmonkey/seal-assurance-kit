# seal assurance kit

Small, boring, enterprise-friendly tooling for **MCP tool mediation**. One CLI, three
commands, PASS/FAIL/WARN output a stranger can run against their own boundary.

```
seal verify <receipt.json>    verify a decision receipt (re-derive, trust nothing)
seal test   <server|profile>  MCP boundary conformance oracle      [coming]
seal scan   <tools> <policy>  MCP policy coverage auditor          [coming]
```

## Why

An agent boundary can *claim* it mediates tool calls. This kit checks whether it
actually does, and leaves an artifact you can hand to an auditor:

- **`seal verify`** — a decision receipt is only worth something if a third party can
  reproduce it. `seal verify` re-hashes the kernel binary, re-derives the verdict by
  re-running the **same** kernel with the receipt's own policy and call, and compares
  byte-for-byte. It trusts nothing the receipt asserts about itself.
- **`seal test`** — run a boundary against a published conformance profile (default
  deny, approval binding, replay, parser weirdness, receipt determinism...).
- **`seal scan`** — point at an MCP `tools/list` and a policy; get back what is
  guarded, denied, uncovered, and new since the last scan.

## Try it (`seal verify`, live today)

```sh
node src/gen-receipt.cjs        # writes gold receipts to fixtures/
node bin/seal verify fixtures/receipt-block.json
```

Expected:

```
seal verify  fixtures/receipt-block.json
  receipt verdict: BLOCK   kernel: 1cc765c7de2c
  PASS  kernel binary matches receipt
  PASS  kernel binary is the audited build
  PASS  receipt carries policy + call (re-derivable)
  PASS  verdict re-derives identically
  PASS  emitted decision bytes byte-identical
  PASS  canonical request hash matches
  VERIFIED
```

## What the receipt carries

A verifiable kit receipt bundles everything an independent party needs, so verification
needs no access to the issuer:

- `kernel_identity.wasm_sha256` — binary identity of the evaluator that ran
- `kernel_config` — the policy the decision was made under
- `call` — the tool + arguments + approvals
- `input.request_line` + `canonical_request_sha256` — the exact bytes hashed
- `verdict` + `emitted_bytes` — the decision and its verbatim kernel output

## Status

Early. `seal verify` runs today over the vendored public seal kernel. `seal test` and
`seal scan` are next. See `CLAIMS.md` for what is and is not claimed.
