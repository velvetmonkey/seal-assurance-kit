# seal assurance kit

Small, boring, enterprise-friendly tooling for **MCP tool mediation**. One CLI, four
commands, PASS/FAIL/WARN output a stranger can run against their own boundary.

```
seal verify <receipt.json>    verify a decision receipt (re-derive, trust nothing)
seal test   [--profile L0]    MCP boundary conformance oracle
seal scan   <tools> <policy>  MCP policy coverage auditor
seal adequacy check <labels>  finite monitor-resolution adequacy
```

## `seal scan` (live today)

"We have 47 MCP tools. Which mutate state? Which are guarded? Which are uncovered?
What changed since last week?" Point it at a `tools/list` and a coverage policy:

```sh
node bin/seal scan fixtures/tools.json fixtures/policy.json
node bin/seal scan diff fixtures/tools-prev.json fixtures/tools.json fixtures/policy.json
```

```
GUARDED (3):  db.execute [approval]   payments.send [quorum:2-of-3]   secret.read [approval]
DENIED  (1):  shell.exec
FAIL  UNCOVERED effectful tools (3):  file.write   http.post   jira.deleteIssue
  FAIL  3 uncovered, 0 ungated, 3 guarded, 1 denied, 3 read-only
```

Effect is read from MCP tool `annotations` (`readOnlyHint` / `destructiveHint`) when
present, else inferred from a verb heuristic; unknown effect is treated as mutating
(fail-safe). Exits non-zero when a mutating tool is uncovered, so `seal scan` drops
straight into CI as a governance gate.

## `seal adequacy` (live today)

`seal adequacy` is **not** `seal scan`. `seal scan` asks whether every effectful
tool has a catalog policy rule. `seal adequacy` asks a semantic monitor-resolution
question: given labelled states and declared monitor evidence, can those monitors
decide the policy labels in the supplied finite sample at all?

```sh
node bin/seal adequacy check fixtures/adequacy-pass.json
node bin/seal adequacy find-collision fixtures/adequacy-fail.json
```

Input:

```json
{
  "states": [
    { "id": "s1", "label": "allow", "evidence": { "risk": "low" } },
    { "id": "s2", "label": "block", "evidence": { "risk": "high" } }
  ],
  "monitors": ["risk"]
}
```

The oracle buckets states by the joint evidence vector over `monitors`. A `FAIL`
is a same-evidence/different-label collision: no monitor-based policy over those
monitors can be correct on that sample. A `PASS` means only that no collision was
found in the finite sample you supplied; it is not universal adequacy over all
traces. If every state has one label, the command emits `WARN`, because refinement
is vacuous and the sample does not exercise a policy distinction.

Missing declared monitor evidence is malformed input and fails closed. The
"missing distinguisher" line is a heuristic diagnostic over raw state fields, not
part of the theorem.

Correctness warrant: the JS command is the executable finite decision procedure;
the theorem is `AttentionLean.WitnessTheory.witness_computable_iff_refines`, and
collisions are negative certificates by `witness_separation_fails_of_char`.

## `seal test` (live today)

```sh
node bin/seal test --profile L0
```

Runs the published L0 conformance corpus (named bypass / stale-capability / consensus /
convergence attack traces) through the boundary and asserts each is deterministically
blocked by the right gate:

```
seal test  profile=L0  cases=5
  PASS  safety              destructive-sql     blocked by safety
  PASS  consensus           pay-quorum-missing  blocked by consensus
  PASS  temporal (stateful) temporal-stale-cap  blocked by temporal
  CONFORMANT  (5/5 traces, all four gates + deny-rule)
```

Verdicts are read from the kernel at runtime, never hardcoded. Today it self-tests the
vendored reference kernel; `seal test <server-url>` for live MCP endpoints is next.

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
- **`seal adequacy`** — point at labelled states and monitor evidence; get back
  whether those monitors separate the policy labels in that finite sample.

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

Early. `seal verify` runs today over the vendored public seal kernel. `seal test`,
`seal scan`, and `seal adequacy` are live kit checks. See `CLAIMS.md` for what is
and is not claimed.
