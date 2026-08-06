# seal-assurance-kit

[![CI](https://github.com/velvetmonkey/seal-assurance-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/velvetmonkey/seal-assurance-kit/actions/workflows/ci.yml)

**CLI that tells you the truth about your boundary in one line: PASS, FAIL, or the exact gap.**

`seal verify` re-derives a receipt. `seal scan` finds unguarded tools (and exits 1). `seal test` replays the corpus. `seal adequacy` checks whether your evidence actually separates the labels. Output is boring, rerun-able, and honest.

## Quick start: first PASS

**30-second showcase — the family's fastest PASS**

No Lean toolchain, no Docker, no build, no network, zero npm dependencies: just Node and this repo. This is the family front door — the quickest way to watch a real receipt re-derive to `PASS VERIFIED` before you touch anything heavier.

```bash
bash scripts/showcase.sh
```

Or run the one command explicitly:

```bash
node bin/seal verify fixtures/receipt-block.json   # exit 0: PASS VERIFIED
```

Prints `PASS VERIFIED` for a good receipt and `FAIL` (exit 1) for an uncovered scan. Visible terminal outcome, rerun-able, boring on purpose.

![CLI](https://img.shields.io/badge/interface-CLI-black)
![Domain](https://img.shields.io/badge/domain-MCP%20mediation-informational)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary reach the downstream child MCP server only after every applicable Lean kernel returns Allow. Effects configured as guarded additionally require a matching live approval record. Seam failures block; every mediated decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 kernel-defined approval tuple. “Canonical” in Seal names the pinned kernel byte rule, not RFC 8785/JCS. Seal verifies the configured authorization evidence. Whether that evidence represents the intended human, device or service is an identity and key-custody assumption, not a proved property.
<!-- truthbox:end -->
> Map: [EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) · profile detail: [PROFILE.md](https://github.com/velvetmonkey/seal-host/blob/main/PROFILE.md) — both in private repos; the links resolve only for authorised evaluators.

## What happens when you need evidence for a boundary review

You hand the kit an artifact and it gives you a one-line verdict plus the gap:

- **A receipt** → `seal verify` re-derives it from its own bytes (schema, kernel-binary match, canonical request hash, verdict). PASS or the exact failing check.
- **A tool catalogue + policy** → `seal scan` names every mutating tool no approval covers and exits 1, so unguarded surface fails CI instead of shipping.
- **Two receipts** → `seal receipt-diff` classifies every field change as AUTHORIZATION-SURFACE (loud, exit 1) or MINOR.
- **A label set** → `seal adequacy` checks the evidence actually separates the labels rather than looking like it does.

The [Verify in five minutes](#verify-in-five-minutes) block below runs each of these against shipped fixtures. Nothing here reaches the network or mutates your tree.

## For evaluators and auditors

Seal's proof story is intentionally narrow. The Lean theorems cover the mediation kernel and selected model properties. The binaries and browser artifacts are connected to that proof by reproducible conformance tests, not by a theorem about every compiled instruction.

Start with the family [claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) (one table: proven / tested / assumed / not claimed), then [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) for theorem names and file locations, [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the byte-identity claim, and [docs/TCB.md](docs/TCB.md) for what remains trusted.

Mandatory non-claims (canonical copy: [docs/LIMITATIONS.md](docs/LIMITATIONS.md)):

<!-- claims:begin -->
- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- Axiom footprint {propext, Classical.choice, Quot.sound} is the minimal classical fragment; no extra axioms.
- The axiom-footprint line is a per-theorem ceiling for theorems named in the family's axiom-pin gates; it is not a repository-wide census. Pin scope and named exceptions are indexed in the seal claims matrix (seal/docs/CLAIMS-MATRIX.md).
<!-- claims:end -->

## Verify in five minutes

```sh
npm test                                          # full suite; leaves the working tree untouched
node bin/seal verify fixtures/receipt-block.json  # exit 0: PASS VERIFIED
node bin/seal scan fixtures/tools.json fixtures/policy.json
# ^ expected output: FAIL, exit 1. The sample policy deliberately leaves three
#   mutating tools uncovered (file.write, http.post, jira.deleteIssue) — scan
#   exists to catch exactly this. A fully covered catalogue exits 0.
node bin/seal adequacy check fixtures/adequacy-pass.json
```

Input formats for `scan` and `adequacy` (policy / tools / labels JSON) are
documented with annotated examples in [docs/SCHEMAS.md](docs/SCHEMAS.md).

Principal-bearing receipts require the operator config-signing key to be
provisioned independently; never copy the pin from the receipt:

```sh
node bin/seal verify principal-receipt.json \
  --expected-config-pubkey "$SEAL_CONFIG_PUBKEY"
```

Without a matching pin, otherwise valid principal evidence is `REDUCED SCOPE`
(exit 4), never `PASS VERIFIED`. Principal receipts carry reusable credential
material and are not safe to publish; see [CLAIMS.md](CLAIMS.md).

## `seal receipt-diff` — authorization-surface diff

Two receipts can look alike and authorize different effects. `seal receipt-diff A.json B.json`
computes a field-level diff and classifies every difference:

| group | fields | meaning |
|---|---|---|
| **AUTHORIZATION-SURFACE** (flag loud, exit 1) | `tool`, `arguments` (key order significant — compared via the canonical request pre-image, schema §2), derived `canonical_request_sha256`, `args_hash`, `verdict`, `deny_kernel`, `bypass`, `approval` (identity, policy_hash, and freshness fields when a channel emits them), `granted_capabilities`, `kernel_config`, `kernel_identity.wasm_sha256` | the change alters what was authorized, by whom, or under which kernel/policy |
| **MINOR** (reported, exit 0) | `reason`, `now` (logical clock), `asserted_provenance`, `signature`, `policy_id`, `kernel_identity.self_verified`, `certs`, `emitted_bytes`, producer-local blocks | cosmetic, provenance, or derived transcript. `certs`/`emitted_bytes` are MINOR by design: the verdict is the conjunction of gates, so any per-gate flip necessarily moves `verdict` or `deny_kernel` (both AUTHORIZATION) — a change cannot hide in the transcript |

Integrity comes first: each receipt's `canonical_request_sha256` (and v2 `args_hash`) is
re-derived from its **own** (tool, arguments) in stored key order before any diff; a mismatch is
flagged stale/tampered (exit 2) and nothing is diffed. Accepts v2, v1, and legacy `v0-live`;
rejects Schema K with the legacy error naming the schema doc. A pre-v2 vs v2 pair gets an
explicit callout — "approval surface widened: +args_hash, +approval" — the exact upgrade the
sufficiency analysis proved necessary.

**Honest scope:**

| question | tool |
|---|---|
| Is this receipt well-formed, canonical, and re-derivable? | `seal verify` (this kit) |
| Does the field set carry **enough** to justify the claim? | `witness-check` — the sufficiency analyzer (private; see CLAIMS.md) |
| What changed between two receipts — does it touch what is **authorized**? | `seal receipt-diff` (this kit) |
| Gate receipts in CI | `seal-verify-action` — runs `seal verify` in GitHub Actions and fails the build on an unverifiable receipt (the sufficiency and diff checks are local tools today) |

One concept, two surfaces: this kit's `seal adequacy` command answers the same **sufficiency**
question witness-check analyses, over a finite sample at the CLI. Do not read them as two
different ideas.

`receipt-diff` does **not** re-run the kernel, and a clean diff is not a verification of either
receipt. `--json` for machine output. Deterministic: same inputs, same bytes. It may graduate to
a standalone repo later; the implementation lives in `src/receipt-diff.cjs` either way.

## Exit codes

| code | meaning |
|---|---|
| 0 | check passed (also help / `--version`) |
| 1 | check ran and **failed**: NOT VERIFIED, scan FAIL (uncovered tools), NON-CONFORMANT, adequacy collision, receipt-diff authorization drift |
| 2 | usage error: unknown command, flag, or profile; missing argument |
| 3 | internal error (unexpected exception — not a verdict) |
| 4 | **REDUCED SCOPE**: valid evidence that is not eligible for `PASS VERIFIED` (including unpinned/wrong-pinned principal authority) |

A `seal scan` exit 1 on a deliberately incomplete policy is the auditor doing
its job; wire it into CI so new uncovered tools fail the build.

## The Seal family

_All Seal-family repositories are currently private; these links resolve only for authorised evaluators._

- [seal](https://github.com/velvetmonkey/seal): the private umbrella story, product map, and evaluator path.
- [mcp-seal-dev](https://github.com/velvetmonkey/mcp-seal-dev): The rulebook, proven.
- [seal-host](https://github.com/velvetmonkey/seal-host): The guard at the door.
- [seal-check](https://github.com/velvetmonkey/seal-check): Don't trust. Verify.
- [seal-live-demo](https://github.com/velvetmonkey/seal-live-demo): Watch it work.
- [seal-assurance-kit](https://github.com/velvetmonkey/seal-assurance-kit): Check your own boundary.
- [witness-check](https://github.com/velvetmonkey/witness-check): The sufficiency analyzer. (proprietary)
- [seal-verify-action](https://github.com/velvetmonkey/seal-verify-action): Gate receipts in CI.

## Documentation

- [What Seal is NOT](docs/WHAT-SEAL-IS-NOT.md) — read this first
- [Deployment: install to first PASS/FAIL](docs/DEPLOYMENT.md)
- [Family claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) · [family architecture map](https://github.com/velvetmonkey/seal/blob/main/docs/ARCHITECTURE.md) (private umbrella)
- [Architecture](docs/ARCHITECTURE.md)
- [Input schemas: policy / tools / labels](docs/SCHEMAS.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Assumptions](docs/ASSUMPTIONS.md)
- [Proof reference](docs/PROOF-REFERENCE.md)
- [Conformance](docs/CONFORMANCE.md)
- [Trusted computing base](docs/TCB.md)
- [Glossary](docs/GLOSSARY.md)
- [Limitations](docs/LIMITATIONS.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
