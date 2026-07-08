# seal-assurance-kit

CLI tools for checking Seal receipts, MCP mediation coverage, conformance traces, and finite monitor adequacy. **Role:** Check your own boundary.

![CLI](https://img.shields.io/badge/interface-CLI-black)
![Domain](https://img.shields.io/badge/domain-MCP%20mediation-informational)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary require a matching live human approval and an allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical approval tuple, and `seal-live-demo` still emits legacy v0 receipts.
<!-- truthbox:end -->
> Map: [EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) · profile detail: [PROFILE.md](https://github.com/velvetmonkey/seal-host/blob/main/PROFILE.md) — both in private repos; the links resolve only for authorised evaluators.

**Seal is a proven checkpoint for AI agents.** When an AI agent tries to use a real tool over MCP (send money, delete a record, call an external service), Seal stands in the way and asks one question: did a human explicitly approve *this exact request*? No matching approval, no action. Every decision is written into a tamper-evident record you can check yourself. What makes Seal different from other guardrails: the core mediation rules aren't just tested, they're machine-checked theorems in Lean 4. The same decision logic then runs byte-for-byte in the Rust host you deploy, in the browser, and in the checker, each verified against that one proven rulebook.

That is the product line in one sentence: prove the rulebook, then check every body that runs it. Seal is built around MCP because MCP is where agent intent becomes an external effect. The proof says what the kernel must do; the conformance tests show that the Rust, wasm, and JavaScript artifacts used by the product family emit the same decisions and records over the shared corpus.

## What happens when you need evidence for a boundary review

Run `seal verify` on a receipt to re-derive the decision from the receipt's own policy and call. Run `seal scan` on an MCP tool catalogue to find unguarded mutating tools. Run `seal test` to replay the conformance corpus against a boundary. Run `seal adequacy` to check whether supplied monitor evidence separates labels in a finite sample.

The kit is deliberately boring: PASS, FAIL, WARN, and files an auditor can rerun.

## For evaluators and auditors

Seal's proof story is intentionally narrow. The Lean theorems cover the mediation kernel and selected model properties. The binaries and browser artifacts are connected to that proof by reproducible conformance tests, not by a theorem about every compiled instruction.

Start with [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) for theorem names and file locations, [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the byte-identity claim, and [docs/TCB.md](docs/TCB.md) for what remains trusted.

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

## Exit codes

| code | meaning |
|---|---|
| 0 | check passed (also help / `--version`) |
| 1 | check ran and **failed**: NOT VERIFIED, scan FAIL (uncovered tools), NON-CONFORMANT, adequacy collision |
| 2 | usage error: unknown command, flag, or profile; missing argument |
| 3 | internal error (unexpected exception — not a verdict) |

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

## Documentation

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
