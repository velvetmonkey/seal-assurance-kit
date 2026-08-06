# What Seal is NOT

Read this before you read anything else about Seal.

Most security tools lead with what they promise and bury what they don't. Seal
does the opposite, because the boundary of the claim *is* the product. A proof
you cannot state the limits of is a marketing claim wearing a lab coat. This
page states the limits in plain language. The machine-checked version lives in
[LIMITATIONS.md](LIMITATIONS.md) and is enforced identical across every surface
by `scripts/claims-drift.mjs`; if this page and that block ever disagree, that
block wins.

## The one-line version

Seal proves that a guarded action was **authorized** under a stated policy and
that the record of it was **not altered after the fact**. It does not prove the
action was *wise*, *intended*, *legal*, or *safe in the world*. It proves a
narrow, checkable thing, and it tells you exactly how narrow.

## What Seal does NOT claim

**It is not a proof of the whole system.** Seal's theorems cover the mediation
*kernel*, the decision rulebook. The Rust host, the browser build, and the
checker are tied to that rulebook by byte-exact conformance tests over a
corpus, not by a proof about every possible input, and not about your network,
your operating system, or your other software. Kernel proven; deployment
tested; everything else trusted and named.

**It does not prove intent.** This is the one a payments or procurement buyer
will reach for first, so it is the one to be hardest about. Seal cannot tell you
*why* an agent tried to move money. It can tell you that the executed call
matched an approved call byte-for-byte: this amount, this payee, this tool, these
arguments, this once. That is authorization evidence, not intent evidence. If a
human approves a malicious-but-valid request, Seal will faithfully execute it and
faithfully record that it was approved. "Seal verified the transaction" is
honest. "Seal verified the agent's intent" is not, and we will never print it.

**It is not legal liability evidence.** A Seal receipt is audit evidence
relevant to a liability review. It is not a determination of liability and not
court-grade proof of anything on its own. It shows what was authorized, by which
key, and that the record is intact. Who is responsible for that authorization is
a question for people, not for the kernel.

**A principal-bearing receipt is not safe to publish.** It carries reusable
credential material. Treat it as an access-controlled audit artifact, not as a
capability and not as a public badge. Today its principal envelope binds only
`nonce`, `issuedAt`, and the judged request line; envelope-level binding to the
operator config authority lands separately via Fix B. Until then, the kit
withholds `PASS VERIFIED` unless the receipt's config signer matches an operator
key pinned independently at verification time.

**It is tamper-evident, not tamper-proof.** Seal's audit chain makes alteration
*detectable*. It does not make alteration *impossible*. Anyone holding the
signing keys can produce valid records; Seal's job is to ensure you can tell an
untampered chain from a tampered one, not to stop a key-holder from lying.

**It does not certify compliance.** A green Seal check means the boundary
behaved like the proven kernel on the tested corpus. It does not mean your
deployment is compliant with any regulation, standard, or internal policy. Seal
gives your risk team machine-checkable evidence to reason with. It does not
replace their judgment or a regulator's.

**Coverage is what it was shown, not everything that exists.** `seal scan`
reports the mutating tools present in the catalogue you point it at. A clean
scan of a partial catalogue is not proof that every dangerous path in your
system is guarded. Scan finds gaps; it cannot promise there are none it never
saw.

**A receipt is only as meaningful as what the approver actually saw.** If a
human clicks approve on an opaque 64-character hash, the cryptography is real but
the human authorization is hollow: nobody can meaningfully approve what they
cannot read. Seal's approval surface must show a human-readable preimage of the
request. A receipt for a blind approval is a receipt for a rubber stamp, and we
treat that as a defect, not a feature.

**It does not make the AI smarter.** Seal does not reduce hallucinations, does
not improve the agent's judgment, and does not vet the agent's plan. It stops an
unapproved *effect* at the boundary. The agent can be as wrong as it likes; Seal
governs what it is allowed to *do*.

## What Seal DOES claim, precisely

So the page is not all shadow, here is the light, stated just as narrowly:

- **Authorization match.** A guarded action is forwarded only if it matches a
  live, single-use approval record bound to the exact request. No match, no
  action. (That the record was minted by the human you intend is a declared
  identity/key-custody assumption, not part of the theorem.)
- **Tamper-evident replay.** Every decision emits a signed record from which the
  decision can be independently re-derived. Alter the record and re-derivation
  fails.
- **Conformance to a proven rulebook.** The kernel's decision logic is
  machine-checked in Lean 4 with a minimal classical axiom footprint, and the
  deployed Rust, wasm, and JS are shown by conformance testing to decide the
  same way over a shared corpus.

If a claim about Seal is not on that short list and not derivable from the
kernel theorems, treat it as unproven until it is.

## Where the machine checks it

- Canonical, CI-enforced non-claims: [LIMITATIONS.md](LIMITATIONS.md)
- What the proofs cover and where they live: [PROOF-REFERENCE.md](PROOF-REFERENCE.md)
- What the conformance tests bind: [CONFORMANCE.md](CONFORMANCE.md)
- What remains trusted rather than proven: [TCB.md](TCB.md)
- The threat model: [THREAT-MODEL.md](THREAT-MODEL.md)
