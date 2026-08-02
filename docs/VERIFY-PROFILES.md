# VERIFY-PROFILES — the per-use-case verifier contract

Version 2 · 2026-07-19 · Status: normative for every receipt-verifier copy in
the seal fleet. Machine-readable mirror: `test/corpus/verify-profiles.json`
(the differentials load that file; this document is the prose authority — the
two are kept in agreement by `test/verify-profile.test.cjs`).

## 1. Why profiles, and why the copies stay plural

The fleet ships several independent receipt-verifier implementations on
purpose. Independent copies disagreeing is how the 2026-07-16 forged-receipt
P0 was caught; one shared core would have been one shared silent bug (the same
lesson as the three-way kernel lane). The copies are NOT drifting versions of
one verifier — they serve different use cases, and the 2026-07-16 kit
re-vendor (seal-verify-action `fbe0ca8`) established that the biggest
divergence (`signed_config` + trust-anchor enforcement) is a deliberate,
kit-acknowledged fork, not lag.

What was implicit until now is the CONTRACT each use case is held to. This
document abstracts that contract into named **verification profiles**: exact,
testable requirement sets. Each copy declares which profile it implements
(§6), and the differentials derive their expected agreement/divergence from
the DECLARED profiles instead of hand-named cases (§7). A copy behaving off
its declared profile is a RED test — and a finding to report, never a thing
to silently re-green.

## 2. Verdict classes (shared vocabulary)

Every copy maps receipts onto its own surface (exit codes, UI states, status
strings), but the classes underneath are shared. These are the classes the
differentials compare:

| class | meaning | the copy's surface must … |
|---|---|---|
| `VERIFIED` | full independent re-derivation passed; the copy's TOP verdict | be the copy's unique success surface (exit 0 / success banner) |
| `REDUCED` | verification coverage is honestly incomplete: §11.1 replay was impossible, or a principal attribution lacks independently pinned config authority | be its own state — never the success surface, never plain invalid (§11.2) |
| `UNPINNED` | authentic + replay-consistent, but operator authority NOT established against a pinned key | be distinct from both `VERIFIED` and `FAIL` |
| `FAIL` | hard rejection (tamper, forged binding, format violation, bypass) | never be mistakable for success. `NOT MEDIATED` (bypass) is a named sub-label of `FAIL` |

`P-SELFAUDIT` (§5.3) uses a two-class surface; its success class is
`SELF-CONSISTENT`, which is deliberately NOT `VERIFIED` (no independent
authority is ever claimed).

## 3. Universal invariants — hold in EVERY profile

These are profile-independent. A copy that violates any of these is broken no
matter what it declares.

- **U1 — pathological input never crashes and never passes.** The
  pathological-number vector (`1e9999999999`; the fail-closed guard landed in
  kernel `ff1bfd68` and is carried forward by `0b5e7925`) and its family: the
  verifier must not throw/abort, and the input must
  never class `VERIFIED` (kernel route `block`, never `passthrough`).
  Teeth: `test/pathological-number.*` in every repo; the cross-copy and
  fleet-verify differentials assert no-crash + non-success.
- **U2 — a forged unparseable receipt is never verified.** A kernel-less
  receipt carrying `request_parse_error` must never reach the success surface,
  whether it reuses a validly-signed public `signed_config` (→ at most
  `REDUCED`) or carries none (→ `FAIL`). This is the fleet P0 (kit `706d644`,
  seal-check `bb6cc11`, verify-action `e0f3b2f`).
- **U3 — tamper fails closed.** Any mutation of the authorization surface
  (arguments, binding hashes, signed payload, signature, verdict) → `FAIL`.
  An empty check list is a failure, not a pass (vacuity guard).
- **U4 — reduced scope is distinct from verified.** A §11.1 receipt never
  reaches the success surface, and in every profile whose input scope includes
  §11.1 receipts it gets its OWN state (label/exit distinct from the success
  surface AND not collapsed into plain invalid — rejecting it outright would
  restore the producer-stripped veto, §11.2). `P-SELFAUDIT` receipts cannot be
  §11.1 (its own producer always emits parseable canonical lines), so there
  the invariant binds as: a §11.1-shaped input must never class as success.

## 4. Canonical input classes

The differentials drive these input classes (built from existing fixtures by
mutation — no hand-crafted third dialects):

| input class | construction |
|---|---|
| `pass-pinned` | genuine parseable receipt with valid `signed_config`, verifier given the config-signer pin |
| `pass-unpinned` | same receipt, no pin supplied |
| `configless-parseable` | same receipt with `signed_config` deleted |
| `config-reusing-unparseable-forge` | kernel-less unparseable ALLOW reusing a real signed config (fleet P0 forge) |
| `configless-unparseable-forge` | the same forge with `signed_config`/`kernel_config` deleted |
| `legit-unparseable` | the real §11.1 fixture (native seal-host mint, argument-less call) |
| `pathological-number` | `1e9999999999` injected into `arguments` (re-derived hash mismatches; exercises U1) |
| `binding-tamper` | flip one hex digit of a binding hash |

## 5. The profiles

### 5.1 P-REF — reference-kernel lane

Use case: `seal verify` in this kit — the reference verifier for receipts the
bare kernel lane mints, where no host exists and therefore no authority
evidence (`signed_config`, operator pin) can exist. Requiring it universally
would make the validator reject its own producer's output (the
`signed-config-known-gap`, `test/corpus/red-corpus.json`). The interim C1
exception is principal-bearing input: its attribution may reach the top verdict
only with an independently supplied operator config-signer pin.

Requirements:

- **REF-1** `--expected-config-pubkey` is a conditional trust-anchor input for
  principal-bearing receipts only. A matching signer may proceed to the top
  verdict; absent or mismatched authority yields `REDUCED`, never `VERIFIED`
  and never hard `FAIL` merely for the authority mismatch.
- **REF-2** A config-less MEDIATED parseable NON-principal receipt is
  acceptable: schema layer accepts, and full re-derivation may class it
  `VERIFIED`. A carried `signed_config` is always cryptographically checked on
  the parseable path; an invalid one is `FAIL`.
- **REF-3** Outcome set {`VERIFIED`, `REDUCED`, `FAIL`}. Principal authority
  absence/mismatch maps to `REDUCED`, not a fourth `UNPINNED` class.
  `REDUCED` is distinct at the primary surface and exit code: 0/4/1 for
  `VERIFIED`/`REDUCED`/`FAIL`.
- **REF-4** The unparseable path still requires an Ed25519-signed
  `signed_config` matching `kernel_config` (no replay is possible there, so
  the signature is the only evidence left): config-less unparseable → `FAIL`.
- **REF-5** Everything in §3.

### 5.2 P-ENFORCE — production receipt gate

Use case: every surface that verifies PRODUCTION receipts (host-minted, CI,
browser replay): seal-check, the seal-verify-action vendored fork, the
seal-host receipt-verifier/conformance gate, the seal-live-demo PWA.

Requirements:

- **ENF-1** `signed_config` binding is REQUIRED: a mediated receipt without a
  well-formed `signed_config` is `FAIL` (format layer), and the signed payload
  must byte-bind `kernel_config` + `approval.policy_hash`.
- **ENF-2** A trust-anchor pin input (expected config-signer pubkey) exists,
  and the TOP verdict (`VERIFIED`) requires `authority_trusted === true`.
  With no pin supplied the ceiling is `UNPINNED`. A pinned-but-mismatched
  signer is `FAIL` ("unauthorised config signer").
- **ENF-3** Distinct-outcome set {`VERIFIED`, `REDUCED`, `UNPINNED`, `FAIL`}:
  all four distinct at the copy's primary surface. Exit-code deployments use
  the 0/4/3/1 shape (0 verified, 4 reduced-scope, 3 unpinned, 1 hard fail);
  UI deployments use four distinct states. The OUTCOME SET is the spec; the
  surface mapping is per copy (§6).
- **ENF-4** Deployments may be STRICTER than the ceiling, never looser: an
  exhibit deployment may permanently withhold the pin (everything caps at
  `UNPINNED`) or refuse to render the top verdict at all (seal-live-demo PWA
  renders a pinned-authorised result as "PIN NOT ACCEPTED HERE" and points at
  the pinned CLI/CI gates). What it must never do is map a non-`VERIFIED`
  class onto a success surface.
- **ENF-5** Everything in §3.

### 5.3 P-SELFAUDIT — producer self-audit

Use case: seal-demo's Act-3 audit — the SAME page that minted a receipt
re-checks it on-device. Its honesty register says so explicitly:
self-consistency, not independent audit.

Requirements:

- **SELF-1** Input scope: receipts minted by this surface in this session,
  signed with its own (fixed, public, test) key. Foreign receipts are out of
  the advertised scope.
- **SELF-2** `signed_config` binding is checked (payload byte-binds
  `kernel_config` and `approval.policy_hash`; replay from the receipt's own
  envelope reports `signature_valid`).
- **SELF-3** No independent authority claim: there is no trust-anchor input,
  no `UNPINNED` state, and the success class is `SELF-CONSISTENT` — the
  surface must not use the word "verified" as an authority claim.
- **SELF-4** Two-class surface {`SELF-CONSISTENT`, `FAIL`} is acceptable
  BECAUSE of SELF-1: its own producer never emits a §11.1 receipt, so no
  honest reduced-scope state is reachable. Any §11.1-shaped or foreign input
  that arrives anyway must class `FAIL`-side (never success) — U2/U4 still
  bind.
- **SELF-5** Tamper beat: mutating any bound field of the just-minted receipt
  must flip the surface to `FAIL` (U3, demonstrated live in the demo).
- **SELF-6** Everything in §3.

## 6. Declarations — one per copy, machine-readable

Each copy declares its profile with a one-line constant using this exact
grammar (regex-extractable from any language, no imports/side effects
needed):

```
VERIFY_PROFILE <=|:|: &str => "P-REF" | "P-ENFORCE" | "P-SELFAUDIT"
```

i.e. the token `VERIFY_PROFILE`, an assignment/keying operator, and the
double-quoted profile id on one line. Extraction regex (used by the fleet
differentials): `/VERIFY_PROFILE[^"']*["'](P-[A-Z]+)["']/`.

The declaration lives next to the copy's verifier (its pin constants or the
verify module itself), NEVER inside `receipt-format.js` (those six copies are
byte-compared by the fleet differential and must not fork) and never inside a
vendored-out directory that another repo's fork would inherit.

Roster (what the spec expects each copy to declare — the fleet differential
cross-checks live declarations against this):

| copy | declaration site | profile | primary surface mapping |
|---|---|---|---|
| kit `src/verify.cjs` (`bin/seal verify`) | `src/verify.cjs` | `P-REF` | exit 0 `PASS VERIFIED` / exit 4 `REDUCED SCOPE` (authorised-unparseable or principal authority not established) / exit 1 `FAIL NOT VERIFIED` · `FAIL NOT MEDIATED` |
| seal-check `receipt.js` (CLI `test/verify-file.cjs` + browser `app.js`) | `receipt.js` | `P-ENFORCE` | CLI exits 0/4/3/1 (+2 usage); browser four states (deployed unpinned → ceiling `UNPINNED`) |
| seal-verify-action vendored fork (`lib/main.js` → `vendor/…/src/verify.cjs`) | `lib/pin.js` | `P-ENFORCE` | exits 0/4/3/1; statuses `verified`/`reduced-scope`/`unpinned`/`not-mediated`/`not-verified` |
| seal-host receipt-verifier (embedded re-derivation body + `scripts/v2_receipt_conformance.py` gate) | `rust/src/decision_receipt.rs` | `P-ENFORCE` | conformance gate supplies the pin and delegates to the pinned external verifiers' exit codes |
| seal-live-demo PWA (`pwa/receipt.js`) | `pwa/receipt.js` | `P-ENFORCE` | UI tones; exhibit deployment (ENF-4): unpinned, and a pinned-authorised result renders `PIN NOT ACCEPTED HERE` |
| seal-demo (`public/audit.js`) | `public/audit.js` | `P-SELFAUDIT` | `allGood` boolean → PASS/FAIL chips; tamper beat |

Note: the seal-host conformance gate also drives the kit lane (`seal verify`),
i.e. it exercises a `P-REF` verifier alongside the `P-ENFORCE` ones; its own
verdict discipline (pin supplied, exit codes consumed) is `P-ENFORCE`.

## 7. Expected outcomes per profile (the differential key)

The machine-readable table in `test/corpus/verify-profiles.json` §`profiles`
is derived from §5 and is what the teeth key off. Prose version:

| input class (§4) | P-REF | P-ENFORCE | P-SELFAUDIT |
|---|---|---|---|
| `pass-pinned` | `VERIFIED` (these canonical profile rows are non-principal) | `VERIFIED` | n/a (no pin input) |
| `pass-unpinned` | `VERIFIED` (non-principal) | `UNPINNED` | success iff own fresh receipt |
| `configless-parseable` | `VERIFIED` | `FAIL` | `FAIL` |
| `config-reusing-unparseable-forge` | `REDUCED` | `REDUCED` | never success |
| `configless-unparseable-forge` | `FAIL` | `FAIL` | never success |
| `legit-unparseable` | `REDUCED` | `REDUCED` | never success (out of scope, SELF-4) |
| `pathological-number` | non-`VERIFIED`, no crash | non-`VERIFIED`, no crash | non-success, no crash |
| `binding-tamper` | `FAIL` | `FAIL` | `FAIL` |

P-REF principal extension: a parseable principal receipt with a valid
`signed_config` is `VERIFIED` only when its signer matches the independently
supplied operator pin; no pin or a different pin is `REDUCED`; an invalid
signature is `FAIL`. These are kit-specific RED teeth because the current
shared canonical fixture set predates the `principal` field.

Agreement/divergence between two copies is DERIVED: same expected class →
the differential asserts agreement; different expected classes → the
differential asserts the divergence IN BOTH DIRECTIONS (a copy drifting onto
the other's behaviour is RED). The two historical hand-named divergences
(config-less parseable: kit verifies / enforce fails; unpinned pass: kit
verifies / enforce holds `UNPINNED`) are now rows of this table, not prose.

Teeth keyed off declarations:

- kit `test/fleet-verify-differential.cjs` — the three gating entrypoints,
  expectations per live declared profile (manual, fleet-root).
- kit `test/fleet-copy-differential.cjs` — the six format copies; the
  known-gap expectation (accepts config-less mediated) is now derived:
  a copy accepts iff its repo declares `P-REF` (manual, fleet-root).
- seal-verify-action `test/cross-copy-differential.test.js` — fork (declared
  in `lib/pin.js`) vs kit@0aeb35a reference (profile pinned `P-REF` from this
  roster; the reference predates declarations) — hermetic, in CI.
- per-repo `verify-profile` self-checks — each repo asserts its own copy's
  declared profile against its local fixtures in its own CI (where CI
  exists; seal-live-demo's is a manual script like the rest of its suite).

## 8. Change discipline

- Changing a copy's declared profile, adding a profile, or moving a row of
  the §7 table is a DESIGN decision (Ben), recorded by bumping the version at
  the top of this file and its JSON mirror together.
- A differential going red because a copy is off its declared profile is a
  FINDING. Report it; do not adjust the declaration, the table, or the copy
  to re-green without the design decision above. (Audit, not surgery.)
- If a new use case appears that these three profiles would have to stretch
  to cover, name a fourth profile instead.
