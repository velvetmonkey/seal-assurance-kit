# Input schemas

The three JSON formats you author yourself. Everything here is derived from the
parsing code (`src/scan.cjs`, `src/adequacy.cjs`) and the shipped fixtures; if
they ever disagree, the code wins and this file has a bug.

## 1. Policy (`seal scan <tools> <policy>`)

`seal scan`'s policy argument is a TrustedConfig — the same signed-bundle
shape `seal policy sign` validates (§1b) and the kernel loads. There is no
separate, simpler "scan policy" format: `seal scan` runs
`validateTrustedConfig` on this file before it scans anything, and that
validator requires `epoch` and `safety` unconditionally. A working example
needs both, even for scan-only use:

```json
{
  "epoch": 1,
  "safety": {
    "approval": { "control_file": "/tmp/seal-approvals.ndjson", "ttl_seconds": 120 },
    "tools": [
      { "name": "db.query",      "mode": "allow" },
      { "name": "db.execute",    "mode": "guard", "target": [{ "full_arguments": true }] },
      { "name": "payments.send", "mode": "guard", "target": [{ "full_arguments": true }] },
      { "name": "shell.exec",    "mode": "deny" },
      { "name": "search.docs",   "mode": "allow" }
    ]
  }
}
```

Run against a tool catalogue naming exactly those five tools (§2), this
passes: `PASS  0 uncovered, 0 ungated, 2 guarded, 1 denied, 2 read-only`,
exit 0. `fixtures/policy-v2.json` is the same shape and is exercised by
`test/scan-v2.test.cjs` and `test/scan-pin.test.cjs` on every kit test run.

- `epoch` — integer ≥ 1. Required at the top level.
- `safety` — required object; the only kernel section that cannot be turned
  off. `safety.approval.control_file` is required; `ttl_seconds` and
  `replay_store` are optional.
- `safety.tools` — array of rules, each `{ "name", "mode", "match"?,
  "target"? }`:
  - `name` — the exact tool name. **There is no prefix-glob support** in this
    shape (unlike the legacy `rules` format below) — `"search.*"` matches
    nothing; name each tool.
  - `mode` — one of `"allow"`, `"guard"` (or `"guarded"`, accepted as a
    synonym), `"deny"`.
    - `"deny"`: the tool is flat-denied → bucket DENIED.
    - `"allow"`: the tool passes. A *mutating* tool with `mode: "allow"` is
      reported as **WARN allowed but ungated** (explicit allow = accepted
      risk) — see the correction below: this **does** fail the scan.
    - `"guard"`/`"guarded"`: the tool is **guarded**; requires a non-empty
      `target` array (§3 target shape).
  - `match` — optional; omitted means "always" (unconditional). When present,
    conditional matches on the call's arguments are also supported (§1b);
    a no-match case denies.
- Effect (mutating vs. readonly) for a `safety.tools` policy always comes from
  MCP annotations or the verb heuristic (§ Effect precedence below); this
  shape has no per-rule `effect` override field.

**Scan verdict:** exit 0 unless at least one *mutating* tool has **no matching
rule** (bucket UNCOVERED) — those are listed under `FAIL UNCOVERED effectful
tools` — **or** at least one mutating tool is allowed but ungated (see below).
A FAIL on a deliberately incomplete policy (like `fixtures/policy-v2.json`
against `fixtures/tools.json`) is the tool working, not breaking.

### Allowed-but-ungated mutating tools fail the scan

An allowed, ungated mutating tool is printed under `WARN  allowed but ungated`
— but that label does not mean the scan passes. Verified directly against the
real scanner:

A one-tool config where the mutating tool is `mode: "allow"`:

```json
{
  "epoch": 1,
  "safety": {
    "approval": { "control_file": "/tmp/seal-approvals.ndjson" },
    "tools": [
      { "name": "db.execute", "mode": "allow" }
    ]
  }
}
```

against a catalogue naming only `db.execute` (`destructiveHint: true`) prints
`WARN  allowed but ungated (mutating, guard=allow) (1): db.execute` and then
`FAIL  0 uncovered, 1 ungated, 0 guarded, 0 denied, 0 read-only`, **exit 1**.

The same tool with `mode: "guard"` and a `target` instead:

```json
{
  "epoch": 1,
  "safety": {
    "approval": { "control_file": "/tmp/seal-approvals.ndjson" },
    "tools": [
      { "name": "db.execute", "mode": "guard", "target": [{ "full_arguments": true }] }
    ]
  }
}
```

prints `GUARDED (1): db.execute  [guard]` and
`PASS  0 uncovered, 0 ungated, 1 guarded, 0 denied, 0 read-only`, **exit 0**.

### Legacy `rules` format (historical)

Before the TrustedConfig/`safety.tools` shape above, `seal scan` accepted a
simpler top-level `rules` map with no `epoch` or `safety` wrapper:

```json
{
  "rules": {
    "db.query":      { "guard": "allow", "effect": "readonly" },
    "db.execute":    { "guard": "approval" },
    "payments.send": { "guard": "quorum:2-of-3" },
    "shell.exec":    { "guard": "deny" },
    "search.*":      { "guard": "allow", "effect": "readonly" }
  }
}
```

**This shape is no longer accepted.** `validateTrustedConfig` runs
unconditionally before scanning and requires `epoch` and `safety`; a bare
`rules` document fails closed with `FAIL  TRUSTED CONFIG INVALID` (missing
`epoch`, missing `safety`, plus an unknown-top-level-key error for `rules`
itself) before any tool is classified — verified by running this exact
document against the shipped scanner. `classify()` in `src/scan.cjs` still
contains the old `policy.rules || {}` fallback code for this shape, but it is
unreachable: nothing can pass `validateTrustedConfig` and still be a legacy
document. The mapping for anyone migrating a `rules` map to `safety.tools`:
`guard: "allow"` → `mode: "allow"`; `guard: "deny"` → `mode: "deny"`;
any other label (`"approval"`, `"quorum:2-of-3"`, …) → `mode: "guard"` plus a
`target` (the old label itself, like a quorum threshold, is not preserved —
current guarded rules do not carry that detail); a trailing-`*` name glob
must be expanded into one explicit rule per tool name; the `effect` override
and top-level `default` key both have no `safety.tools` equivalent.

**Effect precedence** (first hit wins):
1. MCP annotations on the tool: `readOnlyHint: true` → readonly;
   `destructiveHint: true` or `idempotentHint: false` → mutating.
2. The matched rule's `effect` field. This step only applies to the legacy
   `rules` format below; a `safety.tools` rule has no `effect` field, so this
   step never fires for the current TrustedConfig shape.
3. Verb heuristic over `name + description` (write/delete/send/… vs
   read/get/list/…).
4. Unknown → **mutating** (fail-safe: unknown effects must be covered).

## 1b. TrustedConfig — the 7-kernel bundle (`seal policy sign`)

`seal policy sign` validates and signs the policy-v2 TrustedConfig the verified
kernel loads (`Seal.parsePolicyBundle`, mcp-seal-dev `Seal/PolicyBundle.lean`;
narrative: mcp-seal-dev `docs/POLICY-V2.md` §"The 7-kernel bundle"). Top-level keys:
`epoch` (integer ≥ 1), optional `server`, required `safety`, and one optional
declarative section per non-Safety kernel: `temporal`, `consensus`,
`convergence`, `calibration`, `linear`, `budget`.

- Every optional section accepts `enabled` (boolean). Default `true` —
  except `calibration`, which defaults to **`false`** (EXPERIMENTAL, opt-in
  twice). `safety` accepts **no** `enabled` key: Safety is never off.
- `enabled: false` collapses consensus/convergence/linear/budget to absent
  (kernel unregistered); temporal stays registered but vacuous; calibration's
  present-but-disabled state is distinct and pinned.
- **Unknown keys are hard errors** at section and entry level, mirroring the
  kernel parser — the signer refuses to sign what the kernel will refuse to
  load. This includes `_comment`: review markers may live only inside a safety
  rule's interior (rule-level strictness is a named follow-up). `seal init`
  recipes place their EDIT-ME markers there for this reason.
- `safety.approval` keys: `control_file`, `ttl_seconds`, `replay_store` (the
  host-layer replay-store pointer).

The validated participation report (ACTIVE / PRESENT-BUT-INACTIVE / ABSENT)
is printed before signing; run `node bin/seal policy sign` with no arguments for usage.

## 2. Tool catalogue (`seal scan`, first argument)

Either a bare array of tools or an object with a `tools` array — the shape MCP
`tools/list` returns:

```json
{
  "tools": [
    { "name": "db.query",   "description": "Run a read-only SQL query",
      "annotations": { "readOnlyHint": true } },
    { "name": "db.execute", "description": "Execute a SQL statement",
      "annotations": { "destructiveHint": true } },
    { "name": "http.post",  "description": "POST a body to an external URL" }
  ]
}
```

- `name` — required; matched against policy rules.
- `description` — optional; feeds the verb heuristic.
- `annotations` — optional MCP tool annotations; `readOnlyHint`,
  `destructiveHint`, `idempotentHint` are honoured (highest precedence).

## 3. Adequacy labels (`seal adequacy check | find-collision`)

```json
{
  "monitors": ["risk_score", "has_approval"],
  "states": [
    { "id": "safe-approved",   "label": "allow",
      "trace_kind": "approved low-risk change",
      "evidence": { "risk_score": "low",  "has_approval": true  } },
    { "id": "risky-unapproved", "label": "block",
      "trace_kind": "unapproved high-risk change",
      "evidence": { "risk_score": "high", "has_approval": false } }
  ]
}
```

- `monitors` — non-empty strings, no duplicates. The declared observation
  channels.
- `states` — the finite sample. Each state needs:
  - `id` — unique, non-empty (any JSON scalar; compared as a string).
  - `label` — the policy label the monitors are supposed to determine. Any
    JSON value; compared structurally (key order does not matter).
  - `evidence` — object with a value for **every** declared monitor (missing
    ones are a malformed-input FAIL). Values are arbitrary JSON, compared
    structurally.
  - Extra fields (like `trace_kind`) are allowed; on a collision they feed the
    "missing distinguisher" heuristic, which names raw fields that differ
    between the colliding states.

**Verdicts:** two states with identical evidence vectors but different labels
are a **collision** → FAIL (no monitor-based policy over these monitors can be
correct on this sample). No collisions but only one distinct label → **WARN
VACUOUS** (refinement holds, nothing was distinguished; exit 0). Otherwise
**PASS ADEQUATE** with a certificate line. PASS is over the supplied finite
sample only — it is not universal adequacy over all traces.

Worked fixtures for all three formats live in [`fixtures/`](../fixtures/):
`policy-v2.json` (the current TrustedConfig shape used by `seal scan`;
`fixtures/policy.json` is the legacy pre-TrustedConfig shape from the section
above and now FAILs at the schema gate, as README.md's own "Verify in five
minutes" section notes), `tools.json`, and the five `adequacy-*.json` samples
(pass, vacuous, fail, malformed, numeric).

## 4. Receipt number compatibility (`seal verify`, cross-repo)

The Protect v2 receipt format (`velvetmonkey/seal`'s
[`docs/SEAL-RECEIPT-V2.md`](https://github.com/velvetmonkey/seal/blob/main/docs/SEAL-RECEIPT-V2.md))
accepts finite decimal numbers in receipt arguments. This kit's `src/verify.cjs`
(`spineJsonIsCanonical`) accepts finite JSON numbers (`Number.isFinite`), including
decimals, negative fractions, and scientific notation. Non-finite numbers and
malformed numeric JSON are refused. The `now` field still requires a non-negative
safe integer. Signature, commitment, and replay checks still apply.
