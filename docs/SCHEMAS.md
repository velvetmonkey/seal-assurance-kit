# Input schemas

The three JSON formats you author yourself. Everything here is derived from the
parsing code (`src/scan.cjs`, `src/adequacy.cjs`) and the shipped fixtures; if
they ever disagree, the code wins and this file has a bug.

## 1. Policy (`seal scan <tools> <policy>`)

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

- `rules` — map from tool name (or trailing-`*` prefix glob) to a rule.
  An exact name match wins over globs; among globs, the longest prefix wins.
- `guard` — three behaviours:
  - `"deny"`: the tool is flat-denied → bucket DENIED.
  - `"allow"`: the tool passes. A *mutating* tool with `guard: "allow"` is
    reported as **WARN allowed-ungated** (explicit allow = accepted risk) but
    does **not** fail the scan.
  - anything else (`"approval"`, `"quorum:2-of-3"`, any label your boundary
    understands): the tool is **guarded** — scan only records the label.
- `effect` — optional `"mutating"` | `"readonly"` override, used when the tool
  carries no MCP annotations (see precedence below).
- A `default` key at the top level is accepted but currently **ignored** by the
  scanner: a mutating tool with no matching rule is always bucketed UNCOVERED.

**Scan verdict:** exit 0 unless at least one *mutating* tool has **no matching
rule** (bucket UNCOVERED) — those are listed under `FAIL UNCOVERED effectful
tools`. A FAIL on a deliberately incomplete policy (like the shipped fixtures)
is the tool working, not breaking.

**Effect precedence** (first hit wins):
1. MCP annotations on the tool: `readOnlyHint: true` → readonly;
   `destructiveHint: true` or `idempotentHint: false` → mutating.
2. The matched rule's `effect` field.
3. Verb heuristic over `name + description` (write/delete/send/… vs
   read/get/list/…).
4. Unknown → **mutating** (fail-safe: unknown effects must be covered).

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
`policy.json`, `tools.json`, and the five `adequacy-*.json` samples (pass,
vacuous, fail, malformed, numeric).
