# seal-assurance-kit — Claim Audit Findings

Sampled from README, "What you run", "Verify in five minutes", non-claims, CLAIMS.md.

Backed by: bin/seal + src/, test/, fixtures/, npm test.

All "PASS/FAIL/WARN", "boring", "rerun-able", honesty preserved.

## Sampled

| Claim | Backed? | Evidence | Action |
|-------|---------|----------|--------|
| `seal verify` re-derives verdict from receipt's policy+call; PASS VERIFIED or fail. | Yes (runnable) | src/verify.cjs + bin/seal + fixtures/receipt-*.json + test | keep |
| `seal scan` finds unguarded mutating tools and exits 1 on uncovered. | Yes | src/scan.cjs + fixtures + expected FAIL in README | keep |
| `seal adequacy` checks evidence separates labels. | Yes | src/adequacy + fixtures/adequacy-*.json + test | keep |
| The kit is deliberately boring: PASS/FAIL/WARN + rerun-able files. | Yes (documented + true) | README | keep |

## NEEDS BEN
- Full npm test run output (source + fixtures provide the behavior).

See CLAIMS.md + family.