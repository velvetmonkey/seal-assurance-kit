# Architecture

`seal-assurance-kit` is a CLI layer around Seal evidence.

## Components

- `bin/seal`: command dispatcher.
- `src/`: receipt verification, policy scanning, conformance checks, and adequacy checks.
- `kernel/`: vendored reference kernel files shared with `seal-check`.
- `fixtures/`: generated receipts and sample policies.
- `test/`: vector, adequacy, and verification tests.

## Data flow

1. For parseable mediated kit/host receipts, `seal verify` checks the local kernel against the receipt hash and pin, re-derives the canonical request hash, re-runs the decision, and compares emitted bytes modulo the kernel request commitment. For shipped spine-v2 receipts, it checks the worker schema and action/verdict pair, verifies the arguments/config commitments and Ed25519 body signature using `--receipt-pubkey`, checks the local kernel pin, and replays verdict and reason; there are no receipt-carried kernel hashes or emitted bytes on that path. Unparseable kit/host receipts receive reduced-scope checks without replay; bypass receipts are NOT MEDIATED.
2. `seal scan` compares MCP tool metadata against a policy and flags uncovered mutating tools.
3. `seal test` replays a conformance corpus.
4. `seal adequacy` checks whether monitor evidence separates labels in a supplied finite sample.

## Trust boundaries

The kit verifies artifacts and samples. It does not prove the live boundary is wired correctly unless the live boundary is the thing being tested.
