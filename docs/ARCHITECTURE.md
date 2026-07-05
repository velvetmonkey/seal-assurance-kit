# Architecture

`seal-assurance-kit` is a CLI layer around Seal evidence.

## Components

- `bin/seal`: command dispatcher.
- `src/`: receipt verification, policy scanning, conformance checks, and adequacy checks.
- `kernel/`: vendored reference kernel files shared with `seal-check`.
- `fixtures/`: generated receipts and sample policies.
- `test/`: vector, adequacy, and verification tests.

## Data flow

1. `seal verify` reads a receipt, re-hashes the local kernel, re-runs the decision, and compares emitted bytes.
2. `seal scan` compares MCP tool metadata against a policy and flags uncovered mutating tools.
3. `seal test` replays a conformance corpus.
4. `seal adequacy` checks whether monitor evidence separates labels in a supplied finite sample.

## Trust boundaries

The kit verifies artifacts and samples. It does not prove the live boundary is wired correctly unless the live boundary is the thing being tested.
