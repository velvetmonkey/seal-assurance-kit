#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
node bin/seal verify fixtures/receipt-block.json
node bin/seal scan fixtures/tools.json fixtures/policy-v2.json || true
