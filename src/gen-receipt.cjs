// SPDX-License-Identifier: Apache-2.0
// Generate gold decision receipts for `seal verify` fixtures/tests.
// Receipts are schema v1 (seal-host/docs/DECISION-RECEIPT-SCHEMA.md): the
// vendored kernel.js buildReceipt already carries the policy (kernel_config),
// the call as tool/arguments/now/granted_capabilities, and the canonical
// request hash — everything an independent verifier needs to re-derive the
// decision without trusting the issuer. No augmentation needed here.
const path = require("path");
const fs = require("fs");
const { decide } = require("../kernel/runner.cjs");

async function makeReceipt(config, call) {
  // Approval targets are lowercase 64-hex strings; normalize defensively for callers.
  call = { ...call, approvals: (call.approvals || []).map(String) };
  const { receipt } = await decide(config, call);
  return receipt;
}

(async () => {
  const cfg = await import("file://" + path.resolve(__dirname, "../kernel/seal-config.js"));
  const outDir = path.resolve(__dirname, "../fixtures");
  const block = await makeReceipt(cfg.CFG_STANDARD,
    { tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [] });
  const allow = await makeReceipt(cfg.CFG_STANDARD,
    { tool: "store.update", args: { op: "orset.add", key: "k1" },
      approvals: [cfg.stableHash(["store.update", "store"])] });
  fs.writeFileSync(path.join(outDir, "receipt-block.json"), JSON.stringify(block, null, 2) + "\n");
  fs.writeFileSync(path.join(outDir, "receipt-allow.json"), JSON.stringify(allow, null, 2) + "\n");
  console.log(`wrote fixtures: block=${block.verdict}  allow=${allow.verdict}`);
  process.exit(0);
})().catch((e) => { console.error("ERR", e.message); process.exit(1); });
