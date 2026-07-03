// SPDX-License-Identifier: Apache-2.0
// Generate gold decision receipts for `seal verify` fixtures/tests.
// A kit receipt = the seal-check canonical receipt AUGMENTED with the policy
// (kernel_config), the call, and the canonical request hash — everything an
// independent verifier needs to re-derive the decision without trusting the issuer.
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { decide } = require("../kernel/runner.cjs");

const bigintSafe = (_k, v) => (typeof v === "bigint" ? v.toString() : v);

async function makeReceipt(config, call) {
  // approvals may be BigInt hashes; normalize to strings (the kernel maps String anyway)
  call = { ...call, approvals: (call.approvals || []).map(String) };
  const { receipt } = await decide(config, call);
  receipt.kernel_config = config;
  receipt.call = call;
  receipt.canonical_request_sha256 =
    crypto.createHash("sha256").update(receipt.input.request_line).digest("hex");
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
  fs.writeFileSync(path.join(outDir, "receipt-block.json"), JSON.stringify(block, bigintSafe, 2) + "\n");
  fs.writeFileSync(path.join(outDir, "receipt-allow.json"), JSON.stringify(allow, bigintSafe, 2) + "\n");
  console.log(`wrote fixtures: block=${block.verdict}  allow=${allow.verdict}`);
  process.exit(0);
})().catch((e) => { console.error("ERR", e.message); process.exit(1); });
