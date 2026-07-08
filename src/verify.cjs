// SPDX-License-Identifier: Apache-2.0
// `seal verify <receipt.json>` — independent decision-receipt verification.
//
// Trusts NOTHING the receipt claims. It validates the schema (v1 per
// seal-host/docs/DECISION-RECEIPT-SCHEMA.md; legacy v0-live accepted,
// Schema K rejected), re-hashes the kernel binary, derives the canonical
// request line from the SAME (tool, arguments) it feeds the kernel,
// recomputes approval targets from the carried grants, re-derives the
// verdict, and compares byte-for-byte. A receipt that cannot be re-derived
// is not verified. Bypass receipts are reported NOT MEDIATED — never
// "verified" (spec §6).
const { decide, kernelSha, pinnedSha } = require("../kernel/runner.cjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

async function verify(receiptPath) {
  let receipt;
  try {
    receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  } catch (e) {
    console.error(`FAIL  cannot read receipt: ${e.message}`);
    return false;
  }
  const F = await import("file://" + path.resolve(__dirname, "../kernel/receipt-format.js"));
  const checks = [];
  const add = (name, pass, detail = "") => checks.push({ name, pass, detail });

  // 0. Schema first (version discriminator, field table, hard split,
  //    stored-line-vs-derived-line equality). Malformed => never reaches the kernel.
  const shape = F.validateReceipt(receipt);
  add(`schema valid (${shape.version || "unrecognized"})`, shape.ok, shape.errors.join("; "));
  if (!shape.ok) return report(checks, receipt, receiptPath);

  // 1. Bypass: seal was removed from the path. No kernel verdict exists.
  if (receipt.bypass) {
    add("mediated (a kernel verdict exists)", false,
      "bypass receipt — NOT MEDIATED; nothing to verify, and its ALLOW is not a kernel verdict");
    return report(checks, receipt, receiptPath, { notMediated: true });
  }

  // 2. Kernel identity: the binary on disk is what the receipt names AND the audited build.
  const local = kernelSha();
  const pinned = await pinnedSha();
  add("kernel binary matches receipt", receipt.kernel_identity.wasm_sha256 === local,
    `local ${local.slice(0, 12)} / claimed ${receipt.kernel_identity.wasm_sha256.slice(0, 12)}`);
  add("kernel binary is the audited build", local === pinned, `pinned ${pinned.slice(0, 12)}`);

  // 3. Canonical request: derived from the SAME (tool, arguments) fed to the
  //    kernel below (spec §2/§7 — never hash one stored string and re-derive
  //    from another field).
  const line = F.canonicalRequest(receipt.tool, receipt.arguments);
  if (typeof receipt.canonical_request === "string") {
    add("stored canonical_request equals derived line", receipt.canonical_request === line);
  }
  const h = crypto.createHash("sha256").update(line).digest("hex");
  add("canonical request hash matches", h === receipt.canonical_request_sha256, h.slice(0, 12));

  // 4. Approval targets recomputed from the carried grants (spec §3).
  const grants = F.capabilityTargetsFromPolicy(receipt.kernel_config, receipt.granted_capabilities);
  add("grants resolve to approval targets", grants.errors.length === 0,
    grants.errors.join("; ") || `${grants.approvals.length} target(s), ${grants.opaque} opaque`);
  if (grants.errors.length > 0) return report(checks, receipt, receiptPath);

  // 5. Re-derive through the same kernel with the receipt's own policy + call.
  const red = await decide(receipt.kernel_config, {
    tool: receipt.tool, args: receipt.arguments, approvals: grants.approvals,
    now: receipt.now ?? 1000,
  });
  add("verdict re-derives identically", red.verdict === receipt.verdict,
    `re-derived ${red.verdict} / claimed ${receipt.verdict}`);
  add("emitted decision bytes byte-identical", red.raw === receipt.emitted_bytes);

  return report(checks, receipt, receiptPath);
}

function report(checks, receipt, receiptPath, { notMediated = false } = {}) {
  const allGood = checks.every((c) => c.pass);
  console.log(`seal verify  ${receiptPath}`);
  const kid = (receipt.kernel_identity || {}).wasm_sha256;
  console.log(`  receipt verdict: ${receipt.verdict}   kernel: ${kid ? kid.slice(0, 12) : "?"}`);
  for (const c of checks) {
    console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "   (" + c.detail + ")" : ""}`);
  }
  console.log(`  ${notMediated ? "FAIL  NOT MEDIATED (bypass receipt)" : allGood ? "PASS  VERIFIED" : "FAIL  NOT VERIFIED"}`);
  return allGood;
}

module.exports = { verify };
