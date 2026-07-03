// SPDX-License-Identifier: Apache-2.0
// `seal verify <receipt.json>` — independent decision-receipt verification.
//
// Trusts NOTHING the receipt claims. It re-hashes the kernel binary, re-derives
// the verdict by re-running the SAME kernel with the receipt's own policy + call,
// and compares byte-for-byte. A receipt that cannot be re-derived is not verified.
const { decide, kernelSha, pinnedSha } = require("../kernel/runner.cjs");
const crypto = require("crypto");
const fs = require("fs");

async function verify(receiptPath) {
  let receipt;
  try {
    receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  } catch (e) {
    console.error(`FAIL  cannot read receipt: ${e.message}`);
    return false;
  }
  const checks = [];
  const add = (name, pass, detail = "") => checks.push({ name, pass, detail });

  // A. Kernel identity: the binary on disk is what the receipt names AND the audited build.
  const local = kernelSha();
  const pinned = await pinnedSha();
  const claimed = receipt.kernel_identity && receipt.kernel_identity.wasm_sha256;
  add("kernel binary matches receipt", claimed === local,
    `local ${local.slice(0, 12)} / claimed ${(claimed || "none").slice(0, 12)}`);
  add("kernel binary is the audited build", local === pinned, `pinned ${pinned.slice(0, 12)}`);

  // B. Re-derivation requires the policy + the call. No policy => not independently verifiable.
  if (!receipt.kernel_config || !receipt.call) {
    add("receipt carries policy + call (re-derivable)", false, "missing kernel_config / call");
  } else {
    add("receipt carries policy + call (re-derivable)", true);
    const red = await decide(receipt.kernel_config, receipt.call);
    add("verdict re-derives identically", red.verdict === receipt.verdict,
      `re-derived ${red.verdict} / claimed ${receipt.verdict}`);
    add("emitted decision bytes byte-identical",
      red.receipt.emitted_bytes === receipt.emitted_bytes);
    if (receipt.canonical_request_sha256) {
      const h = crypto.createHash("sha256").update(receipt.input.request_line).digest("hex");
      add("canonical request hash matches", h === receipt.canonical_request_sha256,
        `${h.slice(0, 12)}`);
    }
  }
  return report(checks, receipt, receiptPath);
}

function report(checks, receipt, receiptPath) {
  const allGood = checks.every((c) => c.pass);
  console.log(`seal verify  ${receiptPath}`);
  console.log(`  receipt verdict: ${receipt.verdict}   kernel: ${(receipt.kernel_identity || {}).wasm_sha256 ? receipt.kernel_identity.wasm_sha256.slice(0, 12) : "?"}`);
  for (const c of checks) {
    console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "   (" + c.detail + ")" : ""}`);
  }
  console.log(`  ${allGood ? "VERIFIED" : "NOT VERIFIED"}`);
  return allGood;
}

module.exports = { verify };
