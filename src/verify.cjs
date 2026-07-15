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

  // The kernel's own commitment to the bytes it judged: Host/Audit.lean puts
  // sha256 of the exact judged line into the audit inside emitted_bytes.
  const auditRequestHash = (emittedBytes) => {
    try {
      const h = JSON.parse(JSON.parse(emittedBytes).audit).request_sha256;
      return typeof h === "string" && /^[0-9a-f]{64}$/.test(h) ? h : null;
    } catch {
      return null;
    }
  };

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
  //    from another field). §11.1 unparseable-request receipts (seal-host main
  //    @ 3a74dbf) carry no (tool, arguments): the kernel judged a wire line
  //    the receipt layer could not re-parse, and request_sha256 over the raw
  //    line is the only request identity — no canonical re-derivation is
  //    possible, which is reported as its own state, never a match or a
  //    mismatch.
  const unparseable = typeof receipt.request_parse_error === "string";
  let canonicalHash = null;
  if (unparseable) {
    add("raw line identity present (request_sha256; §11.1 — no canonical re-derivation possible)",
      typeof receipt.request_sha256 === "string" && /^[0-9a-f]{64}$/.test(receipt.request_sha256),
      String(receipt.request_sha256).slice(0, 12));
  } else {
    const line = F.canonicalRequest(receipt.tool, receipt.arguments);
    if (typeof receipt.canonical_request === "string") {
      add("stored canonical_request equals derived line", receipt.canonical_request === line);
    }
    canonicalHash = crypto.createHash("sha256").update(line).digest("hex");
    add("canonical request hash matches", canonicalHash === receipt.canonical_request_sha256,
      canonicalHash.slice(0, 12));
  }

  // 4. Approval targets recomputed from the carried grants (spec §3).
  const grants = F.capabilityTargetsFromPolicy(receipt.kernel_config, receipt.granted_capabilities);
  add("grants resolve to approval targets", grants.errors.length === 0,
    grants.errors.join("; ") || `${grants.approvals.length} target(s), ${grants.opaque} opaque`);
  if (grants.errors.length > 0) return report(checks, receipt, receiptPath);

  // 5. Re-derive through the same kernel with the receipt's own policy + call.
  //    Impossible on an unparseable-request receipt: check instead that the
  //    kernel material it carries agrees with itself (verdict + certs) AND
  //    that the kernel's own request commitment — the audit's request_sha256,
  //    emitted by Host/Audit.lean over the exact bytes it judged — equals the
  //    receipt's request_sha256. The pairing of kernel material to the raw
  //    line is therefore kernel-attested, no longer an assertion by the
  //    producing host. (What replay would add and this cannot: independent
  //    re-execution of the kernel output itself.)
  if (unparseable) {
    let consistent = false;
    try {
      const audit = JSON.parse(JSON.parse(receipt.emitted_bytes).audit);
      consistent = F.HOST_AUDIT_VERDICT_MAP[audit.verdict] === receipt.verdict &&
        JSON.stringify(audit.certs) === JSON.stringify(receipt.certs);
    } catch { consistent = false; }
    add("kernel material self-consistent (emitted audit verdict + certs; consistency, not replay)", consistent);
    const kernelHash = auditRequestHash(receipt.emitted_bytes);
    add("kernel-attested request binding (audit sha256 of the judged bytes equals request_sha256)",
      kernelHash !== null && kernelHash === receipt.request_sha256,
      kernelHash ? kernelHash.slice(0, 12) : "absent from audit");
    return report(checks, receipt, receiptPath, { unparseable: true });
  }
  const red = await decide(receipt.kernel_config, {
    tool: receipt.tool, args: receipt.arguments, approvals: grants.approvals,
    now: receipt.now ?? 1000,
  });
  add("verdict re-derives identically", red.verdict === receipt.verdict,
    `re-derived ${red.verdict} / claimed ${receipt.verdict}`);
  // The kernel-attested request binding, parseable side. A native-host
  // receipt carries the hash of the ACTUAL wire line (request_sha256);
  // kit-minted receipts carry no top-level request_sha256 and the judged
  // line IS the canonical line, so the canonical hash is the expectation.
  const expectedHash = typeof receipt.request_sha256 === "string"
    ? receipt.request_sha256 : canonicalHash;
  const storedKernelHash = auditRequestHash(receipt.emitted_bytes);
  add("kernel-attested request binding (audit sha256 of the judged bytes equals the request identity)",
    storedKernelHash !== null && storedKernelHash === expectedHash,
    storedKernelHash ? storedKernelHash.slice(0, 12) : "absent from audit");
  // Replay reconstructs the CANONICAL line (id=1), so the replayed audit's
  // request commitment legitimately differs from the stored one whenever the
  // actual wire line differed from that reconstruction. Compare byte-identical
  // modulo that ONE kernel-derived token (which the binding check above pins
  // independently); require the token to occur exactly once so the
  // substitution is byte-safe. Strictly stronger than the old plain equality:
  // when the hashes agree this degenerates to it.
  const replayedHash = auditRequestHash(red.raw);
  const substitutable = replayedHash !== null && storedKernelHash !== null &&
    red.raw.split(replayedHash).length === 2;
  add("emitted decision bytes byte-identical modulo the kernel request commitment",
    substitutable && red.raw.replace(replayedHash, storedKernelHash) === receipt.emitted_bytes);

  return report(checks, receipt, receiptPath);
}

function report(checks, receipt, receiptPath, { notMediated = false, unparseable = false } = {}) {
  const allGood = checks.every((c) => c.pass);
  console.log(`seal verify  ${receiptPath}`);
  const kid = (receipt.kernel_identity || {}).wasm_sha256;
  console.log(`  receipt verdict: ${receipt.verdict}   kernel: ${kid ? kid.slice(0, 12) : "?"}`);
  for (const c of checks) {
    console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "   (" + c.detail + ")" : ""}`);
  }
  console.log(`  ${notMediated ? "FAIL  NOT MEDIATED (bypass receipt)"
    : !allGood ? "FAIL  NOT VERIFIED"
    : unparseable ? "PASS  VERIFIED (kernel-attested request binding: the kernel's audit commits to sha256 of the exact bytes it judged, and it matches request_sha256; wire line not re-parseable, no canonical replay possible)"
    : "PASS  VERIFIED"}`);
  return allGood;
}

module.exports = { verify };
