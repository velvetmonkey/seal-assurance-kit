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
const { isDeepStrictEqual } = require("util");
const fs = require("fs");
const path = require("path");

// Declared verification profile of THIS copy (docs/VERIFY-PROFILES.md):
// P-REF — the reference-kernel lane. No trust-anchor input exists, and a
// config-less mediated receipt is acceptable (the signed-config-known-gap:
// the bare kernel lane has no host, so no authority evidence can exist).
// The fleet differentials key their expected agreement/divergence off this
// declaration; changing it is a design decision, not a refactor.
const VERIFY_PROFILE = "P-REF";

// Ed25519 verification of a receipt's signed_config. Proves the mediated policy
// the kernel judged under was signed by the key the config carries AND that the
// signed payload IS the carried kernel_config. Host-produced receipts always
// carry signed_config (the kit's own producer emits parseable canonical
// receipts, so it never reaches the unparseable path — see the KNOWN GAP in
// kernel/receipt-format.js). A forge that omits signed_config, corrupts the
// signature, or mutates the policy after signing fails here.
//
// TRUST ANCHOR (stated honestly): this establishes that the config is
// internally SIGNED and self-consistent, NOT that the signer is a trusted
// authority — `seal verify` takes no trust root, so unlike seal-check it cannot
// compute `authority_trusted` against a pinned key set. A self-signed config
// with a matching kernel_config would pass this check; the REDUCED SCOPE label
// (never "verified") is what keeps the claim honest for a signed-but-unpinned
// config. Requiring a trust anchor (`--trusted <keys>`) is the strictly stronger
// follow-up; this check already fails the config-less forge outright.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function configSignatureValid(receipt) {
  const sc = receipt.signed_config;
  if (!sc || typeof sc.payload !== "string" || typeof sc.signature !== "string" ||
      typeof sc.pubkey !== "string")
    return { ok: false, detail: "signed_config absent or malformed" };
  if (!/^[0-9a-f]{64}$/.test(sc.pubkey) || !/^[0-9a-f]+$/.test(sc.signature))
    return { ok: false, detail: "signed_config pubkey/signature not hex" };
  let sigOk = false;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(sc.pubkey, "hex")]),
      format: "der", type: "spki",
    });
    sigOk = crypto.verify(null, Buffer.from(sc.payload, "utf8"), key,
      Buffer.from(sc.signature, "hex"));
  } catch { sigOk = false; }
  if (!sigOk) return { ok: false, detail: "signed_config Ed25519 signature invalid" };
  let signedPolicy;
  try { signedPolicy = JSON.parse(sc.payload); } catch { return { ok: false, detail: "signed_config payload not JSON" }; }
  if (!isDeepStrictEqual(signedPolicy, receipt.kernel_config))
    return { ok: false, detail: "signed_config payload != kernel_config" };
  return { ok: true, detail: `signed by ${sc.pubkey.slice(0, 12)}` };
}

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
    // Reduced-scope core (seal-check receipt.js:278-290 parity): the wire line
    // is not re-parseable, so independent kernel REPLAY is impossible. This
    // receipt is therefore NEVER "verified" — it is reported REDUCED SCOPE and
    // returns not-passing (non-zero exit), exactly as seal-check maps
    // unparseable -> authorised-unparseable (allGood=false). What we CAN still
    // require, and do: (a) the kernel material is internally consistent, (b) the
    // kernel's own audit commitment binds to request_sha256, and (c) the policy
    // the kernel judged under is Ed25519-signed and IS the carried
    // kernel_config. (a)+(b) alone are pure self-consistency of
    // attacker-controlled JSON — a forge satisfies them trivially; (c) is what
    // makes a config-less / unsigned forge fail closed rather than pass.
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
    const sig = configSignatureValid(receipt);
    add("mediated policy Ed25519-signed and equals kernel_config (authority evidence; replay not possible)",
      sig.ok, sig.detail);
    return report(checks, receipt, receiptPath, { reducedScope: true });
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

function report(checks, receipt, receiptPath, { notMediated = false, reducedScope = false } = {}) {
  // Fail closed on an empty check list: `[].every()` is `true`, so without
  // this guard a zero-check report would vouch for a receipt nothing checked.
  // Unreachable through verify() today (every call site adds >=1 check first);
  // pinned as an invariant in test/verify-vacuity.test.cjs.
  const allGood = checks.length > 0 && checks.every((c) => c.pass);
  console.log(`seal verify  ${receiptPath}`);
  const kid = (receipt.kernel_identity || {}).wasm_sha256;
  console.log(`  receipt verdict: ${receipt.verdict}   kernel: ${kid ? kid.slice(0, 12) : "?"}`);
  for (const c of checks) {
    console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "   (" + c.detail + ")" : ""}`);
  }
  // A reduced-scope (unparseable-request) receipt is NEVER "VERIFIED": the wire
  // line could not be re-parsed, so no independent kernel replay was performed.
  // Even when every reduced check passes it is reported REDUCED SCOPE and
  // returns not-passing (non-zero exit) — a CI/product gate must not treat it as
  // verified. This is the P0 fix: the old `unparseable` branch printed
  // "PASS VERIFIED" and returned allGood=true, so a forged unparseable ALLOW
  // (self-consistent JSON, no kernel, no signature) was stamped verified. A
  // reduced check that FAILS (unsigned/forged config, broken binding) is a hard
  // FAIL, distinct from the honest reduced-scope label. `ok` drives the exit
  // code (bin/seal: exit 0 iff ok); reduced scope is ok=false either way.
  let summary, ok;
  if (notMediated) { summary = "FAIL  NOT MEDIATED (bypass receipt)"; ok = false; }
  else if (!allGood) { summary = "FAIL  NOT VERIFIED"; ok = false; }
  else if (reducedScope) {
    summary = "REDUCED SCOPE (authorised-unparseable): kernel-attested request binding and " +
      "Ed25519-signed policy only, no independent replay — NOT independently verified";
    ok = false;
  } else { summary = "PASS  VERIFIED"; ok = true; }
  console.log(`  ${summary}`);
  return ok;
}

module.exports = { verify, report, VERIFY_PROFILE };
