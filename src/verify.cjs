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
// P-REF — the reference-kernel lane. A config-less NON-PRINCIPAL mediated
// receipt remains acceptable (the signed-config-known-gap: the bare kernel
// lane has no host, so no authority evidence can exist). Interim C1 rule:
// principal-bearing receipts may reach the top verdict only when their config
// signer matches an independently supplied operator pin; otherwise their
// ceiling is REDUCED SCOPE. This conditional authority input does not turn the
// reference lane into the production-wide P-ENFORCE profile.
const VERIFY_PROFILE = "P-REF";

const EXIT_CODES = Object.freeze({ VERIFIED: 0, FAIL: 1, REDUCED: 4 });

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
// authority. For a principal-bearing receipt, authority is established only by
// separately comparing sc.pubkey with `--expected-config-pubkey`; self-signing
// is never sufficient for PASS VERIFIED.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
// Object B uses the same Ed25519 public-key encoding, but signs the canonical
// receipt preimage supplied by receipt-format.js rather than signed_config.
// The format layer stays dependency-free and fails closed unless its caller
// injects this primitive.
function receiptSignatureValid(message, signature, publicKey) {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKey)]),
      format: "der", type: "spki",
    });
    return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

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

function principalAuthority(receipt, expectedConfigPubkey) {
  const signer = receipt.signed_config && receipt.signed_config.pubkey;
  if (expectedConfigPubkey === undefined) {
    return { trusted: false, detail: "no pinned operator config-signing key supplied" };
  }
  if (typeof expectedConfigPubkey !== "string" || !/^[0-9a-f]{64}$/.test(expectedConfigPubkey)) {
    return { trusted: false, detail: "pinned operator config-signing key is not 64 lowercase hex" };
  }
  if (signer !== expectedConfigPubkey) {
    return {
      trusted: false,
      detail: `config signer ${String(signer).slice(0, 12)} does not match pinned operator key ${expectedConfigPubkey.slice(0, 12)}`,
    };
  }
  return { trusted: true, detail: `pinned operator key ${expectedConfigPubkey.slice(0, 12)}` };
}

async function verifyDetailed(receiptPath, { expectedConfigPubkey } = {}) {
  let receiptDocument;
  let receipt;
  try {
    receiptDocument = fs.readFileSync(receiptPath, "utf8");
    receipt = JSON.parse(receiptDocument);
  } catch (e) {
    console.error(`FAIL  cannot read receipt: ${e.message}`);
    return { ok: false, outcome: "fail", exitCode: EXIT_CODES.FAIL };
  }
  const F = await import("file://" + path.resolve(__dirname, "../kernel/receipt-format.js"));
  const checks = [];
  const add = (name, pass, detail = "") => checks.push({ name, pass, detail });
  const addScope = (name, detail = "") => checks.push({ name, pass: null, detail });

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
  const shape = F.validateReceipt(receiptDocument, { ed25519Verify: receiptSignatureValid });
  add(`schema valid (${shape.version || "unrecognized"})`, shape.ok, shape.errors.join("; "));
  if (!shape.ok) return reportOutcome(checks, receipt, receiptPath);

  // 1. Bypass: seal was removed from the path. No kernel verdict exists.
  if (receipt.bypass) {
    add("mediated (a kernel verdict exists)", false,
      "bypass receipt — NOT MEDIATED; nothing to verify, and its ALLOW is not a kernel verdict");
    return reportOutcome(checks, receipt, receiptPath, { notMediated: true });
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
  if (grants.errors.length > 0) return reportOutcome(checks, receipt, receiptPath);

  // 4a. A carried signed_config is always checked, including on the parseable
  // path. The config-less parseable P-REF lane remains accepted only when the
  // receipt is NON-principal. A principal receipt cannot turn a missing or
  // invalid signature into mere reduced scope: invalid evidence is a hard FAIL.
  const principalBearing = Object.prototype.hasOwnProperty.call(receipt, "principal");
  if (unparseable || principalBearing || receipt.signed_config !== undefined) {
    const sig = configSignatureValid(receipt);
    add("mediated policy Ed25519-signed and equals kernel_config", sig.ok, sig.detail);
  }

  // Interim C1 authority gate. A valid self-signature authenticates bytes but
  // does not authorise a principal attribution. Missing or mismatched operator
  // authority lowers the ceiling to REDUCED SCOPE; it is not a hard failure.
  let principalAuthorityReduced = false;
  if (principalBearing) {
    const authority = principalAuthority(receipt, expectedConfigPubkey);
    if (authority.trusted) {
      add("principal config signer matches pinned operator authority", true, authority.detail);
    } else {
      principalAuthorityReduced = true;
      addScope("principal config authority not established", authority.detail);
    }
  }

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
    return reportOutcome(checks, receipt, receiptPath, {
      reducedScope: true,
      reducedReason: "unparseable",
    });
  }

  // TODO(Fix B): when the frozen principal-envelope contract lands, consume
  // the receipt-carried raw envelope fields and replay the exact signed line.
  // This Fix A deliberately checks only config authority; it does not invent
  // the producer carry/replay contract ahead of Fix B.
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

  // TODO(Fix B / C2): replay PrincipalBudget from the receipt's ordered trace
  // once Fix B freezes the trace/envelope receipt contract. Single-call replay
  // here must not be described as PrincipalBudget trace verification.

  return reportOutcome(checks, receipt, receiptPath, {
    reducedScope: principalAuthorityReduced,
    reducedReason: principalAuthorityReduced ? "principal-authority" : undefined,
  });
}

async function verify(receiptPath, options) {
  return (await verifyDetailed(receiptPath, options)).ok;
}

function reportOutcome(checks, receipt, receiptPath,
  { notMediated = false, reducedScope = false, reducedReason } = {}) {
  // Fail closed on an empty check list: `[].every()` is `true`, so without
  // this guard a zero-check report would vouch for a receipt nothing checked.
  // Unreachable through verify() today (every call site adds >=1 check first);
  // pinned as an invariant in test/verify-vacuity.test.cjs.
  const allGood = checks.length > 0 &&
    checks.every((c) => c.pass === true || c.pass === null);
  console.log(`seal verify  ${receiptPath}`);
  const kid = (receipt.kernel_identity || {}).wasm_sha256;
  console.log(`  receipt verdict: ${receipt.verdict}   kernel: ${kid ? kid.slice(0, 12) : "?"}`);
  for (const c of checks) {
    const label = c.pass === null ? "SCOPE" : c.pass ? "PASS" : "FAIL";
    console.log(`  ${label}  ${c.name}${c.detail ? "   (" + c.detail + ")" : ""}`);
  }
  // A reduced-scope (unparseable-request) receipt is NEVER "VERIFIED": the wire
  // line could not be re-parsed, so no independent kernel replay was performed.
  // Even when every reduced check passes it is reported REDUCED SCOPE and
  // returns not-passing (non-zero exit) — a CI/product gate must not treat it as
  // verified. This is the P0 fix: the old `unparseable` branch printed
  // "PASS VERIFIED" and returned allGood=true, so a forged unparseable ALLOW
  // (self-consistent JSON, no kernel, no signature) was stamped verified. A
  // reduced check that FAILS (unsigned/forged config, broken binding) is a hard
  // FAIL, distinct from the honest reduced-scope label. The CLI preserves all
  // three states as exit 0 VERIFIED / exit 4 REDUCED / exit 1 FAIL.
  let summary, outcome;
  if (notMediated) { summary = "FAIL  NOT MEDIATED (bypass receipt)"; outcome = "fail"; }
  else if (!allGood) { summary = "FAIL  NOT VERIFIED"; outcome = "fail"; }
  else if (reducedScope) {
    summary = reducedReason === "principal-authority"
      ? "REDUCED SCOPE (principal config authority not established): receipt is replay-consistent, " +
        "but the principal attribution is not backed by the pinned operator config-signing key — NOT VERIFIED"
      : "REDUCED SCOPE (authorised-unparseable): kernel-attested request binding and " +
        "Ed25519-signed policy only, no independent replay — NOT independently verified";
    outcome = "reduced";
  } else { summary = "PASS  VERIFIED"; outcome = "verified"; }
  console.log(`  ${summary}`);
  return {
    ok: outcome === "verified",
    outcome,
    exitCode: outcome === "verified" ? EXIT_CODES.VERIFIED
      : outcome === "reduced" ? EXIT_CODES.REDUCED : EXIT_CODES.FAIL,
  };
}

function report(checks, receipt, receiptPath, options) {
  return reportOutcome(checks, receipt, receiptPath, options).ok;
}

module.exports = { verify, verifyDetailed, report, VERIFY_PROFILE, EXIT_CODES };
