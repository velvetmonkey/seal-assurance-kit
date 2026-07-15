// SPDX-License-Identifier: Apache-2.0
// Vector test for the vendored kernel/receipt-format.js against the frozen
// vectors in seal-host/docs/DECISION-RECEIPT-SCHEMA.md (§2 V1/V4, §3 V2/V3),
// plus a kit-local regression: the Schema-K block fixture's stored
// canonical_request_sha256 must equal what the shared v1 function derives
// from that fixture's own (tool, args) — the convergence guarantee.
//
// Run:  node test/format-check.cjs   (or npm run test:format)
const path = require("path");
const fs = require("fs");

let failures = 0;
function check(name, got, want) {
  const pass = got === want;
  if (!pass) failures++;
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `\n      got  ${got}\n      want ${want}`}`);
}

(async () => {
  const F = await import("file://" + path.resolve(__dirname, "..", "kernel", "receipt-format.js"));

  // --- frozen spec vectors (identical set to seal-check's test) -------------
  check("sha256Hex(\"\")",
    F.sha256Hex(new Uint8Array(0)),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("V1 canonical_request_sha256 (live-demo receipt)",
    F.canonicalRequestSha256("db.execute", { operation: "insert", table: "staging_deploy_audit",
      payload: "{\"deploy_ref\":\"deploy-2026-06-30\"}" }),
    "66330ea2242d45a5a6b32d85007464125608fec7e88430fa3c23d5c5303db756");
  check("V4 canonical_request_sha256 (kit block fixture pre-image)",
    F.canonicalRequestSha256("db.execute", { database: "prod", sql: "drop table users" }),
    "460d746ba064ab9398885158dddfd6d32f1722b0efe0d3b6085c8441e9127793");
  check("V2 store.update literal grant", F.capabilityTarget("store.update", ["store"]), "6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984");
  check("V3 live-demo arg-selected grant",
    F.capabilityTarget("db.execute", ["staging_deploy_audit", "insert"]), "351f47a44bcf935c7242432e24bd11db1536d7c1da873f0ca953c8b80ae02433");

  // --- §11.3 v2 derived-hash vectors (V5-V7) --------------------------------
  check("V5 args_hash (§2 V4 args)",
    F.canonicalJsonSha256({ database: "prod", sql: "drop table users" }),
    "46657b69f15f78859ead6dd0d416cbfc9809922757ba90aa16a56b7d73afafc8");
  check("V6 args_hash (§2 V1 args)",
    F.canonicalJsonSha256({ operation: "insert", table: "staging_deploy_audit",
      payload: "{\"deploy_ref\":\"deploy-2026-06-30\"}" }),
    "53ae7fa46f79dd2637b3d5af5a160834b755d0a00a66fec11cb313db8bca753c");
  const PAYCFG = { epoch: 1, safety: { approval: { ttl_seconds: 120 }, tools: [
    { name: "payments.send", mode: "guarded",
      payment: { class: "payment", bind: { amount: "amount", merchant: "to", currency: "currency" } },
      target: [{ literal: "pay" }, { arg: "to" }, { arg: "amount" }] },
  ] } };
  check("V7 policy_hash (§11.4 example config)",
    F.canonicalJsonSha256(PAYCFG),
    "436c50ce0860d500c188e7e7c8133eed1e41e626b01174727159f3f664e84407");

  // --- §11.5 v2 assembly + roundtrip through the vendored copy ---------------
  const payArgs = { amount: 40000, to: "supplier-77", currency: "GBP" };
  const v2r = F.assembleReceiptV2({
    tool: "payments.send", arguments: payArgs, now: 1000,
    canonical_request_sha256: F.canonicalRequestSha256("payments.send", payArgs),
    bypass: false, verdict: "ALLOW", authorization: "approval", reason: "ok", deny_kernel: null,
    amount: 40000, merchant: "supplier-77", currency: "GBP",
    approval: { approval_identity: { channel: "ed25519", key_id: "ab12cd34" },
      nonce: "f".repeat(64), issued_at: 1751900000000, expiry: 1751900120000 },
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    kernel_config: PAYCFG, granted_capabilities: [],
  });
  let rv = F.validateReceipt(v2r);
  check("v2 assembled receipt validates", JSON.stringify([rv.ok, rv.version, rv.errors]), JSON.stringify([true, "v2", []]));
  check("v2 roundtrip byte-identical",
    JSON.stringify(F.assembleReceiptV2(JSON.parse(JSON.stringify(v2r)))), JSON.stringify(v2r));
  rv = F.validateReceipt({ ...v2r, amount: 39999 });
  check("v2 rejects amount != bound argument (gate:amount-merchant-mismatch)", rv.ok, false);
  rv = F.validateReceipt({ ...v2r, args_hash: "0".repeat(64) });
  check("v2 rejects args_hash mismatch", rv.ok, false);

  // --- kit-local regressions against the on-disk v1 fixtures ----------------
  const fx = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-block.json"), "utf8"));
  let v = F.validateReceipt(fx);
  check("block fixture validates as v2", JSON.stringify([v.ok, v.version, v.errors]), JSON.stringify([true, "v2", []]));
  check("block fixture canonical_request == derived line (§2)",
    fx.canonical_request, F.canonicalRequest(fx.tool, fx.arguments));
  check("block fixture canonical_request_sha256 == derived-from-call (§2 verifier obligation)",
    fx.canonical_request_sha256, F.canonicalRequestSha256(fx.tool, fx.arguments));
  check("block fixture hard split honored (no toolchain/axioms in kernel_identity)",
    !("lean_toolchain" in fx.kernel_identity) && !("axioms" in fx.kernel_identity), true);

  // legacy Schema K must still be rejected (embedded sample; the fixtures are v1 now)
  const legacyK = { seal_check_receipt: "v0", input: { request_line: "x" }, witness: { certs: [] } };
  check("legacy Schema K rejected (version v0-check)",
    JSON.stringify([F.validateReceipt(legacyK).ok, F.validateReceipt(legacyK).version]),
    JSON.stringify([false, "v0-check"]));

  // --- capability convention matches the kit's own fixture grants -----------
  const allow = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-allow.json"), "utf8"));
  check("allow-fixture opaque grant == capabilityTarget convention",
    (allow.granted_capabilities || []).map((g) => g.target)[0],
    F.capabilityTarget("store.update", ["store"]));

  // --- cross-tool fixture (produced by seal-check) validates here too -------
  const cross = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-crosstool.json"), "utf8"));
  v = F.validateReceipt(cross);
  check("cross-tool fixture (seal-check-produced) validates as v2",
    JSON.stringify([v.ok, v.version]), JSON.stringify([true, "v2"]));

  // --- unparseable-request fixture: REAL seal-host receipt (§11.1) -----------
  // Produced by seal-host main @ 3a74dbf on the pinned 1e309 line
  // (test/host_path.rs:722 form). Not hand-written; not regenerable by this
  // kit's producer — its provenance is the host, recorded in the commit that
  // added it.
  const unpFx = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-unparseable.json"), "utf8"));
  v = F.validateReceipt(unpFx);
  check("unparseable fixture (seal-host-produced) validates as v2",
    JSON.stringify([v.ok, v.version, v.errors]), JSON.stringify([true, "v2", []]));
  check("unparseable fixture carries the raw line identity and parse error",
    /^[0-9a-f]{64}$/.test(unpFx.request_sha256) && typeof unpFx.request_parse_error === "string", true);
  check("unparseable fixture omits every structured request field",
    ["tool", "arguments", "args_hash", "canonical_request", "canonical_request_sha256"]
      .every((k) => !(k in unpFx)), true);

  // --- §11.1/§11.5 unparseable-request rule: assembly ------------------------
  // seal-host (main @ 3a74dbf) emits request_sha256 on every native receipt and
  // request_parse_error when serde could not re-parse the wire line the kernel
  // judged; on those lines the structured request fields are absent and
  // request_sha256 is the ONLY request identity. The assembler must not drop it.
  const unpAsm = F.assembleReceiptV2({
    now: 1000,
    request_sha256: "c".repeat(64),
    request_parse_error: "cannot parse mediated request for receipt: number out of range at line 1 column 145",
    bypass: false, verdict: "BLOCK", reason: "safety kernel: cert", deny_kernel: "safety",
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    kernel_config: PAYCFG, granted_capabilities: [],
  });
  check("assembleReceiptV2 preserves request_sha256 + request_parse_error (§11.5)",
    JSON.stringify(Object.keys(unpAsm)),
    JSON.stringify(["seal_receipt", "now", "request_sha256", "request_parse_error", "bypass",
      "verdict", "reason", "deny_kernel", "certs", "emitted_bytes", "kernel_identity",
      "kernel_config", "granted_capabilities"]));
  check("unparseable-request roundtrip byte-identical",
    JSON.stringify(F.assembleReceiptV2(JSON.parse(JSON.stringify(unpAsm)))), JSON.stringify(unpAsm));
  const withBoth = F.assembleReceiptV2({ ...v2r, request_sha256: "c".repeat(64) });
  check("request_sha256 sits between canonical_request_sha256 and bypass (§11.5 order)",
    JSON.stringify(Object.keys(withBoth).slice(
      Object.keys(withBoth).indexOf("canonical_request_sha256"),
      Object.keys(withBoth).indexOf("bypass") + 1)),
    JSON.stringify(["canonical_request_sha256", "request_sha256", "bypass"]));

  // --- §11.1/§11.2 unparseable-request rule: validation ----------------------
  // "iff parsed": a receipt naming request_parse_error is well-formed exactly
  // when the structured request fields are ABSENT — rejecting it would restore
  // to the verifier the veto the producer was deliberately stripped of, and a
  // producer naming a parse error while supplying structured fields is
  // fabricating.
  rv = F.validateReceipt(unpAsm);
  check("unparseable-request receipt validates clean (§11.2)",
    JSON.stringify([rv.ok, rv.version, rv.errors]), JSON.stringify([true, "v2", []]));
  for (const [k, vv] of [["tool", "payments.send"], ["arguments", {}],
    ["args_hash", "0".repeat(64)], ["canonical_request", "{}"],
    ["canonical_request_sha256", "0".repeat(64)]]) {
    rv = F.validateReceipt({ ...unpAsm, [k]: vv });
    check(`unparseable + ${k} rejected (fabrication)`, rv.ok, false);
  }
  rv = F.validateReceipt({ ...unpAsm, request_sha256: "nothex" });
  check("unparseable non-hex request_sha256 rejected", rv.ok, false);
  const noRaw = { ...unpAsm }; delete noRaw.request_sha256;
  rv = F.validateReceipt(noRaw);
  check("unparseable without request_sha256 rejected", rv.ok, false);
  rv = F.validateReceipt({ ...unpAsm, request_parse_error: "" });
  check("empty request_parse_error rejected", rv.ok, false);
  rv = F.validateReceipt({ ...unpAsm, bypass: true });
  check("bypass + request_parse_error rejected (mediated receipts only)",
    rv.errors.some((e) => e.includes("only a mediated receipt")), true);
  rv = F.validateReceipt({ ...v2r, request_sha256: "c".repeat(64) });
  check("normal mediated receipt may carry request_sha256",
    JSON.stringify([rv.ok, rv.errors]), JSON.stringify([true, []]));
  rv = F.validateReceipt({ ...v2r, request_sha256: "nothex" });
  check("normal receipt non-hex request_sha256 rejected", rv.ok, false);

  console.log(failures === 0 ? "\nALL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
