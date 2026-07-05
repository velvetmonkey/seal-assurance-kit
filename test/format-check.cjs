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

  // --- kit-local regressions against the on-disk v1 fixtures ----------------
  const fx = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-block.json"), "utf8"));
  let v = F.validateReceipt(fx);
  check("block fixture validates as v1", JSON.stringify([v.ok, v.version, v.errors]), JSON.stringify([true, "v1", []]));
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
  check("cross-tool fixture (seal-check-produced) validates as v1",
    JSON.stringify([v.ok, v.version]), JSON.stringify([true, "v1"]));

  console.log(failures === 0 ? "\nALL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
