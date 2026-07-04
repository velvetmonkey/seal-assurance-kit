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
  check("V2 store.update literal grant", F.capabilityTarget("store.update", ["store"]).toString(), "11662918066780758608");
  check("V3 live-demo arg-selected grant",
    F.capabilityTarget("db.execute", ["staging_deploy_audit", "insert"]).toString(), "11517196862591714860");

  // --- kit-local convergence regression against the on-disk fixture ---------
  const fx = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-block.json"), "utf8"));
  const call = fx.call || {};
  check("fixture request_line == canonicalRequest(call.tool, call.args)",
    fx.input.request_line, F.canonicalRequest(call.tool, call.args));
  check("fixture canonical_request_sha256 == derived-from-call (§2 verifier obligation)",
    fx.canonical_request_sha256, F.canonicalRequestSha256(call.tool, call.args));
  check("fixture is legacy Schema K (validateReceipt must reject, version v0-check)",
    JSON.stringify([F.validateReceipt(fx).ok, F.validateReceipt(fx).version]),
    JSON.stringify([false, "v0-check"]));

  // --- capability convention matches the kit's own fixture approvals --------
  const allow = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "fixtures", "receipt-allow.json"), "utf8"));
  check("allow-fixture approval == capabilityTarget convention",
    (allow.call.approvals || [])[0],
    F.capabilityTarget("store.update", ["store"]).toString());

  console.log(failures === 0 ? "\nALL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
