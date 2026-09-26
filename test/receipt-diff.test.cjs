// SPDX-License-Identifier: Apache-2.0
// receipt-diff: authorization-surface diff. Mutated receipts are built from
// the REAL fixtures with hashes recomputed through kernel/receipt-format.js —
// never hand-typed — so the vectors cannot rot.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const ROOT = path.resolve(__dirname, "..");
const BIN = path.join(ROOT, "bin", "seal");
const FIX = (n) => path.join(ROOT, "fixtures", n);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "receipt-diff-"));

function run(args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [BIN, "receipt-diff", ...args], { encoding: "utf8" }) };
  } catch (e) {
    return { code: e.status, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

function write(name, obj) {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
  return p;
}

async function fmt() {
  return import(pathToFileURL(path.join(ROOT, "kernel", "receipt-format.js")).href);
}

const allow = () => JSON.parse(fs.readFileSync(FIX("receipt-allow.json"), "utf8"));

test("identical receipts: exit 0, empty authorization diff", () => {
  const { code, out } = run([FIX("receipt-allow.json"), FIX("receipt-allow.json")]);
  assert.equal(code, 0);
  assert.match(out, /AUTHORIZATION-SURFACE DRIFT \(0\)/);
  assert.match(out, /no authorization-surface drift/);
});

test("different arguments with correctly recomputed hashes: auth drift, exit 1", async () => {
  const F = await fmt();
  const r = allow();
  r.arguments = { op: "orset.add", key: "k2" };
  r.canonical_request = undefined;
  delete r.canonical_request;
  r.canonical_request_sha256 = F.canonicalRequestSha256(r.tool, r.arguments);
  r.args_hash = F.canonicalJsonSha256(r.arguments);
  const { code, out } = run([FIX("receipt-allow.json"), write("args-changed.json", r)]);
  assert.equal(code, 1);
  assert.match(out, /arguments: .*k1.* -> .*k2/);
  assert.match(out, /AUTHORIZATION DRIFT/);
});

test("argument key ORDER change (recomputed hashes): auth drift with order note", async () => {
  const F = await fmt();
  const r = allow();
  r.arguments = { key: "k1", op: "orset.add" }; // same pairs, swapped order
  delete r.canonical_request;
  r.canonical_request_sha256 = F.canonicalRequestSha256(r.tool, r.arguments);
  r.args_hash = F.canonicalJsonSha256(r.arguments);
  const { code, out } = run([FIX("receipt-allow.json"), write("args-reordered.json", r)]);
  assert.equal(code, 1);
  assert.match(out, /key order changed/);
});

test("same displayed args, stale stored hash: tamper flag, exit 2, no diff", () => {
  const r = allow();
  r.arguments = { op: "orset.add", key: "TAMPERED" }; // stored hashes now lie
  const { code, out } = run([FIX("receipt-allow.json"), write("stale-hash.json", r)]);
  assert.equal(code, 2);
  assert.match(out, /canonical_request: does not equal the line derived from \(tool, arguments\)/);
  assert.match(out, /FAIL/);
  assert.ok(!out.includes("AUTHORIZATION-SURFACE DRIFT ("), "must not diff tampered evidence");
});

test("pre-v2 vs v2 of the same decision: approval-surface-widened callout, exit 1", () => {
  const r = allow();
  r.seal_receipt = "v1";
  delete r.args_hash;
  delete r.approval;
  const { code, out } = run([write("pre-v2.json", r), FIX("receipt-allow.json")]);
  assert.equal(code, 1);
  assert.match(out, /approval surface widened: \+args_hash, \+approval/);
  assert.match(out, /args_hash: \(absent\)/);
  assert.match(out, /approval: \(absent\)/);
});

test("ALLOW vs BLOCK: auth drift includes verdict", () => {
  const { code, out } = run([FIX("receipt-allow.json"), FIX("receipt-block.json")]);
  assert.equal(code, 1);
  assert.match(out, /verdict: "ALLOW" -> "BLOCK"/);
});

test("reason-only change: exit 0, reported MINOR", () => {
  const r = allow();
  r.reason = "reworded human-readable ground, decision unchanged";
  const { code, out } = run([FIX("receipt-allow.json"), write("reason-only.json", r)]);
  assert.equal(code, 0);
  assert.match(out, /AUTHORIZATION-SURFACE DRIFT \(0\)/);
  assert.match(out, /MINOR \(1\)/);
  assert.match(out, /reason:/);
});

test("Schema-K rejected with legacy error naming the schema doc, exit 2", () => {
  const p = write("schema-k.json", { seal_check_receipt: true, tool: "x", arguments: {} });
  const { code, out } = run([FIX("receipt-allow.json"), p]);
  assert.equal(code, 2);
  assert.match(out, /legacy Schema K/);
  assert.match(out, /DECISION-RECEIPT-SCHEMA\.md/);
});

test("usage: wrong arity exit 2; unknown flag exit 2", () => {
  assert.equal(run([FIX("receipt-allow.json")]).code, 2);
  assert.equal(run([FIX("receipt-allow.json"), FIX("receipt-block.json"), "--nope"]).code, 2);
});

test("--json: machine output, byte-deterministic across runs", () => {
  const a = run([FIX("receipt-allow.json"), FIX("receipt-block.json"), "--json"]);
  const b = run([FIX("receipt-allow.json"), FIX("receipt-block.json"), "--json"]);
  assert.equal(a.out, b.out);
  assert.equal(a.code, 1);
  const j = JSON.parse(a.out);
  assert.equal(j.result, "AUTHORIZATION DRIFT");
  assert.ok(j.authorization.some((d) => d.field === "verdict"));
  assert.ok(j.minor.some((d) => d.field === "reason"));
});

test("bin alias seal-receipt-diff works", () => {
  const out = execFileSync(process.execPath, [path.join(ROOT, "bin", "seal-receipt-diff"), FIX("receipt-allow.json"), FIX("receipt-allow.json")], { encoding: "utf8" });
  assert.match(out, /no authorization-surface drift/);
});

test("unparseable-request receipts diff by raw line identity, never a false 'tampered' (§11.1)", async () => {
  const base = {
    seal_receipt: "v2", now: 1000,
    request_sha256: "c".repeat(64),
    request_parse_error: "cannot parse mediated request for receipt: number out of range at line 1 column 145",
    bypass: false, verdict: "BLOCK", reason: "safety kernel: cert", deny_kernel: "safety",
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    kernel_config: { epoch: 1 }, granted_capabilities: [],
  };
  // identical unparseable receipts: clean, exit 0 — the integrity gate must not
  // brand the honestly-absent canonical fields as "stale or tampered"
  const p1 = write("unp-a.json", base);
  let res = run([p1, p1]);
  assert.equal(res.code, 0, res.out);
  assert.match(res.out, /no authorization-surface drift/);
  // different raw lines: authorization drift on the request identity, exit 1
  const p2 = write("unp-b.json", { ...base, request_sha256: "d".repeat(64) });
  res = run([p1, p2]);
  assert.equal(res.code, 1, res.out);
  assert.match(res.out, /raw line sha256/);
  // mixed parseable/unparseable pair: distinct identity domains, no crash
  res = run([FIX("receipt-allow.json"), p1]);
  assert.equal(res.code, 1, res.out);
  assert.match(res.out, /unparseable-request/);
});


test("v3 missing release_status: either input fails before classification", async () => {
  const F = await fmt();
  const r = JSON.parse(fs.readFileSync(FIX("object-b-v2-host-04f7ba83.json"), "utf8"));
  delete r.release_status;
  const shape = F.validateReceipt(r);
  assert.equal(shape.ok, false);
  assert.equal(shape.version, "v3");
  assert.match(shape.errors.join("; "), /release_status:/);
  const malformed = write("v3-missing-release.json", r);
  for (const pair of [
    [malformed, FIX("receipt-allow.json")],
    [FIX("receipt-allow.json"), malformed],
  ]) {
    const { code, out } = run(pair);
    assert.equal(code, 2, out);
    assert.match(out, /FAIL/);
    assert.match(out, /release_status:/);
    assert.ok(!out.includes("AUTHORIZATION-SURFACE DRIFT ("), "must not classify malformed evidence");
  }
});

test("valid legacy v1 HMAC signature still permits a diff", async () => {
  const F = await fmt();
  const r = allow();
  r.seal_receipt = "v1";
  delete r.args_hash;
  delete r.approval;
  r.signature = { algorithm: "HMAC-SHA256", value: "legacy" };
  const shape = F.validateReceipt(r);
  assert.equal(shape.ok, true);
  assert.equal(shape.version, "v1");
  const p = write("v1-hmac.json", r);
  const { code, out } = run([p, p]);
  assert.equal(code, 0, out);
  assert.match(out, /no authorization-surface drift/);
});


test("valid signed v3 receipts diff; a changed signature fails on either input", async () => {
  const crypto = require("node:crypto");
  const { receiptSignatureValid } = require("../src/verify.cjs");
  const F = await fmt();
  const r = JSON.parse(fs.readFileSync(FIX("receipt-block.json"), "utf8"));
  delete r.seal_receipt;
  Object.assign(r, {
    record_type: "seal.authorization-decision", record_version: 3,
    release_status: "NOT_APPLICABLE", operation_id: "ab".repeat(32),
    durability_class: "asserted_local_fsync",
  });
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  r.signature = {
    domain: F.RECEIPT_SIGNATURE_DOMAIN, algorithm: "Ed25519",
    public_key: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex"),
    encoding: "base64url-nopad",
    value: crypto.sign(null, Buffer.from(F.receiptSignaturePreimage(r)), privateKey).toString("base64url"),
  };
  assert.equal(F.validateReceipt(r, { ed25519Verify: receiptSignatureValid }).ok, true);
  const valid = write("valid-signed-v3.json", r);
  const result = run([valid, valid]);
  assert.equal(result.code, 0, result.out);
  assert.match(result.out, /no authorization-surface drift/);
  const signature = Buffer.from(r.signature.value, "base64url");
  signature[0] ^= 1;
  r.signature.value = signature.toString("base64url");
  const invalid = write("invalid-signed-v3.json", r);
  for (const pair of [[invalid, valid], [valid, invalid]]) {
    const { code, out } = run(pair);
    assert.equal(code, 2, out);
    assert.match(out, /FAIL/);
    assert.match(out, /Ed25519 verification failed/);
    assert.ok(!out.includes("AUTHORIZATION-SURFACE DRIFT ("));
  }
});

// These vectors test classification, not seal verification. Recompute all
// derived release identities with the product's format implementation.
async function signReceipt(r) {
  const crypto = require("node:crypto");
  const F = await fmt();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  delete r.signature;
  r.signature = {
    domain: F.RECEIPT_SIGNATURE_DOMAIN, algorithm: "Ed25519",
    public_key: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex"),
    encoding: "base64url-nopad",
    value: crypto.sign(null, Buffer.from(F.receiptSignaturePreimage(r)), privateKey).toString("base64url"),
  };
  return r;
}

async function releaseReceipt() {
  const F = await fmt();
  const r = allow();
  delete r.seal_receipt;
  r.record_type = "seal.authorization-decision";
  r.record_version = 3;
  r.durability_class = "asserted_local_fsync";
  r.release_status = "PENDING";
  r.operation_id = F.sha256Hex(Buffer.from("receipt-diff operation"));
  r.release_valid_until = r.now + 60000;
  const frame = Buffer.from(JSON.stringify({ operation_id: r.operation_id, tool: r.tool, arguments: r.arguments }));
  r.release_frame = { encoding: "base64", length: frame.length, sha256: F.sha256Hex(frame), base64: frame.toString("base64") };
  r.post_state_hash = F.postStateHash(r.operation_id, r.release_frame.sha256);
  r.request_sha256 = F.sha256Hex(Buffer.from(F.canonicalRequest(r.tool, r.arguments)));
  r.host_identity = {
    native_executable_sha256: F.sha256Hex(Buffer.from("native executable")),
    lean_ffi_sha256: F.sha256Hex(Buffer.from("lean ffi")),
    equivalence: "not_proven",
  };
  return signReceipt(r);
}

// release_status and release_valid_until are unconditionally / ALLOW-required
// v3 fields (kernel/receipt-format.js validateV3Extras): a receipt missing
// either is MALFORMED, not a diffable authorization change, and that path is
// already covered by "v3 missing release_status: either input fails before
// classification" above. An added/removed sub-case here would just rebuild
// that same test under a different field name, so only the value-CHANGED
// case (which keeps both sides independently valid) is tested for these two.
for (const field of ["release_status", "release_valid_until"]) {
  test(`v3 ${field}: a value change is AUTH, never MINOR`, async () => {
    const a = await releaseReceipt();
    const b = structuredClone(a);
    if (field === "release_status") b.release_status = "RELEASED";
    else b.release_valid_until += 1;
    await signReceipt(b);
    const res = run([write(`${field}-changed-a.json`, a), write(`${field}-changed-b.json`, b), "--json"]);
    assert.equal(res.code, 1, res.out);
    const j = JSON.parse(res.out);
    assert.equal(j.result, "AUTHORIZATION DRIFT");
    assert.deepEqual(j.authorization.map((d) => d.field), [field]);
    // Re-signing a legitimately-differing v3 receipt necessarily changes
    // signature.value (Ed25519 covers the whole record); that is the one
    // expected MINOR entry, never an extra AUTH-surface field.
    assert.deepEqual(j.minor.map((d) => d.field), ["signature"]);
  });
}

// request_sha256 and host_identity are genuinely optional v3 fields (present
// iff the producer chooses to emit them), so — unlike the release-authority
// fields above — adding or removing them keeps both sides independently
// valid, and the original changed/added/removed shape still applies.
for (const field of ["request_sha256", "host_identity"]) {
  test(`v3 ${field}: changes, additions and removals are AUTH, never MINOR`, async () => {
    const F = await fmt();
    const a = await releaseReceipt();
    const b = structuredClone(a);
    const otherHash = F.sha256Hex(Buffer.from(`changed ${field}`));
    if (field === "host_identity") b[field].native_executable_sha256 = otherHash;
    else b[field] = otherHash;
    await signReceipt(b);
    const absent = structuredClone(a);
    delete absent[field];
    await signReceipt(absent);
    for (const [label, left, right] of [["changed", a, b], ["added", absent, a], ["removed", a, absent]]) {
      const res = run([write(`${field}-${label}-a.json`, left), write(`${field}-${label}-b.json`, right), "--json"]);
      assert.equal(res.code, 1, res.out);
      const j = JSON.parse(res.out);
      assert.equal(j.result, "AUTHORIZATION DRIFT");
      assert.deepEqual(j.authorization.map((d) => d.field), [field]);
      assert.deepEqual(j.minor.map((d) => d.field), ["signature"]);
    }
  });
}

// operation_id, release_frame and post_state_hash form ONE cryptographic hash
// chain, not three independent fields: release_frame embeds operation_id,
// and post_state_hash = sha256(operation_id, release_frame.sha256). Changing
// any one of the three in isolation makes the receipt internally
// inconsistent, and the malformed-receipt gate (#23) correctly refuses to
// classify it — that is the gate working, not a bug to route around. A tool
// that reports drift between two VALID receipts should be exercised with two
// valid receipts, so this builds a second, genuinely consistent release
// identity (a new operation_id, a frame that embeds it, and the
// post_state_hash bound to that frame) and asserts all three surface
// together as AUTH, rather than isolating one field per test.
test("v3 coupled release identity: a consistent operation_id/release_frame/post_state_hash change is AUTH on all three, together", async () => {
  const F = await fmt();
  const a = await releaseReceipt();
  const b = structuredClone(a);
  b.operation_id = F.sha256Hex(Buffer.from("a different operation"));
  const frame = Buffer.from(JSON.stringify({ operation_id: b.operation_id, tool: b.tool, arguments: b.arguments }));
  b.release_frame = { encoding: "base64", length: frame.length, sha256: F.sha256Hex(frame), base64: frame.toString("base64") };
  b.post_state_hash = F.postStateHash(b.operation_id, b.release_frame.sha256);
  await signReceipt(b);
  const res = run([write("triad-changed-a.json", a), write("triad-changed-b.json", b), "--json"]);
  assert.equal(res.code, 1, res.out);
  const j = JSON.parse(res.out);
  assert.equal(j.result, "AUTHORIZATION DRIFT");
  assert.deepEqual(j.authorization.map((d) => d.field), ["operation_id", "post_state_hash", "release_frame"]);
  assert.deepEqual(j.minor.map((d) => d.field), ["signature"]);
});

test("release lifecycle pair: status and recomputed post-state hash are AUTH in text output", async () => {
  const F = await fmt();
  const a = await releaseReceipt();
  const b = structuredClone(a);
  b.release_status = "RELEASED";
  // post_state_hash is bound to release_frame.sha256 (same hash-chain rule as
  // the coupled triad above): a release against a genuinely different frame
  // moves both together, so build a real second frame rather than hand-typing
  // an unbound post_state_hash, which the gate now correctly rejects.
  const frame = Buffer.from(JSON.stringify({ operation_id: b.operation_id, tool: b.tool, arguments: { ...b.arguments, note: "different release" } }));
  b.release_frame = { encoding: "base64", length: frame.length, sha256: F.sha256Hex(frame), base64: frame.toString("base64") };
  b.post_state_hash = F.postStateHash(b.operation_id, b.release_frame.sha256);
  await signReceipt(b);
  const res = run([write("release-pair-a.json", a), write("release-pair-b.json", b)]);
  assert.equal(res.code, 1, res.out);
  assert.match(res.out, /AUTHORIZATION-SURFACE DRIFT \(3\)/);
  assert.match(res.out, /release_status: "PENDING" -> "RELEASED"/);
  assert.match(res.out, /post_state_hash:/);
  assert.match(res.out, /release_frame:/);
  assert.match(res.out, /MINOR \(1\)/);
});

test("schema-only v2/v3 drift: exit 1 with a distinct JSON result in both directions", async () => {
  const a = await releaseReceipt();
  const b = { ...a, record_version: 2 };
  for (const [left, right] of [[a, b], [b, a]]) {
    const files = [write("schema-only-a.json", left), write("schema-only-b.json", right)];
    const res = run([...files, "--json"]);
    assert.equal(res.code, 1, res.out);
    const j = JSON.parse(res.out);
    assert.equal(j.exit, 1);
    assert.equal(j.result, "SCHEMA DRIFT");
    assert.equal(j.schema_drift.a, `v${left.record_version}`);
    assert.equal(j.schema_drift.b, `v${right.record_version}`);
    assert.deepEqual(j.authorization, []);
    assert.deepEqual(j.minor, [{ field: "record_version", a: left.record_version, b: right.record_version }]);
    const text = run(files);
    assert.equal(text.code, 1);
    assert.match(text.out, /RESULT: SCHEMA DRIFT/);
    assert.doesNotMatch(text.out, /authorize the same thing/);
  }
});

test("record_version representation within v2 is explicit MINOR, with no schema drift", () => {
  const a = allow();
  const b = { ...a, record_type: "seal.authorization-decision", record_version: 2 };
  delete b.seal_receipt;
  const res = run([write("v2-old-disc.json", a), write("v2-new-disc.json", b), "--json"]);
  assert.equal(res.code, 0, res.out);
  const j = JSON.parse(res.out);
  assert.equal(j.schema_drift, null);
  assert.deepEqual(j.authorization, []);
  assert.deepEqual(j.minor.find((d) => d.field === "record_version"), { field: "record_version", b: 2, note: "added" });
});

test("parse-error wording is explicit MINOR when the raw request identity is unchanged", async () => {
  const F = await fmt();
  const a = JSON.parse(fs.readFileSync(FIX("receipt-block.json"), "utf8"));
  for (const field of ["tool", "arguments", "args_hash", "canonical_request", "canonical_request_sha256"]) delete a[field];
  a.request_sha256 = F.sha256Hex(Buffer.from("unparseable request"));
  a.request_parse_error = "cannot parse request";
  const b = { ...a, request_parse_error: "request parse failed" };
  const res = run([write("parse-wording-a.json", a), write("parse-wording-b.json", b), "--json"]);
  assert.equal(res.code, 0, res.out);
  const j = JSON.parse(res.out);
  assert.deepEqual(j.authorization, []);
  assert.deepEqual(j.minor, [{ field: "request_parse_error", a: a.request_parse_error, b: b.request_parse_error }]);
});

test("unknown producer-local fields still use the MINOR fallback", () => {
  const a = allow();
  const b = { ...a, producer_extension: { note: "local detail" } };
  const res = run([write("unknown-a.json", a), write("unknown-b.json", b), "--json"]);
  assert.equal(res.code, 0, res.out);
  const j = JSON.parse(res.out);
  assert.deepEqual(j.authorization, []);
  assert.deepEqual(j.minor, [{ field: "producer_extension", b: b.producer_extension, note: "added" }]);
});


test("unknown null presence: added and removed are MINOR", () => {
  const a = allow(), b = { ...a, extra_probe: null };
  for (const [left, right, note] of [[a, b, "added"], [b, a, "removed"]]) {
    const res = run([write("presence-a.json", left), write("presence-b.json", right), "--json"]);
    assert.equal(res.code, 0, res.out);
    const j = JSON.parse(res.out);
    assert.deepEqual(j.authorization, []);
    assert.deepEqual(j.minor, [{ field: "extra_probe", ...(note === "added" ? { b: null } : { a: null }), note }]);
  }
  const same = JSON.parse(run([write("presence-same-a.json", b), write("presence-same-b.json", b), "--json"]).out);
  assert.deepEqual(same.authorization, []);
  assert.deepEqual(same.minor, []);
});

test("duplicate grant count: AUTH drift in both directions", () => {
  const a = allow(), b = structuredClone(a);
  b.granted_capabilities.push(structuredClone(b.granted_capabilities[0]));
  b.kernel_inputs = { approvals: b.granted_capabilities.map(g => g.target), votes: "", grants: "", forecasts: "" };
  const file = write("duplicate-grant.json", b);
  const verified = execFileSync(process.execPath, [BIN, "verify", file], { encoding: "utf8" });
  assert.match(verified, /PASS  VERIFIED/);
  for (const [left, right, note] of [[a, b, "+1 grant(s)"], [b, a, "-1 grant(s)"]]) {
    const res = run([write("grant-count-a.json", left), write("grant-count-b.json", right), "--json"]);
    assert.equal(res.code, 1, res.out);
    const j = JSON.parse(res.out);
    assert.equal(j.result, "AUTHORIZATION DRIFT");
    assert.deepEqual(j.authorization, [{ field: "granted_capabilities", a: left.granted_capabilities, b: right.granted_capabilities, note }]);
  }
});

// Bypass receipts may omit grants or carry null; these are distinct from
// an empty grant multiset. Keep all 16 ordered pairs in the npm test chain.
const grantStates = ["absent", "null", "empty", "one"];
for (const leftState of grantStates) {
  for (const rightState of grantStates) {
    test(`bypass grant states: ${leftState} -> ${rightState}`, async () => {
      const F = await fmt();
      const receipt = (state) => {
        const r = JSON.parse(fs.readFileSync(FIX("receipt-bypass.json"), "utf8"));
        if (state === "null") r.granted_capabilities = null;
        if (state === "empty") r.granted_capabilities = [];
        if (state === "one") r.granted_capabilities = [allow().granted_capabilities[0]];
        assert.equal(F.validateReceipt(r).ok, true, `${state} must be schema-valid`);
        return r;
      };
      const a = receipt(leftState), b = receipt(rightState);
      const res = run([write(`states-${leftState}-a.json`, a), write(`states-${rightState}-b.json`, b), "--json"]);
      const same = leftState === rightState;
      assert.equal(res.code, same ? 0 : 1, res.out);
      const j = JSON.parse(res.out);
      assert.deepEqual(j.minor, []);
      assert.equal(j.schema_drift, null);
      if (same) {
        assert.deepEqual(j.authorization, []);
        assert.equal(j.result, "NO AUTHORIZATION-SURFACE DRIFT");
      } else {
        const note = leftState === "absent" ? "added" : rightState === "absent" ? "removed"
          : leftState === "null" || rightState === "null" ? "value changed"
          : leftState === "empty" ? "+1 grant(s)" : "-1 grant(s)";
        assert.equal(j.result, "AUTHORIZATION DRIFT");
        assert.deepEqual(j.authorization, [{ field: "granted_capabilities",
          ...(leftState === "absent" ? {} : { a: a.granted_capabilities }),
          ...(rightState === "absent" ? {} : { b: b.granted_capabilities }), note }]);
      }
    });
  }
}
