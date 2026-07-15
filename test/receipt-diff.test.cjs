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
  return import("file://" + path.join(ROOT, "kernel", "receipt-format.js"));
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
  assert.match(out, /stale or tampered/);
  assert.match(out, /INTEGRITY FLAG/);
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
