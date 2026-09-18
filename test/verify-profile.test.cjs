// SPDX-License-Identifier: Apache-2.0
// Profile self-check (docs/VERIFY-PROFILES.md): this repo's verifier copy
// declares VERIFY_PROFILE = "P-REF", and its behaviour on the local fixtures
// matches the P-REF row of the spec table (test/corpus/verify-profiles.json).
// This is the CI-enforceable half of the profile teeth: the fleet
// differentials (manual, fleet-root) check cross-repo agreement; this checks
// that THIS copy is on its own declared profile using only local files.
//
// If a leg here goes red, the copy is OFF ITS DECLARED PROFILE. That is a
// finding to report — not a test to re-green by editing the declaration or
// the spec table (VERIFY-PROFILES.md §8).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const KIT_ROOT = path.resolve(__dirname, "..");
const verifier = require(path.join(KIT_ROOT, "src", "verify.cjs"));
const SPEC = JSON.parse(fs.readFileSync(
  path.join(__dirname, "corpus", "verify-profiles.json"), "utf8"));

// Run verify() with console captured; return { ok, output }.
async function runVerify(file) {
  const buf = [];
  const ol = console.log, oe = console.error;
  console.log = (...a) => buf.push(a.join(" "));
  console.error = (...a) => buf.push(a.join(" "));
  let ok;
  try { ok = await verifier.verify(file); }
  finally { console.log = ol; console.error = oe; }
  return { ok, output: buf.join("\n") };
}

function tmpMutated(baseName, mutate) {
  const r = JSON.parse(fs.readFileSync(path.join(KIT_ROOT, "fixtures", baseName), "utf8"));
  mutate(r);
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "kit-profile-"));
  const file = path.join(dir, baseName);
  fs.writeFileSync(file, JSON.stringify(r, null, 2) + "\n");
  return file;
}

test("declaration: VERIFY_PROFILE is P-REF, grammar-extractable, and matches the spec roster", () => {
  assert.equal(verifier.VERIFY_PROFILE, "P-REF");
  assert.equal(SPEC.roster.kit.profile, "P-REF");
  assert.equal(SPEC.roster.kit.declaration, "src/verify.cjs");
  // The fleet tools extract declarations by regex, not by import — the
  // declaration must satisfy the spec grammar in the declared file.
  const src = fs.readFileSync(path.join(KIT_ROOT, "src", "verify.cjs"), "utf8");
  const m = src.match(new RegExp(SPEC.declaration_regex));
  assert.ok(m, "VERIFY_PROFILE declaration not extractable by the spec regex");
  assert.equal(m[1], "P-REF");
});

test("spec mirror: the JSON table and the prose doc agree on version and profiles", () => {
  const doc = fs.readFileSync(path.join(KIT_ROOT, "docs", "VERIFY-PROFILES.md"), "utf8");
  assert.match(doc, new RegExp(`^Version ${SPEC.version} `, "m"),
    "docs/VERIFY-PROFILES.md version line != verify-profiles.json version — bump both together");
  for (const p of Object.keys(SPEC.profiles)) {
    assert.ok(doc.includes(p), `profile ${p} in the JSON mirror but not the doc`);
  }
  for (const [repo, row] of Object.entries(SPEC.roster)) {
    assert.ok(SPEC.profiles[row.profile], `roster ${repo} names unknown profile ${row.profile}`);
  }
});

test("P-REF behaviour: a config-less mediated receipt VERIFIES (the profile-distinguishing row)", async () => {
  // fixtures/receipt-allow.json is config-less by design (the
  // signed-config-known-gap): P-REF accepts it; every P-ENFORCE copy fails it.
  const r = await runVerify(path.join(KIT_ROOT, "fixtures", "receipt-allow.json"));
  assert.equal(r.ok, true, "P-REF must verify its own producer's config-less receipt");
  assert.match(r.output,
    /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("P-REF behaviour: the §11.1 fixture is REDUCED — distinct label, never the success banner", async () => {
  const r = await runVerify(path.join(KIT_ROOT, "fixtures", "receipt-unparseable.json"));
  assert.equal(r.ok, false, "reduced scope is not a pass (U4)");
  assert.match(r.output, /REDUCED SCOPE \(authorised-unparseable\)/);
  assert.doesNotMatch(r.output,
    /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("P-REF behaviour: binding tamper fails closed (U3)", async () => {
  const file = tmpMutated("receipt-allow.json", (r) => {
    // Flip the bound argument value: the re-derived canonical request no
    // longer matches the receipt's hashes; re-derivation must FAIL.
    r.arguments = { ...r.arguments, tampered: true };
  });
  const r = await runVerify(file);
  assert.equal(r.ok, false, "tampered arguments must never verify");
  assert.doesNotMatch(r.output,
    /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

// Independent spine-v2 corpus: no producer imports or copied serializer.
const crypto = require("node:crypto");
const { decide } = require("../kernel/runner.cjs");
const spineDir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "kit-spine-"));
const spineKeys = crypto.generateKeyPairSync("ed25519");
const spinePubkey = spineKeys.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
let spineBase;
async function spineReceipt(approved) {
  const cfg = await import("../kernel/seal-config.js");
  const tool = "demo.mutate", args = { line: "spine regression" };
  const config = { epoch: 1, safety: { approval: { control_file: "product-adapter", ttl_seconds: 120 },
    tools: [{ name: tool, mode: "guarded", match: { type: "always" }, target: [{ full_arguments: true }] }] },
    temporal: { policies: [] } };
  const approvals = approved ? [cfg.guardTarget(tool, args)] : [];
  const result = await decide(config, { tool, args, approvals, now: 1000 });
  return { seal_receipt: "v2", tool, action: approved ? "ALLOW" : "BLOCK", arguments: args, now: 1000,
    kernel_config: config, granted_capabilities: approvals.map(target => ({ target })),
    kernel_inputs: { approvals, votes: "", grants: "", forecasts: "" },
    verdict: result.verdict, reason: result.receipt.reason,
    replay: { args_sha256: hash(args), config_sha256: hash(config) } };
}
function spineWrite(name, receipt, rawMutation = s => s) {
  const unsigned = { ...receipt }; delete unsigned.signature;
  const signed = { ...unsigned, signature: { algorithm: "ed25519",
    value: crypto.sign(null, Buffer.from(JSON.stringify(unsigned)), spineKeys.privateKey).toString("hex") } };
  const file = path.join(spineDir, name + ".json");
  fs.writeFileSync(file, rawMutation(JSON.stringify(signed)));
  return file;
}
async function spineVerify(file, key = spinePubkey) {
  const lines = [], original = console.log, originalError = console.error;
  console.log = console.error = (...args) => lines.push(args.join(" "));
  try { return { ...await verifier.verifyDetailed(file, { receiptPubkey: key }), output: lines.join("\n") }; }
  finally { console.log = original; console.error = originalError; }
}

test("spine-v2: honest decisions and optional approval identity verify", async () => {
  spineBase = await spineReceipt(true);
  for (const [name, receipt] of [["allow", spineBase], ["block", await spineReceipt(false)],
    ["input-required", { ...await spineReceipt(false), action: "INPUT_REQUIRED" }],
    ["bound-allow", { ...spineBase, kernel_inputs: { ...spineBase.kernel_inputs,
      approval_handle_sha256: crypto.createHash("sha256").update("approval handle").digest("hex") } }]]) {
    assert.equal((await spineVerify(spineWrite(name, receipt))).exitCode, 0, name);
  }
  fs.writeFileSync(path.join(spineDir, "pubkey"), spinePubkey);
  if (process.env.SPINE_EVIDENCE_DIR) fs.writeFileSync(path.join(process.env.SPINE_EVIDENCE_DIR, "corpus-path"), spineDir);
});

const spineMutations = [
  ["p1-extra-replay-member", r => { r.replay.nonce = "extra"; }],
  ["p2-nonempty-grants", r => { r.kernel_inputs.grants = "tampered"; }],
  ["p3-nonempty-forecasts", r => { r.kernel_inputs.forecasts = "tampered"; }],
  ["p4-malformed-handle", r => { r.kernel_inputs.approval_handle_sha256 = "not-a-sha256"; }],
  ["p5-action-allow-verdict-block", r => { r.action = "ALLOW"; }, true],
  ["p6-extra-grant-field", r => { r.granted_capabilities[0].extra = true; }],
  ["p7-extra-kernel-inputs-member", r => { r.kernel_inputs.foo = "bar"; }],
  ["p8-numeric-action", r => { r.action = 1; }],
  ["p9-fabricated-reason", r => { r.reason = "because I said so"; }],
  ["p10-garbage-votes", r => { r.kernel_inputs.votes = "garbage-not-ndjson"; }],
];
for (const [name, mutate, blocked] of spineMutations) {
  test(`spine-v2: refuses producer-impossible ${name} even with a valid signature`, async () => {
    const receipt = blocked ? await spineReceipt(false) : structuredClone(spineBase);
    mutate(receipt);
    const result = await spineVerify(spineWrite(name, receipt));
    assert.equal(result.exitCode, 1, result.output);
    if (name === "p9-fabricated-reason") assert.match(result.output, /FAIL  kernel reason re-derives/);
  });
}

test("spine-v2: duplicate members at top level and nested depth fail closed", async () => {
  for (const [name, mutate] of [
    ["p12-duplicate-member", s => s.replace('{"seal_receipt":', '{"seal_receipt":"v2","seal_receipt":')],
    ["nested-duplicate", s => s.replace('"votes":""', '"votes":"hidden","votes":""')],
    ["escaped-duplicate", s => s.replace('"votes":""', '"vo\\u0074es":"hidden","votes":""')],
  ]) {
    const result = await spineVerify(spineWrite(name, spineBase, mutate));
    assert.equal(result.exitCode, 1);
    assert.match(result.output, /duplicate member/);
  }
});

test("spine-v2: nonhex target still fails verdict replay", async () => {
  const receipt = structuredClone(spineBase);
  receipt.granted_capabilities[0].target = "not-hex";
  receipt.kernel_inputs.approvals = ["not-hex"];
  const result = await spineVerify(spineWrite("p11-nonhex-target", receipt));
  assert.equal(result.exitCode, 1);
  assert.match(result.output, /FAIL  kernel verdict re-derives/);
});

test("spine-v2: ten signature and envelope tampers remain refused", async () => {
  const file = spineWrite("tamper-base", spineBase);
  const base = JSON.parse(fs.readFileSync(file, "utf8"));
  const other = JSON.parse(fs.readFileSync(spineWrite("other-body", { ...spineBase, reason: "other" }), "utf8"));
  const mutations = [
    r => { r.signature.value = (r.signature.value[0] === "0" ? "1" : "0") + r.signature.value.slice(1); },
    r => { r.reason += "x"; },
    r => { delete r.signature; },
    r => { r.signature.algorithm = "rsa"; },
    r => { r.signature.value = r.signature.value.slice(2); },
    r => { r.signature.value = other.signature.value; },
    r => {},
    r => { r.signature.key_id = "unexpected"; },
    r => { r.extra = true; },
    r => { r.signature = {}; },
  ];
  const wrongKey = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
  for (const [index, mutate] of mutations.entries()) {
    const receipt = structuredClone(base); mutate(receipt);
    const target = path.join(spineDir, `t${index + 1}.json`);
    fs.writeFileSync(target, JSON.stringify(receipt));
    const key = index === 6 ? wrongKey : spinePubkey;
    fs.writeFileSync(path.join(spineDir, `t${index + 1}.pubkey`), key);
    const result = await spineVerify(target, key);
    assert.equal(result.exitCode, 1, `tamper ${index + 1}: ${result.output}`);
    if (index === 1) assert.match(result.output, /FAIL  receipt Ed25519 signature/);
  }
});

test("spine-v2: signed policies and approval cardinality must match the worker", async () => {
  const receipt = structuredClone(spineBase);
  receipt.kernel_config.safety.approval.ttl_seconds = 121;
  receipt.replay.config_sha256 = hash(receipt.kernel_config);
  const policyResult = await spineVerify(spineWrite("nonworker-policy", receipt));
  assert.equal(policyResult.exitCode, 1);
  assert.match(policyResult.output, /FAIL  worker policy shape/);
  const repeated = structuredClone(spineBase);
  repeated.kernel_inputs.approvals.push(repeated.kernel_inputs.approvals[0]);
  repeated.granted_capabilities.push({ ...repeated.granted_capabilities[0] });
  const grantResult = await spineVerify(spineWrite("multiple-approvals", repeated));
  assert.equal(grantResult.exitCode, 1);
  assert.match(grantResult.output, /FAIL  worker approval targets/);
});

test("spine-v2: signed finite decimal arguments verify; non-finite wire numbers refuse", async () => {
  for (const value of [1.5, -0.125, 1e-7, 0, 42, Number.MAX_SAFE_INTEGER]) {
    const receipt = await spineReceipt(false);
    receipt.arguments = { values: [value] };
    const result = await decide(receipt.kernel_config, {
      tool: receipt.tool, args: receipt.arguments, approvals: [], now: receipt.now,
    });
    receipt.verdict = result.verdict;
    receipt.reason = result.receipt.reason;
    receipt.replay.args_sha256 = hash(receipt.arguments);
    const file = spineWrite(`finite-${value}`, receipt);
    const verified = await spineVerify(file);
    assert.equal(verified.exitCode, 0, verified.output);
    if (value === 1.5) {
      for (const token of ["1e9999", "-1e9999", "NaN"]) {
        const malformed = spineWrite(`nonfinite-${token}`, receipt,
          text => text.replace('"values":[1.5]', `"values":[${token}]`));
        const refused = await spineVerify(malformed);
        assert.equal(refused.exitCode, 1, refused.output);
        assert.match(refused.output, /only finite JSON numbers|cannot read receipt/);
      }
    }
  }
});
