// SPDX-License-Identifier: Apache-2.0
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { signPolicy, validatePolicy } = require("../src/policy-sign.cjs");

const policy = {
  epoch: 1,
  server: "dbhub-main",
  safety: {
    approval: { control_file: "/tmp/unused", ttl_seconds: 120 },
    tools: [
      { name: "search_objects", mode: "allow", match: { type: "always" } },
      { name: "execute_sql", mode: "guard", match: { type: "always" }, target: [{ full_arguments: true }] },
    ],
  },
};

test("policy signer validates and emits a verifiable exact-payload envelope", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-policy-sign-"));
  const input = path.join(dir, "policy.json"), key = path.join(dir, "key"), out = path.join(dir, "trusted.json");
  fs.writeFileSync(input, JSON.stringify(policy, null, 2));
  fs.writeFileSync(key, "07".repeat(32));
  const result = signPolicy(input, { keyPath: key, outputPath: out });
  const envelope = JSON.parse(fs.readFileSync(out, "utf8"));
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(result.publicKey, "hex")]),
    format: "der", type: "spki",
  });
  assert.equal(crypto.verify(null, Buffer.from(envelope.payload), publicKey, Buffer.from(envelope.signature, "hex")), true);
  assert.deepEqual(JSON.parse(envelope.payload), policy);
  assert.equal(result.policyHash.length, 64);
});

// --- 7-kernel bundle round-trip (a3790181 vocabulary) ------------------------
// The verified parser (mcp-seal-dev Seal/PolicyBundle.lean, kernel a3790181)
// accepts one declarative section per non-Safety kernel with per-section
// `enabled`, and hard-errors on unknown keys at section and entry level. These
// teeth prove the kit's sign+validate accepts exactly that shape, the signed
// payload round-trips byte-exactly, and the REAL shipped wasm loads the result.
const bundlePolicy = {
  epoch: 1,
  server: "dbhub-main",
  safety: {
    approval: { control_file: "/tmp/unused", ttl_seconds: 120, replay_store: { sqlite_path: "/tmp/replay-store.sqlite" } },
    tools: [
      { name: "docs.read", mode: "allow", match: { type: "always" } },
      { name: "write_item", mode: "guard", match: { type: "always" }, target: [{ full_arguments: true }] },
    ],
  },
  temporal: { enabled: true, policies: [
    { name: "freeze-after-revoke", type: "no_after", trigger: ["revoke"], forbidden: ["write_item"] }] },
  consensus: { enabled: false, roster: [1, 2, 3], votes_file: "/path/votes.ndjson", high_stakes: ["deploy"] },
  convergence: { enabled: true, tools: [{ tool: "store.update", op_arg: "operation.kind" }] },
  calibration: { enabled: false, delta_num: 1, delta_den: 20, min_samples: 100,
    records_file: "/path/forecasts.ndjson", gated_tools: ["auto_publish"] },
  linear: { enabled: true, grants_file: "/path/grants.ndjson", tools: [{ tool: "spend", cap_arg: "capability.id" }] },
  budget: { enabled: true, budgets: [
    { name: "write-units", cap: 100, tools: ["write_item"], cost_arg: "usage.units" }] },
};

test("7-kernel bundle: sign round-trips exactly and the shipped kernel accepts the envelope", async () => {
  const shape = validatePolicy(bundlePolicy);
  assert.equal(shape.ok, true, shape.errors.join("; "));
  const states = Object.fromEntries(shape.participation.states.map((entry) => [entry.symbol, entry.status]));
  // enabled semantics: T active (enabled, non-vacuous), C inactive (enabled:false
  // collapses to absent), V/L/B active, K inactive (explicit enabled:false —
  // the distinct present-but-disabled state).
  assert.deepEqual(states, { S: "active", T: "active", C: "inactive", V: "active", K: "inactive", L: "active", B: "active" });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-bundle-sign-"));
  const input = path.join(dir, "bundle.json"), key = path.join(dir, "key"), out = path.join(dir, "trusted.json");
  fs.writeFileSync(input, JSON.stringify(bundlePolicy, null, 2));
  fs.writeFileSync(key, "07".repeat(32));
  const result = signPolicy(input, { keyPath: key, outputPath: out });
  const envelope = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.deepEqual(JSON.parse(envelope.payload), bundlePolicy); // byte-exact round-trip

  // Drive the REAL vendored wasm: sign output must be loadable by the kernel.
  const WASM_DIR = path.resolve(__dirname, "..", "kernel", "wasm");
  globalThis.require = require;
  globalThis.__dirname = WASM_DIR;
  (0, eval)(fs.readFileSync(path.join(WASM_DIR, "seal.js"), "utf8"));
  const M = await globalThis.SealModule({ locateFile: (p) => path.join(WASM_DIR, p), print() {}, printErr() {} });
  const initResult = JSON.parse(M.ccall("seal_init", "string", ["string", "string"],
    [JSON.stringify({ payload: envelope.payload, signature: envelope.signature }), result.publicKey]));
  assert.equal(initResult.ok, true, `kernel rejected the kit-signed bundle: ${JSON.stringify(initResult)}`);
});

test("bundle validation matches the kernel's hard errors (negatives)", () => {
  // safety rejects `enabled` (Safety is never off by design)
  const safetyEnabled = structuredClone(bundlePolicy);
  safetyEnabled.safety.enabled = true;
  assert.equal(validatePolicy(safetyEnabled).ok, false);
  assert.match(validatePolicy(safetyEnabled).errors.join("; "), /safety: unknown key "enabled"/);

  // unknown section key = hard error in the kernel; the signer must refuse too
  const unknownSectionKey = structuredClone(bundlePolicy);
  unknownSectionKey.consensus.extra = 1;
  assert.match(validatePolicy(unknownSectionKey).errors.join("; "), /consensus: unknown key "extra"/);

  // entry-level unknown key — the golden-path landmine shape: _comment inside a
  // budget entry (kernel: "unknown key '_comment' in budget spec")
  const budgetComment = structuredClone(bundlePolicy);
  budgetComment.budget.budgets[0]._comment = "reviewed cap";
  assert.match(validatePolicy(budgetComment).errors.join("; "), /budget\.budgets\[0\]: unknown key "_comment"/);

  // enabled must be boolean
  const badEnabled = structuredClone(bundlePolicy);
  badEnabled.temporal.enabled = "yes";
  assert.match(validatePolicy(badEnabled).errors.join("; "), /temporal\.enabled: boolean/);

  // replay_store must match the host contract: null or {sqlite_path: non-empty}
  const badReplayStore = structuredClone(bundlePolicy);
  badReplayStore.safety.approval.replay_store = "/tmp/not-an-object";
  assert.match(validatePolicy(badReplayStore).errors.join("; "), /replay_store: null or object/);

  // calibration defaults OFF (EXPERIMENTAL, opt-in twice): flag absent => inactive
  const calibrationDefault = structuredClone(bundlePolicy);
  delete calibrationDefault.calibration.enabled;
  const shape = validatePolicy(calibrationDefault);
  assert.equal(shape.ok, true, shape.errors.join("; "));
  const calState = shape.participation.states.find((entry) => entry.symbol === "K");
  assert.equal(calState.status, "inactive");
  assert.match(calState.reason, /defaults to false/);
});

test("policy validation rejects an unbound guard", () => {
  const bad = structuredClone(policy);
  bad.safety.tools[1].target = [];
  const result = validatePolicy(bad);
  assert.equal(result.ok, false);
  assert.match(result.errors.join("; "), /non-empty array/);
});

test("CLI sign confirmation blocks N and --yes explicitly acknowledges for CI", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-policy-confirm-"));
  const input = path.join(dir, "policy.json"), key = path.join(dir, "key"), out = path.join(dir, "trusted.json");
  fs.writeFileSync(input, JSON.stringify(policy, null, 2));
  fs.writeFileSync(key, "07".repeat(32));
  const cli = path.resolve(__dirname, "..", "bin", "seal");
  const quote = (value) => `'${String(value).replaceAll("'", `'"'"'`)}'`;
  const command = `${quote(process.execPath)} ${quote(cli)} policy sign ${quote(input)} --key ${quote(key)} --out ${quote(out)}`;
  const rejected = spawnSync("script", ["-qec", command, "/dev/null"], { input: "N\n", encoding: "utf8" });
  const rejectedOutput = `${rejected.stdout || ""}${rejected.stderr || ""}`;
  assert.notEqual(rejected.status, 0, rejectedOutput);
  assert.match(rejectedOutput, /EFFECTIVE KERNEL PARTICIPATION \(signed payload\)/);
  assert.match(rejectedOutput, /ACTIVE \(1\):[\s\S]*Safety \(S\)/);
  assert.match(rejectedOutput, /ABSENT\/OFF \(6\):/);
  assert.match(rejectedOutput, /1 guarded, 1 allow\(unverified\), 1 unknown→guarded — acknowledge effective participation and sign anyway\? \[y\/N\]/);
  assert.match(rejectedOutput, /signing cancelled/);
  assert.equal(fs.existsSync(out), false);

  const accepted = spawnSync(process.execPath, [cli, "policy", "sign", input, "--key", key, "--out", out, "--yes"], { encoding: "utf8" });
  const acceptedOutput = `${accepted.stdout || ""}${accepted.stderr || ""}`;
  assert.equal(accepted.status, 0, acceptedOutput);
  assert.match(acceptedOutput, /ACKNOWLEDGED  --yes supplied/);
  assert.equal(fs.existsSync(out), true);
});
