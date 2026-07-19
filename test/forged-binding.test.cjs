// SPDX-License-Identifier: Apache-2.0
// RED tests for the kernel-attested request binding.
//
// The defect this guards against: kernel material paired with a DIFFERENT
// request than the kernel judged. Before the kernel committed to the judged
// bytes (Host/Audit.lean request_sha256), nothing could catch that pairing
// lying — flipping request_sha256 on an unparseable receipt still verified.
// Both cases below must fail closed, or Items 1-3 of the kernel-request-
// commitment change are decoration.
const test = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
// The pinned wasm the verifier re-hashes against; read from a fixture so a pin
// bump does not silently invalidate the forge (which must clear kernel identity
// to reach the unparseable path — the point is that identity is not the defence).
const PINNED_WASM = JSON.parse(
  fs.readFileSync(path.join(ROOT, "fixtures", "receipt-unparseable.json"), "utf8")
).kernel_identity.wasm_sha256;

// The crown-jewel P0 (red-team round 2, council 144f497f Grok T1; reproduced by
// Monkey 2026-07-16): a FORGED unparseable ALLOW. Every field is
// attacker-chosen and internally self-consistent — the audit maps to ALLOW, its
// certs match, and its request_sha256 equals the receipt's — but no kernel ever
// ran and no policy is signed. The pre-fix unparseable branch printed
// "PASS VERIFIED" and returned allGood=true (exit 0). It must now fail closed.
function forgedUnparseableAllow() {
  const H = crypto.createHash("sha256")
    .update('{"attacker":"chosen raw line the kernel never judged"}').digest("hex");
  const certs = [{ certHash: "111", kernel: "safety", reason: "forged", verdict: "allow" }];
  const audit = { certs, epoch: 1, request_sha256: H, tool: "db.execute", verdict: "allow" };
  const emitted = JSON.stringify({
    audit: JSON.stringify(audit),
    response: '{"id":1,"jsonrpc":"2.0","result":{"content":[],"isError":false}}\n',
    route: "forward",
  });
  return {
    seal_receipt: "v2", now: 1784110716264, request_sha256: H,
    request_parse_error: "cannot parse mediated request for receipt: attacker-crafted unparseable line",
    bypass: false, verdict: "ALLOW", authorization: "explicit_policy_allow",
    reason: "forged explicit policy allow", deny_kernel: null, certs, emitted_bytes: emitted,
    kernel_identity: { wasm_sha256: PINNED_WASM, self_verified: true },
    kernel_config: { epoch: 1, safety: { approval: { control_file: "/x", ttl_seconds: 120 }, tools: [] } },
    granted_capabilities: [],
  };
}

function runVerify(receipt) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "forged-binding-"));
  const file = path.join(dir, "receipt.json");
  fs.writeFileSync(file, JSON.stringify(receipt, null, 2) + "\n");
  const result = spawnSync(process.execPath, [path.join(ROOT, "bin/seal"), "verify", file], {
    encoding: "utf8",
  });
  fs.rmSync(dir, { recursive: true, force: true });
  return result;
}

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", name), "utf8"));
}

function flipHexDigit(hex) {
  const last = hex[hex.length - 1];
  return hex.slice(0, -1) + (last === "0" ? "1" : "0");
}

test("forged pairing on an unparseable receipt is refused (request_sha256 flipped)", () => {
  const receipt = loadFixture("receipt-unparseable.json");
  receipt.request_sha256 = flipHexDigit(receipt.request_sha256);
  const result = runVerify(receipt);
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /FAIL {2}kernel-attested request binding/);
});

test("forged kernel material on a parseable receipt is refused (audit hash spliced)", () => {
  const receipt = loadFixture("receipt-allow.json");
  const emitted = JSON.parse(receipt.emitted_bytes);
  const audit = JSON.parse(emitted.audit);
  assert.match(String(audit.request_sha256), /^[0-9a-f]{64}$/,
    "fixture audit must carry the kernel request commitment");
  audit.request_sha256 = flipHexDigit(audit.request_sha256);
  emitted.audit = JSON.stringify(audit);
  receipt.emitted_bytes = JSON.stringify(emitted);
  const result = runVerify(receipt);
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /FAIL {2}kernel-attested request binding/);
});

test("P0: a forged unparseable ALLOW (no kernel replay, no signed config) is NOT verified", () => {
  const result = runVerify(forgedUnparseableAllow());
  assert.notEqual(result.status, 0,
    "forged unparseable ALLOW must not exit 0: " + result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout, /PASS {2}VERIFIED/, "the forge must never be stamped VERIFIED");
  assert.match(result.stdout, /FAIL {2}NOT VERIFIED/,
    "a config-less forge is a hard FAIL, not merely reduced scope");
  assert.match(result.stdout, /signed_config absent or malformed/,
    "the load-bearing refusal is the missing Ed25519-signed config");
});

test("the untampered PARSEABLE fixture still verifies (blue control)", () => {
  const result = runVerify(loadFixture("receipt-allow.json"));
  assert.equal(result.status, 0, `receipt-allow.json: ${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /PASS {2}VERIFIED/);
});

test("a LEGITIMATE unparseable receipt is honest REDUCED SCOPE, not a false failure", () => {
  const result = runVerify(loadFixture("receipt-unparseable.json"));
  // Reduced scope is NOT-passing (no independent replay is possible on a line
  // that cannot be re-parsed), so exit is non-zero — a CI gate must not treat it
  // as verified. But it is NOT invalid/malformed: every reduced check, including
  // the Ed25519-signed config, passes, and the summary is REDUCED SCOPE, never
  // "FAIL NOT VERIFIED". This is the distinction the P0 fix must preserve.
  assert.equal(result.status, 4, "reduced scope has its own exit state: " + result.stdout);
  assert.match(result.stdout, /REDUCED SCOPE \(authorised-unparseable\)/, result.stdout);
  assert.doesNotMatch(result.stdout, /FAIL {2}NOT VERIFIED/,
    "a legitimate unparseable receipt must not be failed as if invalid");
  assert.doesNotMatch(result.stdout, /PASS {2}VERIFIED/, "reduced scope is never VERIFIED");
});
