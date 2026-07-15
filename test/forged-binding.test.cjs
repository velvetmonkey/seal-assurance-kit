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
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

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

test("the untampered fixtures still verify (blue control)", () => {
  for (const name of ["receipt-unparseable.json", "receipt-allow.json"]) {
    const result = runVerify(loadFixture(name));
    assert.equal(result.status, 0, `${name}: ${result.stdout}${result.stderr}`);
  }
});
