// SPDX-License-Identifier: Apache-2.0
// RED teeth for interim C1: principal attribution is never PASS VERIFIED on
// the strength of a receipt-carried, self-selected config signer.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

function keyPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  const pubkey = Buffer.from(pair.publicKey.export({ type: "spki", format: "der" }))
    .subarray(-32).toString("hex");
  return { ...pair, pubkey };
}

function signedReceipt({ principal = true, pair = keyPair() } = {}) {
  const receipt = JSON.parse(fs.readFileSync(
    path.join(ROOT, "fixtures", "receipt-allow.json"), "utf8"));
  if (principal) receipt.principal = "alice";
  const payload = JSON.stringify(receipt.kernel_config);
  receipt.signed_config = {
    payload,
    signature: crypto.sign(null, Buffer.from(payload, "utf8"), pair.privateKey).toString("hex"),
    pubkey: pair.pubkey,
  };
  return { receipt, pair };
}

function runVerify(receipt, expectedConfigPubkey) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-authority-gate-"));
  const file = path.join(dir, "receipt.json");
  fs.writeFileSync(file, JSON.stringify(receipt, null, 2) + "\n");
  const args = [path.join(ROOT, "bin/seal"), "verify", file];
  if (expectedConfigPubkey !== undefined)
    args.push("--expected-config-pubkey", expectedConfigPubkey);
  const result = spawnSync(process.execPath, args, { encoding: "utf8" });
  fs.rmSync(dir, { recursive: true, force: true });
  return { ...result, output: `${result.stdout || ""}${result.stderr || ""}` };
}

test("RED C1: rogue self-signed-config principal receipt is REDUCED SCOPE, never PASS VERIFIED", () => {
  const { receipt } = signedReceipt();
  const result = runVerify(receipt);
  assert.equal(result.status, 4, result.output);
  assert.match(result.output, /REDUCED SCOPE \(principal config authority not established\)/);
  assert.match(result.output, /no pinned operator config-signing key supplied/);
  assert.doesNotMatch(result.output, /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("RED C1: wrong operator pin also reduces a valid principal receipt instead of failing it", () => {
  const { receipt } = signedReceipt();
  const wrongOperator = keyPair();
  const result = runVerify(receipt, wrongOperator.pubkey);
  assert.equal(result.status, 4, result.output);
  assert.match(result.output, /config signer .* does not match pinned operator key/);
  assert.doesNotMatch(result.output, /FAIL {2}NOT VERIFIED/);
  assert.doesNotMatch(result.output, /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("RED C1: genuine principal receipt with the pinned operator key may PASS VERIFIED", () => {
  const operator = keyPair();
  const { receipt } = signedReceipt({ pair: operator });
  const result = runVerify(receipt, operator.pubkey);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /PASS {2}principal config signer matches pinned operator authority/);
  assert.match(result.output, /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("RED C1: parseable receipt with an invalid carried config signature hard-fails", () => {
  const { receipt } = signedReceipt({ principal: false });
  const last = receipt.signed_config.signature.at(-1);
  receipt.signed_config.signature = receipt.signed_config.signature.slice(0, -1) +
    (last === "0" ? "1" : "0");
  const result = runVerify(receipt);
  assert.equal(result.status, 1, result.output);
  assert.match(result.output, /FAIL {2}mediated policy Ed25519-signed and equals kernel_config/);
  assert.match(result.output, /signed_config Ed25519 signature invalid/);
  assert.match(result.output, /FAIL {2}NOT VERIFIED/);
  assert.doesNotMatch(result.output, /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("P-REF control: valid signed_config without principal needs no operator pin", () => {
  const { receipt } = signedReceipt({ principal: false });
  const result = runVerify(receipt);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /PASS {2}mediated policy Ed25519-signed and equals kernel_config/);
  assert.match(result.output, /PASS {2}VERIFIED \(bundled self-check; not independent verification\)/);
});

test("RED C1: VERIFIED, REDUCED SCOPE, and FAIL use distinct exits 0, 4, and 1", () => {
  const operator = keyPair();
  const { receipt: genuine } = signedReceipt({ pair: operator });
  const { receipt: unpinned } = signedReceipt();
  const invalid = structuredClone(genuine);
  invalid.signed_config.signature = "00".repeat(64);
  assert.equal(runVerify(genuine, operator.pubkey).status, 0);
  assert.equal(runVerify(unpinned).status, 4);
  assert.equal(runVerify(invalid, operator.pubkey).status, 1);
});
