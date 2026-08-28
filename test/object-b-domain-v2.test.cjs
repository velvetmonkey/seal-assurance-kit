// SPDX-License-Identifier: Apache-2.0
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verify(message, signature, publicKey) {
  const key = crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKey)]),
    format: "der", type: "spki",
  });
  return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
}

function fixture(name) {
  return fs.readFileSync(path.resolve(__dirname, "../fixtures", name), "utf8");
}

async function format() {
  return import("file://" + path.resolve(__dirname, "../kernel/receipt-format.js"));
}

// Existing v1 evidence, copied byte-for-byte from seal-check's tracked
// test/fixtures/host-v3-block.receipt.json at d1969e3a. It uses the retired
// signature.key_id member, so the current exact-shape rule must refuse it.
test("an existing host Object B v1 receipt with signature.key_id is refused", async () => {
  const F = await format();
  const result = F.validateReceipt(fixture("object-b-v1-host.json"), { ed25519Verify });
  assert.equal(result.ok, false);
  assert.equal(result.receipt_signature_valid, false);
  assert.match(result.errors.join("; "), /signature: exactly the members/);
  console.log("V1_FIXTURE_REFUSED signature.key_id");
});

// Issued by seal-host at 04f7ba83 through `./demo/run c1`; this is not a
// locally invented signature or a v1 fixture with its label edited. It uses
// the retired signature.key_id member, so the current exact-shape rule refuses it.
test("a seal-host 04f7ba83 Object B v2 receipt with signature.key_id is refused", async () => {
  const F = await format();
  const result = F.validateReceipt(fixture("object-b-v2-host-04f7ba83.json"), { ed25519Verify });
  assert.equal(result.ok, false);
  assert.equal(result.receipt_signature_valid, false);
  assert.match(result.errors.join("; "), /signature: exactly the members/);
  console.log("V2_FIXTURE_REFUSED signature.key_id host=04f7ba83");
});

test("real v1 and v2 signatures fail when presented under the other domain", async () => {
  const F = await format();
  for (const [name, claimedDomain, expectedCheck] of [
    ["object-b-v2-host-04f7ba83.json", "seal.object-b/v1",
      /signature\.value: Ed25519 verification failed over the seal\.object-b\/v1 preimage/],
    ["object-b-v1-host.json", "seal.object-b/v2",
      /signature\.value: cannot construct seal\.object-b\/v2 preimage/],
  ]) {
    const record = JSON.parse(fixture(name));
    delete record.signature.key_id;
    const signedDomain = record.signature.domain;
    record.signature.domain = claimedDomain;
    const result = F.validateReceipt(JSON.stringify(record), { ed25519Verify });
    assert.equal(result.ok, false);
    assert.equal(result.receipt_signature_valid, false);
    const namedCheck = result.errors.find((error) => expectedCheck.test(error));
    assert.ok(namedCheck, result.errors.join("; "));
    console.log(`CROSS_DOMAIN_REFUSED signed=${signedDomain} claimed=${claimedDomain} check=${namedCheck}`);
  }
});
