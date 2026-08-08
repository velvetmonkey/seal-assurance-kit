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

async function signedV3Block() {
  const F = await import("file://" + path.resolve(__dirname, "../kernel/receipt-format.js"));
  const v2 = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../fixtures/receipt-block.json"), "utf8"));
  delete v2.seal_receipt;
  const record = {
    record_type: "seal.authorization-decision",
    record_version: 3,
    ...v2,
    release_status: "NOT_APPLICABLE",
    operation_id: "ab".repeat(32),
    durability_class: "asserted_local_fsync",
  };
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const signature = crypto.sign(null, Buffer.from(F.receiptSignaturePreimage(record)), privateKey);
  record.signature = {
    domain: F.RECEIPT_SIGNATURE_DOMAIN,
    algorithm: "Ed25519",
    public_key: publicKeyRaw.toString("hex"),
    key_id: F.sha256Hex(publicKeyRaw),
    encoding: "base64url-nopad",
    value: signature.toString("base64url"),
  };
  return { F, record };
}

test("P-REF recognizes and cryptographically validates a config-less v3 BLOCK", async () => {
  const { F, record } = await signedV3Block();
  assert.equal("signed_config" in record, false);
  const result = F.validateReceipt(JSON.stringify(record), { ed25519Verify });
  assert.deepEqual(
    { ok: result.ok, version: result.version, errors: result.errors,
      receipt_signature_valid: result.receipt_signature_valid, document_checked: result.document_checked },
    { ok: true, version: "v3", errors: [], receipt_signature_valid: true, document_checked: true },
  );
});

test("v3 fails closed without an Ed25519 primitive", async () => {
  const { F, record } = await signedV3Block();
  const result = F.validateReceipt(record);
  assert.equal(result.ok, false);
  assert.equal(result.version, "v3");
  assert.equal(result.receipt_signature_valid, false);
  assert.match(result.errors.join("; "), /UNVERIFIED/);
});

test("unknown versions and conflicting discriminator families remain refused", async () => {
  const { F, record } = await signedV3Block();
  const unknown = structuredClone(record);
  unknown.record_version = 4;
  assert.deepEqual(F.validateReceipt(unknown), {
    ok: false, version: null, errors: ["no recognized version discriminator"], document_checked: false,
  });

  const conflict = structuredClone(record);
  conflict.seal_receipt = "v2";
  const result = F.validateReceipt(conflict, { ed25519Verify });
  assert.equal(result.ok, false);
  assert.equal(result.version, null);
  assert.match(result.errors[0], /conflicting version discriminators/);
});
