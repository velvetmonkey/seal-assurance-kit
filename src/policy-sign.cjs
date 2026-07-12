// SPDX-License-Identifier: Apache-2.0
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { validateTrustedConfig } = require("./trusted-config.cjs");

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function validatePolicy(policy) {
  return validateTrustedConfig(policy);
}

function signingKey(seedHex) {
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) throw new Error("signing key must contain one 32-byte Ed25519 seed in hex");
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKey(privateKey) {
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(-32);
}

function summarizePolicy(policy) {
  const tools = policy.safety.tools;
  const guarded = tools.filter((rule) => rule.mode === "guard" || rule.mode === "guarded");
  const allowUnverified = tools.filter((rule) => rule.mode === "allow");
  const unknownGuarded = guarded.filter((rule) => {
    const reason = rule._seal_scaffold?.reason;
    return reason !== "destructive" && reason !== "conflict";
  });
  return {
    guarded: guarded.length,
    allowUnverified: allowUnverified.length,
    unknownGuarded: unknownGuarded.length,
  };
}

function preparePolicy(policyPath) {
  let policy;
  try { policy = JSON.parse(fs.readFileSync(policyPath, "utf8")); }
  catch (error) { throw new Error(`cannot read policy: ${error.message}`); }
  const shape = validatePolicy(policy);
  if (!shape.ok) throw new Error(`policy validation failed: ${shape.errors.join("; ")}`);
  return {
    policyPath,
    payload: JSON.stringify(policy),
    summary: summarizePolicy(policy),
    participation: shape.participation,
  };
}

function signPreparedPolicy(prepared, { keyPath, outputPath }) {
  const seed = fs.readFileSync(keyPath, "utf8").trim();
  const privateKey = signingKey(seed);
  const publicKey = rawPublicKey(privateKey);
  const payload = prepared.payload;
  const signature = crypto.sign(null, Buffer.from(payload, "utf8"), privateKey).toString("hex");
  const envelope = JSON.stringify({ payload, signature }) + "\n";
  const out = outputPath || `${prepared.policyPath}.signed.json`;
  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, envelope, { mode: 0o600 });
  return {
    output: out,
    publicKey: publicKey.toString("hex"),
    policyHash: crypto.createHash("sha256").update(payload).digest("hex"),
  };
}

function signPolicy(policyPath, options) {
  return signPreparedPolicy(preparePolicy(policyPath), options);
}

module.exports = {
  preparePolicy,
  signPolicy,
  signPreparedPolicy,
  summarizePolicy,
  validatePolicy,
};
