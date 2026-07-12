// SPDX-License-Identifier: Apache-2.0
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateMatch(match, where, errors) {
  if (!isObject(match) || typeof match.type !== "string") {
    errors.push(`${where}: match object with type required`);
    return;
  }
  if (["always"].includes(match.type)) return;
  if (["equals", "starts_with"].includes(match.type)) {
    if (typeof match.arg !== "string" || !match.arg) errors.push(`${where}.arg: non-empty string required`);
    if (typeof match.value !== "string") errors.push(`${where}.value: string required`);
    return;
  }
  if (match.type === "contains_any_ci") {
    if (typeof match.arg !== "string" || !match.arg) errors.push(`${where}.arg: non-empty string required`);
    if (!Array.isArray(match.needles) || !match.needles.every((v) => typeof v === "string"))
      errors.push(`${where}.needles: string array required`);
    return;
  }
  if (["all", "any"].includes(match.type)) {
    if (!Array.isArray(match.matches) || match.matches.length === 0) {
      errors.push(`${where}.matches: non-empty match array required`);
      return;
    }
    match.matches.forEach((child, index) => validateMatch(child, `${where}.matches[${index}]`, errors));
    return;
  }
  errors.push(`${where}.type: unsupported match type ${JSON.stringify(match.type)}`);
}

function validatePolicy(policy) {
  const errors = [];
  if (!isObject(policy)) return { ok: false, errors: ["policy must be an object"] };
  if (!Number.isInteger(policy.epoch) || policy.epoch < 1) errors.push("epoch: integer >= 1 required");
  if ("server" in policy && (typeof policy.server !== "string" || !policy.server))
    errors.push("server: non-empty string when present");
  if (!isObject(policy.safety)) errors.push("safety: object required");
  const approval = policy.safety?.approval;
  if (!isObject(approval)) errors.push("safety.approval: object required");
  else {
    if (typeof approval.control_file !== "string") errors.push("safety.approval.control_file: string required");
    if ("ttl_seconds" in approval && (!Number.isInteger(approval.ttl_seconds) || approval.ttl_seconds < 0))
      errors.push("safety.approval.ttl_seconds: non-negative integer required");
  }
  const tools = policy.safety?.tools;
  if (!Array.isArray(tools)) errors.push("safety.tools: array required");
  else tools.forEach((rule, index) => {
    const where = `safety.tools[${index}]`;
    if (!isObject(rule)) { errors.push(`${where}: object required`); return; }
    if (typeof rule.name !== "string" || !rule.name) errors.push(`${where}.name: non-empty string required`);
    if (!["allow", "guard", "guarded", "deny"].includes(rule.mode))
      errors.push(`${where}.mode: allow|guard|guarded|deny required`);
    validateMatch(rule.match || { type: "always" }, `${where}.match`, errors);
    if (rule.mode === "guard" || rule.mode === "guarded") {
      if (!Array.isArray(rule.target) || rule.target.length === 0)
        errors.push(`${where}.target: non-empty array required for guarded rules`);
      else rule.target.forEach((part, partIndex) => {
        if (!isObject(part)) { errors.push(`${where}.target[${partIndex}]: object required`); return; }
        const choices = [typeof part.literal === "string", typeof part.arg === "string", part.full_arguments === true]
          .filter(Boolean).length;
        if (choices !== 1) errors.push(`${where}.target[${partIndex}]: exactly one literal, arg, or full_arguments:true required`);
      });
    }
  });
  return { ok: errors.length === 0, errors };
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
  return { policyPath, payload: JSON.stringify(policy), summary: summarizePolicy(policy) };
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
