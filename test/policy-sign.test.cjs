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
  assert.match(rejectedOutput, /1 guarded, 1 allow\(unverified\), 1 unknown→guarded — sign anyway\? \[y\/N\]/);
  assert.match(rejectedOutput, /signing cancelled/);
  assert.equal(fs.existsSync(out), false);

  const accepted = spawnSync(process.execPath, [cli, "policy", "sign", input, "--key", key, "--out", out, "--yes"], { encoding: "utf8" });
  const acceptedOutput = `${accepted.stdout || ""}${accepted.stderr || ""}`;
  assert.equal(accepted.status, 0, acceptedOutput);
  assert.match(acceptedOutput, /ACKNOWLEDGED  --yes supplied/);
  assert.equal(fs.existsSync(out), true);
});
