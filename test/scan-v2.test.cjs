// SPDX-License-Identifier: Apache-2.0
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { classify } = require("../src/scan.cjs");

const policy = (mode) => ({ safety: { tools: [{
  name: "read_file",
  mode,
  match: { type: "starts_with", arg: "path", value: "/safe/" },
}] } });

test("conditional read allow is reported as bounded by default deny", () => {
  const result = classify({ name: "read_file", annotations: { readOnlyHint: true } }, policy("allow"));
  assert.equal(result.bucket, "readonly");
  assert.match(result.guard, /conditional; no-match denies/);
});

test("conditional allow never blesses a mutating operation", () => {
  const result = classify({ name: "read_file", annotations: { destructiveHint: true } }, policy("allow"));
  assert.equal(result.bucket, "allowed-ungated");
});

test("missing v2 coverage remains uncovered even though runtime default-denies", () => {
  const result = classify({ name: "other", annotations: { readOnlyHint: true } }, policy("allow"));
  assert.equal(result.bucket, "uncovered");
});

test("JS scan is differentially bound to Lean scanPass over corpus C", {
  skip: !process.env.SCAN_LEAN_ROOT,
}, () => {
  const result = spawnSync(process.execPath, ["scripts/scan_bridge.mjs"], {
    cwd: path.resolve(__dirname, ".."),
    encoding: "utf8",
    env: process.env,
    maxBuffer: 10 * 1024 * 1024,
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, 0, output);
  assert.match(output, /orphan-explicit-allow: JS=false Lean=false expected=false/);
  assert.match(output, /SCAN BRIDGE: PASS 6\/6/);
});
