// SPDX-License-Identifier: Apache-2.0
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
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

function baseConfig() {
  return {
    epoch: 1,
    server: "matrix/server",
    safety: {
      approval: { control_file: "/tmp/unused", ttl_seconds: 120 },
      tools: [{ name: "read_item", mode: "allow", match: { type: "always" } }],
    },
  };
}

function fullConfig() {
  return {
    ...baseConfig(),
    temporal: { policies: [{ name: "freeze", type: "no_after", trigger: ["revoke"], forbidden: ["write_item"] }] },
    consensus: { roster: [1, 2, 3], votes_file: "/tmp/votes.ndjson", high_stakes: ["write_item"] },
    convergence: { tools: [{ tool: "store.update", op_arg: "operation.kind" }] },
    calibration: {
      enabled: true,
      delta_num: 1,
      delta_den: 20,
      min_samples: 10,
      records_file: "/tmp/forecasts.ndjson",
      gated_tools: ["write_item"],
    },
    linear: { grants_file: "/tmp/grants.ndjson", tools: [{ tool: "spend", cap_arg: "cap.id" }] },
    budget: { budgets: [{ name: "writes", cap: 5, tools: ["write_item"], cost_arg: "cost" }] },
  };
}

test("TrustedConfig authoring matrix validates sign and scan across all seven kernels", async (t) => {
  const cases = [
    {
      name: "safety-only",
      config: baseConfig(),
      ok: true,
      output: /ABSENT\/OFF \(6\)/,
    },
    {
      name: "full-7",
      config: fullConfig(),
      ok: true,
      output: /ACTIVE \(7\)/,
    },
    {
      name: "empty V/B",
      config: { ...fullConfig(), convergence: { tools: [] }, budget: { budgets: [] } },
      ok: true,
      output: /PRESENT-BUT-INACTIVE \(2\):[\s\S]*Convergence \(V\).*VACUOUS[\s\S]*Budget \(B\).*VACUOUS/,
    },
    {
      name: "K-disabled",
      config: { ...fullConfig(), calibration: { ...fullConfig().calibration, enabled: false } },
      ok: true,
      output: /Calibration \(K, EXPERIMENTAL\) — enabled:false; explicitly inactive/,
    },
    {
      name: "K-enabled",
      config: fullConfig(),
      ok: true,
      output: /ACTIVE \(7\):[\s\S]*Calibration \(K, EXPERIMENTAL\)/,
    },
    {
      name: "malformed-section",
      config: { ...baseConfig(), temporal: { policies: "not-an-array" } },
      ok: false,
      output: /temporal\.policies: array required/,
    },
    {
      name: "server-identity-conflict",
      config: { ...baseConfig(), safety: { ...baseConfig().safety, server: "other/server" } },
      ok: false,
      output: /server identity conflicts between trusted config and safety policy/,
    },
    {
      name: "typoed-top-key",
      config: { ...baseConfig(), temporral: { policies: [] } },
      ok: false,
      output: /UNKNOWN TOP-LEVEL KEY "temporral".*silently off/,
    },
  ];
  const root = path.resolve(__dirname, "..");
  const cli = path.join(root, "bin", "seal");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-trusted-config-matrix-"));
  const key = path.join(dir, "key");
  const manifest = path.join(dir, "manifest.tools.json");
  fs.writeFileSync(key, "07".repeat(32));
  fs.writeFileSync(manifest, JSON.stringify({
    server: "matrix/server",
    tools: [{ name: "read_item", annotations: { readOnlyHint: true } }],
  }));

  for (const item of cases) {
    await t.test(item.name, () => {
      const input = path.join(dir, `${item.name.replaceAll(/[^a-z0-9]+/gi, "-")}.json`);
      const signed = `${input}.signed.json`;
      fs.writeFileSync(input, JSON.stringify(item.config));
      const sign = spawnSync(process.execPath, [cli, "policy", "sign", input, "--key", key, "--out", signed, "--yes"], { encoding: "utf8" });
      const signOutput = `${sign.stdout || ""}${sign.stderr || ""}`;
      assert.equal(sign.status, item.ok ? 0 : 1, signOutput);
      assert.match(signOutput, item.output);
      assert.equal(fs.existsSync(signed), item.ok, `${item.name}: signature emission mismatch`);

      const scan = spawnSync(process.execPath, [cli, "scan", manifest, input], { encoding: "utf8" });
      const scanOutput = `${scan.stdout || ""}${scan.stderr || ""}`;
      assert.equal(scan.status, item.ok ? 0 : 1, scanOutput);
      assert.match(scanOutput, item.output);
    });
  }
});
