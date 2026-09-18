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

test("scan and diff reject malformed manifests before reading the policy", async (t) => {
  const { scan, diff } = require("../src/scan.cjs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-manifest-shape-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const valid = path.join(dir, "valid.json");
  const invalid = path.join(dir, "invalid.json");
  const missingPolicy = path.join(dir, "missing-policy.json");
  fs.writeFileSync(valid, "[]");
  const cases = [
    ["null root", null, "root must"],
    ["string root", "tools", "root must"],
    ["number root", 42, "root must"],
    ["boolean root", false, "root must"],
    ["missing tools", {}, "tools must"],
    ["string tools", { tools: "not-an-array-oops" }, "tools must"],
    ["object tools", { tools: { weird: true } }, "tools must"],
    ["number tools", { tools: 1 }, "tools must"],
    ["null tools", { tools: null }, "tools must"],
    ["boolean tools", { tools: false }, "tools must"],
  ];
  for (const entry of [null, "read_item", 1, false, [], {}, { name: null }, { name: 1 }]) {
    const tools = [{ name: "read_item" }, entry];
    cases.push([`bare entry ${JSON.stringify(entry)}`, tools, "tools[1]"]);
    cases.push([`wrapped entry ${JSON.stringify(entry)}`, { tools }, "tools[1]"]);
  }
  for (const [label, document, reason] of cases) {
    await t.test(label, () => {
      fs.writeFileSync(invalid, JSON.stringify(document));
      for (const run of [
        () => scan(invalid, missingPolicy),
        () => diff(invalid, valid, missingPolicy),
        () => diff(valid, invalid, missingPolicy),
      ]) {
        assert.throws(run, (error) => {
          assert.equal(error.name, "ManifestValidationError");
          assert.ok(error.message.includes(JSON.stringify(invalid)), error.message);
          assert.ok(error.message.includes(reason), error.message);
          return true;
        });
      }
    });
  }
});

test("scan and diff accept array and envelope manifests with name-only entries", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-manifest-valid-"));
  try {
    const cli = path.resolve(__dirname, "../bin/seal");
    const config = path.join(dir, "policy.json");
    fs.writeFileSync(config, JSON.stringify({ ...baseConfig(), safety: { ...baseConfig().safety, tools: [{ name: "read", mode: "allow", match: { type: "always" } }] } }));
    for (const tools of [[], [{ name: "read" }]]) {
      const bare = path.join(dir, "bare.json");
      const wrapped = path.join(dir, "wrapped.json");
      fs.writeFileSync(bare, JSON.stringify(tools));
      fs.writeFileSync(wrapped, JSON.stringify({ tools }));
      for (const args of [
        ["scan", bare, config],
        ["scan", wrapped, config],
        ["scan", "diff", bare, wrapped, config],
        ["scan", "diff", wrapped, bare, config],
      ]) {
        const result = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
        assert.equal(result.status, tools.length ? 0 : (args[1] === "diff" ? 0 : 1),
          result.stdout + result.stderr);
        assert.doesNotMatch(result.stderr, /ManifestValidationError/);
        if (args[1] === "diff") assert.match(result.stdout, /0 new, 0 removed/);
        else if (tools.length) assert.match(result.stdout, /1 read-only/);
        else assert.match(result.stdout, /ORPHAN explicit ALLOW/);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function runDiffCase(t, oldTools, newTools, config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-scan-diff-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const files = ["old.json", "new.json", "policy.json"].map((name) => path.join(dir, name));
  [oldTools, newTools, config].forEach((doc, i) => fs.writeFileSync(files[i], JSON.stringify(doc)));
  const cli = path.resolve(__dirname, "../bin/seal");
  const diff = spawnSync(process.execPath, [cli, "scan", "diff", ...files], { encoding: "utf8" });
  const scan = spawnSync(process.execPath, [cli, "scan", files[1], files[2]], { encoding: "utf8" });
  assert.equal(diff.status, scan.status, diff.stdout + diff.stderr);
  return diff;
}

test("diff catches existing uncovered tools and annotation-only reclassification", (t) => {
  const old = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../fixtures/tools.json")));
  const config = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../fixtures/policy-v2.json")));
  const current = structuredClone(old);
  current.tools.find((tool) => tool.name === "db.query").annotations = { destructiveHint: true };
  const result = runDiffCase(t, old, current, config);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stdout, /FAIL  UNCOVERED tools \(3\):\s+file.write\s+http.post\s+jira.deleteIssue/);
  assert.match(result.stdout, /CHANGED \(1\):\s+db.query  ->  readonly -> allowed-ungated/);
  assert.match(result.stdout, /0 new, 0 removed, 1 changed/);
  const invalid = runDiffCase(t, [], [{ name: "write_thing" }], null);
  assert.equal(invalid.status, 1, invalid.stdout + invalid.stderr);
  assert.match(invalid.stdout, /FAIL  TRUSTED CONFIG INVALID/);
  assert.doesNotMatch(invalid.stderr, /TypeError|Cannot read/);
});

test("diff reports changed clean records without failing or treating key order as a change", async (t) => {
  const tool = { name: "read_item", description: "Read an item", annotations: { readOnlyHint: true },
    inputSchema: { type: "object", properties: { id: { type: "string" } } } };
  const cases = [
    ["description", { ...tool, description: "Read one item" }, true],
    ["annotations", { ...tool, annotations: { readOnlyHint: true, title: "Read" } }, true],
    ["schema", { ...tool, inputSchema: { type: "object", properties: { id: { type: "number" } } } }, true],
    ["key order", { inputSchema: { properties: { id: { type: "string" } }, type: "object" },
      annotations: tool.annotations, description: tool.description, name: tool.name }, false],
  ];
  for (const [name, current, changed] of cases) await t.test(name, (t) => {
    const result = runDiffCase(t, [tool], [current], baseConfig());
    assert.equal(result.status, 0, result.stdout);
    if (changed) assert.match(result.stdout, /CHANGED \(1\):\s+read_item  ->  readonly -> readonly/);
    else assert.doesNotMatch(result.stdout, /CHANGED/);
  });
});

test("diff passes a clean covered addition and keeps the removed view", (t) => {
  const read = { name: "read_item", annotations: { readOnlyHint: true } };
  const config = baseConfig();
  config.safety.tools.push({ name: "write_item", mode: "guarded", match: { type: "always" }, target: [{ full_arguments: true }] });
  const result = runDiffCase(t, [read, { name: "retired" }], [read, { name: "write_item", annotations: { destructiveHint: true } }], config);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /SECONDARY VIEW/);
  assert.match(result.stdout, /NEW since last scan \(1\):\s+write_item  ->  guarded/);
  assert.match(result.stdout, /REMOVED \(1\):\s+retired/);
  assert.match(result.stdout, /PASS  full scan of new manifest/);
});
