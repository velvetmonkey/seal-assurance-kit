// SPDX-License-Identifier: Apache-2.0
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const cli = path.resolve(__dirname, "../bin/seal");
function setup(t, tools = []) {
  const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), "seal-init-empty-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifest = path.join(root, "input.tools.json");
  const output = path.join(root, "output.policy.json");
  fs.writeFileSync(manifest, JSON.stringify({ server: "empty-server", tools }));
  const run = (...flags) => spawnSync(process.execPath, [cli, "init", manifest, "--out", output, ...flags], { encoding: "utf8" });
  return { manifest, output, run };
}
test("empty init refuses before creating an output file", (t) => {
  const { manifest, output, run } = setup(t);
  const result = run();
  assert.equal(fs.existsSync(output), false, "refusal must not write a policy");
  assert.equal(result.status, 1);
  assert.ok(result.stderr.includes(manifest));
  assert.match(result.stderr, /policy would gate no tool/);
});
test("empty init with force preserves existing policy bytes", (t) => {
  const { output, run } = setup(t);
  const original = Buffer.from("existing policy bytes\n");
  fs.writeFileSync(output, original);
  const result = run("--force");
  assert.deepEqual(fs.readFileSync(output), original);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /policy would gate no tool/);
});
test("explicit empty init writes a labelled empty policy", (t) => {
  const { output, run } = setup(t);
  const result = run("--allow-empty");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^EMPTY POLICY  this policy gates no tool$/m);
  assert.ok(result.stdout.indexOf("EMPTY POLICY") < result.stdout.indexOf("review every rule"));
  assert.deepEqual(JSON.parse(fs.readFileSync(output, "utf8")).safety.tools, []);
});
test("one-tool init preserves main stdout and policy bytes", (t) => {
  const { output, run } = setup(t, [{ name: "write" }]);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `created policy  ${output}\nreview every rule before signing; annotations are trusted input, not verification\n`);
  assert.equal(fs.readFileSync(output, "utf8"), JSON.stringify({
    epoch: 1, server: "empty-server", safety: {
      approval: { ttl_seconds: 120, control_file: "seal-approvals.jsonl" },
      tools: [{ name: "write", mode: "guard", target: [{ full_arguments: true }], _seal_scaffold: { reason: "unknown" } }],
    },
  }, null, 2) + "\n");
});
