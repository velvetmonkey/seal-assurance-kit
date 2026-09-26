// SPDX-License-Identifier: Apache-2.0
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "seal");
const PRELOAD = path.join(__dirname, "interrupt-write.cjs");
const MANIFEST_SRC = path.join(__dirname, "fixtures", "manifests", "dbhub-0.23.0.tools.json");

function workDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "seal-atomic-policy-"));
}

function writeManifest(dir) {
  const manifest = path.join(dir, "server.tools.json");
  fs.copyFileSync(MANIFEST_SRC, manifest);
  return manifest;
}

function parseFile(file) {
  if (!fs.existsSync(file)) return { exists: false };
  const bytes = fs.readFileSync(file);
  try {
    JSON.parse(bytes.toString("utf8"));
    return { exists: true, size: bytes.length, complete: true, bytes };
  } catch (error) {
    return { exists: true, size: bytes.length, complete: false, parseError: error.message, bytes };
  }
}

function assertAbsentOrComplete(file) {
  const status = parseFile(file);
  if (!status.exists) return status;
  assert.equal(status.complete, true, `destination truncated (${status.size} bytes): ${status.parseError}`);
  return status;
}

function interrupt(args, dest) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require ${PRELOAD}`].filter(Boolean).join(" "),
      SEAL_INTERRUPT_FILE: dest,
    },
  });
  return result;
}

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

test("interrupted seal init leaves destination absent or complete; retry without --force succeeds", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const dest = path.join(dir, "init.policy.json");
  const hit = interrupt(["init", manifest, "--out", dest], dest);
  assert.equal(hit.status, 99, `${hit.stdout}${hit.stderr}`);
  assert.match(hit.stderr, /^interrupted |[\s\S]*\ninterrupted /);
  const after = assertAbsentOrComplete(dest);
  assert.equal(after.exists, false, "uncommitted init interrupt left a destination");
  const retry = run(["init", manifest, "--out", dest]);
  assert.equal(retry.status, 0, retry.stderr);
  const committed = parseFile(dest);
  assert.equal(committed.complete, true);
});

test("interrupted seal add-kernel never shrinks a valid policy", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const dest = path.join(dir, "add.policy.json");
  const created = run(["init", manifest, "--out", dest]);
  assert.equal(created.status, 0, created.stderr);
  const before = parseFile(dest);
  assert.equal(before.complete, true);
  const hit = interrupt(["add-kernel", "T", manifest, "--policy", dest], dest);
  assert.equal(hit.status, 99, `${hit.stdout}${hit.stderr}`);
  assert.match(hit.stderr, /interrupted /);
  const after = assertAbsentOrComplete(dest);
  assert.equal(after.exists, true);
  assert.ok(after.size >= before.size, `add-kernel shrank policy ${before.size} -> ${after.size}`);
  assert.deepEqual(after.bytes, before.bytes);
});

test("interrupted seal policy sign leaves destination absent or complete; retry without --force succeeds", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const policy = path.join(dir, "sign.policy.json");
  const key = path.join(dir, "key");
  const dest = path.join(dir, "trusted.json");
  fs.writeFileSync(key, "07".repeat(32));
  const created = run(["init", manifest, "--out", policy]);
  assert.equal(created.status, 0, created.stderr);
  const hit = interrupt(["policy", "sign", policy, "--key", key, "--out", dest, "--yes"], dest);
  assert.equal(hit.status, 99, `${hit.stdout}${hit.stderr}`);
  assert.match(hit.stderr, /interrupted /);
  const after = assertAbsentOrComplete(dest);
  assert.equal(after.exists, false, "uncommitted sign interrupt left a destination");
  const retry = run(["policy", "sign", policy, "--key", key, "--out", dest, "--yes"]);
  assert.equal(retry.status, 0, retry.stderr);
  const committed = parseFile(dest);
  assert.equal(committed.complete, true);
});

test("wx and --force on the destination are unchanged", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const dest = path.join(dir, "policy.json");
  fs.writeFileSync(dest, "SENTINEL\n");
  const refused = run(["init", manifest, "--out", dest]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /refusing to overwrite.*--force/);
  assert.equal(fs.readFileSync(dest, "utf8"), "SENTINEL\n");
  const forced = run(["init", manifest, "--out", dest, "--force"]);
  assert.equal(forced.status, 0, forced.stderr);
  assert.equal(parseFile(dest).complete, true);
});

let atomicWrite;
try { ({ atomicWrite } = require("../src/atomic-write.cjs")); } catch { atomicWrite = null; }

test("atomicWrite helper: existing destination, missing directory, stale temp, read-only directory", { skip: !atomicWrite }, () => {
  const dir = workDir();
  const dest = path.join(dir, "nested", "target.json");
  atomicWrite(dest, "{\"ok\":true}\n", { mode: 0o600, force: false });
  assert.equal(fs.readFileSync(dest, "utf8"), "{\"ok\":true}\n");

  assert.throws(() => atomicWrite(dest, "{\"other\":true}\n", { force: false }), { code: "EEXIST" });
  assert.equal(fs.readFileSync(dest, "utf8"), "{\"ok\":true}\n");

  atomicWrite(dest, "{\"forced\":true}\n", { force: true });
  assert.equal(fs.readFileSync(dest, "utf8"), "{\"forced\":true}\n");

  const stale = `${dest}.seal-tmp-${process.pid}-stale-from-crash`;
  fs.writeFileSync(stale, "stale", { mode: 0o400 });
  try {
    atomicWrite(dest, "{\"fresh\":true}\n", { force: true });
    assert.equal(fs.readFileSync(dest, "utf8"), "{\"fresh\":true}\n");
    assert.equal(fs.readFileSync(stale, "utf8"), "stale");
  } finally {
    fs.chmodSync(stale, 0o600);
  }

  const ro = fs.mkdtempSync(path.join(os.tmpdir(), "seal-atomic-ro-"));
  const blocked = path.join(ro, "blocked.json");
  fs.chmodSync(ro, 0o555);
  try {
    assert.throws(() => atomicWrite(blocked, "x\n", { force: false }));
    assert.equal(fs.existsSync(blocked), false);
  } finally {
    fs.chmodSync(ro, 0o700);
  }
});
