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

function interrupt(args, dest, point) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require ${PRELOAD}`].filter(Boolean).join(" "),
      SEAL_INTERRUPT_FILE: dest,
      ...(point ? { SEAL_INTERRUPT_POINT: point } : {}),
    },
  });
  return result;
}

function lstatKind(file) {
  try {
    const st = fs.lstatSync(file);
    return { present: true, isSymlink: st.isSymbolicLink(), isFile: st.isFile() };
  } catch (error) {
    if (error.code === "ENOENT") return { present: false };
    throw error;
  }
}

function resolvedLink(file) {
  return path.resolve(path.dirname(file), fs.readlinkSync(file));
}

function assertStillLinkTo(dest, target) {
  const kind = lstatKind(dest);
  assert.equal(kind.present, true, `destination missing: ${dest}`);
  assert.equal(kind.isSymlink, true, `destination symlink was replaced: ${dest}`);
  assert.equal(resolvedLink(dest), path.resolve(target));
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

test("init --force onto a symlink keeps the link and writes the target", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const target = path.join(dir, "shared", "target.json");
  const dest = path.join(dir, "policy.json");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, "SENTINEL\n");
  fs.symlinkSync(target, dest);

  const refused = run(["init", manifest, "--out", dest]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /refusing to overwrite.*--force/);
  assertStillLinkTo(dest, target);
  assert.equal(fs.readFileSync(target, "utf8"), "SENTINEL\n");

  const forced = run(["init", manifest, "--out", dest, "--force"]);
  assert.equal(forced.status, 0, forced.stderr);
  assertStillLinkTo(dest, target);
  const written = parseFile(target);
  assert.equal(written.complete, true);
  assert.notEqual(fs.readFileSync(target, "utf8"), "SENTINEL\n");
});

test("add-kernel onto a symlinked policy keeps the link and writes the target", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const target = path.join(dir, "elsewhere", "real.policy.json");
  const dest = path.join(dir, "policy.json");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const created = run(["init", manifest, "--out", target]);
  assert.equal(created.status, 0, created.stderr);
  const before = parseFile(target);
  assert.equal(before.complete, true);
  fs.symlinkSync(target, dest);

  const added = run(["add-kernel", "T", manifest, "--policy", dest]);
  assert.equal(added.status, 0, added.stderr);
  assertStillLinkTo(dest, target);
  const after = parseFile(target);
  assert.equal(after.complete, true);
  assert.ok(after.size > before.size, `add-kernel did not grow policy ${before.size} -> ${after.size}`);
});

test("policy sign --force onto a symlink keeps the link and writes the target", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const policy = path.join(dir, "sign.policy.json");
  const key = path.join(dir, "key");
  const target = path.join(dir, "elsewhere", "trusted.json");
  const dest = path.join(dir, "trusted.json");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(key, "07".repeat(32));
  const created = run(["init", manifest, "--out", policy]);
  assert.equal(created.status, 0, created.stderr);
  fs.writeFileSync(target, "SENTINEL\n");
  fs.symlinkSync(target, dest);

  const refused = run(["policy", "sign", policy, "--key", key, "--out", dest, "--yes"]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /refusing to overwrite.*--force/);
  assertStillLinkTo(dest, target);
  assert.equal(fs.readFileSync(target, "utf8"), "SENTINEL\n");

  const forced = run(["policy", "sign", policy, "--key", key, "--out", dest, "--yes", "--force"]);
  assert.equal(forced.status, 0, forced.stderr);
  assertStillLinkTo(dest, target);
  const written = parseFile(target);
  assert.equal(written.complete, true);
  assert.notEqual(fs.readFileSync(target, "utf8"), "SENTINEL\n");
});

test("dangling symlink with --force creates the missing target through the link", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const missing = path.join(dir, "elsewhere", "missing.json");
  const dest = path.join(dir, "policy.json");
  fs.mkdirSync(path.dirname(missing), { recursive: true });
  fs.symlinkSync(missing, dest);

  const refused = run(["init", manifest, "--out", dest]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /refusing to overwrite.*--force/);
  assertStillLinkTo(dest, missing);
  assert.equal(lstatKind(missing).present, false);

  const forced = run(["init", manifest, "--out", dest, "--force"]);
  assert.equal(forced.status, 0, forced.stderr);
  assertStillLinkTo(dest, missing);
  const written = parseFile(missing);
  assert.equal(written.complete, true);
});

test("interrupted write on a symlinked destination leaves the target absent or complete and the link in place", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const target = path.join(dir, "elsewhere", "target.json");
  const dest = path.join(dir, "policy.json");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify({ keep: true }) + "\n");
  fs.symlinkSync(target, dest);
  const before = fs.readFileSync(target);

  const hit = interrupt(["init", manifest, "--out", dest, "--force"], dest, "write");
  assert.equal(hit.status, 99, `${hit.stdout}${hit.stderr}`);
  assert.match(hit.stderr, /interrupted /);
  assertStillLinkTo(dest, target);
  const after = assertAbsentOrComplete(target);
  if (after.exists) assert.deepEqual(after.bytes, before);
});

test("interrupted commit on a symlinked destination leaves the target absent or complete and the link in place", () => {
  const dir = workDir();
  const manifest = writeManifest(dir);
  const target = path.join(dir, "elsewhere", "target.json");
  const dest = path.join(dir, "policy.json");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify({ keep: true }) + "\n");
  fs.symlinkSync(target, dest);
  const before = fs.readFileSync(target);

  const hit = interrupt(["init", manifest, "--out", dest, "--force"], dest, "rename");
  assert.equal(hit.status, 99, `${hit.stdout}${hit.stderr}`);
  assert.match(hit.stderr, /interrupted /);
  assertStillLinkTo(dest, target);
  const after = assertAbsentOrComplete(target);
  if (after.exists) assert.deepEqual(after.bytes, before);
});

test("atomicWrite helper: symlink chain, dangling link, cross-directory target, exclusive create on a symlink dest", { skip: !atomicWrite }, () => {
  const dir = workDir();
  const other = path.join(dir, "other");
  fs.mkdirSync(other, { recursive: true });

  const regular = path.join(dir, "regular.json");
  atomicWrite(regular, "{\"ok\":true}\n", { force: true });
  assert.equal(fs.readFileSync(regular, "utf8"), "{\"ok\":true}\n");
  assert.equal(lstatKind(regular).isSymlink, false);

  const missing = path.join(dir, "created.json");
  atomicWrite(missing, "{\"new\":true}\n", { force: false });
  assert.equal(fs.readFileSync(missing, "utf8"), "{\"new\":true}\n");

  const crossTarget = path.join(other, "shared.json");
  const crossDest = path.join(dir, "via-other.json");
  fs.writeFileSync(crossTarget, "SENTINEL\n");
  fs.symlinkSync(crossTarget, crossDest);
  atomicWrite(crossDest, "{\"forced\":true}\n", { force: true });
  assertStillLinkTo(crossDest, crossTarget);
  assert.equal(fs.readFileSync(crossTarget, "utf8"), "{\"forced\":true}\n");

  const chainTarget = path.join(other, "final.json");
  const hop = path.join(dir, "hop.json");
  const chainDest = path.join(dir, "chain.json");
  fs.writeFileSync(chainTarget, "SENTINEL\n");
  fs.symlinkSync(chainTarget, hop);
  fs.symlinkSync(hop, chainDest);
  atomicWrite(chainDest, "{\"chained\":true}\n", { force: true });
  assertStillLinkTo(chainDest, hop);
  assertStillLinkTo(hop, chainTarget);
  assert.equal(fs.readFileSync(chainTarget, "utf8"), "{\"chained\":true}\n");

  const danglingTarget = path.join(other, "absent.json");
  const danglingDest = path.join(dir, "dangling.json");
  fs.symlinkSync(danglingTarget, danglingDest);
  atomicWrite(danglingDest, "{\"dangling\":true}\n", { force: true });
  assertStillLinkTo(danglingDest, danglingTarget);
  assert.equal(fs.readFileSync(danglingTarget, "utf8"), "{\"dangling\":true}\n");

  const exclusiveTarget = path.join(other, "exclusive.json");
  const exclusiveDest = path.join(dir, "exclusive-link.json");
  fs.writeFileSync(exclusiveTarget, "SENTINEL\n");
  fs.symlinkSync(exclusiveTarget, exclusiveDest);
  assert.throws(() => atomicWrite(exclusiveDest, "{\"nope\":true}\n", { force: false }), { code: "EEXIST" });
  assertStillLinkTo(exclusiveDest, exclusiveTarget);
  assert.equal(fs.readFileSync(exclusiveTarget, "utf8"), "SENTINEL\n");
});
