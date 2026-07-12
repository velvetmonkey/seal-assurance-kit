// SPDX-License-Identifier: Apache-2.0
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { connect, disconnect } = require("../src/connect.cjs");

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-connect-"));
  const profile = path.join(dir, "profile.json");
  fs.writeFileSync(profile, JSON.stringify({ mcpServers: { sealed: { command: "/real/seal-host", args: ["--", "/real/server"] } } }));
  return { dir, profile };
}

test("connect is reversible and byte-exact", () => {
  const { dir, profile } = fixture();
  const config = path.join(dir, ".mcp.json");
  const before = '{"unrelated":{"preserve":true}}\n';
  fs.writeFileSync(config, before);
  const first = connect({ profilePath: profile, cwd: dir, home: dir });
  assert.equal(first.changed, true);
  assert.equal(JSON.parse(fs.readFileSync(config)).mcpServers.sealed.command, "/real/seal-host");
  assert.equal(connect({ profilePath: profile, cwd: dir, home: dir }).changed, false);
  disconnect({ cwd: dir, home: dir });
  assert.equal(fs.readFileSync(config, "utf8"), before);
});

test("disconnect refuses overlapping user edits", () => {
  const { dir, profile } = fixture();
  connect({ profilePath: profile, cwd: dir, home: dir });
  fs.appendFileSync(path.join(dir, ".mcp.json"), " \n");
  assert.throws(() => disconnect({ cwd: dir, home: dir }), /changed after Seal connected/);
});

test("connect rejects unresolved profiles and name collisions", () => {
  const { dir } = fixture();
  const unresolved = path.join(dir, "unresolved.json");
  fs.writeFileSync(unresolved, JSON.stringify({ mcpServers: { x: { command: "/ABS/PATH/x", args: ["CONFIG_PUBLIC_KEY_HEX"] } } }));
  assert.throws(() => connect({ profilePath: unresolved, cwd: dir, home: dir }), /placeholders/);
  fs.writeFileSync(path.join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { x: { command: "other" } } }));
  const collision = path.join(dir, "collision.json");
  fs.writeFileSync(collision, JSON.stringify({ mcpServers: { x: { command: "/real/x" } } }));
  assert.throws(() => connect({ profilePath: collision, cwd: dir, home: dir }), /already exists/);
});

test("one-command connect selects and renders the in-repo starter", () => {
  const { dir } = fixture();
  const starterDir = path.join(dir, "profiles", "hosts");
  fs.mkdirSync(path.join(dir, ".seal"), { recursive: true });
  fs.mkdirSync(starterDir, { recursive: true });
  fs.writeFileSync(path.join(dir, ".seal", "config.pub"), "11".repeat(32));
  fs.writeFileSync(path.join(dir, ".seal", "approval.pub"), "22".repeat(32));
  fs.writeFileSync(path.join(starterDir, "claude-code.json"), JSON.stringify({
    mcpServers: { sealed: { command: "/ABS/PATH/rust/target/debug/seal-host-rs", args: ["CONFIG_PUBLIC_KEY_HEX", "APPROVAL_PUBLIC_KEY_HEX"] } },
  }));
  connect({ cwd: dir, home: dir });
  const applied = JSON.parse(fs.readFileSync(path.join(dir, ".mcp.json")));
  assert.equal(applied.mcpServers.sealed.command, path.join(dir, "rust/target/debug/seal-host-rs"));
  assert.deepEqual(applied.mcpServers.sealed.args, ["11".repeat(32), "22".repeat(32)]);
});
