// SPDX-License-Identifier: Apache-2.0
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { connect, disconnect, locations } = require("../src/connect.cjs");

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

test("connect compares the requested server and definition on both surfaces", () => {
  for (const desktop of [false, true]) {
    const { dir, profile } = fixture();
    const options = { profilePath: profile, cwd: dir, home: dir, desktop };
    const loc = locations(options);
    connect(options);
    const applied = fs.readFileSync(loc.config);
    const recorded = fs.readFileSync(loc.metadata);
    const definition = JSON.parse(fs.readFileSync(profile)).mcpServers.sealed;
    assert.deepEqual(JSON.parse(recorded).server_definition, definition);
    for (const servers of [
      { other: definition },
      { sealed: { ...definition, command: "/different/server" } },
      { sealed: { ...definition, args: ["--", "/different/server"] } },
      { sealed: { ...definition, env: { TOKEN: "different" } } },
    ]) {
      fs.writeFileSync(profile, JSON.stringify({ mcpServers: servers }));
      assert.throws(() => connect(options), new RegExp(`requested server ${Object.keys(servers)[0]}.*recorded server sealed.*disconnect first`));
      assert.deepEqual(fs.readFileSync(loc.config), applied);
      assert.deepEqual(fs.readFileSync(loc.metadata), recorded);
    }
    // JSON member order and profile filename do not change the server definition.
    const equivalent = path.join(dir, "equivalent.json");
    fs.writeFileSync(equivalent, JSON.stringify({ mcpServers: { sealed: { args: definition.args, command: definition.command } } }));
    const result = connect({ ...options, profilePath: equivalent });
    assert.equal(result.changed, false);
    assert.equal(result.message, "already connected; no changes");
    assert.deepEqual(fs.readFileSync(loc.config), applied);
    assert.deepEqual(fs.readFileSync(loc.metadata), recorded);
  }
});

test("legacy metadata without a recorded definition requires disconnect", () => {
  const { dir, profile } = fixture();
  const options = { profilePath: profile, cwd: dir, home: dir };
  const loc = locations(options);
  connect(options);
  const metadata = JSON.parse(fs.readFileSync(loc.metadata));
  delete metadata.server_definition;
  fs.writeFileSync(loc.metadata, JSON.stringify(metadata));
  assert.throws(() => connect(options), /requested server sealed.*recorded server sealed.*disconnect first/);
  disconnect(options);
  assert.equal(fs.existsSync(loc.config), false);
});

test("repeated connect and disconnect restores exact prior bytes", () => {
  const { dir, profile } = fixture();
  const options = { profilePath: profile, cwd: dir, home: dir };
  const config = path.join(dir, ".mcp.json");
  const before = Buffer.from('{ "unrelated": "preserve", "mcpServers": {} }\r\n');
  fs.writeFileSync(config, before);
  for (let cycle = 0; cycle < 2; cycle++) {
    assert.equal(connect(options).changed, true);
    assert.equal(disconnect(options).changed, true);
    assert.deepEqual(fs.readFileSync(config), before);
  }
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

test("CLI connect accepts the default and explicit profiles", () => {
  const { spawnSync } = require("node:child_process");
  const cli = path.resolve(__dirname, "..", "bin", "seal");
  for (const explicit of [false, true]) {
    const { dir, profile } = fixture();
    const starters = path.join(dir, "profiles", "hosts");
    fs.mkdirSync(starters, { recursive: true });
    fs.copyFileSync(profile, path.join(starters, "claude-code.json"));
    const args = [cli, "connect", "--client", "claude"];
    if (explicit) args.push("--profile", profile);
    const result = spawnSync(process.execPath, args, { cwd: dir, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /connected: Claude Code project/);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, ".mcp.json"))), JSON.parse(fs.readFileSync(profile)));
    disconnect({ cwd: dir, home: dir });
    assert.equal(fs.existsSync(path.join(dir, ".mcp.json")), false);
  }
});

for (const name of ["plain", "weird\\that", "weird\\\\that", 'weird\\path"dir', 'quote"dir', "dollar$&dir", "cwd/ABS/PATH"]) {
  test(`starter profile preserves literal path bytes: ${JSON.stringify(name)}`, () => {
    for (const desktop of [false, true]) {
      const { dir: parent } = fixture();
      const dir = path.join(parent, name);
      const starters = path.join(dir, "profiles", "hosts");
      fs.mkdirSync(starters, { recursive: true });
      fs.mkdirSync(path.join(dir, ".seal"), { recursive: true });
      fs.writeFileSync(path.join(dir, ".seal", "config.pub"), "AB".repeat(32) + "\n");
      fs.writeFileSync(path.join(dir, ".seal", "approval.pub"), "CD".repeat(32) + "\n");
      const server = {
        command: "/ABS/PATH/rust/target/debug/seal-host-rs",
        args: ["/ABS/PATH", "/ABS/PATH/data:/ABS/PATH/cache", "CONFIG_PUBLIC_KEY_HEX", "APPROVAL_PUBLIC_KEY_HEX"],
        env: { ROOT: "/ABS/PATH", KEYS: "CONFIG_PUBLIC_KEY_HEX:APPROVAL_PUBLIC_KEY_HEX" },
        enabled: true, retries: 3, optional: null,
      };
      fs.writeFileSync(path.join(starters, desktop ? "claude-desktop.json" : "claude-code.json"),
        JSON.stringify({ mcpServers: { sealed: server } }));
      const options = { cwd: dir, home: dir, desktop };
      assert.doesNotThrow(() => connect(options));
      const text = fs.readFileSync(locations(options).config, "utf8");
      const expected = { mcpServers: { sealed: {
        command: dir + "/rust/target/debug/seal-host-rs",
        args: [dir, dir + "/data:" + dir + "/cache", "ab".repeat(32), "cd".repeat(32)],
        env: { ROOT: dir, KEYS: "ab".repeat(32) + ":" + "cd".repeat(32) },
        enabled: true, retries: 3, optional: null,
      } } };
      assert.deepEqual(JSON.parse(text), expected);
      assert.equal(text, JSON.stringify(expected, null, 2) + "\n");
      assert.equal(connect(options).changed, false);
      disconnect(options);
      assert.equal(fs.existsSync(locations(options).config), false);
    }
  });
}
