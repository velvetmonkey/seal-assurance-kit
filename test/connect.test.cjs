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
    // Exercise Desktop behavior on its documented macOS layout on every test host.
    // Inject a module-local process without changing the host process.platform.
    const sandbox = { exports: {} };
    require("node:vm").runInNewContext(fs.readFileSync(require.resolve("../src/connect.cjs"), "utf8"), {
      module: sandbox, require, Buffer, process: { ...process, platform: "darwin" },
    });
    const client = desktop ? sandbox.exports : { connect, locations };
    const loc = client.locations(options);
    client.connect(options);
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
      assert.throws(() => client.connect(options), new RegExp(`requested server ${Object.keys(servers)[0]}.*recorded server sealed.*disconnect first`));
      assert.deepEqual(fs.readFileSync(loc.config), applied);
      assert.deepEqual(fs.readFileSync(loc.metadata), recorded);
    }
    // JSON member order and profile filename do not change the server definition.
    const equivalent = path.join(dir, "equivalent.json");
    fs.writeFileSync(equivalent, JSON.stringify({ mcpServers: { sealed: { args: definition.args, command: definition.command } } }));
    const result = client.connect({ ...options, profilePath: equivalent });
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


test("Desktop locations select documented macOS and Windows paths", () => {
  const options = { cwd: "/project", home: "/home/x", desktop: true, env: { APPDATA: "D:\\Roaming Profile" } };
  const mac = locations({ ...options, platform: "darwin" });
  const windows = locations({ ...options, platform: "win32" });
  assert.deepEqual(mac, {
    config: "/home/x/Library/Application Support/Claude/claude_desktop_config.json",
    metadata: "/home/x/Library/Application Support/Claude/.seal-connect.json",
    label: "Claude Desktop",
  });
  assert.deepEqual(windows, {
    config: "D:\\Roaming Profile\\Claude\\claude_desktop_config.json",
    metadata: "D:\\Roaming Profile\\Claude\\.seal-connect.json",
    label: "Claude Desktop",
  });
  assert.notEqual(windows.config, mac.config);
});

test("Desktop locations refuse unverified platforms with a named error", () => {
  for (const platform of ["linux", "sunos", "", null]) {
    assert.throws(() => locations({ cwd: "/project", home: "/home/x", desktop: true, platform }), {
      name: "UnsupportedDesktopPlatformError",
      message: `Claude Desktop config path is not verified for platform: ${platform}`,
    });
  }
});

test("Windows Desktop locations require absolute APPDATA without a guessed fallback", () => {
  for (const APPDATA of [undefined, "", "relative", "C:relative"]) {
    assert.throws(() => locations({ home: "/home/x", desktop: true, platform: "win32", env: { APPDATA } }), {
      name: "ClaudeDesktopPathError",
    });
  }
});

test("project locations stay independent of platform and APPDATA", () => {
  for (const platform of ["darwin", "win32", "linux", "sunos"]) {
    assert.deepEqual(locations({ cwd: "/project", desktop: false, platform, env: {} }), {
      config: path.join("/project", ".mcp.json"),
      metadata: path.join("/project", ".seal", "connect-claude-code.json"),
      label: "Claude Code project",
    });
  }
});
