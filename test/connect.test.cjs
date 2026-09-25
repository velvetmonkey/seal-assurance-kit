// SPDX-License-Identifier: Apache-2.0
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { connect, disconnect, locations, renderStarterProfile } = require("../src/connect.cjs");

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
      const sandbox = { exports: {} };
      require("node:vm").runInNewContext(fs.readFileSync(require.resolve("../src/connect.cjs"), "utf8"), {
        module: sandbox, require, Buffer, process: { ...process, platform: "darwin" },
      });
      const client = desktop ? sandbox.exports : { connect, disconnect, locations };
      assert.doesNotThrow(() => client.connect(options));
      const text = fs.readFileSync(client.locations(options).config, "utf8");
      const expected = { mcpServers: { sealed: {
        command: dir + "/rust/target/debug/seal-host-rs",
        args: [dir, dir + "/data:" + dir + "/cache", "ab".repeat(32), "cd".repeat(32)],
        env: { ROOT: dir, KEYS: "ab".repeat(32) + ":" + "cd".repeat(32) },
        enabled: true, retries: 3, optional: null,
      } } };
      assert.deepEqual(JSON.parse(text), expected);
      assert.equal(text, JSON.stringify(expected, null, 2) + "\n");
      assert.equal(client.connect(options).changed, false);
      client.disconnect(options);
      assert.equal(fs.existsSync(client.locations(options).config), false);
    }
  });
}


test("literal /ABS/PATH cwd renders valid JSON with its exact value and key", () => {
  const source = JSON.stringify({ mcpServers: { sealed: {
    command: "/ABS/PATH/bin/host", env: { "/ABS/PATH": "/ABS/PATH" },
  } } });
  const rendered = renderStarterProfile(source, "/ABS/PATH");
  assert.equal(rendered.residue, false);
  const { dir } = fixture();
  const config = path.join(dir, ".mcp.json");
  fs.writeFileSync(config, rendered.text);
  assert.deepEqual(JSON.parse(fs.readFileSync(config, "utf8")), {
    mcpServers: { sealed: { command: "/ABS/PATH/bin/host", env: { "/ABS/PATH": "/ABS/PATH" } } },
  });
});

test("connect resolves nested keys and values and names unresolved placeholders", () => {
  const { dir, profile } = fixture();
  fs.mkdirSync(path.join(dir, ".seal"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".seal", "config.pub"), "AB".repeat(32));
  fs.writeFileSync(path.join(dir, ".seal", "approval.pub"), "CD".repeat(32));
  fs.writeFileSync(profile, JSON.stringify({ mcpServers: { sealed: {
    command: "/ABS/PATH/host", env: { "/ABS/PATH": ["/ABS/PATH", { CONFIG_PUBLIC_KEY_HEX: "APPROVAL_PUBLIC_KEY_HEX" }] },
  } } }));
  connect({ profilePath: profile, cwd: dir, home: dir });
  const config = JSON.parse(fs.readFileSync(path.join(dir, ".mcp.json")));
  assert.deepEqual(config.mcpServers.sealed.env[dir], [dir, { ["ab".repeat(32)]: "cd".repeat(32) }]);
  disconnect({ cwd: dir, home: dir });
  fs.writeFileSync(profile, JSON.stringify({ mcpServers: { sealed: { command: "/real/host", env: { UNKNOWN_PUBLIC_KEY_HEX: "ok" } } } }));
  assert.throws(() => connect({ profilePath: profile, cwd: dir, home: dir }), /placeholders: UNKNOWN_PUBLIC_KEY_HEX/);
  assert.equal(fs.existsSync(path.join(dir, ".mcp.json")), false);
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

function atomicWriter(fsImpl = fs) {
  const sandbox = { exports: {} };
  require("node:vm").runInNewContext(
    fs.readFileSync(require.resolve("../src/connect.cjs"), "utf8") + "\nmodule.exports = atomicWrite;",
    { module: sandbox, require: (name) => name === "node:fs" ? fsImpl : require(name), process },
  );
  return sandbox.exports;
}

test("atomic writes bypass a read-only stale PID temporary without changing it", () => {
  const { dir } = fixture();
  const file = path.join(dir, "target");
  const stale = `${file}.seal-tmp-${process.pid}`;
  fs.writeFileSync(stale, "stale bytes", { mode: 0o400 });
  try {
    atomicWriter()(file, "new bytes");
    assert.equal(fs.readFileSync(file, "utf8"), "new bytes");
    assert.equal(fs.readFileSync(stale, "utf8"), "stale bytes");
    assert.deepEqual(fs.readdirSync(dir).sort(), ["profile.json", "target", path.basename(stale)].sort());
  } finally {
    fs.chmodSync(stale, 0o600);
  }
});

test("atomic writes clean their temporary after a real rename failure", () => {
  const { dir } = fixture();
  const file = path.join(dir, "target");
  fs.mkdirSync(file);
  fs.writeFileSync(path.join(file, "keep"), "original");
  assert.throws(() => atomicWriter()(file, "replacement"), { code: "EISDIR" });
  assert.equal(fs.readFileSync(path.join(file, "keep"), "utf8"), "original");
  assert.deepEqual(fs.readdirSync(dir).sort(), ["profile.json", "target"]);
});

test("atomic writes clean a partially written temporary when writing throws", () => {
  const { dir } = fixture();
  const file = path.join(dir, "target");
  fs.writeFileSync(file, "original");
  const failure = Object.assign(new Error("injected disk full after partial write"), { code: "ENOSPC" });
  const write = atomicWriter({ ...fs, writeFileSync(temporary, text, options) {
    fs.writeFileSync(temporary, text.slice(0, 2), options);
    throw failure;
  } });
  assert.throws(() => write(file, "replacement"), (error) => error === failure);
  assert.equal(fs.readFileSync(file, "utf8"), "original");
  assert.deepEqual(fs.readdirSync(dir).sort(), ["profile.json", "target"]);
});

test("rapid same-process atomic writes use distinct temporaries and retain the final bytes", () => {
  const { dir } = fixture();
  const names = [];
  const write = atomicWriter({ ...fs, writeFileSync(temporary, text, options) {
    names.push(temporary);
    fs.writeFileSync(temporary, text, options);
  } });
  for (let i = 0; i < 20; i++) write(path.join(dir, "target"), String(i));
  assert.equal(new Set(names).size, 20);
  assert.equal(fs.readFileSync(path.join(dir, "target"), "utf8"), "19");
  assert.deepEqual(fs.readdirSync(dir).sort(), ["profile.json", "target"]);
});
