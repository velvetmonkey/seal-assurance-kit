// SPDX-License-Identifier: Apache-2.0
"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { isDeepStrictEqual } = require("node:util");
const { atomicWrite } = require("./atomic-write.cjs");

function sha256(text) { return crypto.createHash("sha256").update(text).digest("hex"); }

function locations({ cwd, home, desktop, platform = process.platform, env = process.env }) {
  if (desktop) {
    const desktopPath = platform === "win32" ? path.win32 : path.posix;
    let dir;
    if (platform === "darwin") {
      dir = desktopPath.join(home, "Library", "Application Support", "Claude");
    } else if (platform === "win32") {
      if (!env.APPDATA || !path.win32.isAbsolute(env.APPDATA)) {
        const error = new Error("Claude Desktop requires an absolute APPDATA path on Windows");
        error.name = "ClaudeDesktopPathError";
        throw error;
      }
      dir = desktopPath.join(env.APPDATA, "Claude");
    } else {
      const error = new Error(`Claude Desktop config path is not verified for platform: ${platform}`);
      error.name = "UnsupportedDesktopPlatformError";
      throw error;
    }
    return { config: desktopPath.join(dir, "claude_desktop_config.json"), metadata: desktopPath.join(dir, ".seal-connect.json"), label: "Claude Desktop" };
  }
  return { config: path.join(cwd, ".mcp.json"), metadata: path.join(cwd, ".seal", "connect-claude-code.json"), label: "Claude Code project" };
}

function parseObject(text, label) {
  let value;
  try { value = JSON.parse(text); } catch (error) { throw new Error(`${label} is not valid JSON: ${error.message}`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
  return value;
}

function renderStarterProfile(text, cwd) {
  const readKey = (name) => {
    const file = path.join(cwd, ".seal", name);
    if (!fs.existsSync(file)) return "";
    const value = fs.readFileSync(file, "utf8").trim();
    if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${file} must contain one 32-byte public key in hex`);
    return value.toLowerCase();
  };
  const profile = JSON.parse(text);
  const replacements = {
    "/ABS/PATH": cwd,
    SEAL_BIN_PATH: path.join(cwd, "rust", "target", "debug", "seal-host-rs"),
    CONFIG_PUBLIC_KEY_HEX: readKey("config.pub"),
    APPROVAL_PUBLIC_KEY_HEX: readKey("approval.pub"),
  };
  const unresolved = new Set();
  const substitute = (value) => value.replace(/\/ABS\/PATH|SEAL_BIN_PATH|[A-Z_]*PUBLIC_KEY_HEX/g, (token) => {
    if (!Object.hasOwn(replacements, token) || !replacements[token]) {
      unresolved.add(token);
      return token;
    }
    return replacements[token];
  });
  const replaceTree = (value) => {
    if (typeof value === "string") return substitute(value);
    if (Array.isArray(value)) return value.map(replaceTree);
    if (value !== null && typeof value === "object") {
      const result = {};
      for (const [key, child] of Object.entries(value)) {
        const renderedKey = substitute(key);
        if (Object.hasOwn(result, renderedKey))
          throw new Error(`profile placeholder replacement produces duplicate key ${renderedKey}`);
        Object.defineProperty(result, renderedKey, {
          value: replaceTree(child), enumerable: true, writable: true, configurable: true,
        });
      }
      return result;
    }
    return value;
  };
  const rendered = JSON.stringify(replaceTree(profile));
  return { text: rendered, residue: unresolved.size > 0, unresolved: [...unresolved] };
}

function connect({ profilePath, cwd = process.cwd(), home = os.homedir(), desktop = false }) {
  const loc = locations({ cwd, home, desktop });
  const selectedProfile = profilePath || path.join(cwd, "profiles", "hosts", desktop ? "claude-desktop.json" : "claude-code.json");
  if (!fs.existsSync(selectedProfile))
    throw new Error(`starter profile not found at ${selectedProfile}; run from the seal-host checkout or pass --profile`);
  const { text: profileText, residue, unresolved } = renderStarterProfile(fs.readFileSync(selectedProfile, "utf8"), cwd);
  if (residue) throw new Error(`profile still contains placeholders: ${unresolved.join(", ")}`);
  const profile = parseObject(profileText, "profile");
  if (!profile.mcpServers || typeof profile.mcpServers !== "object")
    throw new Error("Claude profile must contain mcpServers");
  const names = Object.keys(profile.mcpServers);
  if (names.length !== 1) throw new Error("profile must contain exactly one MCP server");

  if (fs.existsSync(loc.metadata)) {
    const metadata = parseObject(fs.readFileSync(loc.metadata, "utf8"), "Seal connection metadata");
    const current = fs.existsSync(loc.config) ? fs.readFileSync(loc.config, "utf8") : "";
    if (sha256(current) === metadata.applied_sha256) {
      if (metadata.server !== names[0] || !Object.hasOwn(metadata, "server_definition") ||
          !isDeepStrictEqual(metadata.server_definition, profile.mcpServers[names[0]]))
        throw new Error(`requested server ${names[0]} does not match recorded server ${metadata.server} and definition; disconnect first before connecting this profile`);
      return { changed: false, ...loc, server: names[0], message: "already connected; no changes" };
    }
    throw new Error(`existing Seal connection metadata overlaps edits in ${loc.config}; disconnect or recover manually`);
  }

  const existed = fs.existsSync(loc.config);
  const before = existed ? fs.readFileSync(loc.config, "utf8") : "";
  const current = existed ? parseObject(before, loc.config) : {};
  current.mcpServers ||= {};
  const name = names[0];
  if (current.mcpServers[name] && JSON.stringify(current.mcpServers[name]) !== JSON.stringify(profile.mcpServers[name]))
    throw new Error(`server ${name} already exists with a different definition`);
  current.mcpServers[name] = profile.mcpServers[name];
  const applied = JSON.stringify(current, null, 2) + "\n";
  const metadata = {
    seal_connect: "v1",
    client: "claude",
    surface: desktop ? "desktop" : "code-project",
    config: loc.config,
    before_existed: existed,
    before_base64: Buffer.from(before, "utf8").toString("base64"),
    before_sha256: sha256(before),
    applied_sha256: sha256(applied),
    server: name,
    server_definition: profile.mcpServers[name],
  };
  // Persist rollback bytes before changing the config. If applying fails or the
  // process stops here, disconnect can recognize and clear the unapplied record.
  atomicWrite(loc.metadata, JSON.stringify(metadata, null, 2) + "\n");
  atomicWrite(loc.config, applied);
  return { changed: true, ...loc, server: name, message: "connected" };
}

function disconnect({ cwd = process.cwd(), home = os.homedir(), desktop = false }) {
  const loc = locations({ cwd, home, desktop });
  if (!fs.existsSync(loc.metadata)) throw new Error(`no Seal connection metadata at ${loc.metadata}`);
  const metadata = parseObject(fs.readFileSync(loc.metadata, "utf8"), "Seal connection metadata");
  const existed = fs.existsSync(loc.config);
  const current = existed ? fs.readFileSync(loc.config, "utf8") : "";
  const before = Buffer.from(metadata.before_base64, "base64").toString("utf8");
  if (sha256(before) !== metadata.before_sha256) throw new Error("rollback metadata failed its own hash check");
  // This also covers a completed rollback whose metadata removal failed. Match
  // existence as well as bytes so an absent file is not confused with an empty one.
  if (existed === metadata.before_existed && current === before) {
    fs.rmSync(loc.metadata);
    return { changed: true, ...loc, server: metadata.server, message: "cleared unapplied or already restored connection; config unchanged" };
  }
  if (sha256(current) !== metadata.applied_sha256)
    throw new Error(`refusing rollback: ${loc.config} changed after Seal connected; restore manually using ${loc.metadata}`);
  if (metadata.before_existed) atomicWrite(loc.config, before);
  else fs.rmSync(loc.config);
  fs.rmSync(loc.metadata);
  return { changed: true, ...loc, server: metadata.server, message: "disconnected and restored exact prior bytes" };
}

module.exports = { connect, disconnect, locations, renderStarterProfile };
