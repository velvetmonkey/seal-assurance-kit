// SPDX-License-Identifier: Apache-2.0
"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function sha256(text) { return crypto.createHash("sha256").update(text).digest("hex"); }

function locations({ cwd, home, desktop }) {
  if (desktop) {
    const dir = path.join(home, "Library", "Application Support", "Claude");
    return { config: path.join(dir, "claude_desktop_config.json"), metadata: path.join(dir, ".seal-connect.json"), label: "Claude Desktop" };
  }
  return { config: path.join(cwd, ".mcp.json"), metadata: path.join(cwd, ".seal", "connect-claude-code.json"), label: "Claude Code project" };
}

function parseObject(text, label) {
  let value;
  try { value = JSON.parse(text); } catch (error) { throw new Error(`${label} is not valid JSON: ${error.message}`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
  return value;
}

function atomicWrite(file, text, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.seal-tmp-${process.pid}`;
  fs.writeFileSync(temporary, text, { mode });
  fs.renameSync(temporary, file);
}

function renderStarterProfile(text, cwd) {
  const readKey = (name) => {
    const file = path.join(cwd, ".seal", name);
    if (!fs.existsSync(file)) return "";
    const value = fs.readFileSync(file, "utf8").trim();
    if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${file} must contain one 32-byte public key in hex`);
    return value.toLowerCase();
  };
  return text
    .replaceAll("/ABS/PATH", cwd)
    .replaceAll("CONFIG_PUBLIC_KEY_HEX", readKey("config.pub") || "CONFIG_PUBLIC_KEY_HEX")
    .replaceAll("APPROVAL_PUBLIC_KEY_HEX", readKey("approval.pub") || "APPROVAL_PUBLIC_KEY_HEX");
}

function connect({ profilePath, cwd = process.cwd(), home = os.homedir(), desktop = false }) {
  const loc = locations({ cwd, home, desktop });
  const selectedProfile = profilePath || path.join(cwd, "profiles", "hosts", desktop ? "claude-desktop.json" : "claude-code.json");
  if (!fs.existsSync(selectedProfile))
    throw new Error(`starter profile not found at ${selectedProfile}; run from the seal-host checkout or pass --profile`);
  const profileText = renderStarterProfile(fs.readFileSync(selectedProfile, "utf8"), cwd);
  const profile = parseObject(profileText, "profile");
  if (!profile.mcpServers || typeof profile.mcpServers !== "object")
    throw new Error("Claude profile must contain mcpServers");
  const names = Object.keys(profile.mcpServers);
  if (names.length !== 1) throw new Error("profile must contain exactly one MCP server");
  const serializedProfile = JSON.stringify(profile);
  if (/\/ABS\/PATH|PUBLIC_KEY_HEX/.test(serializedProfile))
    throw new Error("profile still contains path or public-key placeholders");

  if (fs.existsSync(loc.metadata)) {
    const metadata = parseObject(fs.readFileSync(loc.metadata, "utf8"), "Seal connection metadata");
    const current = fs.existsSync(loc.config) ? fs.readFileSync(loc.config, "utf8") : "";
    if (sha256(current) === metadata.applied_sha256)
      return { changed: false, ...loc, server: names[0], message: "already connected; no changes" };
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
  };
  atomicWrite(loc.config, applied);
  atomicWrite(loc.metadata, JSON.stringify(metadata, null, 2) + "\n");
  return { changed: true, ...loc, server: name, message: "connected" };
}

function disconnect({ cwd = process.cwd(), home = os.homedir(), desktop = false }) {
  const loc = locations({ cwd, home, desktop });
  if (!fs.existsSync(loc.metadata)) throw new Error(`no Seal connection metadata at ${loc.metadata}`);
  const metadata = parseObject(fs.readFileSync(loc.metadata, "utf8"), "Seal connection metadata");
  const current = fs.existsSync(loc.config) ? fs.readFileSync(loc.config, "utf8") : "";
  if (sha256(current) !== metadata.applied_sha256)
    throw new Error(`refusing rollback: ${loc.config} changed after Seal connected; restore manually using ${loc.metadata}`);
  const before = Buffer.from(metadata.before_base64, "base64").toString("utf8");
  if (sha256(before) !== metadata.before_sha256) throw new Error("rollback metadata failed its own hash check");
  if (metadata.before_existed) atomicWrite(loc.config, before);
  else fs.rmSync(loc.config);
  fs.rmSync(loc.metadata);
  return { changed: true, ...loc, server: metadata.server, message: "disconnected and restored exact prior bytes" };
}

module.exports = { connect, disconnect, locations, renderStarterProfile };
