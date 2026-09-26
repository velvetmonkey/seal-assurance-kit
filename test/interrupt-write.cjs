// SPDX-License-Identifier: Apache-2.0
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const origWrite = fs.writeFileSync;
const origRename = fs.renameSync;
const origLink = fs.linkSync;
const destEnv = process.env.SEAL_INTERRUPT_FILE;
if (!destEnv) throw new Error("SEAL_INTERRUPT_FILE is required");
const destResolved = path.resolve(destEnv);
const point = process.env.SEAL_INTERRUPT_POINT || "write";
if (point !== "write" && point !== "rename") {
  throw new Error("SEAL_INTERRUPT_POINT must be write or rename");
}

function resolveThroughLinks(file) {
  let current = path.resolve(file);
  const seen = new Set();
  for (;;) {
    if (seen.has(current)) return current;
    seen.add(current);
    let st;
    try { st = fs.lstatSync(current); }
    catch (error) {
      if (error.code === "ENOENT") return current;
      throw error;
    }
    if (!st.isSymbolicLink()) return current;
    current = path.resolve(path.dirname(current), fs.readlinkSync(current));
  }
}

const targetResolved = resolveThroughLinks(destResolved);

function isWatchedPath(file) {
  const resolved = path.resolve(String(file));
  if (resolved === destResolved || resolved === targetResolved) return true;
  if (resolved.startsWith(`${destResolved}.seal-tmp-`)) return true;
  if (resolved.startsWith(`${targetResolved}.seal-tmp-`)) return true;
  return false;
}

if (point === "write") {
  fs.writeFileSync = function writeFileSync(file, data, opts) {
    if (isWatchedPath(file)) {
      const resolved = path.resolve(String(file));
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
      origWrite.call(fs, file, buf.subarray(0, Math.max(1, Math.floor(buf.length / 3))), opts);
      process.stderr.write(`interrupted ${resolved}\n`);
      process.exit(99);
    }
    return origWrite.apply(fs, arguments);
  };
} else {
  fs.renameSync = function renameSync(from, to) {
    if (isWatchedPath(from) || isWatchedPath(to)) {
      process.stderr.write(`interrupted ${path.resolve(String(from))} -> ${path.resolve(String(to))}\n`);
      process.exit(99);
    }
    return origRename.apply(fs, arguments);
  };
  fs.linkSync = function linkSync(from, to) {
    if (isWatchedPath(from) || isWatchedPath(to)) {
      process.stderr.write(`interrupted ${path.resolve(String(from))} -> ${path.resolve(String(to))}\n`);
      process.exit(99);
    }
    return origLink.apply(fs, arguments);
  };
}
