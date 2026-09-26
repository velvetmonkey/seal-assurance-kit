// SPDX-License-Identifier: Apache-2.0
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function optionsFrom(modeOrOptions) {
  if (modeOrOptions === undefined || modeOrOptions === null) {
    return { mode: 0o600, force: true };
  }
  if (typeof modeOrOptions === "number") {
    return { mode: modeOrOptions, force: true };
  }
  const mode = modeOrOptions.mode === undefined ? 0o600 : modeOrOptions.mode;
  let force = true;
  if (modeOrOptions.force !== undefined) force = Boolean(modeOrOptions.force);
  else if (modeOrOptions.flag === "wx") force = false;
  else if (modeOrOptions.flag === "w") force = true;
  return { mode, force };
}

function commitExclusive(temporary, file) {
  try {
    fs.linkSync(temporary, file);
    return;
  } catch (error) {
    if (error.code === "EEXIST") throw error;
    // Hard-link exclusive create is the wx primitive. On volumes that refuse
    // links (some Windows/FAT paths), fall back to existsSync then rename.
    // Remaining race: another process can create `file` between the check and
    // rename; rename replaces an existing file, so wx is lost in that window.
    if (error.code !== "EPERM" && error.code !== "ENOTSUP" && error.code !== "EXDEV") {
      throw error;
    }
    if (fs.existsSync(file)) {
      const exists = new Error(`EEXIST: file already exists, link '${file}'`);
      exists.code = "EEXIST";
      throw exists;
    }
    fs.renameSync(temporary, file);
  }
}

// Follow a chain of symbolic links to the final target path. A dangling link
// (and a chain that ends in one) resolves to the missing path so --force can
// create the target through the link. Exclusive create (force: false) does
// not call this: a symlink inode at the destination name is already EEXIST.
// Remaining race: a link retargeted between this resolve and the later
// rename/link commits onto the old target; the new target is untouched.
function resolveFinalTarget(file) {
  let current = path.resolve(file);
  const seen = new Set();
  for (;;) {
    if (seen.has(current)) {
      const error = new Error(`ELOOP: too many symbolic links, resolve '${file}'`);
      error.code = "ELOOP";
      throw error;
    }
    seen.add(current);
    let st;
    try {
      st = fs.lstatSync(current);
    } catch (error) {
      if (error.code === "ENOENT") return current;
      throw error;
    }
    if (!st.isSymbolicLink()) return current;
    current = path.resolve(path.dirname(current), fs.readlinkSync(current));
  }
}

function atomicWrite(file, text, modeOrOptions) {
  const { mode, force } = optionsFrom(modeOrOptions);
  const dest = path.resolve(file);
  const commitPath = force ? resolveFinalTarget(dest) : dest;
  fs.mkdirSync(path.dirname(commitPath), { recursive: true });
  const temporary = `${commitPath}.seal-tmp-${process.pid}-${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(temporary, text, { mode });
    if (force) fs.renameSync(temporary, commitPath);
    else commitExclusive(temporary, commitPath);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

module.exports = { atomicWrite };
