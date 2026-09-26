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

function atomicWrite(file, text, modeOrOptions) {
  const { mode, force } = optionsFrom(modeOrOptions);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.seal-tmp-${process.pid}-${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(temporary, text, { mode });
    if (force) fs.renameSync(temporary, file);
    else commitExclusive(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

module.exports = { atomicWrite };
