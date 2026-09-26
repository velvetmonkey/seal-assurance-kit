// SPDX-License-Identifier: Apache-2.0
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const orig = fs.writeFileSync;
const destEnv = process.env.SEAL_INTERRUPT_FILE;
if (!destEnv) throw new Error("SEAL_INTERRUPT_FILE is required");
const destResolved = path.resolve(destEnv);

function isDestOrSiblingTemp(file) {
  const resolved = path.resolve(String(file));
  if (resolved === destResolved) return true;
  return resolved.startsWith(destResolved + ".seal-tmp-");
}

fs.writeFileSync = function writeFileSync(file, data, opts) {
  if (isDestOrSiblingTemp(file)) {
    const resolved = path.resolve(String(file));
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    orig.call(fs, file, buf.subarray(0, Math.max(1, Math.floor(buf.length / 3))), opts);
    process.stderr.write(`interrupted ${resolved}\n`);
    process.exit(99);
  }
  return orig.apply(fs, arguments);
};
