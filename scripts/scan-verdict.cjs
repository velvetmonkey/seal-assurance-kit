// SPDX-License-Identifier: Apache-2.0
// Run `seal scan` on one corpus item and scrape its final verdict — the
// single mechanics shared by test/scan-pin.test.cjs (always-on JS↔pin leg)
// and mirrored by scripts/scan_bridge.mjs (live JS↔Lean leg).
"use strict";
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

// Returns { verdict: true|false|null, exitOk: boolean, output: string }.
function scanVerdict(item) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "seal-scan-verdict-"));
  try {
    const manifestPath = path.join(work, `${item.name}.tools.json`);
    const policyPath = path.join(work, `${item.name}.policy.json`);
    fs.writeFileSync(manifestPath, JSON.stringify(item.manifest, null, 2) + "\n");
    fs.writeFileSync(policyPath, JSON.stringify(item.policy, null, 2) + "\n");
    const js = spawnSync(process.execPath,
      [path.join(ROOT, "bin/seal"), "scan", manifestPath, policyPath],
      { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
    const output = `${js.stdout || ""}${js.stderr || ""}`;
    const finalVerdict = output.match(/^\s*(PASS|FAIL)\s+\d+ uncovered,/m)?.[1];
    const verdict = finalVerdict === "PASS" ? true : finalVerdict === "FAIL" ? false : null;
    return { verdict, exitOk: js.status === (verdict ? 0 : 1), output };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

module.exports = { scanVerdict };
