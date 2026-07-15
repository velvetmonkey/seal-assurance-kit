// SPDX-License-Identifier: Apache-2.0
// Fixture-drift check, non-mutating. Generates receipts into a TEMP directory
// through the same producer (src/gen-receipt.cjs) and byte-compares them with
// the committed fixtures. Proves the committed fixtures match the current
// producer WITHOUT rewriting tracked files — `git status` stays clean after
// `npm test`. If the producer changed intentionally, regenerate the committed
// fixtures with `npm run gen`.
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const FILES = ["receipt-block.json", "receipt-allow.json", "receipt-crosstool.json"];

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "seal-kit-drift-"));
let failures = 0;
try {
  const r = spawnSync(process.execPath, [path.join(ROOT, "src", "gen-receipt.cjs"), tmp], { encoding: "utf8" });
  if (r.status !== 0) {
    console.error(r.stdout || "", r.stderr || "");
    console.error("FAIL  fixture drift: generator exited non-zero");
    process.exit(1);
  }
  for (const f of FILES) {
    const fresh = fs.readFileSync(path.join(tmp, f), "utf8");
    const committed = fs.readFileSync(path.join(ROOT, "fixtures", f), "utf8");
    const same = fresh === committed;
    if (!same) failures++;
    console.log(same
      ? `PASS  fixture drift: ${f} byte-identical to a fresh generation`
      : `FAIL  fixture drift: ${f} DIFFERS from a fresh generation (if the producer changed intentionally, run \`npm run gen\` and commit)`);
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
process.exit(failures === 0 ? 0 : 1);
