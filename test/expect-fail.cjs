// SPDX-License-Identifier: Apache-2.0
// Run argv as a subprocess; exit 0 iff it exits non-zero.
// Portable replacement for the shell `!` prefix (works on Windows shells too).
const { spawnSync } = require("child_process");
const r = spawnSync(process.argv[2], process.argv.slice(3), { stdio: "inherit" });
process.exit(r.status === 0 ? 1 : 0);
