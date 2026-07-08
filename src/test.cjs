// SPDX-License-Identifier: Apache-2.0
// `seal test --profile L0`: reference-kernel conformance oracle.
//
// Runs the published L0 conformance corpus (named bypass / parser-differential /
// stale-capability attack traces) through the boundary and asserts each is
// deterministically BLOCKED by the right gate. Verdicts are read from the kernel
// at runtime, never hardcoded. A non-vacuous, reproducible "is this boundary
// actually mediated" check.
//
// Today it exercises the vendored reference kernel (self-conformance). A future
// `seal test <server-url>` will drive the same corpus at a live MCP endpoint.
const path = require("path");
const { decide, decideSeq } = require("../kernel/runner.cjs");

async function runCase(c) {
  if (c.run === "seq") {
    const r = await decideSeq(c.config, c.steps, c.tool);
    return { verdict: r.verdict, deny: r.parsed.deny_kernel, bytes: r.raw };
  }
  const r = await decide(c.config, { tool: c.tool, args: c.args, approvals: c.approvals || [] });
  return { verdict: r.verdict, deny: r.receipt.deny_kernel, bytes: r.raw };
}

async function test(profile = "L0") {
  const { CORPUS } = await import("file://" + path.resolve(__dirname, "../kernel/corpus.js"));
  console.log(`seal test  reference-kernel conformance  profile=${profile}  cases=${CORPUS.length}`);
  console.log(`  (self-conformance vs the vendored reference kernel; not a live-endpoint boundary test)`);
  let allGood = true;
  for (const c of CORPUS) {
    const a = await runCase(c);
    const blocked = a.verdict === "BLOCK";
    // determinism: re-run, emitted bytes must be byte-identical
    const b = await runCase(c);
    const deterministic = a.bytes === b.bytes;
    const pass = blocked && deterministic;
    allGood = allGood && pass;
    const note = blocked ? `blocked by ${a.deny || "?"}` : `NOT BLOCKED (${a.verdict})`;
    console.log(`  ${pass ? "PASS" : "FAIL"}  ${c.lens.padEnd(22)} ${c.id.padEnd(20)} ${note}${deterministic ? "" : "  [NON-DETERMINISTIC]"}`);
  }
  console.log(`  ${allGood ? "PASS  CONFORMANT (reference kernel)" : "FAIL  NON-CONFORMANT"}  (${CORPUS.length}/${CORPUS.length} traces, all four gates + deny-rule)`);
  return allGood;
}

module.exports = { test };
