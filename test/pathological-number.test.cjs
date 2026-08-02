// SPDX-License-Identifier: Apache-2.0
//
// Uniformity catalogue vector #4 — pathological JSON number, fail-closed.
//
// A wire line carrying a monster-exponent number (1e9999999999) used to split
// the fleet: the native seal-host aborted (Json.parse evaluating 10^exponent)
// while the OLD d3067bc0 wasm returned classify-default passthrough — a
// mediation BYPASS in the browser lane. The ff1bfd68 repin closed it (guard
// carried forward unchanged by the current 0b5e7925 kernel):
// Seal.JsonUtil.wireNumbersSafe refuses the line BEFORE Json.parse, and the
// refuse route is `block`. This test drives the SHIPPED vendored wasm directly
// (the exact bytes bin/seal / seal-check load) and pins: block, never
// passthrough, never a verifier crash. Same input, same verdict, every copy.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { load } = require("../kernel/runner.cjs");

// seal_decide needs a session; init one exactly as kernel/runner.cjs does — a
// signed config envelope over CFG_STANDARD. The refuse path short-circuits
// before any kernel/state, so which policy is loaded is immaterial here.
const _keys = crypto.generateKeyPairSync("ed25519");
const _pub = Buffer.from(_keys.publicKey.export({ type: "spki", format: "der" }))
  .subarray(-32).toString("hex");
function initSession(M, cfg) {
  const payload = JSON.stringify(cfg.CFG_STANDARD);
  const signature = crypto.sign(null, Buffer.from(payload, "utf8"), _keys.privateKey).toString("hex");
  const envelope = JSON.stringify({ payload, signature });
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [envelope, _pub]));
  assert.equal(ir.ok, true, `seal_init failed: ${JSON.stringify(ir)}`);
}

// The monster number lives INSIDE the raw wire line (a string field of the step
// input) — exactly where an attacker controls it. 10-digit exponent, far past
// the guard's 6-digit bound; on the old wasm this returned passthrough.
const PATHOLOGICAL = "1e9999999999";

function stepInputWithLine(line, now = 1000) {
  return JSON.stringify({ line, now, approvals: [], votes: "", grants: "", forecasts: "" });
}

function decideRaw(M, line) {
  const raw = M.ccall("seal_decide", "string", ["string"], [stepInputWithLine(line)]);
  return { raw, parsed: JSON.parse(raw) };
}

test("pathological number on a tools/call is BLOCKED (fail-closed), never passthrough", async () => {
  const { M, cfg } = await load();
  initSession(M, cfg);
  const line =
    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute",` +
    `"arguments":{"database":"prod","sql":"drop table users","x":${PATHOLOGICAL}}}}`;
  const { parsed } = decideRaw(M, line);
  assert.equal(parsed.route, "block", `expected fail-closed block, got ${JSON.stringify(parsed)}`);
  assert.notEqual(parsed.route, "passthrough", "the OLD d3067bc0 fail-open: must never recur");
  assert.ok(!parsed.error, `verifier must not error/crash on the pathological line: ${parsed.error || ""}`);
});

test("pathological number is refused even on a would-be-passthrough line", async () => {
  const { M, cfg } = await load();
  initSession(M, cfg);
  // A notification normally passes through untouched. With a monster number it
  // must be refused: the guard fires BEFORE the passthrough/act classification.
  const line =
    `{"jsonrpc":"2.0","method":"notifications/progress","params":{"x":${PATHOLOGICAL}}}`;
  const { parsed } = decideRaw(M, line);
  assert.equal(parsed.route, "block", `refuse must dominate passthrough, got ${JSON.stringify(parsed)}`);
  assert.notEqual(parsed.route, "passthrough");
});

test("control: a benign notification (no pathological number) still passes through", async () => {
  const { M, cfg } = await load();
  initSession(M, cfg);
  const line = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"x":1}}`;
  const { parsed } = decideRaw(M, line);
  assert.equal(parsed.route, "passthrough",
    `the guard must not blanket-block: benign lines still pass through, got ${JSON.stringify(parsed)}`);
});
