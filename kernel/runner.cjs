// SPDX-License-Identifier: Apache-2.0
// Node runner for the vendored seal kernel (wasm/seal.js + seal.wasm).
// Loads the SAME public wasm the browser seal-check uses, runs one decision,
// and builds the canonical receipt. Trusts nothing: hashes the binary itself.
// The load pattern mirrors seal-check/test/receipt-harness.cjs (proven working).
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname);
const WASM_DIR = path.join(ROOT, "wasm");
let _M = null, _cfg = null, _K = null;
const configKeys = crypto.generateKeyPairSync("ed25519");
const configPublicKey = Buffer.from(configKeys.publicKey.export({ type: "spki", format: "der" }))
  .subarray(-32).toString("hex");

function signedEnvelope(config) {
  const payload = JSON.stringify(config);
  const signature = crypto.sign(null, Buffer.from(payload, "utf8"), configKeys.privateKey).toString("hex");
  return JSON.stringify({ payload, signature });
}

async function load() {
  if (_M) return { M: _M, cfg: _cfg, K: _K };
  globalThis.require = require;            // wasm glue's NODE branch needs these
  globalThis.__dirname = WASM_DIR;
  (0, eval)(fs.readFileSync(path.join(WASM_DIR, "seal.js"), "utf8")); // -> globalThis.SealModule
  _M = await globalThis.SealModule({
    locateFile: (p) => path.join(WASM_DIR, p), print() {}, printErr() {},
  });
  _cfg = await import("file://" + path.join(ROOT, "seal-config.js"));
  _K = await import("file://" + path.join(ROOT, "kernel.js"));
  return { M: _M, cfg: _cfg, K: _K };
}

// sha256 of the ACTUAL kernel binary on disk — the only thing self-verified.
function kernelSha() {
  const bytes = fs.readFileSync(path.join(WASM_DIR, "seal.wasm"));
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

// One self-contained decision. Returns { raw, verdict, receipt } — receipt
// is schema v1 (seal-host/docs/DECISION-RECEIPT-SCHEMA.md) via the vendored
// kernel.js buildReceipt.
async function decide(config, { tool, args = {}, approvals = [], now = 1000 }) {
  const { M, cfg, K } = await load();
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"],
    [signedEnvelope(config), configPublicKey]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + JSON.stringify(ir));
  const step = cfg.buildStepInput({ tool, args, approvals, now });
  const raw = M.ccall("seal_decide", "string", ["string"], [step]);
  const parsed = cfg.parseVerdict(raw, tool);
  const computed = kernelSha();
  const sha = { computed, pinned: K.KERNEL_WASM_SHA256, match: computed === K.KERNEL_WASM_SHA256 };
  const base = JSON.parse(K.canonicalReceiptJson(K.buildReceipt({
    call: { tool, args, approvals, now }, config, parsed, raw, sha,
  })));
  return { raw, verdict: base.verdict, receipt: base };
}

// Ordered multi-step session in ONE init (stateful kernels: temporal/budget/linear
// only fire across a trace). Returns the LAST step's verdict.
async function decideSeq(config, steps, tool) {
  const { M, cfg } = await load();
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"],
    [signedEnvelope(config), configPublicKey]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + JSON.stringify(ir));
  let raw, step;
  steps.forEach((s, i) => {
    step = cfg.buildStepInput({ ...s, id: i + 1 });
    raw = M.ccall("seal_decide", "string", ["string"], [step]);
  });
  const parsed = cfg.parseVerdict(raw, tool);
  const verdict = parsed.verdict === "DENY" ? "BLOCK" : parsed.verdict;
  return { raw, verdict, parsed };
}

async function pinnedSha() { const { K } = await load(); return K.KERNEL_WASM_SHA256; }

module.exports = { load, decide, decideSeq, kernelSha, pinnedSha };
