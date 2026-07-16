// SPDX-License-Identifier: Apache-2.0
//
// ================= Fleet VERIFY-LAYER (semantic) differential =================
// The sibling `fleet-copy-differential.cjs` compares the BYTES of the six
// receipt-format.js copies. That is the FORMAT layer. It is blind to the VERIFY
// layer — how each repo's gating verifier turns a receipt into a pass/fail
// verdict a human or CI consumes. The fleet P0 (2026-07-16) lived entirely in
// that blind spot: every verifier EXCEPT the fixed kit mapped an unparseable
// receipt (outcome authorised-unparseable, replay excluded) onto a SUCCESS
// verdict, so a kernel-less forged unparseable ALLOW was stamped
// AUTHORISED/exit-0. This script is the semantic differential the byte tool
// could never be: the SAME forge input, driven through EVERY gating verifier,
// must yield the SAME non-passing verdict.
//
// *** MANUAL ONLY. THIS IS NOT RUN BY CI. NOBODY IS WATCHING BUT YOU. ***
// It is a FLEET-ROOT tool: it spawns the real verifier ENTRYPOINTS of three
// private sibling repos, which no CI runner can check out without
// SEAL_CI_READ_TOKEN. A CI job that skipped green without them would be the very
// gap this exists to close, so it is deliberately manual — run on a box that has
// the whole fleet, as part of a frisk. The CI-enforceable half of the P0 is the
// PER-REPO teeth (kit forged-binding.test.cjs, seal-check unparseable-forge.test.cjs,
// seal-verify-action forged-unparseable.test.js), each self-contained in that
// repo's own CI. This tool is the cross-repo agreement check on top.
//
// Verdict CLASSES (labels differ per verifier; the class is the unit compared):
//   VERIFIED  — exit 0 / a success banner. The forbidden outcome for a forge.
//   REDUCED   — a distinct non-passing reduced-scope state (§11.1).
//   UNPINNED  — authentic but authority not established.
//   FAIL      — hard rejection.
//
// Run:  node test/fleet-verify-differential.cjs
//       SEAL_FLEET_ROOT=/path/to/checkouts node test/fleet-verify-differential.cjs
// ==============================================================================
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const KIT_ROOT = path.resolve(__dirname, "..");
const FLEET_ROOT = process.env.SEAL_FLEET_ROOT
  ? path.resolve(process.env.SEAL_FLEET_ROOT)
  : path.resolve(KIT_ROOT, "..");

// The shared public test key every fixture in the fleet is signed under.
const PIN = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

const SEAL_CHECK = path.join(FLEET_ROOT, "seal-check");
const VERIFY_ACTION = path.join(FLEET_ROOT, "seal-verify-action");

// The three GATING verifier entrypoints (not the format validators).
const VERIFIERS = [
  { name: "kit", entry: path.join(KIT_ROOT, "bin", "seal") },
  { name: "seal-check", entry: path.join(SEAL_CHECK, "test", "verify-file.cjs") },
  { name: "seal-verify-action", entry: path.join(VERIFY_ACTION, "lib", "main.js") },
];

let failures = 0;
function check(name, cond, detail = "") {
  if (!cond) failures++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : `   (${detail})`}`);
}

// --- classify one verifier's run of one receipt file into a verdict class ----
function classifyKit(file) {
  const r = spawnSync(process.execPath, [VERIFIERS[0].entry, "verify", file], { encoding: "utf8" });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  if (r.status === 0 && /PASS {2}VERIFIED/.test(out)) return "VERIFIED";
  if (r.status !== 0 && /REDUCED SCOPE \(authorised-unparseable\)/.test(out)) return "REDUCED";
  if (r.status !== 0 && /UNPINNED/.test(out)) return "UNPINNED";
  return "FAIL";
}
function classifySealCheck(file) {
  const r = spawnSync(process.execPath, [VERIFIERS[1].entry, file, "--expected-config-pubkey", PIN], { encoding: "utf8" });
  if (r.status === 0) return "VERIFIED";
  if (r.status === 4) return "REDUCED";
  if (r.status === 3) return "UNPINNED";
  return "FAIL";
}
function classifyAction(file) {
  // Drive lib/main.js headless exactly as seal-host's conformance harness does:
  // env-supplied inputs + temp GITHUB_OUTPUT/SUMMARY, exit code is the verdict.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fleet-action-"));
  const script =
    `require(${JSON.stringify(VERIFIERS[2].entry)}).run().then(c => process.exit(c));`;
  const r = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8", cwd: VERIFY_ACTION,
    env: { ...process.env, INPUT_RECEIPTS: file, "INPUT_EXPECTED-CONFIG-PUBKEY": PIN,
      GITHUB_OUTPUT: path.join(dir, "out"), GITHUB_STEP_SUMMARY: path.join(dir, "sum") },
  });
  fs.rmSync(dir, { recursive: true, force: true });
  if (r.status === 0) return "VERIFIED";
  if (r.status === 4) return "REDUCED";
  if (r.status === 3) return "UNPINNED";
  return "FAIL";
}
const CLASSIFY = { kit: classifyKit, "seal-check": classifySealCheck, "seal-verify-action": classifyAction };

// classify one input across ALL verifiers; returns { verifier: class }.
function classifyAll(file) {
  const out = {};
  for (const v of VERIFIERS) out[v.name] = CLASSIFY[v.name](file);
  return out;
}

(async () => {
  console.log(`fleet verify-layer differential   root=${FLEET_ROOT}`);

  // --- 0. Presence: fail loud on any missing verifier entrypoint ---
  const missing = VERIFIERS.filter((v) => !fs.existsSync(v.entry));
  if (missing.length) {
    for (const m of missing) console.log(`FAIL  verifier MISSING: ${m.name} -> ${m.entry}`);
    console.log(`\nCannot check fleet verify agreement: ${missing.length} verifier entrypoint(s) not present.`);
    console.log(`This is a FLEET-ROOT tool. Check out kit + seal-check + seal-verify-action side by side under SEAL_FLEET_ROOT (default ${FLEET_ROOT}).`);
    process.exit(1);
  }

  // seal-check enforces canonical serialization (assembleReceiptV2 roundtrip);
  // kit and the action do not. Serialize every input once through seal-check's
  // serializer so the SAME bytes are accepted by all three verifiers.
  const F = await import(path.join(SEAL_CHECK, "receipt-format.js"));
  const legitUnparseable = JSON.parse(fs.readFileSync(
    path.join(KIT_ROOT, "fixtures", "receipt-unparseable.json"), "utf8"));

  function writeCanonical(dir, name, obj) {
    const file = path.join(dir, name);
    fs.writeFileSync(file, JSON.stringify(F.assembleReceiptV2(obj), null, 2) + "\n");
    return file;
  }

  // Kernel-less forged unparseable ALLOW, reusing the legit fixture's real
  // Ed25519-signed config + pinning its pubkey. Every field self-consistent.
  function forgedUnparseableAllow() {
    const H = crypto.createHash("sha256")
      .update('{"attacker":"chosen raw line the kernel never judged"}').digest("hex");
    const certs = [{ certHash: "111", kernel: "safety", reason: "forged", verdict: "allow" }];
    const audit = { certs, epoch: 1, request_sha256: H, tool: "db.execute", verdict: "allow" };
    const emitted = JSON.stringify({
      audit: JSON.stringify(audit),
      response: '{"id":1,"jsonrpc":"2.0","result":{"content":[],"isError":false}}\n',
      route: "forward",
    });
    return {
      seal_receipt: "v2", now: 1784110716264, request_sha256: H,
      request_parse_error: "cannot parse mediated request for receipt: attacker-crafted unparseable line",
      bypass: false, verdict: "ALLOW", authorization: "explicit_policy_allow",
      reason: "forged explicit policy allow", deny_kernel: null, certs, emitted_bytes: emitted,
      kernel_identity: legitUnparseable.kernel_identity,
      host_identity: legitUnparseable.host_identity,
      asserted_provenance: legitUnparseable.asserted_provenance,
      signed_config: legitUnparseable.signed_config,
      kernel_config: legitUnparseable.kernel_config,
      granted_capabilities: [],
    };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fleet-verify-diff-"));
  const forgeFile = writeCanonical(dir, "forge.receipt.json", forgedUnparseableAllow());
  const configless = forgedUnparseableAllow();
  delete configless.signed_config;
  delete configless.kernel_config;
  const configlessFile = writeCanonical(dir, "configless.receipt.json", configless);
  const legitFile = writeCanonical(dir, "legit-unparseable.receipt.json", legitUnparseable);

  const INPUTS = [
    { id: "config-reusing forge", file: forgeFile, expect: "REDUCED", neverVerified: true },
    { id: "config-less forge", file: configlessFile, expect: "FAIL", neverVerified: true },
    { id: "legit unparseable", file: legitFile, expect: "REDUCED", neverVerified: true },
  ];

  let runs = 0;
  for (const input of INPUTS) {
    const classes = classifyAll(input.file);
    runs += VERIFIERS.length;
    const rendered = VERIFIERS.map((v) => `${v.name}=${classes[v.name]}`).join(" ");
    console.log(`\n  ${input.id}: ${rendered}`);

    // (a) the forbidden outcome: no verifier may class a forge / unparseable as VERIFIED.
    if (input.neverVerified) {
      check(`${input.id}: no verifier reports VERIFIED`,
        VERIFIERS.every((v) => classes[v.name] !== "VERIFIED"), rendered);
    }
    // (b) class AGREEMENT across all verifiers (the semantic differential).
    const distinct = [...new Set(VERIFIERS.map((v) => classes[v.name]))];
    check(`${input.id}: same verdict class across all verifiers`, distinct.length === 1, rendered);
    // (c) the class is the expected one (pins the §11.2 distinction: legit
    //     unparseable is REDUCED, never collapsed to FAIL or VERIFIED).
    check(`${input.id}: class is ${input.expect}`,
      distinct.length === 1 && distinct[0] === input.expect, rendered);
  }

  // Non-vacuity: every verifier actually ran on every input (no silent skip).
  check("non-vacuity: all verifiers ran on all inputs",
    runs === INPUTS.length * VERIFIERS.length, `${runs} runs`);

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failures === 0
    ? "\nFLEET VERIFY-LAYER DIFFERENTIAL PASS — every verifier agrees, no forge reaches VERIFIED"
    : `\n${failures} FAILURE(S) — a verifier disagrees or stamps a forge VERIFIED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
