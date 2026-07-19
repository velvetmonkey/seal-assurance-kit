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
// could never be: the SAME input, driven through EVERY gating verifier, must
// yield the verdict class its DECLARED PROFILE requires.
//
// PROFILE-KEYED (docs/VERIFY-PROFILES.md): each verifier copy declares a
// VERIFY_PROFILE constant; this tool extracts the LIVE declaration from each
// repo, cross-checks it against the spec roster, and derives every expected
// verdict from test/corpus/verify-profiles.json — not from hand-named cases.
// Where profiles agree the copies must agree; where they differ (P-REF accepts
// a config-less/unpinned receipt that P-ENFORCE holds down) the divergence is
// asserted IN BOTH DIRECTIONS: a copy drifting onto the other profile's
// behaviour goes RED, not silently green. A copy off its declared profile is
// a FINDING to report — never a thing to re-green by editing the table.
//
// *** MANUAL ONLY. THIS IS NOT RUN BY CI. NOBODY IS WATCHING BUT YOU. ***
// It is a FLEET-ROOT tool: it spawns the real verifier ENTRYPOINTS of three
// private sibling repos, which no CI runner can check out without
// SEAL_CI_READ_TOKEN. A CI job that skipped green without them would be the very
// gap this exists to close, so it is deliberately manual — run on a box that has
// the whole fleet, as part of a frisk. The CI-enforceable half is the PER-REPO
// teeth (each repo's verify-profile self-check + forge teeth), each
// self-contained in that repo's own CI. This tool is the cross-repo agreement
// check on top.
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

// The profile spec: expected verdict class per (declared profile, input class).
const SPEC = JSON.parse(fs.readFileSync(
  path.join(__dirname, "corpus", "verify-profiles.json"), "utf8"));
const DECL_RE = new RegExp(SPEC.declaration_regex);

// The three GATING verifier entrypoints (not the format validators), each with
// the file its VERIFY_PROFILE declaration lives in (spec roster §6).
const VERIFIERS = [
  { name: "kit", rosterKey: "kit", entry: path.join(KIT_ROOT, "bin", "seal"),
    declFile: path.join(KIT_ROOT, "src", "verify.cjs") },
  { name: "seal-check", rosterKey: "seal-check",
    entry: path.join(SEAL_CHECK, "test", "verify-file.cjs"),
    declFile: path.join(SEAL_CHECK, "receipt.js") },
  { name: "seal-verify-action", rosterKey: "seal-verify-action",
    entry: path.join(VERIFY_ACTION, "lib", "main.js"),
    declFile: path.join(VERIFY_ACTION, "lib", "pin.js") },
];

let failures = 0;
function check(name, cond, detail = "") {
  if (!cond) failures++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : `   (${detail})`}`);
}

// --- classify one verifier's run of one receipt file into a verdict class ----
// `pinned` controls whether the trust-anchor pin is supplied. P-REF consumes it
// only for principal-bearing receipts; the canonical fleet inputs here are
// non-principal, so their established profile outcomes remain unchanged.
function classifyKit(file, pinned) {
  const args = [VERIFIERS[0].entry, "verify", file];
  if (pinned) args.push("--expected-config-pubkey", PIN);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  if (r.signal) return "CRASHED:" + r.signal;
  if (r.status === 0 && /PASS {2}VERIFIED/.test(out)) return "VERIFIED";
  if (r.status === 4 && /REDUCED SCOPE/.test(out)) return "REDUCED";
  if (r.status !== 0 && /UNPINNED/.test(out)) return "UNPINNED";
  return "FAIL";
}
function classifySealCheck(file, pinned) {
  const args = [VERIFIERS[1].entry, file];
  if (pinned) args.push("--expected-config-pubkey", PIN);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  if (r.signal) return "CRASHED:" + r.signal;
  if (r.status === 0) return "VERIFIED";
  if (r.status === 4) return "REDUCED";
  if (r.status === 3) return "UNPINNED";
  return "FAIL";
}
function classifyAction(file, pinned) {
  // Drive lib/main.js headless exactly as seal-host's conformance harness does:
  // env-supplied inputs + temp GITHUB_OUTPUT/SUMMARY, exit code is the verdict.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fleet-action-"));
  const script =
    `require(${JSON.stringify(VERIFIERS[2].entry)}).run().then(c => process.exit(c));`;
  const env = { ...process.env, INPUT_RECEIPTS: file,
    GITHUB_OUTPUT: path.join(dir, "out"), GITHUB_STEP_SUMMARY: path.join(dir, "sum") };
  if (pinned) env["INPUT_EXPECTED-CONFIG-PUBKEY"] = PIN;
  else delete env["INPUT_EXPECTED-CONFIG-PUBKEY"];
  const r = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8", cwd: VERIFY_ACTION, env,
  });
  fs.rmSync(dir, { recursive: true, force: true });
  if (r.signal) return "CRASHED:" + r.signal;
  if (r.status === 0) return "VERIFIED";
  if (r.status === 4) return "REDUCED";
  if (r.status === 3) return "UNPINNED";
  return "FAIL";
}
const CLASSIFY = { kit: classifyKit, "seal-check": classifySealCheck, "seal-verify-action": classifyAction };

(async () => {
  console.log(`fleet verify-layer differential   root=${FLEET_ROOT}`);

  // --- 0. Presence: fail loud on any missing verifier entrypoint ---
  const missing = VERIFIERS.filter((v) => !fs.existsSync(v.entry) || !fs.existsSync(v.declFile));
  if (missing.length) {
    for (const m of missing) console.log(`FAIL  verifier MISSING: ${m.name} -> ${m.entry} / ${m.declFile}`);
    console.log(`\nCannot check fleet verify agreement: ${missing.length} verifier entrypoint(s)/declaration(s) not present.`);
    console.log(`This is a FLEET-ROOT tool. Check out kit + seal-check + seal-verify-action side by side under SEAL_FLEET_ROOT (default ${FLEET_ROOT}).`);
    process.exit(1);
  }

  // --- 1. Extract each copy's LIVE declared profile; cross-check the roster ---
  // A copy with no declaration, an unknown profile, or a declaration that
  // disagrees with the spec roster is a hard failure: the differential's
  // expectations are DERIVED from these declarations, so an undeclared copy is
  // a copy this tool cannot vouch for.
  for (const v of VERIFIERS) {
    const m = fs.readFileSync(v.declFile, "utf8").match(DECL_RE);
    v.profile = m ? m[1] : null;
    const rosterProfile = (SPEC.roster[v.rosterKey] || {}).profile;
    check(`declaration: ${v.name} declares a known profile`,
      v.profile !== null && !!SPEC.profiles[v.profile],
      `no VERIFY_PROFILE declaration (or unknown profile ${v.profile}) in ${v.declFile}`);
    check(`declaration: ${v.name} = ${rosterProfile} per spec roster`,
      v.profile === rosterProfile,
      `live declaration ${v.profile} != roster ${rosterProfile} — a copy re-declared itself; design decision required`);
  }
  if (failures) {
    console.log(`\n${failures} FAILURE(S) — declarations unusable; not running the behavioural differential on top of them`);
    process.exit(1);
  }

  // seal-check enforces canonical serialization (assembleReceiptV2 roundtrip);
  // kit and the action do not. Serialize every input once through seal-check's
  // serializer so the SAME bytes are accepted by all three verifiers.
  const F = await import(path.join(SEAL_CHECK, "receipt-format.js"));
  const legitUnparseable = JSON.parse(fs.readFileSync(
    path.join(KIT_ROOT, "fixtures", "receipt-unparseable.json"), "utf8"));
  // A genuine parseable pass receipt WITH a valid signed_config (the kit's own
  // pass fixtures are config-less by design — the known gap — so the shared
  // pass input comes from seal-check's example, signed under the fleet test key).
  const passReceipt = JSON.parse(fs.readFileSync(
    path.join(SEAL_CHECK, "examples", "allow.receipt.json"), "utf8"));

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
  const passFile = writeCanonical(dir, "pass.receipt.json", passReceipt);
  const configlessParseable = structuredClone(passReceipt);
  delete configlessParseable.signed_config;
  const configlessParseableFile = writeCanonical(dir, "configless-parseable.receipt.json", configlessParseable);

  // Input classes are the spec's (§4); every expectation below is LOOKED UP,
  // not hand-named. `pinned` says whether the trust-anchor pin is supplied.
  const INPUTS = [
    { id: "pass-pinned", file: passFile, pinned: true },
    { id: "pass-unpinned", file: passFile, pinned: false },
    { id: "configless-parseable", file: configlessParseableFile, pinned: true },
    { id: "config-reusing-unparseable-forge", file: forgeFile, pinned: true },
    { id: "configless-unparseable-forge", file: configlessFile, pinned: true },
    { id: "legit-unparseable", file: legitFile, pinned: true },
  ];

  let runs = 0;
  let divergentInputs = 0;
  for (const input of INPUTS) {
    const classes = {};
    const expected = {};
    for (const v of VERIFIERS) {
      classes[v.name] = CLASSIFY[v.name](input.file, input.pinned);
      expected[v.name] = SPEC.profiles[v.profile].expected[input.id];
      runs++;
    }
    const rendered = VERIFIERS.map((v) =>
      `${v.name}[${v.profile}]=${classes[v.name]}(want ${expected[v.name]})`).join(" ");
    console.log(`\n  ${input.id}: ${rendered}`);

    // (a) the forbidden outcome: if NO profile expects VERIFIED for this input
    //     (a forge / unparseable / stripped receipt), no verifier may emit it.
    const anyExpectVerified = VERIFIERS.some((v) => expected[v.name] === "VERIFIED");
    if (!anyExpectVerified) {
      check(`${input.id}: no verifier reports VERIFIED`,
        VERIFIERS.every((v) => classes[v.name] !== "VERIFIED"), rendered);
    }
    // (b) every verifier lands EXACTLY on its declared profile's expected class.
    //     Where profiles agree this asserts agreement; where they differ it
    //     asserts the divergence in both directions (either side drifting onto
    //     the other's class is RED because its own lookup no longer matches).
    for (const v of VERIFIERS) {
      check(`${input.id}: ${v.name} matches its declared profile ${v.profile} (${expected[v.name]})`,
        classes[v.name] === expected[v.name],
        `OFF-PROFILE: got ${classes[v.name]} — report as a finding; do not re-green`);
    }
    if (new Set(VERIFIERS.map((v) => expected[v.name])).size > 1) divergentInputs++;
  }

  // Non-vacuity: every verifier actually ran on every input (no silent skip),
  // and the profile keying is doing real work — at least one input class must
  // have DIFFERING expectations across the declared profiles (P-REF vs
  // P-ENFORCE), otherwise the table degenerated and divergence is untested.
  check("non-vacuity: all verifiers ran on all inputs",
    runs === INPUTS.length * VERIFIERS.length, `${runs} runs`);
  check("non-vacuity: profile-derived divergence exercised",
    divergentInputs >= 2,
    `only ${divergentInputs} input(s) with differing per-profile expectations — the profile keying is vacuous`);

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failures === 0
    ? "\nFLEET VERIFY-LAYER DIFFERENTIAL PASS — every verifier matches its declared profile; agreement and divergence both derived from declarations"
    : `\n${failures} FAILURE(S) — a verifier is off its declared profile (a finding), or declarations are unusable`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
