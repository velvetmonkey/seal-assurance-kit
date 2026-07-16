// SPDX-License-Identifier: Apache-2.0
//
// ===================== Fleet six-copy verifier differential ====================
// ARIA Part B / T5. The receipt validator (receipt-format.js) is hand-copied into
// six repos with NO sync script. On 2026-07-15 one copy (this kit's kernel/) had
// silently fallen 21 lines behind the other five. NOTHING in the fleet checked
// that the copies agree — this script is that check.
//
// *** MANUAL ONLY. THIS IS NOT RUN BY CI. NOBODY IS WATCHING BUT YOU. ***
// It is a FLEET-ROOT tool, not a single-repo CI step: it must see all six repos
// checked out side by side (the layout on Monkey's frisk box; also this repo's
// parent dir). All five siblings are PRIVATE, so no CI runner can check them out
// without SEAL_CI_READ_TOKEN, and a job that skipped green without it would be
// the very defect this corpus exists to pin. So it is deliberately MANUAL: run
// by a human (or Monkey) on a box that has the whole fleet, as part of a frisk.
// Deliberate does not mean safe — a manual check decays into a check that never
// runs. If you are reading this and cannot say when it last ran, run it now.
//
// It resolves siblings under SEAL_FLEET_ROOT (default: the kit's parent
// directory) and FAILS LOUD if any copy is missing — a copy it cannot read is a
// copy it cannot vouch for, never a silent pass.
//
// What it asserts:
//   1. The FIVE downstream copies are byte-identical to each other (catches drift
//      among them — the exact failure that went unnoticed for 21 lines).
//   2. Every js-validator corpus vector produces the SAME verdict across all six
//      copies — EXCEPT the single named known-gap (signed-config-known-gap), where
//      the kit is documented to diverge fail-closed. That one is asserted to hold
//      EXACTLY (kit accepts, five reject); if it ever changes, RED.
//   3. The kit copy is allowed to differ in bytes ONLY in ways that do not change
//      any non-known-gap verdict. A kit byte-divergence that flips a verdict is a
//      failure.
//
// Run:  node test/fleet-copy-differential.cjs
//       SEAL_FLEET_ROOT=/path/to/checkouts node test/fleet-copy-differential.cjs
// ==============================================================================
const fs = require("fs");
const path = require("path");

const KIT_ROOT = path.resolve(__dirname, "..");
const FLEET_ROOT = process.env.SEAL_FLEET_ROOT
  ? path.resolve(process.env.SEAL_FLEET_ROOT)
  : path.resolve(KIT_ROOT, "..");

const MANIFEST = JSON.parse(fs.readFileSync(path.join(__dirname, "corpus", "red-corpus.json"), "utf8"));

// The profile spec (docs/VERIFY-PROFILES.md): the known-gap expectation below
// is DERIVED from each repo's live declared VERIFY_PROFILE, not hand-named.
const SPEC = JSON.parse(fs.readFileSync(path.join(__dirname, "corpus", "verify-profiles.json"), "utf8"));
const DECL_RE = new RegExp(SPEC.declaration_regex);

// The six copies. `kit` is the canonical source that had fallen behind; the other
// five are the downstream copies expected byte-identical to each other.
// `rosterKey`/`declFile` name the repo-level VERIFY_PROFILE declaration each
// format copy belongs to (seal-live-demo's two copies share one declaration).
const COPIES = [
  { name: "kit (kernel/)", role: "source", file: path.join(KIT_ROOT, "kernel", "receipt-format.js"),
    rosterKey: "kit", declFile: path.join(KIT_ROOT, "src", "verify.cjs") },
  { name: "seal-check", role: "downstream", file: path.join(FLEET_ROOT, "seal-check", "receipt-format.js"),
    rosterKey: "seal-check", declFile: path.join(FLEET_ROOT, "seal-check", "receipt.js") },
  { name: "seal-demo/public", role: "downstream", file: path.join(FLEET_ROOT, "seal-demo", "public", "receipt-format.js"),
    rosterKey: "seal-demo", declFile: path.join(FLEET_ROOT, "seal-demo", "public", "audit.js") },
  { name: "seal-live-demo/pwa", role: "downstream", file: path.join(FLEET_ROOT, "seal-live-demo", "pwa", "receipt-format.js"),
    rosterKey: "seal-live-demo", declFile: path.join(FLEET_ROOT, "seal-live-demo", "pwa", "receipt.js") },
  { name: "seal-live-demo/seal-gateway", role: "downstream", file: path.join(FLEET_ROOT, "seal-live-demo", "seal-gateway", "receipt-format.js"),
    rosterKey: "seal-live-demo", declFile: path.join(FLEET_ROOT, "seal-live-demo", "pwa", "receipt.js") },
  { name: "seal-verify-action/vendor", role: "fork-downstream", file: path.join(FLEET_ROOT, "seal-verify-action", "vendor", "seal-assurance-kit", "kernel", "receipt-format.js"),
    rosterKey: "seal-verify-action", declFile: path.join(FLEET_ROOT, "seal-verify-action", "lib", "pin.js") },
];

const KNOWN_GAP_ID = "signed-config-known-gap";

let failures = 0;
function check(name, cond, detail = "") {
  if (!cond) failures++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : `   (${detail})`}`);
}

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(KIT_ROOT, "fixtures", name), "utf8"));
}
function buildInput(vector) {
  if (vector.inline) return structuredClone(vector.inline);
  if (vector.base_fixture) {
    const r = loadFixture(vector.base_fixture);
    if (vector.mutate && vector.mutate.set) Object.assign(r, structuredClone(vector.mutate.set));
    return r;
  }
  return null;
}

(async () => {
  console.log(`fleet six-copy differential   root=${FLEET_ROOT}`);

  // --- 0. Presence: fail loud on any missing copy (never a silent skip) ---
  const missing = COPIES.filter((c) => !fs.existsSync(c.file));
  if (missing.length) {
    for (const m of missing) console.log(`FAIL  copy MISSING: ${m.name} -> ${m.file}`);
    console.log(`\nCannot vouch for six-copy agreement: ${missing.length} copy/copies not present in this checkout.`);
    console.log(`This is a FLEET-ROOT tool. Check out all six repos side by side under SEAL_FLEET_ROOT (default ${FLEET_ROOT}).`);
    process.exit(1);
  }

  // --- 0b. Live declared profiles: every copy's repo must declare, and the
  // declaration must match the spec roster (docs/VERIFY-PROFILES.md §6). The
  // known-gap assertion below is DERIVED from these declarations.
  for (const c of COPIES) {
    const m = fs.existsSync(c.declFile) && fs.readFileSync(c.declFile, "utf8").match(DECL_RE);
    c.profile = m ? m[1] : null;
    const rosterProfile = (SPEC.roster[c.rosterKey] || {}).profile;
    check(`declaration: ${c.name} repo declares ${rosterProfile}`,
      c.profile === rosterProfile && !!SPEC.profiles[c.profile],
      `live declaration ${c.profile} != roster ${rosterProfile} (${c.declFile}) — undeclared or re-declared copy; report, do not re-green`);
  }
  if (failures) {
    console.log(`\n${failures} FAILURE(S) — declarations unusable; not deriving expectations from them`);
    process.exit(1);
  }

  // --- 1. The downstream copies must be byte-identical to each other -------
  // The seal-verify-action copy is a MAINTAINED FORK since kit re-vendor
  // fbe0ca8 (2026-07-16): it carries a mandatory FORK DELTA header naming the
  // fork. Its contract here is byte-identity MODULO exactly that header —
  // the header must be PRESENT (a vendor-sync sweep silently flattening it is
  // RED) and stripping the leading FORK DELTA comment block must yield the
  // canonical seal-check bytes (any drift beyond the declared header is RED).
  const downstream = COPIES.filter((c) => c.role === "downstream");
  const bytes = new Map(downstream.map((c) => [c.name, fs.readFileSync(c.file, "utf8")]));
  const ref = downstream[0];
  const refBytes = bytes.get(ref.name);
  for (const c of downstream.slice(1)) {
    check(`downstream byte-identical: ${c.name} == ${ref.name}`, bytes.get(c.name) === refBytes,
      "a downstream copy has drifted from its siblings");
  }
  for (const c of COPIES.filter((x) => x.role === "fork-downstream")) {
    const forkLines = fs.readFileSync(c.file, "utf8").split("\n");
    const refLines = refBytes.split("\n");
    // The fork copy must be EXACTLY the canonical bytes with ONE contiguous
    // pure-comment block (containing "FORK DELTA") inserted. Find the first
    // diverging line; the extra lines start there and their count is the
    // length difference; everything after must match the canonical remainder.
    const extra = forkLines.length - refLines.length;
    let firstDiff = 0;
    while (firstDiff < refLines.length && forkLines[firstDiff] === refLines[firstDiff]) firstDiff++;
    const inserted = forkLines.slice(firstDiff, firstDiff + extra);
    const headerOk = extra > 0 &&
      inserted.every((l) => l.startsWith("//")) &&
      inserted.some((l) => /FORK DELTA/.test(l));
    check(`fork header present: ${c.name} carries its FORK DELTA header`,
      headerOk,
      "the fork header was flattened (or is not a pure comment block) — the fbe0ca8 fork formalization regressed");
    const stripped = forkLines.slice(0, firstDiff).concat(forkLines.slice(firstDiff + extra)).join("\n");
    check(`fork byte-identical modulo header: ${c.name} == ${ref.name} after stripping FORK DELTA`,
      headerOk && stripped === refBytes,
      "the fork copy drifted beyond its declared FORK DELTA header");
  }

  // --- 2. Load every copy's validateReceipt ---
  const validators = {};
  for (const c of COPIES) {
    const F = await import("file://" + c.file + "?t=" + c.name.replace(/\W/g, ""));
    if (typeof F.validateReceipt !== "function") {
      check(`${c.name} exports validateReceipt`, false, "missing export");
      continue;
    }
    validators[c.name] = F.validateReceipt;
  }

  // --- 3. Verdict agreement across all six on every js-validator vector ---
  const jsVectors = MANIFEST.vectors.filter((v) =>
    v.surfaces.some((s) => s.startsWith("js-validator")) && buildInput(v.vector) !== null);

  // Non-vacuity: this script's PURPOSE #2 is six-copy verdict agreement over
  // the js-validator vectors. If the filter matches nothing (a renamed
  // `surfaces` tag, a manifest that failed to load its vectors), the loop
  // below runs zero times and the script would still print PASS — verifying
  // nothing. Fail loud instead. Also require the named known-gap vector to be
  // present, since its EXACT-hold check (kit accepts / five reject) is the one
  // asserted divergence and is silently skipped if the vector is absent.
  const jsValidatorVectorCount = MANIFEST.vectors.filter((v) =>
    v.surfaces.some((s) => s.startsWith("js-validator"))).length;
  check(`js-validator vectors present (non-vacuous differential)`,
    jsVectors.length > 0 && jsVectors.length === jsValidatorVectorCount,
    `expected ${jsValidatorVectorCount} runnable js-validator vectors, got ${jsVectors.length} — ` +
    `a differential over zero (or a dropped) vectors proves nothing`);
  check(`known-gap vector present in the differential set`,
    jsVectors.some((v) => v.id === KNOWN_GAP_ID),
    `${KNOWN_GAP_ID} absent — its exact-hold assertion (kit accepts / five reject) would be silently skipped`);

  for (const v of jsVectors) {
    const input = buildInput(v.vector);
    const verdicts = COPIES.map((c) => ({ name: c.name, ok: validators[c.name](structuredClone(input)).ok }));

    if (v.id === KNOWN_GAP_ID) {
      // The one documented, intentional divergence — DERIVED from profiles:
      // a copy accepts a mediated-no-signed_config receipt iff its repo
      // declares a profile whose `configless_mediated` is "accept" (P-REF).
      // Today that is exactly the kit; if a copy re-profiles, the roster
      // check above goes red FIRST — this stays keyed to declarations.
      for (const c of COPIES) {
        const want = SPEC.profiles[c.profile].configless_mediated === "accept";
        const got = verdicts.find((x) => x.name === c.name).ok;
        check(`KNOWN GAP per profile: ${c.name} [${c.profile}] ${want ? "ACCEPTS" : "REJECTS"} mediated-no-signed_config`,
          got === want,
          want
            ? "a P-REF copy no longer accepts — the signed_config gap changed; revisit the design decision, do not re-green"
            : "an enforcing copy stopped rejecting missing signed_config — fail-open drift; report as a finding");
      }
      const accepters = COPIES.filter((c) => SPEC.profiles[c.profile].configless_mediated === "accept");
      check(`KNOWN GAP non-vacuity: divergence exists (some accept, some reject)`,
        accepters.length > 0 && accepters.length < COPIES.length,
        "profile table degenerated — the known-gap divergence is no longer exercised");
      continue;
    }

    // Every other vector: all six must AGREE (here: all reject).
    const allAgree = verdicts.every((x) => x.ok === verdicts[0].ok);
    check(`six-copy verdict agreement: ${v.id} (all ok=${verdicts[0].ok})`, allAgree,
      "copies disagree: " + JSON.stringify(verdicts));
  }

  console.log(failures === 0
    ? `\nFLEET DIFFERENTIAL PASS  (4 downstream byte-identical + 1 fork byte-identical modulo its FORK DELTA header; declarations match the roster; 6-copy verdict agreement on ${jsVectors.length - 1} vectors + 1 profile-derived known-gap)`
    : `\n${failures} FAILURE(S) — the six verifier copies do not agree as pinned`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
