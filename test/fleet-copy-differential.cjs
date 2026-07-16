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

// The six copies. `kit` is the canonical source that had fallen behind; the other
// five are the downstream copies expected byte-identical to each other.
const COPIES = [
  { name: "kit (kernel/)", role: "source", file: path.join(KIT_ROOT, "kernel", "receipt-format.js") },
  { name: "seal-check", role: "downstream", file: path.join(FLEET_ROOT, "seal-check", "receipt-format.js") },
  { name: "seal-demo/public", role: "downstream", file: path.join(FLEET_ROOT, "seal-demo", "public", "receipt-format.js") },
  { name: "seal-live-demo/pwa", role: "downstream", file: path.join(FLEET_ROOT, "seal-live-demo", "pwa", "receipt-format.js") },
  { name: "seal-live-demo/seal-gateway", role: "downstream", file: path.join(FLEET_ROOT, "seal-live-demo", "seal-gateway", "receipt-format.js") },
  { name: "seal-verify-action/vendor", role: "downstream", file: path.join(FLEET_ROOT, "seal-verify-action", "vendor", "seal-assurance-kit", "kernel", "receipt-format.js") },
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

  // --- 1. The five downstream copies must be byte-identical to each other ---
  const downstream = COPIES.filter((c) => c.role === "downstream");
  const bytes = new Map(downstream.map((c) => [c.name, fs.readFileSync(c.file, "utf8")]));
  const ref = downstream[0];
  const refBytes = bytes.get(ref.name);
  for (const c of downstream.slice(1)) {
    check(`downstream byte-identical: ${c.name} == ${ref.name}`, bytes.get(c.name) === refBytes,
      "a downstream copy has drifted from its siblings");
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
      // The one documented, intentional divergence: kit accepts, five reject.
      const kit = verdicts.find((x) => x.name.startsWith("kit")).ok;
      const five = verdicts.filter((x) => !x.name.startsWith("kit"));
      check(`KNOWN GAP holds exactly: kit ACCEPTS mediated-no-signed_config`, kit === true,
        "kit no longer accepts — the signed_config gap changed; revisit the fix decision, do not re-green");
      check(`KNOWN GAP holds exactly: all five downstream REJECT`, five.every((x) => x.ok === false),
        "a downstream copy stopped rejecting missing signed_config: " + JSON.stringify(five));
      continue;
    }

    // Every other vector: all six must AGREE (here: all reject).
    const allAgree = verdicts.every((x) => x.ok === verdicts[0].ok);
    check(`six-copy verdict agreement: ${v.id} (all ok=${verdicts[0].ok})`, allAgree,
      "copies disagree: " + JSON.stringify(verdicts));
  }

  console.log(failures === 0
    ? `\nFLEET DIFFERENTIAL PASS  (5 downstream byte-identical; 6-copy verdict agreement on ${jsVectors.length - 1} vectors + 1 named known-gap)`
    : `\n${failures} FAILURE(S) — the six verifier copies do not agree as pinned`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
