// SPDX-License-Identifier: Apache-2.0
// `seal receipt-diff <A.json> <B.json>` — authorization-surface diff between
// two decision receipts.
//
// Third sibling of the family: `seal verify` answers "is this receipt
// well-formed and re-derivable?"; the (private) sufficiency analyzer answers
// "does this field set carry enough to justify the claim?"; receipt-diff
// answers "what changed between these two receipts, and does the change touch
// what is AUTHORIZED?".
//
// Honest scope: this command reports differences and classifies them. It does
// NOT re-run the kernel or re-verify a seal (that is `seal verify`), and it
// does NOT judge whether the field set is sufficient to authorize the effect.
//
// Integrity comes first: each receipt's canonical_request_sha256 (and v2
// args_hash) is re-derived from its OWN (tool, arguments) in stored key order
// (schema §2) before any diff. A receipt whose stored hash contradicts its own
// arguments is stale or tampered; diffing it would launder that.
//
// Classification is a fixed map (see AUTH_FIELDS / MINOR_FIELDS). Unknown
// top-level fields are producer-local blocks per the schema ("verifiers MUST
// ignore unknown top-level fields") — reported under MINOR, never hidden.
// `certs` and `emitted_bytes` are MINOR by design: the seal verdict is the
// conjunction of gates, so any per-gate flip necessarily moves `verdict` or
// `deny_kernel` (both AUTH); the transcript cannot hide an authorization
// change, and keeping it MINOR stops a reason-only edit reading as drift.
//
// Exit codes (kit convention): 0 no authorization-surface drift (MINOR-only
// is 0) · 1 drift · 2 malformed / legacy-rejected / integrity-flagged ·
// 3 internal error.

const fs = require("fs");
const path = require("path");

// Top-level fields that change WHAT IS AUTHORIZED, in report order.
// `arguments` is compared via the derived canonical request line, so argument
// key ORDER is significant, exactly as in the schema §2 pre-image.
// The whole `approval` block is AUTH: its subfields (approval_identity,
// policy_hash, and nonce/issued_at/expiry when a channel emits them) change
// WHICH approval authorized the effect.
const AUTH_FIELDS = [
  "tool", "arguments", "canonical_request_sha256", "args_hash", "verdict",
  "deny_kernel", "bypass", "approval", "granted_capabilities", "kernel_config",
];
const AUTH_SUBFIELDS = [["kernel_identity", "wasm_sha256"]];

// Known-MINOR fields: cosmetic, provenance, or derived transcript.
const MINOR_FIELDS = [
  "reason", "now", "asserted_provenance", "signature", "policy_id",
  "certs", "emitted_bytes",
];
const MINOR_SUBFIELDS = [["kernel_identity", "self_verified"]];

// Fields consumed elsewhere (never diffed directly): discriminators are the
// schema-version note; canonical_request (stored string) is an integrity
// input checked against the derived line.
const CONSUMED = new Set([
  "seal_receipt", "seal_live_receipt", "canonical_request", "kernel_identity",
  ...AUTH_FIELDS, ...MINOR_FIELDS,
]);

function show(v, max = 96) {
  if (v === undefined) return "(absent)";
  const s = JSON.stringify(v);
  return s.length <= max ? s : s.slice(0, max) + `…(${s.length} chars)`;
}

async function loadFormat() {
  return import("file://" + path.resolve(__dirname, "../kernel/receipt-format.js"));
}

function loadReceipt(F, file) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return { error: `cannot read receipt ${file}: ${e.message}` };
  }
  const shape = F.validateReceipt(raw);
  if (shape.version === "v0-check" || (!shape.ok && shape.version === null)) {
    // Schema-K legacy and unrecognized discriminators are hard rejects; other
    // validation errors are reported but do not block a diff (the diff is not
    // a verifier), EXCEPT that integrity below still gates.
    return { error: `${file}: ${shape.errors.join("; ")}` };
  }
  return { receipt: raw, version: shape.version, file };
}

// Re-derive the hashes a receipt asserts about ITSELF. Returns a list of
// integrity findings; empty = clean.
function integrityFindings(F, r) {
  const out = [];
  if (typeof r.receipt.tool !== "string" || typeof r.receipt.arguments !== "object" || r.receipt.arguments === null) {
    out.push("tool/arguments missing — cannot re-derive the canonical request");
    return out;
  }
  const line = F.canonicalRequest(r.receipt.tool, r.receipt.arguments);
  if (typeof r.receipt.canonical_request === "string" && r.receipt.canonical_request !== line) {
    out.push("stored canonical_request does not equal the line derived from (tool, arguments) in stored key order");
  }
  const sha = F.canonicalRequestSha256(r.receipt.tool, r.receipt.arguments);
  if (r.receipt.canonical_request_sha256 !== sha) {
    out.push(`stored canonical_request_sha256 (${show(r.receipt.canonical_request_sha256, 20)}) does not match the hash re-derived from this receipt's own arguments (${sha.slice(0, 12)}…) — stale or tampered`);
  }
  if ("args_hash" in r.receipt) {
    const ah = F.canonicalJsonSha256(r.receipt.arguments);
    if (r.receipt.args_hash !== ah) {
      out.push(`stored args_hash does not match sha256 of the canonical arguments serialization (${ah.slice(0, 12)}…) — stale or tampered`);
    }
  }
  return out;
}

function canon(F, v) {
  // Stable serialization for equality checks where the schema does NOT make
  // order significant (grants are a set; config/approval are objects whose
  // meaning is key-value). Sorting keys here is a comparison discipline only.
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map((x) => canon(F, x)).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(F, v[k])).join(",") + "}";
}

function diffReceipts(F, A, B) {
  const auth = [];
  const minor = [];
  const push = (list, field, a, b, note) => list.push({ field, a, b, ...(note ? { note } : {}) });

  const lineA = F.canonicalRequest(A.receipt.tool, A.receipt.arguments);
  const lineB = F.canonicalRequest(B.receipt.tool, B.receipt.arguments);

  for (const f of AUTH_FIELDS) {
    const a = A.receipt[f], b = B.receipt[f];
    if (f === "arguments") {
      if (lineA === lineB) continue;
      const ka = Object.keys(a), kb = Object.keys(b);
      const added = kb.filter((k) => !ka.includes(k));
      const removed = ka.filter((k) => !kb.includes(k));
      const changed = ka.filter((k) => kb.includes(k) && canon(F, a[k]) !== canon(F, b[k]));
      const orderOnly = !added.length && !removed.length && !changed.length;
      const parts = [];
      if (added.length) parts.push(`+{${added.join(", ")}}`);
      if (removed.length) parts.push(`-{${removed.join(", ")}}`);
      if (changed.length) parts.push(`~{${changed.join(", ")}}`);
      if (orderOnly) parts.push("key order changed (order is significant in the canonical pre-image, schema §2)");
      push(auth, "arguments", a, b, parts.join(" "));
      continue;
    }
    if (f === "canonical_request_sha256") {
      // compare the DERIVED hashes (integrity already pinned stored == derived)
      const da = F.canonicalRequestSha256(A.receipt.tool, A.receipt.arguments);
      const db = F.canonicalRequestSha256(B.receipt.tool, B.receipt.arguments);
      if (da !== db) push(auth, f, da, db, "derived from each receipt's own (tool, arguments)");
      continue;
    }
    if (f === "granted_capabilities") {
      if (a === undefined && b === undefined) continue;
      const sa = new Set((Array.isArray(a) ? a : []).map((g) => canon(F, g)));
      const sb = new Set((Array.isArray(b) ? b : []).map((g) => canon(F, g)));
      const added = [...sb].filter((g) => !sa.has(g)).sort();
      const removed = [...sa].filter((g) => !sb.has(g)).sort();
      if (added.length || removed.length) {
        push(auth, f, a, b, [removed.length ? `-${removed.length} grant(s)` : "", added.length ? `+${added.length} grant(s)` : ""].filter(Boolean).join(" "));
      }
      continue;
    }
    if ((a === undefined) !== (b === undefined)) {
      push(auth, f, a, b, a === undefined ? "added" : "removed");
      continue;
    }
    if (a !== undefined && canon(F, a) !== canon(F, b)) push(auth, f, a, b);
  }
  for (const [obj, key] of AUTH_SUBFIELDS) {
    const a = A.receipt[obj]?.[key], b = B.receipt[obj]?.[key];
    if (canon(F, a ?? null) !== canon(F, b ?? null)) push(auth, `${obj}.${key}`, a, b);
  }

  for (const f of MINOR_FIELDS) {
    const a = A.receipt[f], b = B.receipt[f];
    if ((a === undefined) !== (b === undefined)) { push(minor, f, a, b, a === undefined ? "added" : "removed"); continue; }
    if (a !== undefined && canon(F, a) !== canon(F, b)) push(minor, f, a, b);
  }
  for (const [obj, key] of MINOR_SUBFIELDS) {
    const a = A.receipt[obj]?.[key], b = B.receipt[obj]?.[key];
    if (canon(F, a ?? null) !== canon(F, b ?? null)) push(minor, `${obj}.${key}`, a, b);
  }

  // Producer-local / unknown top-level fields (schema: verifiers MUST ignore).
  const unknown = [...new Set([...Object.keys(A.receipt), ...Object.keys(B.receipt)])]
    .filter((k) => !CONSUMED.has(k)).sort();
  for (const f of unknown) {
    const a = A.receipt[f], b = B.receipt[f];
    if (canon(F, a ?? null) !== canon(F, b ?? null)) push(minor, f, a, b, "producer-local block");
  }

  return { auth, minor };
}

function schemaDrift(A, B) {
  if (A.version === B.version) return null;
  const pre = (v) => v === "v1" || v === "v0-live";
  let note = `schema version differs: ${A.version} vs ${B.version}`;
  if (pre(A.version) && B.version === "v2") {
    note += " — approval surface widened: +args_hash, +approval (the upgrade the sufficiency analysis proved necessary: the pre-v2 field set could not uniquely identify the authorized effect)";
  } else if (A.version === "v2" && pre(B.version)) {
    note += " — approval surface NARROWED: -args_hash, -approval (reverting the fields that close the known pre-v2 collision)";
  }
  return { a: A.version, b: B.version, note };
}

async function receiptDiff(fileA, fileB, { json = false } = {}) {
  const F = await loadFormat();
  const A = loadReceipt(F, fileA);
  const B = loadReceipt(F, fileB);
  for (const r of [A, B]) {
    if (r.error) {
      console.error(`FAIL  ${r.error}`);
      return 2;
    }
  }
  const integ = { a: integrityFindings(F, A), b: integrityFindings(F, B) };
  if (integ.a.length || integ.b.length) {
    if (json) {
      console.log(JSON.stringify({ a: { file: fileA, version: A.version }, b: { file: fileB, version: B.version }, integrity: integ, result: "INTEGRITY", exit: 2 }, null, 2));
    } else {
      console.log(`seal receipt-diff  ${fileA}  ${fileB}`);
      for (const [name, list] of [["A", integ.a], ["B", integ.b]]) {
        for (const finding of list) console.log(`FAIL  integrity ${name}: ${finding}`);
      }
      console.log("RESULT: INTEGRITY FLAG — a receipt disagrees with its own arguments; not diffing stale/tampered evidence");
    }
    return 2;
  }

  const drift = schemaDrift(A, B);
  const { auth, minor } = diffReceipts(F, A, B);
  const exit = auth.length ? 1 : 0;

  if (json) {
    console.log(JSON.stringify({
      a: { file: fileA, version: A.version },
      b: { file: fileB, version: B.version },
      integrity: "clean",
      schema_drift: drift,
      authorization: auth,
      minor,
      result: exit ? "AUTHORIZATION DRIFT" : "NO AUTHORIZATION-SURFACE DRIFT",
      exit,
    }, null, 2));
    return exit;
  }

  console.log(`seal receipt-diff  ${fileA}  ${fileB}`);
  console.log(`  A: ${A.version}   B: ${B.version}   integrity: both receipts consistent with their own arguments`);
  if (drift) console.log(`NOTE  ${drift.note}`);
  console.log(`AUTHORIZATION-SURFACE DRIFT (${auth.length})`);
  for (const d of auth) console.log(`  ${d.field}: ${show(d.a)} -> ${show(d.b)}${d.note ? `   [${d.note}]` : ""}`);
  if (!auth.length) console.log("  (none — the two receipts authorize the same thing at this surface)");
  console.log(`MINOR (${minor.length})`);
  for (const d of minor) console.log(`  ${d.field}: ${show(d.a)} -> ${show(d.b)}${d.note ? `   [${d.note}]` : ""}`);
  if (!minor.length) console.log("  (none)");
  console.log(exit
    ? "RESULT: AUTHORIZATION DRIFT — these receipts do not authorize the same thing"
    : "RESULT: no authorization-surface drift (minor differences do not change what was authorized)");
  console.log("scope: reports what changed, not whether either receipt verifies (`seal verify`) or whether the field set is sufficient to authorize the effect");
  return exit;
}

module.exports = { receiptDiff };
