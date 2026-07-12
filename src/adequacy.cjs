// SPDX-License-Identifier: Apache-2.0
// `seal adequacy check <labels.json>` — finite monitor-resolution adequacy.
// `seal adequacy find-collision <labels.json>`
//
// This is not `seal scan`: scan audits tool-list catalog coverage. Adequacy
// checks whether the declared monitor evidence refines the supplied policy labels
// over the finite state sample.
const fs = require("fs");

function stableStringify(x) {
  if (x === undefined) return "<undefined>";
  if (x === null || typeof x !== "object") return JSON.stringify(x);
  if (Array.isArray(x)) return `[${x.map(stableStringify).join(",")}]`;
  const keys = Object.keys(x).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(x[k])}`).join(",")}}`;
}

function readJson(p) { return JSON.parse(fs.readFileSync(p, "utf8")); }
function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
function labelOf(s) { return stableStringify(s.label); }
function displayValue(v) { return stableStringify(v); }
function stateName(s) { return String(s.id); }

function validate(doc) {
  const errors = [];
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { ok: false, errors: ["top-level JSON must be an object"] };
  }
  if (!Array.isArray(doc.states)) errors.push("states must be an array");
  if (!Array.isArray(doc.monitors)) errors.push("monitors must be an array");
  if (errors.length) return { ok: false, errors };

  const seenStates = new Set();
  for (const [i, s] of doc.states.entries()) {
    const where = `state[${i}]`;
    if (!s || typeof s !== "object" || Array.isArray(s)) {
      errors.push(`${where} must be an object`);
      continue;
    }
    if (!own(s, "id") || s.id === "") errors.push(`${where} missing id`);
    else if (seenStates.has(String(s.id))) errors.push(`duplicate state id ${JSON.stringify(String(s.id))}`);
    else seenStates.add(String(s.id));
    if (!own(s, "label")) errors.push(`${where} missing label`);
    if (!own(s, "evidence") || !s.evidence || typeof s.evidence !== "object" || Array.isArray(s.evidence)) {
      errors.push(`${where} evidence must be an object`);
      continue;
    }
    for (const m of doc.monitors) {
      if (typeof m !== "string" || m === "") continue;
      if (!own(s.evidence, m)) {
        errors.push(`state ${JSON.stringify(String(s.id))} evidence missing declared monitor ${JSON.stringify(m)}`);
      }
    }
  }

  const seenMonitors = new Set();
  for (const [i, m] of doc.monitors.entries()) {
    if (typeof m !== "string" || m === "") {
      errors.push(`monitors[${i}] must be a non-empty string`);
    } else if (seenMonitors.has(m)) {
      errors.push(`duplicate monitor ${JSON.stringify(m)}`);
    } else {
      seenMonitors.add(m);
    }
  }

  return { ok: errors.length === 0, errors };
}

function vectorFor(state, monitors) {
  return monitors.map((m) => state.evidence[m]);
}

function evidenceLine(vector, monitors) {
  if (monitors.length === 0) return "<empty witness vector>";
  return monitors.map((m, i) => `${m}=${displayValue(vector[i])}`).join(", ");
}

function analyze(doc) {
  const buckets = new Map();
  for (const s of doc.states) {
    const vector = vectorFor(s, doc.monitors);
    const key = stableStringify(vector);
    if (!buckets.has(key)) buckets.set(key, { vector, states: [] });
    buckets.get(key).states.push(s);
  }

  const collisions = [];
  for (const bucket of buckets.values()) {
    const states = bucket.states;
    for (let i = 0; i < states.length; i++) {
      for (let j = i + 1; j < states.length; j++) {
        if (labelOf(states[i]) !== labelOf(states[j])) {
          collisions.push({ left: states[i], right: states[j], vector: bucket.vector });
        }
      }
    }
  }

  const labels = new Set(doc.states.map((s) => labelOf(s)));
  return { buckets, collisions, labels };
}

function missingDistinguisher(pair, monitors) {
  const excluded = new Set(["id", "label", "evidence", ...monitors]);
  const keys = new Set([...Object.keys(pair.left), ...Object.keys(pair.right)]);
  const differing = [];
  for (const k of [...keys].sort()) {
    if (excluded.has(k)) continue;
    const lv = own(pair.left, k) ? pair.left[k] : undefined;
    const rv = own(pair.right, k) ? pair.right[k] : undefined;
    if (stableStringify(lv) !== stableStringify(rv)) differing.push(k);
  }
  if (differing.length) return `missing distinguisher (heuristic): ${differing.join(", ")}`;
  return "missing distinguisher (heuristic): no differing raw top-level field found";
}

function load(labelsPath) {
  try {
    const doc = readJson(labelsPath);
    const shape = validate(doc);
    if (!shape.ok) return { ok: false, errors: shape.errors };
    return { ok: true, doc };
  } catch (e) {
    return { ok: false, errors: [`cannot read labels: ${e.message}`] };
  }
}

function printPrelude(mode, labelsPath, doc) {
  console.log(`seal adequacy ${mode}  ${labelsPath}`);
  console.log(`  states: ${doc.states.length}   monitors: ${doc.monitors.length}`);
  console.log("  warrant: Lean check_implies_finite_witness_computable + collision_refutes_aggregator; JS agrees on corpus C");
  console.log("  scope: finite supplied sample only; PASS is not universal adequacy over all traces");
}

function printMalformed(mode, labelsPath, errors) {
  console.log(`seal adequacy ${mode}  ${labelsPath}`);
  for (const e of errors) console.log(`  FAIL  malformed input: ${e}`);
}

function printCollision(pair, monitors) {
  console.log(`  collision: ${stateName(pair.left)} vs ${stateName(pair.right)}`);
  console.log(`    labels: ${displayValue(pair.left.label)} vs ${displayValue(pair.right.label)}`);
  console.log(`    shared evidence: ${evidenceLine(pair.vector, monitors)}`);
  console.log(`    ${missingDistinguisher(pair, monitors)}`);
}

function report(mode, labelsPath, doc, firstOnly = false) {
  const result = analyze(doc);
  printPrelude(mode, labelsPath, doc);

  if (result.collisions.length) {
    console.log("  FAIL  monitor evidence does not refine labels over the observed finite sample");
    const shown = firstOnly ? result.collisions.slice(0, 1) : result.collisions;
    for (const pair of shown) printCollision(pair, doc.monitors);
    console.log(`  FAIL  ${result.collisions.length} collision(s); no monitor-based policy over these monitors can be correct on this sample`);
    return false;
  }

  if (result.labels.size <= 1) {
    const label = doc.states.length ? displayValue(doc.states[0].label) : "<none>";
    console.log(`  WARN  VACUOUS over observed finite sample: all ${doc.states.length} state(s) share label ${label}`);
    console.log("  WARN  refinement holds, but this sample does not exercise a policy distinction");
    return true;
  }

  console.log("  PASS  ADEQUATE over observed finite sample: monitor evidence refines labels in this input");
  console.log(`  certificate: ${doc.monitors.length} monitor(s), ${result.buckets.size} evidence fibre(s), ${result.labels.size} label(s), 0 collision(s)`);
  return true;
}

function check(labelsPath) {
  const loaded = load(labelsPath);
  if (!loaded.ok) {
    printMalformed("check", labelsPath, loaded.errors);
    return false;
  }
  return report("check", labelsPath, loaded.doc, false);
}

function findCollision(labelsPath) {
  const loaded = load(labelsPath);
  if (!loaded.ok) {
    printMalformed("find-collision", labelsPath, loaded.errors);
    return false;
  }
  return report("find-collision", labelsPath, loaded.doc, true);
}

module.exports = { check, findCollision, stableStringify, validate, analyze };
