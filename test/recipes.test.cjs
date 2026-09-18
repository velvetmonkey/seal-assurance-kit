// SPDX-License-Identifier: Apache-2.0
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { RECIPE_ACTIVE, referencedTools, applyRecipe, addKernelToPolicy } = require("../src/recipes.cjs");
const { validateTrustedConfig } = require("../src/trusted-config.cjs");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "seal");
const MANIFEST_ROOT = path.join(__dirname, "fixtures", "manifests");
const MANIFESTS = [
  "dbhub-0.23.0.tools.json",
  "filesystem-2026.7.10.tools.json",
  "github-mcp-v1.0.5.tools.json",
];

function run(args, expected = 0) {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, expected, `${args.join(" ")} exited ${result.status}:\n${output}`);
  return output;
}

function activeSymbols(output) {
  const block = output.match(/ACTIVE \(\d+\):\n([\s\S]*?)\n\s*PRESENT-BUT-INACTIVE/);
  assert.ok(block, `ACTIVE block missing:\n${output}`);
  return [...block[1].matchAll(/\(([STCVKLB])(?:, EXPERIMENTAL)?\)/g)]
    .map((match) => match[1]).sort();
}

function assertGeneratedPolicy(policy, manifest, expected) {
  const shape = validateTrustedConfig(policy);
  assert.equal(shape.ok, true, shape.errors.join("; "));
  assert.deepEqual(shape.participation.active.map((entry) => entry.symbol).sort(), [...expected].sort());
  assert.deepEqual(shape.participation.inactive, []);
  assert.equal(Object.prototype.hasOwnProperty.call(policy, "calibration"), false, "recipe emitted K");
  const names = new Set(manifest.tools.map((tool) => tool.name));
  for (const name of referencedTools(policy)) assert.equal(names.has(name), true, `non-manifest kernel reference: ${name}`);
  assert.match(JSON.stringify(policy), /EDIT-ME/, "recipe omitted visible placeholders/review markers");
}

for (const [recipe, expected] of Object.entries(RECIPE_ACTIVE)) {
  for (const filename of MANIFESTS) {
    test(`${recipe} × ${filename}: distinct roles or refusal; sign-ack/scan agree on success`, () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-recipe-"));
      const manifestPath = path.join(MANIFEST_ROOT, filename);
      const policyPath = path.join(dir, "policy.json");
      const keyPath = path.join(dir, "key");
      const signedPath = path.join(dir, "trusted.json");
      fs.writeFileSync(keyPath, "07".repeat(32));

      const collision = (filename.startsWith("dbhub") && recipe !== "prod-db") ||
        (filename.startsWith("filesystem") && recipe === "token-governor");
      if (collision) {
        const refused = run(["init", "--recipe", recipe, manifestPath, "--out", policyPath], 1);
        assert.match(refused, /roles '.*' and '.*' both select tool/);
        assert.match(refused, /second, distinct guarded tool/);
        assert.equal(fs.existsSync(policyPath), false, "collision wrote a policy");
        return;
      }
      const init = run(["init", "--recipe", recipe, manifestPath, "--out", policyPath]);
      assert.match(init, new RegExp(`recipe ${recipe.replaceAll("-", "\\-")}  ACTIVE`));
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
      assertGeneratedPolicy(policy, manifest, expected);

      const sign = run(["policy", "sign", policyPath, "--key", keyPath, "--out", signedPath, "--yes"]);
      const scan = run(["scan", manifestPath, policyPath]);
      assert.deepEqual(activeSymbols(sign), [...expected].sort());
      assert.deepEqual(activeSymbols(scan), [...expected].sort());
      assert.match(sign, /PRESENT-BUT-INACTIVE \(0\)/);
      assert.match(scan, /PRESENT-BUT-INACTIVE \(0\)/);
      assert.match(scan, /PASS  0 uncovered, 0 ungated/);
      assert.equal(fs.existsSync(signedPath), true);

      for (const line of init.split("\n").filter((entry) => entry.includes("best-fit mapping")))
        assert.match(line, /Review whether this recipe suits this server at all/);
      console.log(`PASS ${recipe} × ${filename}: ACTIVE {${[...expected].sort()}}; no vacuity; K absent`);
    });
  }
}

test("add-kernel supports derived sibling and explicit --policy without overwriting sections", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-add-kernel-"));
  const source = path.join(MANIFEST_ROOT, MANIFESTS[0]);
  const manifest = path.join(dir, "dbhub.tools.json");
  fs.copyFileSync(source, manifest);
  run(["init", manifest]);
  const derived = path.join(dir, "dbhub.policy.json");
  run(["add-kernel", "B", manifest]);
  let shape = validateTrustedConfig(JSON.parse(fs.readFileSync(derived, "utf8")));
  assert.deepEqual(shape.participation.active.map((entry) => entry.symbol).sort(), ["B", "S"]);

  const custom = path.join(dir, "moved.json");
  run(["init", manifest, "--out", custom]);
  run(["add-kernel", "V", manifest, "--policy", custom]);
  const beforeDuplicate = fs.readFileSync(custom);
  const duplicate = run(["add-kernel", "V", manifest, "--policy", custom], 1);
  assert.match(duplicate, /refusing to overwrite existing policy edits/);
  assert.deepEqual(fs.readFileSync(custom), beforeDuplicate);
  shape = validateTrustedConfig(JSON.parse(beforeDuplicate));
  assert.deepEqual(shape.participation.active.map((entry) => entry.symbol).sort(), ["S", "V"]);
});

test("Calibration K is refused without --experimental and bytes stay unchanged", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-add-k-"));
  const manifest = path.join(MANIFEST_ROOT, MANIFESTS[0]);
  const policy = path.join(dir, "policy.json");
  run(["init", manifest, "--out", policy]);
  const before = fs.readFileSync(policy);
  const refused = run(["add-kernel", "K", manifest, "--policy", policy], 1);
  assert.match(refused, /EXPERIMENTAL K REFUSED/);
  assert.deepEqual(fs.readFileSync(policy), before);

  const accepted = run(["add-kernel", "K", manifest, "--policy", policy, "--experimental"]);
  assert.match(accepted, /CALIBRATION \(K\) IS EXPERIMENTAL/);
  const shape = validateTrustedConfig(JSON.parse(fs.readFileSync(policy, "utf8")));
  assert.equal(shape.ok, true, shape.errors.join("; "));
  assert.equal(shape.participation.active.some((entry) => entry.symbol === "K"), true);
  assert.deepEqual(shape.participation.inactive, []);
});

test("init refuses existing outputs unless --force is explicit, including recipes", () => {
  for (const recipeArgs of [[], ["--recipe", "prod-db"]]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-init-overwrite-"));
    const output = path.join(dir, "policy.json");
    const args = ["init", ...recipeArgs, path.join(MANIFEST_ROOT, MANIFESTS[0]), "--out", output];
    fs.writeFileSync(output, "SENTINEL\n");
    assert.match(run(args, 1), /refusing to overwrite.*--force/);
    assert.equal(fs.readFileSync(output, "utf8"), "SENTINEL\n");
    run([...args, "--force"]);
    assert.equal(validateTrustedConfig(JSON.parse(fs.readFileSync(output))).ok, true);
  }
});

test("init rejects duplicate names before writing and accepts distinct names", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-init-names-"));
  const manifest = path.join(dir, "manifest.tools.json");
  const output = path.join(dir, "policy.json");
  const tools = [{ name: "same" }, { name: "same" }];
  fs.writeFileSync(manifest, JSON.stringify({ server: "names", tools }));
  for (const recipeArgs of [[], ["--recipe", "prod-db"]]) {
    assert.match(run(["init", ...recipeArgs, manifest, "--out", output], 1), /duplicate tool name: same/);
    assert.equal(fs.existsSync(output), false);
  }
  tools[1].name = "different";
  fs.writeFileSync(manifest, JSON.stringify({ server: "names", tools }));
  run(["init", manifest, "--out", output]);
  assert.deepEqual(JSON.parse(fs.readFileSync(output)).safety.tools.map((tool) => tool.name), ["same", "different"]);
});

const DISTINCT_ROLES = [
  ["deploy", "deploy", "rollback", "Deploy a release", "Rollback a release"],
  ["token-governor", "token", "payment", "Generate token completion", "Charge a payment"],
  ["mesh", "shared", "publish", "Merge shared state", "Publish an event"],
];

for (const [recipe, first, second, firstDescription, secondDescription] of DISTINCT_ROLES) {
  const tool = (name, description) => ({ name, description, annotations: { destructiveHint: true } });
  for (const extra of [false, true]) {
    test(`${recipe} refuses role collision with ${extra ? "an extra generic tool" : "one guarded tool"}`, () => {
      const tools = [tool("do_thing", "does a thing")];
      if (extra) tools.push(tool("other_action", "does something else"));
      assert.throws(() => applyRecipe({ server: "demo@1.0.0", tools }, recipe), (error) => {
        assert.ok(error instanceof Error);
        assert.equal(error.name, "RecipeRoleCollisionError");
        for (const value of [recipe, first, second, "do_thing"])
          assert.ok(error.message.includes(`'${value}'`), error.message);
        assert.match(error.message, /second, distinct guarded tool/);
        assert.match(error.message, /roles require distinct operations/);
        return true;
      });
    });
  }
  test(`${recipe} selects distinct tools by their role descriptions`, () => {
    const manifest = { server: "demo@1.0.0", tools: [
      tool("action_alpha", firstDescription), tool("action_beta", secondDescription),
    ] };
    for (const tools of [manifest.tools, [...manifest.tools].reverse()]) {
      const result = applyRecipe({ ...manifest, tools }, recipe);
      assert.deepEqual(result.mappings.map(({ role, tool, bestFit }) => ({ role, tool, bestFit })), [
        { role: first, tool: "action_alpha", bestFit: false },
        { role: second, tool: "action_beta", bestFit: false },
      ]);
      assertGeneratedPolicy(result.policy, manifest, RECIPE_ACTIVE[recipe]);
    }
  });
}

test("single-role kernels and prod-db still accept one guarded tool", () => {
  const manifest = { server: "demo@1.0.0", tools: [
    { name: "do_thing", description: "does a thing", annotations: { destructiveHint: true } },
  ] };
  assertGeneratedPolicy(applyRecipe(manifest, "prod-db").policy, manifest, RECIPE_ACTIVE["prod-db"]);
  const base = addKernelToPolicy({ epoch: 1 }, manifest, "S").policy;
  for (const symbol of ["C", "L", "V", "K"]) {
    const result = addKernelToPolicy(base, manifest, symbol, { experimental: true });
    assert.ok(result.participation.active.some((entry) => entry.symbol === symbol));
    assert.ok(referencedTools(result.policy).includes("do_thing"));
  }
});
