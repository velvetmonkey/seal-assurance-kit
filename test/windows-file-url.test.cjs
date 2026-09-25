// SPDX-License-Identifier: Apache-2.0
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { fileURLToPath, pathToFileURL } = require("node:url");

// TESTED-BY-PROXY: Windows path conversion on Node 22, not a Windows import.
const windowsPath = "C:\\Users\\ben#1\\kernel\\receipt-format.js";

test("file URL concatenation mis-parses a Windows path containing #", () => {
  const url = new URL("file://" + windowsPath);
  assert.notEqual(url.hash, "");
  assert.notEqual(fileURLToPath(url, { windows: true }), windowsPath);
});

test("pathToFileURL preserves the same Windows path", () => {
  const href = pathToFileURL(windowsPath, { windows: true }).href;
  assert.equal(href, "file:///C:/Users/ben%231/kernel/receipt-format.js");
  const url = new URL(href);
  assert.equal(url.protocol, "file:");
  assert.equal(url.hash, "");
  assert.equal(fileURLToPath(url, { windows: true }), windowsPath);
});
