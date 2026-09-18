// SPDX-License-Identifier: Apache-2.0
"use strict";

function scaffoldReason(tool) {
  const annotations = tool.annotations !== null && typeof tool.annotations === "object" &&
    !Array.isArray(tool.annotations) ? tool.annotations : {};
  if (annotations.readOnlyHint === true && annotations.destructiveHint === true) return "conflict";
  if (annotations.readOnlyHint === true) return "readonly";
  if (annotations.destructiveHint === true) return "destructive";
  return "unknown";
}

module.exports = { scaffoldReason };
