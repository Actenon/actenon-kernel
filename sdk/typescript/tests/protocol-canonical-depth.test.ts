import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { canonicalizeJson, type CanonicalValue } from "../src/canonical.js";

test("Protocol's frozen invalid depth vector is refused", () => {
  const vector = JSON.parse(readFileSync(new URL("../../../fixtures/protocol_canonicalisation/deeply_nested_exceeds_limit.json", import.meta.url), "utf8"));
  assert.throws(() => canonicalizeJson(JSON.parse(vector.input_json)), /depth/);
});

for (const depth of [0, 31, 32, 33, 127]) test(`Protocol depth ${depth}`, () => {
  let value: CanonicalValue = "leaf";
  for (let i=0;i<depth;i++) value = {nested:value};
  if (depth <=32) assert.equal(typeof canonicalizeJson(value),"string");
  else assert.throws(() => canonicalizeJson(value), /depth/);
});
