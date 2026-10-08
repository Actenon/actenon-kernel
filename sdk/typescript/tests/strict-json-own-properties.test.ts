import assert from "node:assert/strict";
import test from "node:test";
import { parseStrictJson } from "../src/strict-json.js";

test("__proto__ is an own JSON data property, not a prototype instruction", () => {
  const raw = '{"__proto__":{"inherited":"untrusted"},"safe":"ok"}';
  const parsed = parseStrictJson(raw) as Record<string, unknown>;
  assert.deepEqual(parsed, JSON.parse(raw));
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.hasOwn(parsed, "__proto__"), true);
  assert.equal(parsed.inherited, undefined);
  const descriptor = Object.getOwnPropertyDescriptor(parsed, "__proto__");
  assert.equal(descriptor?.enumerable, true);
  assert.equal(descriptor?.writable, true);
  assert.equal(descriptor?.configurable, true);
});

test("nested and array-contained prototype-like keys remain data", () => {
  for (const value of [null, "text", 7, true, [], { inherited: "untrusted" }]) {
    const entry = JSON.stringify(value);
    const raw = '{"outer":[{"__proto__":' + entry + ',"constructor":{"prototype":{"x":1}}}]}';
    const parsed = parseStrictJson(raw);
    assert.deepEqual(parsed, JSON.parse(raw));
    assert.equal(JSON.stringify(parsed), JSON.stringify(JSON.parse(raw)));
  }
  assert.equal(Object.hasOwn(Object.prototype, "inherited"), false);
});

test("escaped duplicate __proto__ members are still rejected", () => {
  assert.throws(() => parseStrictJson('{"__proto__":{},"\\u005f_proto__":{}}'));
});

test("ordinary objects retain their plain-object shape", () => {
  for (const raw of ['{}', '{"a":1}', '{"constructor":"data","prototype":"data","toString":"data"}']) {
    const parsed = parseStrictJson(raw);
    assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
    assert.deepEqual(parsed, JSON.parse(raw));
  }
});

test("512 deterministic prototype-key documents match native JSON data semantics", () => {
  let state = 20261008;
  for (let index = 0; index < 512; index++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const value = { index, value: state, nested: ["Caf\u00e9", { ok: true }] };
    const raw = '{"__proto__":' + JSON.stringify(value) + ',"nested":{"__proto__":' + JSON.stringify(value) + '}}';
    assert.deepEqual(parseStrictJson(raw), JSON.parse(raw));
  }
});
