// Copied from Actenon/actenon-protocol@626afa2 typescript/tests/conformance.ts. Harness changes: imports the
// INSTALLED @actenon/protocol-types instead of ../src, and takes the vector directory as argv[2]. Run with
// node --experimental-strip-types.
/**
 * Cross-language canonicalisation conformance runner for TypeScript.
 *
 * Run: bun run conformance.ts
 *
 * Verifies that the TypeScript implementation produces the same canonical
 * bytes as the Python reference for all normative vectors.
 */

import { canonicalizeJson, CanonicalisationError } from "@actenon/protocol-types";
import { readFileSync, readdirSync } from "fs";
import { join } from "path";

interface ValidVector {
  name: string;
  description: string;
  input: unknown;
  expected_canonical: string;
}

interface InvalidVector {
  name: string;
  description: string;
  input_json?: string;
  expected_error: string;
  note?: string;
}

function findVectorsDir(): string {
  // Harness change: the canonicalisation vectors of the protocol release tag, passed as argv[2].
  return process.argv[2];
}

function run(): number {
  const vectorsDir = findVectorsDir();
  const validDir = join(vectorsDir, "valid");
  const invalidDir = join(vectorsDir, "invalid");

  let passed = 0;
  let failed = 0;
  let skipped = 0;

  // ── Valid vectors ──────────────────────────────────────────────
  try {
    const files = readdirSync(validDir).filter((f) => f.endsWith(".json"));
    for (const file of files) {
      const content = readFileSync(join(validDir, file), "utf-8");
      const vector = JSON.parse(content) as ValidVector;

      if (vector.input === undefined || vector.expected_canonical === undefined) {
        console.log(`  SKIP  ${vector.name}`);
        skipped++;
        continue;
      }

      // BigInt values can't be represented in JSON, so we need to handle
      // large integers specially. The vectors use numbers within JSON.safe
      // range (< 2^53). For larger values, JS Number loses precision —
      // those vectors are expected to fail in JS and are skipped.
      // Check if any numeric value in the input exceeds safe integer range.
      function hasUnsafeIntegers(val: unknown): boolean {
        if (typeof val === "number" && Number.isInteger(val) && !Number.isSafeInteger(val)) return true;
        if (Array.isArray(val)) return val.some(hasUnsafeIntegers);
        if (val !== null && typeof val === "object") {
          return Object.values(val as Record<string, unknown>).some(hasUnsafeIntegers);
        }
        return false;
      }
      // Also check the expected_canonical for large integer values that
      // would have been precision-lost during JSON.parse of the vector file itself.
      function hasPrecisionLossInExpected(expected: string): boolean {
        // Check for integers with 16+ digits in the expected canonical output
        return /:\d{16,}/.test(expected) || /:-\d{16,}/.test(expected);
      }
      if (hasPrecisionLossInExpected(vector.expected_canonical)) {
        console.log(`  SKIP  ${vector.name} (contains integers > 2^53 — JS Number precision loss)`);
        skipped++;
        continue;
      }

      try {
        const actual = canonicalizeJson(vector.input);
        if (actual === vector.expected_canonical) {
          passed++;
        } else {
          console.log(`  FAIL  ${vector.name}: expected ${vector.expected_canonical}, got ${actual}`);
          failed++;
        }
      } catch (e) {
        console.log(`  FAIL  ${vector.name}: ${e instanceof Error ? e.message : String(e)}`);
        failed++;
      }
    }
  } catch (e) {
    // Never swallow: a vector that cannot be read or parsed is a failure.
    console.log(`  FAIL  valid vectors: ${e instanceof Error ? e.message : String(e)}`);
    failed++;
  }

  // ── Invalid vectors (JSON-representable) ──────────────────────
  try {
    const files = readdirSync(invalidDir).filter((f) => f.endsWith(".json"));
    for (const file of files) {
      const content = readFileSync(join(invalidDir, file), "utf-8");
      const vector = JSON.parse(content) as InvalidVector;

      if (vector.input_json !== undefined) {
        // Skip vectors where JS JSON.parse loses the float/integer distinction.
        // JS Number.isInteger(0.0) === true and Number.isInteger(1.5e10) === true
        // because JS has a single Number type that stores both as IEEE 754 doubles.
        const jsFloatAmbiguous = ["float_zero", "float_exponent"];
        if (jsFloatAmbiguous.includes(vector.name)) {
          console.log(`  SKIP  ${vector.name} (JS Number type cannot distinguish float from integer after JSON.parse)`);
          skipped++;
          continue;
        }

        try {
          const parsed = JSON.parse(vector.input_json);
          try {
            canonicalizeJson(parsed);
            console.log(`  FAIL  ${vector.name}: expected error but got success`);
            failed++;
          } catch (e) {
            if (e instanceof CanonicalisationError || e instanceof TypeError) {
              passed++;
            } else {
              console.log(`  FAIL  ${vector.name}: wrong error type: ${e instanceof Error ? e.constructor.name : typeof e}`);
              failed++;
            }
          }
        } catch {
          // NaN/Infinity aren't valid JSON — skip
          skipped++;
        }
      } else {
        skipped++;
      }
    }
  } catch (e) {
    // Never swallow: a vector that cannot be read or parsed is a failure.
    console.log(`  FAIL  invalid vectors: ${e instanceof Error ? e.message : String(e)}`);
    failed++;
  }

  // ── TypeScript-specific adversarial tests ─────────────────────
  const tsOnlyTests: Array<[string, () => void]> = [
    ["float_nan_direct", () => canonicalizeJson(NaN)],
    ["float_inf_direct", () => canonicalizeJson(Infinity)],
    ["float_neg_inf_direct", () => canonicalizeJson(-Infinity)],
  ];

  for (const [name, fn] of tsOnlyTests) {
    try {
      fn();
      console.log(`  FAIL  ${name}: expected error but got success`);
      failed++;
    } catch (e) {
      if (e instanceof CanonicalisationError || e instanceof TypeError) {
        passed++;
      } else {
        console.log(`  FAIL  ${name}: wrong error type: ${e instanceof Error ? e.constructor.name : typeof e}`);
        failed++;
      }
    }
  }

  // ── BigInt support ────────────────────────────────────────────
  try {
    const result = canonicalizeJson(123456789012345678901234567890n);
    if (result === "123456789012345678901234567890") {
      passed++;
    } else {
      console.log(`  FAIL  bigint_large: expected '123456789012345678901234567890', got ${result}`);
      failed++;
    }
  } catch (e) {
    console.log(`  FAIL  bigint_large: ${e instanceof Error ? e.message : String(e)}`);
    failed++;
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log(`Canonicalisation conformance (TypeScript): ${passed} passed, ${failed} failed, ${skipped} skipped`);
  console.log(`${"=".repeat(60)}`);
  return failed === 0 ? 0 : 1;
}

process.exit(run());
