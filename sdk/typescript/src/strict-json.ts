// Strict JSON for untrusted proof material (RFC 8259 text, plus the limits of
// the Python reference's actenon.core.json.loads_no_duplicate_keys).
//
// JSON.parse is unsafe at a verification edge: it keeps the last of duplicate
// members (a first-wins parser elsewhere in the stack sees a different
// request) and maps 2500.0 / 2.5e3 / 1e0 onto the integers the proof signed.
// This parser refuses duplicate members, any number lexeme with a fraction
// or exponent, integers outside the safe range, lone surrogates, a byte-order
// mark, invalid UTF-8, trailing content, nesting deeper than the reference,
// and input larger than the reference accepts.

export const MAX_JSON_BYTES = 1_048_576;
export const MAX_JSON_DEPTH = 128;

export class StrictJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictJsonError";
  }
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function parseStrictJson(input: string | Uint8Array): unknown {
  let text: string;
  if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > MAX_JSON_BYTES) throw new StrictJsonError("JSON input is too large");
    text = input;
  } else {
    if (input.byteLength > MAX_JSON_BYTES) throw new StrictJsonError("JSON input is too large");
    try {
      text = utf8.decode(input);
    } catch {
      throw new StrictJsonError("JSON input is not valid UTF-8");
    }
  }
  if (text.charCodeAt(0) === 0xfeff) throw new StrictJsonError("JSON input starts with a byte-order mark");
  const parser = new Parser(text);
  parser.ws();
  const value = parser.value(0);
  parser.ws();
  if (parser.pos !== text.length) throw new StrictJsonError("unexpected content after the JSON value");
  return value;
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

class Parser {
  pos = 0;
  constructor(private readonly s: string) {}

  fail(what: string): never {
    throw new StrictJsonError(`${what} at offset ${this.pos}`);
  }

  ws(): void {
    while (this.pos < this.s.length) {
      const c = this.s.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else break;
    }
  }

  value(depth: number): unknown {
    if (depth > MAX_JSON_DEPTH) this.fail("JSON nesting is too deep");
    const c = this.s[this.pos];
    if (c === "{") return this.object(depth + 1);
    if (c === "[") return this.array(depth + 1);
    if (c === '"') return this.string();
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return this.number();
    for (const [lit, val] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.s.startsWith(lit, this.pos)) {
        this.pos += lit.length;
        return val;
      }
    }
    return this.fail("unexpected token");
  }

  object(depth: number): Record<string, unknown> {
    this.pos++;
    const out: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.pos] === "}") {
      this.pos++;
      return { ...out };
    }
    for (;;) {
      this.ws();
      if (this.s[this.pos] !== '"') this.fail("expected a member name");
      const key = this.string();
      if (seen.has(key)) this.fail("duplicate object member");
      seen.add(key);
      this.ws();
      if (this.s[this.pos] !== ":") this.fail("expected ':'");
      this.pos++;
      this.ws();
      out[key] = this.value(depth);
      this.ws();
      const c = this.s[this.pos++];
      if (c === "}") break;
      if (c !== ",") this.fail("expected ',' or '}'");
    }
    // Object spread creates own data properties, including "__proto__".
    // Object.assign invokes the inherited __proto__ setter and silently
    // changes the parsed object instead of preserving the JSON member.
    return { ...out };
  }

  array(depth: number): unknown[] {
    this.pos++;
    const out: unknown[] = [];
    this.ws();
    if (this.s[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth));
      this.ws();
      const c = this.s[this.pos++];
      if (c === "]") break;
      if (c !== ",") this.fail("expected ',' or ']'");
    }
    return out;
  }

  string(): string {
    this.pos++;
    let out = "";
    for (;;) {
      if (this.pos >= this.s.length) this.fail("unterminated string");
      const c = this.s.charCodeAt(this.pos);
      if (c === 0x22) {
        this.pos++;
        break;
      }
      if (c < 0x20) this.fail("unescaped control character in string");
      if (c === 0x5c) {
        const e = this.s[this.pos + 1];
        this.pos += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = this.s.slice(this.pos, this.pos + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("invalid \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            this.pos += 4;
            break;
          }
          default:
            this.fail("invalid escape");
        }
        continue;
      }
      out += this.s[this.pos++];
    }
    // Lone surrogates (escaped or raw) have no UTF-8 encoding: refuse them.
    if (hasLoneSurrogate(out)) this.fail("string contains a lone surrogate");
    return out;
  }

  number(): number {
    const m = /^-?(0|[1-9][0-9]*)([.eE])?/.exec(this.s.slice(this.pos, this.pos + 400));
    if (!m) return this.fail("invalid number");
    if (m[2] !== undefined) this.fail("non-integer number lexeme");
    const lexeme = m[0];
    this.pos += lexeme.length;
    const value = Number(lexeme);
    if (!Number.isSafeInteger(value)) this.fail("integer outside the safe range");
    return value === 0 ? 0 : value;
  }
}
