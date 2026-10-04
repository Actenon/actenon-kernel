"""kernel_diff_v1 ADDENDUM (timestamp grammar), north-star.

Designed AFTER observing (fresh-consumer rehearsal, 2026-10-03) that actenon-kernel 1.3.0 refuses
`time_fraction_short_form_in_intent` and `time_fraction_7_digits_in_intent` on Python 3.10 and accepts them
on 3.11+, because `parse_timestamp` delegates to `datetime.fromisoformat`, whose grammar changed in 3.11.
This addendum is written and frozen BEFORE any implementation is changed. It isolates the grammar:

* every variant denotes the SAME instant as the signed value, and the reference signs over parsed and
  re-serialised timestamps (gen_corpus.resign / PCCB.unsigned_payload; the action hash re-serialises intent
  timestamps), so a valid signature never depends on the text form -- grammar is the only refusal reason;
* `hint` is fixed a priori by the protocol's normative type, JSON Schema `"format": "date-time"`
  (schemas/_common.v1.json) = RFC 3339 section 5.6 `date-time`:
    ACCEPT        valid RFC 3339 date-time
    REFUSE        not an RFC 3339 date-time
    DEVIATION     RFC 3339 permits it but every Actenon implementation refuses it (lower-case "t"/"z"),
                  or RFC 3339 leaves it to the application (space separator, section 5.6 NOTE);
                  recorded, not judged.

argv: outdir. Run with an environment where the kernel is importable (generation only; the kernel is not
under test here -- the base PCCB is byte-identical to kernel_diff_v1's baseline, asserted below).
"""

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "differential"))
out = Path(sys.argv[1])
sys.argv = [sys.argv[0]]
import gen_corpus as g  # noqa: E402

I, C = g.base_intent(), g.base_context()
P = g.mint(I, C)
baseline = json.loads((HERE.parent.parent / "differential" / "corpus" / "baseline_valid_hs256" / "pccb.json").read_text())
assert P == baseline, "base PCCB differs from kernel_diff_v1 baseline_valid_hs256"
assert I["issued_at"] == "2026-01-01T12:00:00Z" and P["expires_at"] == "2026-01-01T12:05:00Z", (I["issued_at"], P["expires_at"])

# (id suffix, text for instant HH:MM:00Z given as a function of (hh, mm), hint, note)
VARIANTS = [
    ("frac_1_digit", lambda h, m: f"2026-01-01T{h}:{m}:00.0Z", "ACCEPT", "time-secfrac = '.' 1*DIGIT"),
    ("frac_3_digits", lambda h, m: f"2026-01-01T{h}:{m}:00.000Z", "ACCEPT", ""),
    ("frac_7_digits", lambda h, m: f"2026-01-01T{h}:{m}:00.0000000Z", "ACCEPT", "beyond microseconds"),
    ("frac_9_digits", lambda h, m: f"2026-01-01T{h}:{m}:00.000000000Z", "ACCEPT", "nanoseconds"),
    ("frac_6_digits_offset", lambda h, m: f"2026-01-01T{h}:{m}:00.000000+00:00", "ACCEPT", ""),
    ("offset_minus0000", lambda h, m: f"2026-01-01T{h}:{m}:00-00:00", "ACCEPT", "RFC 3339 4.3 unknown local offset"),
    ("offset_plus0530", lambda h, m: f"2026-01-01T{int(h) + 5:02d}:{int(m) + 30:02d}:00+05:30", "ACCEPT", "same instant"),
    ("offset_minus0500", lambda h, m: f"2026-01-01T{int(h) - 5:02d}:{m}:00-05:00", "ACCEPT", "same instant"),
    ("no_seconds", lambda h, m: f"2026-01-01T{h}:{m}Z", "REFUSE", "partial-time requires time-second"),
    ("empty_fraction", lambda h, m: f"2026-01-01T{h}:{m}:00.Z", "REFUSE", "secfrac needs 1*DIGIT"),
    ("basic_format", lambda h, m: f"20260101T{h}{m}00Z", "REFUSE", "ISO 8601 basic format"),
    ("basic_time", lambda h, m: f"2026-01-01T{h}{m}00Z", "REFUSE", ""),
    ("week_date", lambda h, m: f"2026-W01-4T{h}:{m}:00Z", "REFUSE", "ISO week date (2026-01-01 is W01-4)"),
    ("ordinal_date", lambda h, m: f"2026-001T{h}:{m}:00Z", "REFUSE", "ISO ordinal date"),
    ("offset_no_colon", lambda h, m: f"2026-01-01T{h}:{m}:00+0000", "REFUSE", "time-numoffset needs ':'"),
    ("offset_hours_only", lambda h, m: f"2026-01-01T{h}:{m}:00+00", "REFUSE", ""),
    ("offset_with_seconds", lambda h, m: f"2026-01-01T{h}:{m}:00+00:00:00", "REFUSE", ""),
    ("comma_fraction", lambda h, m: f"2026-01-01T{h}:{m}:00,0Z", "REFUSE", "ISO comma decimal sign"),
    ("space_before_z", lambda h, m: f"2026-01-01T{h}:{m}:00 Z", "REFUSE", ""),
    ("leading_space", lambda h, m: f" 2026-01-01T{h}:{m}:00Z", "REFUSE", ""),
    ("trailing_newline", lambda h, m: f"2026-01-01T{h}:{m}:00Z\n", "REFUSE", ""),
    ("one_digit_month", lambda h, m: f"2026-1-01T{h}:{m}:00Z", "REFUSE", ""),
    ("arabic_indic_digits", lambda h, m: f"2026-01-01T{h}:{m}:0٠Z", "REFUSE", "non-ASCII digit"),
    ("space_separator", lambda h, m: f"2026-01-01 {h}:{m}:00Z", "DEVIATION", "RFC 3339 5.6 NOTE: application choice"),
    ("lowercase_t", lambda h, m: f"2026-01-01t{h}:{m}:00Z", "DEVIATION", "RFC 3339 5.6 NOTE permits; ecosystem refuses"),
    ("lowercase_z", lambda h, m: f"2026-01-01T{h}:{m}:00z", "DEVIATION", "RFC 3339 5.6 NOTE permits; ecosystem refuses"),
]

for suffix, form, hint, note in VARIANTS:
    # Intent placement: issued_at = T0 (12:00:00Z); the action hash re-serialises intent timestamps.
    i2 = copy.deepcopy(I)
    i2["issued_at"] = form("12", "00")
    g.case(f"tsg_intent_issued_at_{suffix}", "timestamp_grammar", i2, P, C, hint=hint, note=note)
    # PCCB placement: expires_at = 12:05:00Z; the signature covers the re-serialised instant.
    p2 = copy.deepcopy(P)
    p2["expires_at"] = form("12", "05")
    g.case(f"tsg_pccb_expires_at_{suffix}", "timestamp_grammar", I, p2, C, hint=hint, note=note)
# Hour-only exists only for the intent placement (12:05 cannot be written as an hour).
i2 = copy.deepcopy(I)
i2["issued_at"] = "2026-01-01T12Z"
g.case("tsg_intent_issued_at_hour_only", "timestamp_grammar", i2, P, C, hint="REFUSE", note="ISO reduced precision")

g.OUT = out
g.write()
manifest = json.loads((out / "manifest.json").read_text())
manifest["corpus"] = "kernel_diff_v1_addendum_timestamp_grammar"
(out / "manifest.json").write_bytes(json.dumps(manifest, indent=1, ensure_ascii=False).encode())
print(f"wrote {len(g.CASES)} addendum cases to {out}")
