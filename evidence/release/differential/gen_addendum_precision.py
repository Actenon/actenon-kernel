"""kernel_diff_v1 ADDENDUM (precision). Designed AFTER observing kernel_diff_v1
results (TS parses JSON numbers as IEEE doubles; Go/Rust number handling
unknown). Targeted, post-hoc cases; frozen and hashed separately. argv: outdir"""
import copy, json, sys
from pathlib import Path
sys.argv, out = [sys.argv[0]], Path(sys.argv[1])
import gen_corpus as g  # noqa: E402

I, C = g.base_intent(), g.base_context()

def signed_then_presented(cid, signed_val, presented_text, hint, note):
    i, p, c = g._resigned_param(I, C, "amount_minor", signed_val)
    raw = g.j(i).replace(b'"amount_minor":' + json.dumps(signed_val).encode(), b'"amount_minor":' + presented_text.encode(), 1)
    assert raw != g.j(i) or presented_text == json.dumps(signed_val)
    g.case(cid, "numeric_precision", raw, p, c, hint=hint, note=note)

for cid, sv, pt, hint, note in [
    ("prec_signed_2p53_presented_2p53p1", 2**53, str(2**53 + 1), "REFUSE", "doubles round 2^53+1 to 2^53"),
    ("prec_signed_2p53_presented_2p53p1_ctx_signed", 2**53, str(2**53 + 1), "REFUSE", "same; context constraint = signed value"),
    ("prec_signed_2p53p1_presented_2p53", 2**53 + 1, str(2**53), "REFUSE", ""),
    ("prec_signed_2p53_presented_float_text", 2**53, "9007199254740992.0", "REFUSE", ""),
    ("prec_signed_2p53_presented_exp", 2**53, "9.007199254740992e15", "REFUSE", ""),
    ("prec_signed_2p63m1_presented_2p63", 2**63 - 1, str(2**63), "REFUSE", "int64 overflow"),
    ("prec_signed_2p64_presented_2p64p1", 2**64, str(2**64 + 1), "REFUSE", "u64 overflow, f64 rounding"),
    ("prec_signed_1e21_int_presented_exp", 10**21, "1e21", "REFUSE", ""),
    ("prec_signed_big_presented_big_plus1", 10**30, str(10**30 + 1), "REFUSE", "both beyond f64 integer precision"),
    ("prec_signed_0_presented_neg0_float", 0, "-0.0", "REFUSE", ""),
    ("prec_signed_1_presented_1_0", 1, "1.0", "REFUSE", ""),
    ("prec_signed_1_presented_1e0", 1, "1e0", "REFUSE", ""),
    ("prec_signed_1_presented_10e-1", 1, "10e-1", "REFUSE", ""),
]:
    signed_then_presented(cid, sv, pt, hint, note)

# Duplicate member where the attacker's value is a *different representation* of the signed one
i, p, c = g._resigned_param(I, C, "amount_minor", 2**53)
raw = g.j(i).replace(b'"amount_minor":9007199254740992', b'"amount_minor":9007199254740993,"amount_minor":9007199254740992', 1)
g.case("prec_dup_member_first_differs_by_one_ulp", "numeric_precision", raw, p, c, hint="REFUSE", note="first-wins parsers see 2^53+1")
g.OUT = out
g.write()
print(f"wrote {len(g.CASES)} addendum cases to {out}")
