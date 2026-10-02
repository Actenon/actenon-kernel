"""Generate the kernel_diff_v1 differential corpus (raw bytes, frozen by hash).

Run once with the reference kernel importable. Writes corpus/<case>/{intent.json,
pccb.json,context.json} plus corpus/manifest.json and corpus/trust.json. Inputs
are RAW BYTES: every runner must parse them with its implementation's own
parser, so byte-level cases (duplicate members, escapes, BOM, nesting, size)
reach the parser under test.

`hint` is the generator author's expectation (ACCEPT/REFUSE). It is NOT the
oracle: the Python reference decides. Hints that disagree with the reference
are reported separately as reference findings.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("ACTENON_ENV", "test")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from actenon.api.intake import ActionIntentIntakeService  # noqa: E402
from actenon.models import AudienceRef, PartyRef, PolicyDecision  # noqa: E402
from actenon.models.contracts import PCCB, SignatureSpec  # noqa: E402
from actenon.proof import PCCBMinter  # noqa: E402
from actenon.proof.canonical import canonicalize_bytes  # noqa: E402
from actenon.proof.signers.local import HmacSha256Signer  # noqa: E402
from actenon.verifier import VerifierSDK  # noqa: E402

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "corpus")
HMAC_SECRET = b"actenon-differential-corpus-hmac-key-v1-not-a-production-key"
HMAC_KID = "diff-hmac-1"
ED_SEED = hashlib.sha256(b"actenon-differential-corpus-ed25519-seed-v1").digest()
ED_KID = "diff-ed25519-1"
T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(minutes=1)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class Ed25519Signer:
    algorithm = "EdDSA"
    key_id = ED_KID

    def __init__(self) -> None:
        self._priv = ed25519.Ed25519PrivateKey.from_private_bytes(ED_SEED)
        self.public_raw = self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, payload: bytes) -> SignatureSpec:
        return SignatureSpec(algorithm="EdDSA", key_id=ED_KID, encoding="base64url", value=b64u(self._priv.sign(payload)))

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        if signature.algorithm != "EdDSA" or signature.key_id != ED_KID or signature.encoding != "base64url":
            return False
        try:
            raw = base64.urlsafe_b64decode(signature.value + "=" * (-len(signature.value) % 4))
            self._priv.public_key().verify(raw, payload)
            return True
        except Exception:
            return False


HMAC = HmacSha256Signer(secret=HMAC_SECRET, key_id=HMAC_KID)
ED = Ed25519Signer()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + (f".{dt.microsecond:06d}" if dt.microsecond else "") + "Z"


def base_intent() -> dict:
    return {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_diff_001",
        "issued_at": iso(T0),
        "expires_at": iso(T0 + timedelta(minutes=5)),
        "tenant": {"tenant_id": "tenant_acme"},
        "requester": {"type": "agent", "id": "agent_7"},
        "action": {
            "name": "payment.refund",
            "capability": "payments.refund",
            "parameters": {"amount_minor": 2500, "currency": "EUR", "memo": "Rückerstattung für Bestellung #42 ✓"},
        },
        "target": {"resource_type": "charge", "resource_id": "ch_3Nq"},
    }


def base_context() -> dict:
    return {
        "request_id": "req_diff_001",
        "audience": {"type": "service", "id": "payments-edge"},
        "now": iso(NOW),
        "scope_capabilities": ["payments.refund"],
        "parameter_constraints": {"amount_minor": 2500, "currency": "EUR", "memo": "Rückerstattung für Bestellung #42 ✓"},
        "resource_selectors": [{"resource_id": "ch_3Nq"}],
        "clock_skew_ms": 0,
    }


def mint(intent: dict, context: dict, signer=HMAC, *, now: datetime = T0, escrow_id=None) -> dict:
    sdk = VerifierSDK(signer)
    parsed = ActionIntentIntakeService().parse(intent)
    ctx = sdk.build_context(
        request_id=context["request_id"],
        audience=AudienceRef.from_dict(context["audience"], "audience"),
        now=now,
        scope_capabilities=tuple(context["scope_capabilities"]),
        parameter_constraints=dict(context["parameter_constraints"]),
        resource_selectors=tuple(context["resource_selectors"]),
    )
    minter = PCCBMinter(
        signer=signer, issuer=PartyRef(type="service", id="issuer_diff"),
        pccb_id_factory=lambda: "pccb_diff_001", nonce_factory=lambda: "nonce-diff-0000000000000001")
    decision = PolicyDecision(outcome="allow", summary="diff corpus", rule_evaluations=(), reason_codes=("DIFF_ALLOW",))
    pccb = minter.mint(parsed, decision, ctx, escrow_id=escrow_id)
    return pccb.to_dict()


def resign(pccb: dict, signer=HMAC) -> dict:
    """Re-sign a structurally mutated PCCB the way the reference verifies it."""
    unsigned = PCCB.from_dict(pccb).unsigned_payload()
    spec = signer.sign(canonicalize_bytes(unsigned))
    out = copy.deepcopy(pccb)
    out["signature"] = spec.to_dict()
    return out


def j(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


CASES: list[dict] = []


def case(cid, category, intent, pccb, context=None, *, hint, alg="HS256", note=""):
    CASES.append({
        "id": cid, "category": category, "hint": hint, "alg": alg, "note": note,
        "intent": intent if isinstance(intent, bytes) else j(intent),
        "pccb": pccb if isinstance(pccb, bytes) else j(pccb),
        "context": context or base_context(),
    })


def set_path(doc, path, value):
    cur = doc
    for p in path[:-1]:
        cur = cur[p]
    if value is DELETE:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value


DELETE = object()


def build() -> None:
    I, C = base_intent(), base_context()
    P = mint(I, C)
    PE = mint(I, C, ED)

    # ── baseline
    case("baseline_valid_hs256", "baseline", I, P, hint="ACCEPT")
    case("baseline_valid_eddsa", "baseline", I, PE, alg="EdDSA", hint="ACCEPT")

    # ── duplicate JSON members (raw text manipulation)
    ib, pb = j(I), j(P)
    case("dup_param_same_value", "duplicate_members", ib.replace(b'"amount_minor":2500', b'"amount_minor":2500,"amount_minor":2500'), P, hint="REFUSE")
    case("dup_param_attacker_last", "duplicate_members", ib.replace(b'"amount_minor":2500', b'"amount_minor":2500,"amount_minor":999999'), P, hint="REFUSE",
         note="last-wins parsers see 999999; first-wins see the signed value")
    case("dup_param_attacker_first", "duplicate_members", ib.replace(b'"amount_minor":2500', b'"amount_minor":999999,"amount_minor":2500'), P, hint="REFUSE")
    case("dup_target_resource_id", "duplicate_members", ib.replace(b'"resource_id":"ch_3Nq"', b'"resource_id":"ch_3Nq","resource_id":"ch_OTHER"'), P, hint="REFUSE")
    case("dup_pccb_audience", "duplicate_members", I, pb.replace(b'"audience":{', b'"audience":{"type":"service","id":"other-edge"},"audience":{', 1), hint="REFUSE")
    case("dup_pccb_signature_obj", "duplicate_members", I, pb.replace(b'"signature":{', b'"signature":{"algorithm":"HS256","encoding":"base64url","key_id":"diff-hmac-1","value":"AAAA"},"signature":{', 1), hint="REFUSE")
    case("dup_intent_toplevel_intent_id", "duplicate_members", ib.replace(b'"intent_id":"intent_diff_001"', b'"intent_id":"intent_diff_001","intent_id":"intent_diff_001"'), P, hint="REFUSE")

    # ── canonicalisation
    reordered = json.loads(json.dumps(I))
    reordered = {k: reordered[k] for k in reversed(list(reordered))}
    case("canon_member_order_permuted", "canonicalisation", reordered, P, hint="ACCEPT")
    case("canon_pretty_printed", "whitespace", json.dumps(I, indent=2, ensure_ascii=False).encode(), json.dumps(P, indent=2).encode(), hint="ACCEPT")
    case("canon_ascii_escaped_unicode", "unicode", json.dumps(I, ensure_ascii=True).encode(), P, hint="ACCEPT",
         note="\\u00fc escapes decode to the same string")
    case("canon_number_1_0_vs_1", "canonicalisation", ib.replace(b'"amount_minor":2500', b'"amount_minor":2500.0'), P, hint="REFUSE",
         note="2500.0 is a float; JCS-STRICT-1 forbids floats")
    case("canon_number_exponent", "canonicalisation", ib.replace(b'"amount_minor":2500', b'"amount_minor":2.5e3'), P, hint="REFUSE")
    case("canon_number_negative_zero", "numeric_boundaries", *_resigned_param(I, C, "amount_minor", -0), hint="ACCEPT",
         note="-0 as an integer literal is 0")
    i0, p0, c0 = _resigned_param(I, C, "amount_minor", 0)
    case("canon_neg_zero_literal_text", "canonicalisation", j(i0).replace(b'"amount_minor":0', b'"amount_minor":-0'), p0, c0, hint="ACCEPT",
         note="signed over 0, presented as the literal -0")
    case("canon_leading_plus_invalid_json", "malformed", ib.replace(b'"amount_minor":2500', b'"amount_minor":+2500'), P, hint="REFUSE")

    # ── unicode
    import unicodedata
    nfd = unicodedata.normalize("NFD", I["action"]["parameters"]["memo"])
    case("unicode_nfd_vs_signed_nfc", "unicode", _param(I, "memo", nfd), P, hint="REFUSE",
         note="visually identical, different code points")
    case("unicode_lone_surrogate", "unicode", ib.replace("✓".encode(), b"\\ud800"), P, hint="REFUSE")
    case("unicode_invalid_utf8", "unicode", ib.replace("✓".encode(), b"\xff\xfe"), P, hint="REFUSE")
    case("unicode_bom_prefix", "unicode", b"\xef\xbb\xbf" + ib, P, hint="REFUSE", note="UTF-8 BOM before JSON text")
    case("unicode_zero_width_in_target", "unicode", ib.replace(b'"ch_3Nq"', '"ch_3​Nq"'.encode()), P, hint="REFUSE")
    case("unicode_homoglyph_target", "unicode", ib.replace(b'"ch_3Nq"', '"ch_3Νq"'.encode()), P, hint="REFUSE", note="Greek capital nu")
    case("unicode_astral_resigned", "unicode", *_resigned_param(I, C, "memo", "refund 🧾 ok 𝔘"), hint="ACCEPT")
    case("unicode_escaped_astral_resigned", "unicode", *_escaped(_resigned_param(I, C, "memo", "refund 🧾 ok 𝔘")), hint="ACCEPT",
         note="surrogate-pair escapes for astral chars")
    case("unicode_nul_in_string_resigned", "unicode", *_resigned_param(I, C, "memo", "a\u0000b"), hint="ACCEPT")

    # ── timestamps (re-minted so the signature is valid)
    for cid, ctxnow, hint, note in [
        ("time_now_equals_not_before", T0, "ACCEPT", "inclusive lower bound"),
        ("time_now_equals_expires_at", T0 + timedelta(minutes=5), "REFUSE", "boundary: reference decides inclusive/exclusive"),
        ("time_now_1us_after_expiry", T0 + timedelta(minutes=5, microseconds=1), "REFUSE", ""),
        ("time_now_1us_before_not_before", T0 - timedelta(microseconds=1), "REFUSE", ""),
        ("time_now_1us_before_expiry", T0 + timedelta(minutes=5) - timedelta(microseconds=1), "ACCEPT", ""),
    ]:
        c = base_context(); c["now"] = iso(ctxnow)
        case(cid, "expiry" if "expir" in cid else "not_before", I, P, c, hint=hint, note=note)
    c = base_context(); c["now"] = iso(T0 + timedelta(minutes=5, seconds=1)); c["clock_skew_ms"] = 2000
    case("time_expired_within_skew", "expiry", I, P, c, hint="ACCEPT", note="1s past expiry, 2s tolerance")
    c = base_context(); c["now"] = iso(T0 + timedelta(minutes=5, seconds=3)); c["clock_skew_ms"] = 2000
    case("time_expired_beyond_skew", "expiry", I, P, c, hint="REFUSE")
    for cid, repl, hint in [
        ("time_pccb_offset_plus0000", lambda d: d.replace("Z", "+00:00"), "ACCEPT"),
        ("time_pccb_offset_plus0100_same_instant", lambda d: "2026-01-01T13:05:00+01:00", "ACCEPT"),
        ("time_pccb_lowercase_z", lambda d: d.replace("Z", "z"), "REFUSE"),
        ("time_pccb_no_timezone", lambda d: d.replace("Z", ""), "REFUSE"),
        ("time_pccb_fraction_500", lambda d: d.replace("Z", ".500Z"), "REFUSE"),
        ("time_pccb_leap_second", lambda d: "2026-01-01T12:04:60Z", "REFUSE"),
        ("time_pccb_date_only", lambda d: "2026-01-01", "REFUSE"),
        ("time_pccb_space_separator", lambda d: d.replace("T", " "), "REFUSE"),
    ]:
        p2 = copy.deepcopy(P); p2["expires_at"] = repl(P["expires_at"])
        case(cid, "timestamps", I, p2, hint=hint, note="expires_at text changed, signature over the original text")
    i2 = copy.deepcopy(I); i2["issued_at"] = I["issued_at"].replace("Z", "+00:00")
    case("time_intent_offset_plus0000", "timestamps", i2, P, hint="ACCEPT", note="action hash re-serialises timestamps")
    i2 = copy.deepcopy(I); i2["expires_at"] = "2026-01-01T12:05:00.000000Z"
    case("time_intent_zero_fraction", "timestamps", i2, P, hint="ACCEPT")
    i3 = copy.deepcopy(I); i3["issued_at"] = iso(T0 + timedelta(microseconds=500000)); i3["expires_at"] = iso(T0 + timedelta(minutes=5, microseconds=123456))
    p3 = mint(i3, C)
    i3b = copy.deepcopy(i3); i3b["issued_at"] = i3["issued_at"].replace(".500000Z", ".5Z")
    case("time_fraction_resigned", "timestamps", i3, p3, hint="ACCEPT")
    case("time_fraction_short_form_in_intent", "timestamps", i3b, p3, hint="ACCEPT", note=".5 == .500000")
    i3c = copy.deepcopy(i3); i3c["expires_at"] = iso(T0 + timedelta(minutes=5, microseconds=123456)).replace(".123456Z", ".1234567Z")
    case("time_fraction_7_digits_in_intent", "timestamps", i3c, p3, hint="ACCEPT", note="7th digit truncated per README")

    # ── expiry / not-before as signed facts
    pe = copy.deepcopy(P); pe["expires_at"] = iso(T0 + timedelta(seconds=30)); pe = resign(pe)
    case("expiry_signed_short_window", "expiry", I, pe, hint="REFUSE", note="now=T0+60s, proof expired at T0+30s")
    pn = copy.deepcopy(P); pn["not_before"] = iso(T0 + timedelta(minutes=2)); pn = resign(pn)
    case("not_before_signed_future", "not_before", I, pn, hint="REFUSE")
    pi = copy.deepcopy(P); pi["expires_at"] = iso(T0 - timedelta(minutes=1)); pi = resign(pi)
    case("expiry_before_issued", "expiry", I, pi, hint="REFUSE")

    # ── case sensitivity
    case("case_capability_upper", "case", _set(I, ["action", "capability"], "Payments.Refund"), P, hint="REFUSE")
    c = base_context(); c["audience"]["id"] = "Payments-Edge"
    case("case_context_audience", "audience", I, P, c, hint="REFUSE")
    case("case_sig_algorithm_lower", "case", I, _set(P, ["signature", "algorithm"], "hs256"), hint="REFUSE")
    case("case_sig_key_id_upper", "case", I, _set(P, ["signature", "key_id"], "DIFF-HMAC-1"), hint="REFUSE")
    case("case_contract_name", "case", _set(I, ["contract", "name"], "Action_Intent"), P, hint="REFUSE")
    case("case_pccb_contract_name", "case", I, _set(P, ["contract", "name"], "PCCB"), hint="REFUSE")
    case("case_hash_hex_upper", "action_hash", I, _set(P, ["action_hash", "value"], P["action_hash"]["value"].upper()), hint="REFUSE")
    case("case_hash_hex_upper_resigned", "action_hash", I, resign(_set(P, ["action_hash", "value"], P["action_hash"]["value"].upper())), hint="REFUSE")

    # ── whitespace inside values
    case("ws_target_leading_space", "whitespace", _set(I, ["target", "resource_id"], " ch_3Nq"), P, hint="REFUSE")
    case("ws_audience_trailing_space", "whitespace", I, P, _ctx(["audience", "id"], "payments-edge "), hint="REFUSE")
    case("ws_capability_tab", "whitespace", _set(I, ["action", "capability"], "payments.refund\t"), P, hint="REFUSE")

    # ── empty strings
    case("empty_context_audience_id", "empty_strings", I, P, _ctx(["audience", "id"], ""), hint="REFUSE")
    case("empty_intent_tenant_id", "empty_strings", _set(I, ["tenant", "tenant_id"], ""), P, hint="REFUSE")
    case("empty_signature_value", "empty_strings", I, _set(P, ["signature", "value"], ""), hint="REFUSE")
    case("empty_nonce_resigned", "empty_strings", I, _try_resign(_set(P, ["nonce"], "")), hint="REFUSE")
    case("empty_param_value_resigned", "empty_strings", *_resigned_param(I, C, "memo", ""), hint="ACCEPT")
    case("empty_scope_capabilities_ctx", "empty_strings", I, P, _ctx(["scope_capabilities"], []), hint="REFUSE")

    # ── missing fields
    for path in (["signature"], ["action_hash"], ["expires_at"], ["not_before"], ["audience"], ["nonce"], ["scope"], ["tenant"], ["signature", "value"], ["signature", "key_id"], ["scope", "single_use"]):
        case("missing_pccb_" + "_".join(path), "missing_fields", I, _set(P, path, DELETE), hint="REFUSE")
    for path in (["tenant"], ["intent_id"], ["requester"], ["target"], ["action", "parameters"], ["expires_at"], ["contract"]):
        case("missing_intent_" + "_".join(path), "missing_fields", _set(I, path, DELETE), P, hint="REFUSE")

    # ── additional fields
    case("extra_intent_toplevel", "additional_fields", _set(I, ["x_extra"], "ignored?"), P, hint="REFUSE",
         note="unknown top-level intent member")
    case("extra_intent_param", "additional_fields", _param(I, "x_amount_override", 999999), P, hint="REFUSE")
    case("extra_pccb_toplevel_unsigned", "additional_fields", I, _set(P, ["x_extra"], "unsigned"), hint="REFUSE",
         note="unknown PCCB member not covered by the signature")
    case("extra_pccb_signature_member", "additional_fields", I, _set(P, ["signature", "x_note"], "n"), hint="ACCEPT")
    case("extra_pccb_extensions_unsigned", "additional_fields", I, _set(P, ["extensions"], {"x": 1}), hint="REFUSE")

    # ── array ordering
    c = base_context(); c["scope_capabilities"] = ["payments.refund", "payments.read"]
    p2 = mint(I, c)
    c2 = copy.deepcopy(c); c2["scope_capabilities"] = ["payments.read", "payments.refund"]
    case("array_ctx_scope_order_swapped", "array_ordering", I, p2, c2, hint="ACCEPT", note="minted with sorted capabilities")
    pswap = copy.deepcopy(p2); pswap["scope"]["capabilities"] = list(reversed(p2["scope"]["capabilities"]))
    case("array_pccb_scope_order_swapped_unsigned", "array_ordering", I, pswap, c, hint="REFUSE")
    i4 = _param(I, "lines", [1, 2, 3]); c4 = copy.deepcopy(C); c4["parameter_constraints"] = i4["action"]["parameters"]
    p4 = mint(i4, c4)
    case("array_param_order_swapped", "array_ordering", _param(i4, "lines", [3, 2, 1]), p4, c4, hint="REFUSE")

    # ── numeric boundaries (re-signed: the reference decides representability)
    for name, val, hint in [("zero", 0, "ACCEPT"), ("negative", -1, "ACCEPT"), ("2p53", 2**53, "ACCEPT"), ("2p53_plus1", 2**53 + 1, "REFUSE"),
                            ("2p63", 2**63, "REFUSE"), ("2p64_plus1", 2**64 + 1, "REFUSE")]:
        case(f"num_{name}", "numeric_boundaries", *_resigned_param(I, C, "amount_minor", val), hint=hint)
    case("num_string_vs_int", "numeric_boundaries", _param(I, "amount_minor", "2500"), P, hint="REFUSE")
    case("num_bool_vs_int", "numeric_boundaries", _param(I, "amount_minor", True), P, hint="REFUSE")
    big = ib.replace(b'"amount_minor":2500', b'"amount_minor":' + b"9" * 400)
    case("num_huge_literal", "numeric_boundaries", big, P, hint="REFUSE")
    case("num_float_literal_1e400", "numeric_boundaries", ib.replace(b'"amount_minor":2500', b'"amount_minor":1e400'), P, hint="REFUSE")
    case("num_nan_literal", "malformed", ib.replace(b'"amount_minor":2500', b'"amount_minor":NaN'), P, hint="REFUSE")

    # ── deep nesting
    for depth in (16, 31, 32, 33, 64, 1000, 100000):
        nested = 0
        for _ in range(depth):
            nested = {"n": nested}
        if depth <= 64:
            try:
                case(f"nest_{depth}_resigned", "deep_nesting", *_resigned_param(I, C, "deep", nested), hint="ACCEPT" if depth < 32 else "REFUSE")
            except Exception as exc:  # reference refuses to even mint
                case(f"nest_{depth}_unsigned", "deep_nesting", _param(I, "deep", nested), P, hint="REFUSE", note=f"reference cannot mint: {type(exc).__name__}")
        else:
            raw = ib.replace(b'"amount_minor":2500', b'"amount_minor":2500,"deep":' + b'{"n":' * depth + b"0" + b"}" * depth)
            case(f"nest_{depth}_raw", "deep_nesting", raw, P, hint="REFUSE")

    # ── document size
    for size in (64 * 1024, 900 * 1024, 2 * 1024 * 1024):
        try:
            case(f"size_{size // 1024}k_resigned", "document_size", *_resigned_param(I, C, "blob", "x" * size), hint="ACCEPT" if size < 1_000_000 else "REFUSE")
        except Exception as exc:
            case(f"size_{size // 1024}k_unsigned", "document_size", _param(I, "blob", "x" * size), P, hint="REFUSE", note=f"reference cannot mint: {type(exc).__name__}")

    # ── escrow fields
    pesc = mint(I, C, escrow_id="esc_diff_1")
    case("escrow_valid", "escrow", I, pesc, hint="ACCEPT")
    case("escrow_id_altered", "escrow", I, _set(pesc, ["escrow_reference", "escrow_id"], "esc_other"), hint="REFUSE")
    case("escrow_removed", "escrow", I, _set(pesc, ["escrow_reference"], DELETE), hint="REFUSE")
    case("escrow_added_unsigned", "escrow", I, _set(P, ["escrow_reference"], {"escrow_id": "esc_x", "single_use": True}), hint="REFUSE")
    case("escrow_single_use_false", "escrow", I, _set(pesc, ["escrow_reference", "single_use"], False), hint="REFUSE")

    # ── single_use
    case("single_use_false_unsigned", "single_use", I, _set(P, ["scope", "single_use"], False), hint="REFUSE")
    case("single_use_false_resigned", "single_use", I, _try_resign(_set(P, ["scope", "single_use"], False)), hint="REFUSE",
         note="a validly signed non-single-use proof")
    case("single_use_string_true", "single_use", I, _set(P, ["scope", "single_use"], "true"), hint="REFUSE")

    # ── unsupported modes
    case("mode_scope_mode_prefix_resigned", "unsupported_modes", I, _try_resign(_set(P, ["scope", "mode"], "prefix")), hint="REFUSE")
    case("mode_sig_alg_none", "unsupported_modes", I, _set(P, ["signature", "algorithm"], "none"), hint="REFUSE")
    case("mode_sig_alg_rs256", "unsupported_modes", I, _set(P, ["signature", "algorithm"], "RS256"), hint="REFUSE")
    case("mode_sig_encoding_hex", "unsupported_modes", I, _set(P, ["signature", "encoding"], "hex"), hint="REFUSE")
    case("mode_hash_algorithm_sha512_resigned", "unsupported_modes", I, _try_resign(_set(P, ["action_hash", "algorithm"], "sha-512")), hint="REFUSE")
    case("mode_hash_canon_label_unknown_resigned", "unsupported_modes", I, _try_resign(_set(P, ["action_hash", "canonicalization"], "JCS-LOOSE")), hint="REFUSE")
    case("mode_hash_canon_label_rfc8785_resigned", "unsupported_modes", I, _try_resign(_set(P, ["action_hash", "canonicalization"], "RFC8785-JCS")), hint="ACCEPT",
         note="legacy label the verifiers accept")
    case("mode_contract_v2_intent", "unsupported_modes", _set(I, ["contract", "version"], "v2"), P, hint="REFUSE")
    case("mode_contract_v2_pccb", "unsupported_modes", I, _set(P, ["contract", "version"], "v2"), hint="REFUSE")
    case("mode_alg_confusion_eddsa_label_on_hmac", "unsupported_modes", I, _set(P, ["signature", "algorithm"], "EdDSA"), hint="REFUSE")
    case("mode_kid_unknown", "unsupported_modes", I, _set(P, ["signature", "key_id"], "diff-hmac-2"), hint="REFUSE")
    case("mode_kid_cross_ed_on_hmac", "unsupported_modes", I, _set(P, ["signature", "key_id"], ED_KID), hint="REFUSE")

    # ── signature malleability
    v = P["signature"]["value"]
    raw_sig = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    case("sig_padded_base64url", "signature_malleability", I, _set(P, ["signature", "value"], v + "="), hint="REFUSE")
    case("sig_std_base64_alphabet", "signature_malleability", I, _set(P, ["signature", "value"], base64.b64encode(raw_sig).decode().rstrip("=")), hint="REFUSE" if ("-" in v or "_" in v) else "ACCEPT")
    last = v[-1]; alt = {0: "A", 1: "B"}
    noncanon = v[:-1] + _noncanonical_last_char(v)
    case("sig_noncanonical_trailing_bits", "signature_malleability", I, _set(P, ["signature", "value"], noncanon), hint="REFUSE",
         note="same decoded bytes under a lenient decoder")
    case("sig_whitespace_inside", "signature_malleability", I, _set(P, ["signature", "value"], v[:10] + " " + v[10:]), hint="REFUSE")
    case("sig_truncated", "signature_malleability", I, _set(P, ["signature", "value"], v[:-4]), hint="REFUSE")
    case("sig_bitflip", "signature_malleability", I, _set(P, ["signature", "value"], b64u(bytes([raw_sig[0] ^ 1]) + raw_sig[1:])), hint="REFUSE")
    case("sig_extended_bytes", "signature_malleability", I, _set(P, ["signature", "value"], b64u(raw_sig + b"\x00")), hint="REFUSE")
    ve = PE["signature"]["value"]; raw_e = base64.urlsafe_b64decode(ve + "=" * (-len(ve) % 4))
    L = 2**252 + 27742317777372353535851937790883648493
    s = int.from_bytes(raw_e[32:], "little")
    case("sig_ed25519_s_plus_l", "signature_malleability", I, _set(PE, ["signature", "value"], b64u(raw_e[:32] + (s + L).to_bytes(32, "little"))), alg="EdDSA", hint="REFUSE",
         note="non-canonical S (S+L): RFC 8032 requires S < L")
    case("sig_ed25519_bitflip_R", "signature_malleability", I, _set(PE, ["signature", "value"], b64u(bytes([raw_e[0] ^ 1]) + raw_e[1:])), alg="EdDSA", hint="REFUSE")
    case("sig_ed25519_alg_relabelled_hs256", "signature_malleability", I, _set(PE, ["signature", "algorithm"], "HS256"), alg="EdDSA", hint="REFUSE")
    case("sig_ed25519_tamper_amount", "signature_malleability", _param(I, "amount_minor", 999999), PE, alg="EdDSA", hint="REFUSE")

    # ── audience / target / tenant / subject / action / action hash (semantic mismatch)
    case("aud_ctx_id_mismatch", "audience", I, P, _ctx(["audience", "id"], "ledger-edge"), hint="REFUSE")
    case("aud_ctx_type_mismatch", "audience", I, P, _ctx(["audience", "type"], "resource"), hint="REFUSE")
    case("aud_pccb_altered_unsigned", "audience", I, _set(P, ["audience", "id"], "ledger-edge"), hint="REFUSE")
    case("aud_pccb_other_audience_resigned", "audience", I, resign(_set(P, ["audience", "id"], "ledger-edge")), hint="REFUSE",
         note="a valid proof for a different audience")
    case("target_intent_id_mismatch", "target", _set(I, ["target", "resource_id"], "ch_OTHER"), P, hint="REFUSE")
    case("target_intent_type_mismatch", "target", _set(I, ["target", "resource_type"], "payout"), P, hint="REFUSE")
    case("target_ctx_selector_mismatch", "target", I, P, _ctx(["resource_selectors"], [{"resource_id": "ch_OTHER"}]), hint="REFUSE")
    case("target_pccb_resigned_other", "target", I, resign(_set(P, ["target", "resource_id"], "ch_OTHER")), hint="REFUSE")
    case("tenant_intent_mismatch", "tenant", _set(I, ["tenant", "tenant_id"], "tenant_evil"), P, hint="REFUSE")
    case("tenant_pccb_resigned_other", "tenant", I, resign(_set(P, ["tenant", "tenant_id"], "tenant_evil")), hint="REFUSE")
    case("subject_intent_mismatch", "subject", _set(I, ["requester", "id"], "agent_evil"), P, hint="REFUSE")
    case("subject_pccb_resigned_other", "subject", I, resign(_set(P, ["subject", "id"], "agent_evil")), hint="REFUSE")
    case("subject_type_mismatch", "subject", _set(I, ["requester", "type"], "human"), P, hint="REFUSE")
    case("action_name_mismatch", "action", _set(I, ["action", "name"], "payment.capture"), P, hint="REFUSE")
    case("action_capability_mismatch", "action", _set(I, ["action", "capability"], "payments.capture"), P, hint="REFUSE")
    case("action_param_amount_altered", "action", _param(I, "amount_minor", 999999), P, hint="REFUSE")
    case("action_param_removed", "action", _set(I, ["action", "parameters", "memo"], DELETE), P, hint="REFUSE")
    case("action_ctx_constraint_mismatch", "action", I, P, _ctx(["parameter_constraints", "amount_minor"], 1), hint="REFUSE")
    case("action_ctx_scope_capability_missing", "action", I, P, _ctx(["scope_capabilities"], ["payments.read"]), hint="REFUSE")
    case("action_hash_value_altered_unsigned", "action_hash", I, _set(P, ["action_hash", "value"], "0" * 64), hint="REFUSE")
    case("action_hash_value_altered_resigned", "action_hash", I, resign(_set(P, ["action_hash", "value"], "0" * 64)), hint="REFUSE",
         note="validly signed proof whose hash does not match the intent")
    case("action_hash_intent_id_mismatch", "action_hash", _set(I, ["intent_id"], "intent_diff_002"), P, hint="REFUSE")
    case("action_hash_intent_expiry_changed", "action_hash", _set(I, ["expires_at"], iso(T0 + timedelta(minutes=6))), P, hint="REFUSE")
    case("intent_pccb_intent_id_resigned_mismatch", "action_hash", I, resign(_set(P, ["intent_id"], "intent_other")), hint="REFUSE")

    # ── malformed input
    case("malformed_not_json", "malformed", b"not json", P, hint="REFUSE")
    case("malformed_truncated", "malformed", ib[:-5], P, hint="REFUSE")
    case("malformed_array_toplevel", "malformed", b"[" + ib + b"]", P, hint="REFUSE")
    case("malformed_null", "malformed", b"null", P, hint="REFUSE")
    case("malformed_trailing_garbage", "malformed", ib + b"}", P, hint="REFUSE")
    case("malformed_trailing_second_doc", "malformed", ib + b"{}", P, hint="REFUSE")
    case("malformed_pccb_empty", "malformed", I, b"", hint="REFUSE")
    case("malformed_pccb_string", "malformed", I, b'"pccb"', hint="REFUSE")
    case("malformed_param_type_object_for_string", "malformed", _set(I, ["tenant", "tenant_id"], {"a": 1}), P, hint="REFUSE")
    case("malformed_comment", "malformed", ib.replace(b"{", b"{/*c*/", 1), P, hint="REFUSE")
    case("malformed_single_quotes", "malformed", ib.replace(b'"intent_id"', b"'intent_id'"), P, hint="REFUSE")


def _noncanonical_last_char(v: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    idx = alphabet.index(v[-1])
    unused_bits = (6 * len(v)) % 8
    return alphabet[idx | 1] if unused_bits and idx | 1 != idx else alphabet[(idx + 1) % 64]


def _set(doc, path, value):
    d = copy.deepcopy(doc)
    set_path(d, path, value)
    return d


def _param(intent, key, value):
    d = copy.deepcopy(intent)
    d["action"]["parameters"][key] = value
    return d


def _ctx(path, value):
    c = base_context()
    set_path(c, path, value)
    return c


def _with(pccb):
    return (pccb,)


def _resigned_param(intent, context, key, value):
    i = _param(intent, key, value)
    c = copy.deepcopy(context)
    c["parameter_constraints"] = copy.deepcopy(i["action"]["parameters"])
    return i, mint(i, c), c


def _escaped(triple):
    i, p, c = triple
    return json.dumps(i, ensure_ascii=True).encode(), p, c


def _try_resign(pccb):
    try:
        return resign(pccb)
    except Exception:
        return pccb


def write() -> None:
    if OUT.exists():
        raise SystemExit(f"{OUT} exists: the corpus is immutable once written; use a new directory")
    OUT.mkdir(parents=True)
    manifest = {"corpus": "kernel_diff_v1", "base_now": iso(NOW), "cases": []}
    seen = set()
    for c in CASES:
        assert c["id"] not in seen, c["id"]
        seen.add(c["id"])
        d = OUT / c["id"]
        d.mkdir()
        (d / "intent.json").write_bytes(c["intent"])
        (d / "pccb.json").write_bytes(c["pccb"])
        (d / "context.json").write_bytes(j(c["context"]))
        manifest["cases"].append({k: c[k] for k in ("id", "category", "hint", "alg", "note")})
    (OUT / "manifest.json").write_bytes(json.dumps(manifest, indent=1, ensure_ascii=False).encode())
    (OUT / "trust.json").write_bytes(json.dumps({
        "hmac": {"key_id": HMAC_KID, "algorithm": "HS256", "secret_utf8": HMAC_SECRET.decode()},
        "ed25519": {"kid": ED_KID, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": b64u(ED.public_raw)},
    }, indent=1).encode())


if __name__ == "__main__":
    build()
    write()
    print(f"wrote {len(CASES)} cases to {OUT}")
