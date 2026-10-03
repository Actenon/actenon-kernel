#!/usr/bin/env python3
"""Cross-language parity of the INSTALLED release artefacts on the frozen differential corpora.

usage: parity.py FRESH_CONSUMER_OUT_DIR > PARITY.json   (human summary on stderr)

Frozen criteria (phase 2, unchanged):
  * A (implementation ACCEPTs what the Python reference REFUSEs) must be 0.
  * U (UNSUPPORTED / missing) must be 0.
  * B (implementation REFUSEs what the reference ACCEPTs: fail-closed) is enumerated; here it must
    equal, case for case, the B set recorded for the phase-2 FINAL candidates (no new B, none lost).
Additionally:
  * the Python reference on every interpreter equals the phase-2 FINAL Python reference row for row;
  * every implementation's rows (outcome AND code) equal its phase-2 FINAL candidate rows.
Exit 1 if any criterion fails.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
HERE = Path(__file__).resolve().parent
DIFF = HERE.parent.parent / "differential"
P2 = HERE.parent.parent / "phase2" / "differential"
CORPORA = {
    "kernel_diff_v1": (DIFF / "corpus", "diff", P2 / "results"),
    "addendum_precision": (DIFF / "corpus-addendum-precision", "diffadd", P2 / "results-addendum-precision"),
}
IMPLS = {  # new result stem -> phase-2 FINAL result file stem
    "ts-verifier-sdk": "ts-verifier-sdk-0.2.0-FINAL-e775389-STRICT-verifyJSON",
    "go-sdk-strict": "go-sdk-FINAL-e3649cd",
    "go-sdk-usenumber": "go-sdk-FINAL-e3649cd-USENUMBER-context",
    "rust-sdk": "rust-sdk-0.2.0-FINAL-0a16a84-crate",
}
P2_REF = "python-kernel-1.3.0rc1-FINAL-e775389-REFERENCE"


def load(p: Path) -> dict[str, dict]:
    return {r["id"]: r for r in map(json.loads, p.read_text().splitlines())}


def classify(cases: dict, ref: dict, impl: dict) -> dict:
    A, B, C, U, agree = [], [], [], [], 0
    for cid, c in cases.items():
        r, i = ref[cid], impl.get(cid)
        if i is None or i["outcome"] not in ("ACCEPT", "REFUSE"):
            U.append(cid)
        elif i["outcome"] == "ACCEPT" and r["outcome"] == "REFUSE":
            A.append(cid)
        elif i["outcome"] == "REFUSE" and r["outcome"] == "ACCEPT":
            B.append({"id": cid, "category": c["category"], "impl_code": i["code"]})
        else:
            agree += 1
            if i["outcome"] == "REFUSE" and i["code"] != r["code"]:
                C.append(cid)
    return {"cases": len(cases), "agree": agree, "A": A, "B": B, "C_count": len(C), "U": U}


report: dict = {"criteria": {"v1": "kernel_diff_v1 + precision addendum: A=0, U=0, B == phase-2 FINAL B set; rows equal phase-2 FINAL", "v2": "timestamp-grammar addendum: A=0, U=0, py310 == py312, reference == RFC 3339 hint, B only on DEVIATION cases or go-sdk-strict"}, "corpora": {}}
failures: list[str] = []
for corpus_name, (cdir, prefix, p2dir) in CORPORA.items():
    cases = {c["id"]: c for c in json.loads((cdir / "manifest.json").read_text())["cases"]}
    p2ref = load(p2dir / f"{P2_REF}.jsonl")
    entry: dict = {"case_count": len(cases), "python_reference": {}, "implementations": {}}
    ref = load(OUT / f"{prefix}-python-kernel-py312.jsonl")
    for py in ("py310", "py311", "py312"):
        rows = load(OUT / f"{prefix}-python-kernel-{py}.jsonl")
        diffs = [cid for cid in cases if (rows[cid]["outcome"], rows[cid]["code"]) != (p2ref[cid]["outcome"], p2ref[cid]["code"])]
        entry["python_reference"][py] = {"rows_differing_from_phase2_final_reference": diffs}
        if diffs:
            failures.append(f"{corpus_name}: python {py} differs from the phase-2 FINAL reference on {diffs}")
    for stem, p2stem in IMPLS.items():
        new = load(OUT / f"{prefix}-{stem}.jsonl")
        old = load(p2dir / f"{p2stem}.jsonl")
        now, then = classify(cases, ref, new), classify(cases, p2ref, old)
        changed_rows = [cid for cid in cases if (new.get(cid, {}).get("outcome"), new.get(cid, {}).get("code")) != (old[cid]["outcome"], old[cid]["code"])]
        b_now, b_then = sorted(b["id"] for b in now["B"]), sorted(b["id"] for b in then["B"])
        entry["implementations"][stem] = {
            "installed_artefact_result": now,
            "phase2_final_B": b_then,
            "B_set_equal_to_phase2_final": b_now == b_then,
            "rows_differing_from_phase2_final": changed_rows,
        }
        if now["A"]:
            failures.append(f"{corpus_name}: {stem} A={now['A']}")
        if now["U"]:
            failures.append(f"{corpus_name}: {stem} U={now['U']}")
        if b_now != b_then:
            failures.append(f"{corpus_name}: {stem} B set changed: new-only={sorted(set(b_now) - set(b_then))} lost={sorted(set(b_then) - set(b_now))}")
        if changed_rows:
            failures.append(f"{corpus_name}: {stem} rows differ from phase-2 FINAL: {changed_rows}")
        print(f"{corpus_name:20} {stem:18} cases={now['cases']} agree={now['agree']} A={len(now['A'])} "
              f"B={len(now['B'])} C={now['C_count']} U={len(now['U'])} B==phase2:{b_now == b_then} "
              f"rows==phase2:{not changed_rows}", file=sys.stderr)
    report["corpora"][corpus_name] = entry
# ---- Criterion v2 (defined 2026-10-03 before the post-fix run): timestamp-grammar addendum.
# No phase-2 baseline exists for it, so instead: A=0 and U=0 for every implementation; the reference is
# interpreter-independent (py310 rows == py312 rows); the reference agrees with the a-priori RFC 3339 hint on
# every ACCEPT/REFUSE case; and a B is allowed only on a DEVIATION-labelled case, or for go-sdk-strict, whose
# float64 decoding of numeric edge constraints refuses every case (the documented phase-2 B; UseNumber is the
# comparison variant).
tsg_dir = HERE.parent / "differential" / "corpus-addendum-timestamp-grammar"
if (OUT / "difftsg-python-kernel-py312.jsonl").exists():
    cases = {c["id"]: c for c in json.loads((tsg_dir / "manifest.json").read_text())["cases"]}
    ref = load(OUT / "difftsg-python-kernel-py312.jsonl")
    entry = {"case_count": len(cases), "criterion": "v2", "implementations": {}}
    py310 = load(OUT / "difftsg-python-kernel-py310.jsonl")
    entry["python_py310_rows_differing_from_py312"] = [k for k in cases if (py310[k]["outcome"], py310[k]["code"]) != (ref[k]["outcome"], ref[k]["code"])]
    entry["reference_vs_rfc3339_hint_mismatches"] = [k for k, c in cases.items() if c["hint"] in ("ACCEPT", "REFUSE") and (ref[k]["outcome"] == "ACCEPT") != (c["hint"] == "ACCEPT")]
    if entry["python_py310_rows_differing_from_py312"]:
        failures.append(f"timestamp_grammar: py310 differs from py312 on {entry['python_py310_rows_differing_from_py312']}")
    if entry["reference_vs_rfc3339_hint_mismatches"]:
        failures.append(f"timestamp_grammar: reference disagrees with RFC 3339 on {entry['reference_vs_rfc3339_hint_mismatches']}")
    for stem in IMPLS:
        res = classify(cases, ref, load(OUT / f"difftsg-{stem}.jsonl"))
        unjustified_b = [b["id"] for b in res["B"] if cases[b["id"]]["hint"] != "DEVIATION" and stem != "go-sdk-strict"]
        entry["implementations"][stem] = {"installed_artefact_result": res, "unjustified_B": unjustified_b}
        for label, bad in (("A", res["A"]), ("U", res["U"]), ("unjustified B", unjustified_b)):
            if bad:
                failures.append(f"timestamp_grammar: {stem} {label}={bad}")
        print(f"{'timestamp_grammar':20} {stem:18} cases={res['cases']} agree={res['agree']} A={len(res['A'])} "
              f"B={len(res['B'])} C={res['C_count']} U={len(res['U'])} unjustifiedB={len(unjustified_b)}", file=sys.stderr)
    report["corpora"]["timestamp_grammar"] = entry
report["failures"] = failures
report["result"] = "PASS" if not failures else "FAIL"
print(json.dumps(report, indent=2))
print(f"parity: {report['result']}" + "".join(f"\n  {f}" for f in failures), file=sys.stderr)
sys.exit(0 if not failures else 1)
