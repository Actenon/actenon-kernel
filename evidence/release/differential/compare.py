"""Compare implementation results to the reference. argv: corpus reference.jsonl impl.jsonl [impl.jsonl ...]
A = impl ACCEPT / reference REFUSE (dangerous). B = impl REFUSE / reference ACCEPT (fail-closed).
C = both REFUSE with different codes (informational). U = UNSUPPORTED / missing (not counted as agreement)."""
import json, sys
from pathlib import Path
corpus = Path(sys.argv[1])
m = {c["id"]: c for c in json.loads((corpus / "manifest.json").read_text())["cases"]}
load = lambda p: {r["id"]: r for r in map(json.loads, open(p))}
ref = load(sys.argv[2])
summary = []
for p in sys.argv[3:]:
    impl = load(p); name = Path(p).stem
    A, B, C, U, agree = [], [], [], [], 0
    for cid, c in m.items():
        r, i = ref[cid], impl.get(cid)
        if i is None or i["outcome"] not in ("ACCEPT", "REFUSE"):
            U.append((cid, i and i["code"])); continue
        if i["outcome"] == "ACCEPT" and r["outcome"] == "REFUSE": A.append((cid, c["category"], r["code"]))
        elif i["outcome"] == "REFUSE" and r["outcome"] == "ACCEPT": B.append((cid, c["category"], i["code"]))
        else:
            agree += 1
            if i["outcome"] == "REFUSE" and i["code"] != r["code"]: C.append((cid, r["code"], i["code"]))
    summary.append((name, len(m), agree, len(A), len(B), len(C), len(U)))
    print(f"\n## {name}: agree={agree} A(dangerous)={len(A)} B(fail-closed)={len(B)} C(code-differs)={len(C)} U(unsupported)={len(U)}")
    for x in A: print(f"  A  {x[0]:45} [{x[1]}] reference refused {x[2]}")
    for x in B: print(f"  B  {x[0]:45} [{x[1]}] impl refused {x[2]}")
    if "-v" in sys.argv[0:1] or True:
        for x in C[:200]: print(f"  C  {x[0]:45} ref={x[1]} impl={x[2]}")
print("\n| implementation | cases | agree | A dangerous | B fail-closed | C code differs | unsupported |\n|---|---|---|---|---|---|---|")
for s in summary: print("| " + " | ".join(map(str, s)) + " |")
