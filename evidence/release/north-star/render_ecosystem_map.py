"""Render ECOSYSTEM-MAP.md from ECOSYSTEM-MAP.json (no hand-edited facts)."""
import json
d = json.load(open("ECOSYSTEM-MAP.json"))
L = ["# Actenon ecosystem map", "", "Generated from `ECOSYSTEM-MAP.json` by `render_ecosystem_map.py` (collected live by `collect_ecosystem_map.py`).", "",
     "| Repo | Remote | Branch / HEAD | Candidate | Dirty | Published now | Intended | Actenon deps | Release role | Gate-critical |",
     "|---|---|---|---|---|---|---|---|---|---|"]
for n, r in d["repos"].items():
    pub = "<br>".join(f"{k}: {v}" for k, v in r["published"].items()) or "—"
    L.append(f"| **{n}** | {r['remote']} | {r['branch']} `{r['head'][:7]}` | `{(r['candidate'] or '—')}` | {r['dirty_tracked_files']} | {pub} | {r['intended'] or '—'} | {'; '.join(r['actenon_deps']) or 'none'} | {r['release_role']} | {', '.join(r['gate_critical'])} |")
L += ["", "## Runtime roles", ""]
for n, r in d["repos"].items():
    L.append(f"- **{n}**: {r['runtime_role']}")
L += ["", "## Workflows (from the candidate checkout)", ""]
for n, r in d["repos"].items():
    L.append(f"### {n}")
    L.append("| File | Triggers | Jobs (id → displayed name) | Publishes |")
    L.append("|---|---|---|---|")
    for w in r["workflows"]:
        jobs = "; ".join(f"`{k}` → {v['name']}" for k, v in w.get("jobs", {}).items())
        trig = json.dumps(w.get("trigger_detail") or w.get("triggers"))
        L.append(f"| {w['file']} | `{trig[:160]}` | {jobs} | {'**yes**' if w.get('publishes') else ''} |")
    L.append("")
L += ["## Outside the release graph", ""] + [f"- **{k}**: {v}" for k, v in d["out_of_scope"].items()]
L += ["", "## Branch protection expectations", "", "See `CI-GATE-MATRIX.md` (exact required check names, verified against GitHub check-run names)."]
open("ECOSYSTEM-MAP.md", "w").write("\n".join(L) + "\n")
