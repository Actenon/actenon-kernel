# blastradius re-evaluation (north-star)

| Item | Value |
|---|---|
| PyPI | `actenon-blastradius` 0.4.0 (latest; 0.1.0–0.4.0 published) |
| `main` | df10b55 (squash of PR #2): 198 tests pass |
| Candidate | d7f60a6 on `claude/actenon-kernel-mcp-setup-qolk0h`: 13 commits **not on main**; `pyproject` version **0.4.0** (= the published version, so it cannot be published as is) |
| Candidate suite | 342 passed (editable install of d7f60a6, `candidate-d7f60a6-full-suite-editable.txt`); per file from the candidate source: all pass (`candidate-d7f60a6-tests-per-file-SOURCE-TREE.txt`) |
| Published 0.4.0 vs the candidate's tests | `test_bypass_wrappers.py`: **9 failed / 3 passed**; `test_bypass_shell_semantics.py`: **ABORTED** — the pytest process was replaced mid-run, i.e. 0.4.0 executed a wrapped command the test expects it to block (`published-0.4.0-vs-candidate-tests-per-file.txt`) |
| Actenon runtime dependencies | none (`dependencies = []`) |

**Verdict: BLASTRADIUS BLOCKED** (not BLASTRADIUS_PASS). Exact blockers:
1. The bypass fixes are not on `main`: the 13 commits on `claude/actenon-kernel-mcp-setup-qolk0h` (head d7f60a6) need a PR to `main`, green CI, and review.
2. The version must move to a new number (0.5.0) with release notes; 0.4.0 already exists on PyPI.
3. Users of PyPI 0.4.0 are exposed to the wrapper/shell-semantics bypasses the candidate fixes: a private advisory must be prepared and published only together with the fixed release (draft kept outside the public repository).
