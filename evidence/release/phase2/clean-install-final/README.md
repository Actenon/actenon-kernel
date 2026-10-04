# Clean-install run: kernel e775389 suite against its built wheel (final: kernel e775389, Permit a5467ab)

Wheel: `../artefacts-final/actenon_kernel-1.3.0rc1-py3-none-any.whl`. Method as in `../clean-install-78efcf1/`:
the commit is exported, `actenon/` is deleted, and pytest runs from the export so `import actenon` resolves to the wheel.

Result: 819 passed, 10 failed (8 test cases; JUnit counts subtests), 2 allowed skips. `actenon.conformance` 53/53 passed;
`examples/` 27/27 passed. The skip gate reports 0 unexpected skips. The `-rf` short summary (`kernel-wheel-suite-failures.txt`)
lists 7 lines; the JUnit report (`kernel-wheel-suite-junit-failures.txt`) is authoritative and lists 8 test cases. The extra one is
`test_packaging_imports`, which fails deterministically (re-run in isolation: same result).

Every failing test case reads repository source paths (`actenon/...`), or builds a venv from the deleted source tree. None is
a product defect:

| Test | Reads |
|---|---|
| `test_installed_console_script` | builds its own venv from the source tree |
| `test_independence` | scans `actenon/**/*.py` |
| `test_conformance_release` (3) | `actenon/conformance/vectors/...` by repository path |
| `test_packaging_imports` | `actenon/cli.py`, `actenon/local_runtime_server.py`, `actenon/ui/...` source text |
| `test_refusal_message_hygiene` (2) | `actenon/conformance/vectors/...` by repository path |

The 52 scanner-related failures of the 78efcf1 wheel (the registry was not packaged) are gone.
