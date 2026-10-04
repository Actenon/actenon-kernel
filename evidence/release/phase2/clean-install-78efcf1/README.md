# Clean-install run: kernel 78efcf1 test suite against its own built wheel

Wheel: `../artefacts-78efcf1/actenon_kernel-1.3.0rc1-py3-none-any.whl` (sha256 in `../artefacts-78efcf1/SHA256SUMS`).
Venv: fresh, with the kernel wheel, the Permit 2.0.0rc1 wheel `[dev]`, actenon-protocol 1.3.0 from PyPI, langchain-core,
fastapi and mcp.

- `kernel-wheel-suite-RUN1-bare-tests-dir-INVALID-METHOD.txt`: first attempt. It copied only `tests/`, `examples/` and
  `conformance/`. Many kernel tests read repository files, so collection failed. The method was invalid, and the file is
  kept unedited.
- `kernel-wheel-suite.txt`: the method used. The commit was exported (`git archive`), `actenon/` was deleted so that
  `import actenon` can only resolve to the wheel, and pytest ran from the export. Result: 70 failed, 773 passed,
  2 allowed skips. `actenon.conformance` 53/53 passed; `examples/` 27/27 passed.

Classification of the 70 failures:

| Count | Tests | Cause | Product defect? |
|---|---|---|---|
| 25+8+5+5+1+1 | `test_scanner_universal`, `test_scan_cli`, `test_scanner_security`, `test_scanner_safety`, `test_execution_gap_action_outputs`, `test_local_runtime_cli` (doctor --deep) | `actenon/scanner_capability_registry.v1.json` not in the wheel → `FileNotFoundError` | **Yes.** Also present in released 1.2.1 (`actenon-kernel scan repo` fails from the PyPI wheel; reproduced). Fixed in 6c5bf02 |
| 3 | `test_conformance_release` | reads `actenon/conformance/vectors/...` by repository path | no (test needs the source tree) |
| 2 | `test_refusal_message_hygiene` | reads vectors by repository path | no |
| 1 | `test_independence` | scans kernel source files | no |
| 1 | `test_installed_console_script` | builds its own venv from the (deleted) source tree | no |
