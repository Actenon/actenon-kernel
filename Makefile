PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

.PHONY: help install build test verify judge local-proof first-run portable-build portable-verify public-verify release-gate public-hygiene-audit sdk-typescript-test release-archive validate-release-archive reset clean

help:
	@printf "Available targets:\n"
	@printf "  install         Install the repo in editable mode and install build tooling.\n"
	@printf "  build           Build sdist and wheel.\n"
	@printf "  test            Run the Python test suite.\n"
	@printf "  verify          Run the kernel acceptance gate.\n"
	@printf "  judge           Run the judgment summary gate.\n"
	@printf "  local-proof     Run deterministic local proof mode.\n"
	@printf "  first-run       Run the fast first-success path.\n"
	@printf "  portable-build  Build the portable distribution.\n"
	@printf "  portable-verify Verify the portable distribution.\n"
	@printf "  public-verify   Run the full release gate.\n"
	@printf "  release-gate    Run keystone, full tests, lint, boundary, and archive gates.\n"
	@printf "  public-hygiene-audit Check for forbidden tracked build/process residue.\n"
	@printf "  sdk-typescript-test Run the TypeScript verifier SDK tests.\n"
	@printf "  release-archive Build and validate a clean public release archive.\n"
	@printf "  validate-release-archive Validate an existing public release archive.\n"
	@printf "  reset           Reset local demo state.\n"
	@printf "  clean           Remove generated build and cache artifacts.\n"

install:
	$(PIP) install --upgrade pip build
	$(PIP) install -e .

build:
	$(PYTHON) -m build

test:
	$(PYTHON) -m pytest tests/

verify:
	bash ./scripts/verify.sh

judge:
	bash ./scripts/judge.sh

local-proof:
	bash ./scripts/run_local_proof.sh

first-run:
	bash ./scripts/first_run.sh

portable-build:
	bash ./scripts/build_portable_distribution.sh

portable-verify:
	bash ./scripts/verify_portable_distribution.sh

public-verify:
	bash ./scripts/verify_release_gate.sh

release-gate:
	bash ./scripts/verify_release_gate.sh

public-hygiene-audit:
	$(PYTHON) ./scripts/public_hygiene_audit.py

sdk-typescript-test:
	cd sdk/typescript && npm ci && npm test

release-archive:
	bash ./scripts/verify_release_gate.sh

validate-release-archive:
	bash ./scripts/validate_release_archive.sh dist/actenon-kernel-release.zip

reset:
	bash ./scripts/reset_demo_state.sh

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .tox artifacts .actenon coverage.xml
	rm -rf sdk/typescript/dist sdk/typescript/node_modules
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name 'node_modules' -prune -exec rm -rf {} +
	find . -type d -name '__MACOSX' -prune -exec rm -rf {} +
	find . -type f \( -name '.DS_Store' -o -name '._*' \) -delete
