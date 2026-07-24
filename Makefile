.PHONY: test test-all demo fastapi-demo ecosystem verify-claims conformance

# The narrow `test` target runs a curated subset of tests for fast feedback.
# For the full suite, use `make test-all`.
test:
	python -m pytest \
	        examples/protected_policy_preflight_refund \
	        tests/test_interactive_execution_demo.py \
	        tests/test_dx_adoption_fixes.py \
	        examples/financial_agent_protected_transfer \
	        examples/fastmcp_financial_transfer \
	        examples/protected_clinical_ehr_agent \
	        examples/protected_multi_agent_swarm \
	        examples/protected_iam_control_plane \
	        examples/fastapi_resource_boundary_refund \
	        -vv

# Run the full test suite. This is what CI runs on every push and PR.
test-all:
	python -m pytest tests/ -q

# Run the conformance suite. CI runs this on every push and PR (not just
# on conformance-v* tags). The conformance-release.yml workflow handles
# the signed release artefacts on tag pushes.
conformance:
	python -m pytest tests/conformance/ -q

demo:
	python examples/interactive_execution_demo.py

fastapi-demo:
	python -m pytest \
	        examples/fastapi_resource_boundary_refund \
	        -vv

# Machine-verify every claim the README and SUPPORT_AND_COMPATIBILITY_STATUS.md
# make about the kernel itself. Fails CI on any drift.
verify-claims:
	@echo "==> Verifying Python badge in sync"
	@python scripts/sync_badges.py --check
	@echo "==> Verifying README install instructions"
	@python scripts/check_readme_installs.py
	@echo "==> Verifying ecosystem table"
	@python -m actenon_protocol.ecosystem --check README.md --repo actenon-kernel
	@echo "==> Verifying no Cloud or Permit imports in kernel"
	@python -c "import pathlib,sys; \
	        viol=[f'{p}: imports {pkg}' for p in pathlib.Path('actenon').rglob('*.py') \
	                for pkg in ['actenon_cloud','actenon_permit'] \
	                if f'import {pkg}' in p.read_text() or f'from {pkg}' in p.read_text()]; \
	        (sys.exit(1) if viol else print('OK'))"
	@echo "==> Verifying protocol version pin"
	@python -c "import tomllib; \
	        d=tomllib.load(open('pyproject.toml','rb')); \
	        deps=d['project']['dependencies']; \
	        assert any('actenon-protocol' in x and '1.1.0' in x for x in deps), \
	                f'actenon-protocol >= 1.1.0 not pinned: {deps}'; \
	        print('OK: actenon-protocol >= 1.1.0 pinned')"
	@echo "==> Verifying SUPPORT_AND_COMPATIBILITY_STATUS.md matches CI matrix"
	@python -c "import re,pathlib,sys; \
	        doc=pathlib.Path('docs/SUPPORT_AND_COMPATIBILITY_STATUS.md').read_text(); \
	        m=re.search(r'a Python matrix over ([\d\.,\s]+and\s+[\d\.]+|[\d\.,\s]+)', doc); \
	        raw=m.group(1).replace('and', ','); \
	        claimed=sorted({v.strip() for v in raw.split(',') if v.strip()}); \
	        assert claimed == ['3.10','3.11','3.12'], \
	                f'doc claims {claimed} but CI runs [3.10, 3.11, 3.12]'; \
	        print('OK: doc and CI matrix agree')"
	@echo "==> All claims verified."
