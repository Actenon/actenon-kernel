.PHONY: test demo fastapi-demo

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
		examples/fastapi_verifier_only_refund \
		-vv

demo:
	python examples/interactive_execution_demo.py

fastapi-demo:
	python -m pytest \
		examples/fastapi_resource_boundary_refund \
		examples/fastapi_verifier_only_refund \
		-vv
