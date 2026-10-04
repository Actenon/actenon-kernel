#!/usr/bin/env bash
# Documented commands, run from an installed wheel in a clean dir with
# ACTENON_ENV unset (a new user's shell). Usage: run_quickstart.sh <venv-bin> <outdir>
B=$1; OUT=$2; mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"; unset ACTENON_ENV
run() { local name=$1; shift; "$@" >"$OUT/$name.out" 2>&1 </dev/null; local rc=$?; echo "rc=$rc  $name: $* | $(grep -v -i warning "$OUT/$name.out" | tail -1 | cut -c1-150)"; }
echo "## kernel $($B/python -c 'import importlib.metadata as m;print(m.version("actenon-kernel"))')  cwd=$W"
run 01-help $B/actenon-kernel --help
run 02-conformance $B/actenon-kernel conformance run --require-complete
run 03-simulate-replit $B/actenon-kernel simulate --incident replit
run 04-simulate-all $B/actenon-kernel simulate --scenario all
run 05-local-proof $B/python -m actenon.demo.local_proof
run 06-verify-proof-allow $B/python -m actenon.cli verify-proof --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json --audience service:local-refund-endpoint --verification-time pccb-issued-at
run 06b-verify-proof-allow-devintent env ACTENON_ENV=development $B/python -m actenon.cli verify-proof --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json --audience service:local-refund-endpoint --verification-time pccb-issued-at
run 07-verify-proof-wrong-aud env ACTENON_ENV=development $B/python -m actenon.cli verify-proof --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json --audience service:wrong-endpoint --verification-time pccb-issued-at --json
run 08-verify-receipt $B/python -m actenon.cli verify-receipt --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json
run 08b-verify-receipt-devintent env ACTENON_ENV=development $B/python -m actenon.cli verify-receipt --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json
run 09-verify-refusal $B/actenon-kernel verify-refusal --refusal artifacts/local_proof/scenarios/deny/refusal.json --intent artifacts/local_proof/scenarios/deny/action_intent.json --receipt artifacts/local_proof/scenarios/deny/decision_receipt.json
run 10-mcp-demo timeout 15 $B/actenon-mcp --demo
run 11-mcp-demo-prd env ACTENON_ENV=prd timeout 15 $B/actenon-mcp --demo
run 12-mcp-no-key timeout 15 $B/actenon-mcp
