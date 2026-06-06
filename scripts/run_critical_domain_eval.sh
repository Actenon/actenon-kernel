set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p artifacts/evidence/critical_domain_eval/logs
mkdir -p artifacts/evidence/critical_domain_eval/coverage_runs

bash scripts/demo_hero.sh > artifacts/evidence/critical_domain_eval/logs/02_demo_hero.log 2>&1
python3 -m actenon.cli conformance run > artifacts/evidence/critical_domain_eval/logs/03_conformance.log 2>&1
python3 -m pytest tests/ -q > artifacts/evidence/critical_domain_eval/logs/04_pytest.log 2>&1
bash scripts/verify_release_gate.sh > artifacts/evidence/critical_domain_eval/logs/05_release_gate.log 2>&1

for i in $(seq 1 10)
do
  python3 -m actenon.cli coverage run > "artifacts/evidence/critical_domain_eval/coverage_runs/coverage_run_${i}.log" 2>&1
done

echo "Critical-domain evaluation complete."
echo "Logs written under artifacts/evidence/critical_domain_eval/"
