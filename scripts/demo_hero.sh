#!/usr/bin/env bash
set -euo pipefail

DETAILS=false
if [[ "${1:-}" == "--details" ]]; then
  DETAILS=true
fi

clear

BLUE="\033[1;36m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
WHITE="\033[1;37m"
DIM="\033[2m"
RESET="\033[0m"

line() {
  echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

pause() {
  sleep "${1:-1}"
}

echo ""
echo -e "${WHITE}ACTENON HERO DEMO${RESET}"
echo -e "${BLUE}No valid proof, no execution.${RESET}"
echo ""
echo "Every consequential AI action leaves a verifiable receipt."
echo ""
echo -e "${DIM}Safe local simulation. No real database, payment, email, or cloud action is performed.${RESET}"
echo ""
pause 2

clear
line
echo -e "${RED}WITHOUT ACTENON${RESET}"
line
echo ""
echo -e "${WHITE}Agent attempts:${RESET}"
echo "  DROP TABLE production;"
echo ""
pause 0.8
echo -e "${RED}Outcome:${RESET}"
echo -e "  ${RED}WOULD_EXECUTE${RESET}"
echo ""
echo -e "${RED}Side effect:${RESET}"
echo "  Data would be deleted."
echo ""
pause 2

clear
line
echo -e "${BLUE}WITH ACTENON${RESET}"
line
echo ""
echo -e "${WHITE}Same action:${RESET}"
echo "  DROP TABLE production;"
echo ""
pause 0.8
echo -e "${YELLOW}Proof check:${RESET}"
echo "  No valid proof for this exact action."
echo ""
pause 0.8
echo -e "${RED}Outcome:${RESET}"
echo -e "  ${RED}REFUSED${RESET}"
echo ""
echo -e "${GREEN}Side effect executed:${RESET}"
echo "  false"
echo ""
echo -e "${GREEN}Refusal receipt:${RESET}"
echo "  emitted"
echo ""
pause 2.2

clear
line
echo -e "${GREEN}WITH VALID PROOF${RESET}"
line
echo ""
echo -e "${WHITE}Legitimate approved action:${RESET}"
echo "  archive_old_demo_records;"
echo ""
pause 0.8
echo -e "${GREEN}Proof check:${RESET}"
echo "  valid"
echo ""
echo -e "${GREEN}Outcome:${RESET}"
echo "  EXECUTED ONCE"
echo ""
echo -e "${GREEN}Receipt:${RESET}"
echo "  emitted and verifiable"
echo ""
pause 2

clear
line
echo -e "${WHITE}RECEIPT SNAPSHOT${RESET}"
line
echo ""
echo -e "${RED}Refusal:${RESET}"
cat <<'JSON'
{
  "outcome": "refused",
  "reason_code": "ACTION_HASH_MISMATCH",
  "side_effect_executed": false,
  "receipt": "refusal_receipt.json"
}
JSON
echo ""
echo -e "${GREEN}Receipt:${RESET}"
cat <<'JSON'
{
  "outcome": "executed",
  "side_effect_executed": true,
  "receipt": "execution_receipt.json"
}
JSON
echo ""
pause 2.2

clear
echo ""
echo -e "${WHITE}ACTENON${RESET}"
echo -e "${BLUE}No valid proof, no execution.${RESET}"
echo ""
echo -e "${GREEN}Done:${RESET} unproven action refused; valid proof executed once."
echo ""
echo -e "${WHITE}Next:${RESET}"
echo "  python3 -m actenon.cli scan local"
echo "  bash scripts/verify_release_gate.sh"
echo "  open artifacts/hero_demo_runtime/simulations/replit/refusal.json"
echo ""

if [[ "${DETAILS}" == "true" ]]; then
  echo -e "${DIM}Technical details:${RESET}"
  echo "  Refusal artifact: artifacts/hero_demo_runtime/simulations/replit/refusal.json"
  echo "  Execution receipt: artifacts/hero_demo_runtime/simulations/replay-refused/execution_receipt.json"
  echo "  Refusal digest: sha256:9408f4573e097f38d38a483280ec70b3737df74d4119e09af4615b19840ff121"
  echo "  Receipt digest: sha256:353c73da14c3a6884c5308cf7d3826d8faeda8413a80ada9a1e2aab879fbfc71"
  echo ""
fi

pause 1.5
