#!/usr/bin/env bash
set -euo pipefail

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

sleep 0.5

echo ""
echo -e "${WHITE}ACTENON${RESET}"
echo -e "${BLUE}No valid proof, no execution.${RESET}"
echo ""
echo "Every consequential AI action leaves a verifiable receipt."
echo ""
sleep 2

clear
line
echo -e "${RED}WITHOUT ACTENON${RESET}"
line
echo ""
echo -e "${WHITE}Agent attempts:${RESET}"
echo -e "  DROP TABLE production;"
echo ""
sleep 1
echo -e "${RED}Outcome: WOULD_EXECUTE${RESET}"
echo -e "${RED}Side effect: production data deleted${RESET}"
echo ""
sleep 2.5

clear
line
echo -e "${BLUE}WITH ACTENON${RESET}"
line
echo ""
echo -e "${WHITE}Same action:${RESET}"
echo -e "  DROP TABLE production;"
echo ""
sleep 1
echo -e "${YELLOW}Proof check: no valid proof for this exact action${RESET}"
echo ""
sleep 1
echo -e "${RED}Outcome: REFUSED${RESET}"
echo -e "${GREEN}Side effect executed: false${RESET}"
echo -e "${GREEN}Refusal receipt: emitted${RESET}"
echo ""
sleep 3

clear
line
echo -e "${GREEN}WITH VALID PROOF${RESET}"
line
echo ""
echo -e "${WHITE}Approved action:${RESET}"
echo -e "  archive_old_demo_records;"
echo ""
sleep 1
echo -e "${GREEN}Proof check: valid${RESET}"
echo -e "${GREEN}Outcome: EXECUTED ONCE${RESET}"
echo -e "${GREEN}Receipt: emitted and verifiable${RESET}"
echo ""
sleep 2.5

clear
line
echo -e "${WHITE}VERIFIABLE RECEIPTS${RESET}"
line
echo ""
echo -e "${RED}Refusal receipt${RESET}"
echo '  outcome: refused'
echo '  reason_code: ACTION_HASH_MISMATCH'
echo '  side_effect_executed: false'
echo ""
echo -e "${GREEN}Execution receipt${RESET}"
echo '  outcome: executed'
echo '  side_effect_executed: true'
echo '  receipt_digest: sha256:353c73...'
echo ""
sleep 2.5

clear
echo ""
echo -e "${WHITE}ACTENON${RESET}"
echo -e "${BLUE}No valid proof, no execution.${RESET}"
echo ""
echo -e "${GREEN}Unproven action refused.${RESET}"
echo -e "${GREEN}Valid proof executed once.${RESET}"
echo -e "${GREEN}Receipt emitted.${RESET}"
echo ""
sleep 2
