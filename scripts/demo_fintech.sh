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
echo -e "${WHITE}ACTENON / FINTECH${RESET}"
echo -e "${BLUE}No valid proof, no payment execution.${RESET}"
echo ""
echo "Every consequential money movement leaves a verifiable receipt."
echo ""
sleep 2

clear
line
echo -e "${RED}WITHOUT ACTENON${RESET}"
line
echo ""
echo -e "${WHITE}Agent attempts:${RESET}"
echo -e "  transfer £25,000 to new beneficiary;"
echo ""
sleep 1
echo -e "${RED}Outcome: WOULD_EXECUTE${RESET}"
echo -e "${RED}Side effect: payment instruction submitted${RESET}"
echo ""
sleep 2.5

clear
line
echo -e "${BLUE}WITH ACTENON${RESET}"
line
echo ""
echo -e "${WHITE}Same payment:${RESET}"
echo -e "  transfer £25,000 to new beneficiary;"
echo ""
sleep 1
echo -e "${YELLOW}Proof check: no approved intent record${RESET}"
echo ""
sleep 1
echo -e "${RED}Outcome: REFUSED${RESET}"
echo -e "${GREEN}Payment submitted: false${RESET}"
echo -e "${GREEN}Refusal receipt: emitted${RESET}"
echo ""
sleep 3

clear
line
echo -e "${GREEN}WITH VALID PROOF${RESET}"
line
echo ""
echo -e "${WHITE}Approved payment:${RESET}"
echo -e "  refund £42.00 to verified customer;"
echo ""
sleep 1
echo -e "${GREEN}Proof check: valid approval + exact amount match${RESET}"
echo -e "${GREEN}Outcome: EXECUTED ONCE${RESET}"
echo -e "${GREEN}Payment receipt: emitted and verifiable${RESET}"
echo ""
sleep 2.5

clear
line
echo -e "${WHITE}PAYMENT RECEIPTS${RESET}"
line
echo ""
echo -e "${RED}Refusal receipt${RESET}"
echo '  outcome: refused'
echo '  reason_code: NO_APPROVED_INTENT'
echo '  payment_submitted: false'
echo ""
echo -e "${GREEN}Execution receipt${RESET}"
echo '  outcome: executed'
echo '  amount: "GBP 42.00"'
echo '  receipt_digest: sha256:8f2a19...'
echo ""
sleep 2.5

clear
echo ""
echo -e "${WHITE}ACTENON / FINTECH${RESET}"
echo -e "${BLUE}No valid proof, no payment execution.${RESET}"
echo ""
echo -e "${GREEN}Unapproved payment refused.${RESET}"
echo -e "${GREEN}Approved payment executed once.${RESET}"
echo -e "${GREEN}Receipt emitted.${RESET}"
echo ""
sleep 2
