// Protected edge (verifier only): github.com/Actenon/sdk-go v1.1.0 as a consumer installs it, verifying
// Permit-minted EdDSA proofs through VerifyJSON (raw bytes, strict parse). Same arguments and output as
// evidence/release/phase2/e2e/ts_edge.mjs:
//
//	go_edge PROOF JWK LABEL [--audience-id ID] [--capabilities a,b] [--mutate-amount N]
//	        [--param-constraints JSON] [--resource-selectors JSON] [--revocation-db PATH]
//
// --revocation-db: Permit's SQLite state store, read-only, mirroring
// actenon_permit.revocation.StoreRevocationChecker (walk the parent chain; revoked/expired/past
// expires_at => revoked; unknown grant or wrong issuer => error => AUTHORITY_REVOKED).
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Actenon/sdk-go/verifier"
	_ "modernc.org/sqlite"
)

func decode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // edge declarations must reach the SDK JSON-exact (see VerificationContext docs)
	return dec.Decode(v)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func main() {
	args := os.Args[1:]
	proofFile, jwkFile, label := args[0], args[1], args[2]
	opts := map[string]string{"--audience-id": "actenon-permit-gateway", "--capabilities": "payments.refund",
		"--param-constraints": "{}", "--resource-selectors": "[]"}
	for i := 3; i+1 < len(args); i += 2 {
		opts[args[i]] = args[i+1]
	}
	raw, err := os.ReadFile(proofFile)
	must(err)
	var doc map[string]any
	must(decode(raw, &doc))
	intent := doc["intent"].(map[string]any)
	if m, ok := opts["--mutate-amount"]; ok {
		intent["action"].(map[string]any)["parameters"].(map[string]any)["amount_minor"] = json.Number(m)
	}
	intentRaw, err := json.Marshal(intent)
	must(err)
	pccbRaw, err := json.Marshal(doc["pccb"])
	must(err)
	jwk, err := os.ReadFile(jwkFile)
	must(err)
	ed, err := verifier.NewEd25519VerifierFromJWKs(jwk)
	must(err)

	var options []verifier.VerifierOption
	if db, ok := opts["--revocation-db"]; ok {
		options = append(options, verifier.WithRevocationChecker(func(pccb verifier.PCCB, _ verifier.VerificationContext) (bool, error) {
			authority, _ := pccb.Extensions["authority"].(map[string]any)
			grantID, _ := authority["grant_id"].(string)
			if authority == nil || authority["issuer"] != "service:actenon-permit" || grantID == "" {
				return false, errors.New("not a Permit authority reference")
			}
			conn, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
			if err != nil {
				return false, err
			}
			defer conn.Close()
			seen := map[string]bool{}
			for current := grantID; current != ""; {
				if seen[current] || len(seen) >= 64 {
					return false, errors.New("grant ancestry cyclic or too deep")
				}
				seen[current] = true
				var body string
				if err := conn.QueryRow("SELECT body FROM grants WHERE id = ?", current).Scan(&body); err != nil {
					return false, fmt.Errorf("grant %s unknown: %w", current, err)
				}
				var grant map[string]any
				if err := json.Unmarshal([]byte(body), &grant); err != nil {
					return false, err
				}
				expires, err := time.Parse(time.RFC3339Nano, fmt.Sprint(grant["expires_at"]))
				if err != nil {
					return false, err
				}
				if grant["status"] == "revoked" || grant["status"] == "expired" || !expires.After(time.Now()) {
					return false, nil
				}
				parent, _ := grant["parent_grant_id"].(string)
				current = parent
			}
			return true, nil
		}))
	}
	var constraints map[string]any
	must(decode([]byte(opts["--param-constraints"]), &constraints))
	var selectors []map[string]any
	must(decode([]byte(opts["--resource-selectors"]), &selectors))
	var capabilities []string
	for _, c := range strings.Split(opts["--capabilities"], ",") {
		if c != "" {
			capabilities = append(capabilities, c)
		}
	}
	ctx := verifier.VerificationContext{
		RequestID:            "req-go-" + label,
		Audience:             verifier.AudienceRef{Type: "service", ID: opts["--audience-id"]},
		Now:                  time.Now(),
		ScopeCapabilities:    capabilities,
		ParameterConstraints: constraints,
		ResourceSelectors:    selectors,
	}
	_, err = verifier.NewVerifier(ed, options...).VerifyJSON(intentRaw, pccbRaw, ctx)
	out := map[string]any{"label": label, "edge": "go", "outcome": "verified"}
	if err != nil {
		var verr *verifier.VerificationError
		if !errors.As(err, &verr) {
			must(err)
		}
		out = map[string]any{"label": label, "edge": "go", "outcome": "refused", "reason_code": string(verr.Code)}
	}
	line, _ := json.Marshal(out)
	fmt.Println(string(line))
}
