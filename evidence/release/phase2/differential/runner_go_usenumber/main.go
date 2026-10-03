// Phase-2 VARIANT of ../../differential/runner_go/main.go. Only change: context.json is decoded with
// json.Decoder.UseNumber, so the edge's declared numeric constraints reach the SDK as json.Number (exact
// integers) instead of float64. The unmodified runner's results are reported separately.
// Go SDK runner. argv: corpus out.jsonl label
// Uses the module version selected in go.mod (fetched through the Go proxy),
// never a local replace. Raw bytes go through the SDK's own VerifyJSON.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

type caseT struct {
	ID  string `json:"id"`
	Alg string `json:"alg"`
}

func main() {
	corpus, outPath, label := os.Args[1], os.Args[2], os.Args[3]
	var manifest struct{ Cases []caseT `json:"cases"` }
	mustJSON(filepath.Join(corpus, "manifest.json"), &manifest)
	var trust struct {
		HMAC struct {
			KeyID  string `json:"key_id"`
			Secret string `json:"secret_utf8"`
		} `json:"hmac"`
	}
	mustJSON(filepath.Join(corpus, "trust.json"), &trust)
	trustRaw, _ := os.ReadFile(filepath.Join(corpus, "trust.json"))
	var trustAny map[string]json.RawMessage
	_ = json.Unmarshal(trustRaw, &trustAny)
	hmac := verifier.HMACSHA256Verifier{Secret: []byte(trust.HMAC.Secret), KeyID: trust.HMAC.KeyID, Algorithm: "HS256"}
	ed := edVerifier(trustAny["ed25519"])
	out, _ := os.Create(outPath)
	defer out.Close()
	for _, c := range manifest.Cases {
		d := filepath.Join(corpus, c.ID)
		var ctx map[string]any
		mustJSONNumber(filepath.Join(d, "context.json"), &ctx)
		row := map[string]any{"id": c.ID}
		var sv verifier.SignatureVerifier = hmac
		if c.Alg == "EdDSA" {
			if ed == nil {
				row["outcome"], row["code"] = "UNSUPPORTED", "NO_EDDSA_VERIFIER"
				writeRow(out, row)
				continue
			}
			sv = ed
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					row["outcome"], row["code"] = "REFUSE", fmt.Sprintf("PANIC:%v", r)
				}
			}()
			skewMs, _ := ctx["clock_skew_ms"].(json.Number).Int64()
			skew := time.Duration(skewMs) * time.Millisecond
			v := verifier.NewVerifier(sv, verifier.WithClockSkewTolerance(skew))
			intentRaw, _ := os.ReadFile(filepath.Join(d, "intent.json"))
			pccbRaw, _ := os.ReadFile(filepath.Join(d, "pccb.json"))
			vc, err := buildContext(ctx)
			if err == nil {
				_, err = v.VerifyJSON(intentRaw, pccbRaw, vc)
			}
			if err != nil {
				row["outcome"], row["code"] = "REFUSE", errCode(err)
			} else {
				row["outcome"], row["code"] = "ACCEPT", nil
			}
		}()
		writeRow(out, row)
	}
	fmt.Printf("%s: %d cases -> %s\n", label, len(manifest.Cases), outPath)
}

func errCode(err error) string {
	if ve, ok := err.(*verifier.VerificationError); ok {
		return string(ve.Code)
	}
	return fmt.Sprintf("%T", err)
}

func buildContext(raw map[string]any) (vc verifier.VerificationContext, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("context: %v", r)
		}
	}()
	aud := raw["audience"].(map[string]any)
	now, err := time.Parse(time.RFC3339Nano, raw["now"].(string))
	if err != nil {
		return vc, err
	}
	caps := []string{}
	for _, c := range raw["scope_capabilities"].([]any) {
		caps = append(caps, c.(string))
	}
	sels := []map[string]any{}
	for _, s := range raw["resource_selectors"].([]any) {
		sels = append(sels, s.(map[string]any))
	}
	return verifier.VerificationContext{
		RequestID: raw["request_id"].(string),
		Audience:  verifier.AudienceRef{Type: aud["type"].(string), ID: aud["id"].(string)},
		Now:       now, ScopeCapabilities: caps,
		ParameterConstraints: raw["parameter_constraints"].(map[string]any),
		ResourceSelectors:    sels,
	}, nil
}

func mustJSON(path string, v any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		panic(err)
	}
}

func mustJSONNumber(path string, v any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		panic(err)
	}
}

func writeRow(out *os.File, row map[string]any) {
	b, _ := json.Marshal(row)
	out.Write(append(b, '\n'))
}
