package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/actenon/sdk-go/verifier"
)

type requestBody struct {
	Intent json.RawMessage `json:"intent"`
	PCCB   json.RawMessage `json:"pccb"`
}

func main() {
	localVerifier := verifier.BuildLocalProofVerifier()
	sdk := verifier.NewVerifier(localVerifier)

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{
			"ok":       true,
			"endpoint": "/protected-resource",
		})
	})

	http.HandleFunc("/protected-resource", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeJSON(writer, http.StatusNotFound, map[string]any{
				"ok":    false,
				"error": "not_found",
			})
			return
		}

		intentPayload, pccbPayload, err := loadRequestArtifacts(request)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"error":   "invalid_request",
				"message": err.Error(),
			})
			return
		}

		verified, err := sdk.VerifyJSON(intentPayload, pccbPayload, verifier.VerificationContext{
			RequestID:         fmt.Sprintf("go-example-%d", time.Now().UnixNano()),
			Audience:          verifier.AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
			Now:               time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			ScopeCapabilities: []string{"protected_resource.read"},
			ParameterConstraints: map[string]any{
				"exact_message": "portable hello world",
			},
			ResourceSelectors: []map[string]any{
				{"resource_id": "hello_resource_demo_001"},
			},
		})
		if err != nil {
			var verificationErr *verifier.VerificationError
			if errors.As(err, &verificationErr) {
				writeJSON(writer, http.StatusForbidden, map[string]any{
					"ok":       false,
					"category": "proof",
					"code":     verificationErr.Code,
					"message":  verificationErr.Message,
				})
				return
			}
			writeJSON(writer, http.StatusInternalServerError, map[string]any{
				"ok":    false,
				"error": "internal_error",
			})
			return
		}

		message, _ := verified.Intent.Action.Parameters["message"].(string)
		writeJSON(writer, http.StatusOK, map[string]any{
			"ok":      true,
			"pccb_id": verified.PCCB.PCCBID,
			"message": message,
		})
	})

	log.Printf("Protected endpoint example listening on http://127.0.0.1:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func loadRequestArtifacts(request *http.Request) ([]byte, []byte, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return loadFixtures()
	}

	var envelope requestBody
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, nil, err
	}
	if len(envelope.Intent) == 0 || len(envelope.PCCB) == 0 {
		return nil, nil, errors.New("request body must contain intent and pccb JSON payloads")
	}
	return envelope.Intent, envelope.PCCB, nil
}

func loadFixtures() ([]byte, []byte, error) {
	root := filepath.Join("fixtures", "portable-local-proof")
	intent, err := os.ReadFile(filepath.Join(root, "action_intent.json"))
	if err != nil {
		return nil, nil, err
	}
	pccb, err := os.ReadFile(filepath.Join(root, "pccb.json"))
	if err != nil {
		return nil, nil, err
	}
	return intent, pccb, nil
}

func writeJSON(writer http.ResponseWriter, status int, payload map[string]any) {
	writer.Header().Set("content-type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}
