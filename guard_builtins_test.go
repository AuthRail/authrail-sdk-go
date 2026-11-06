package authrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Pin boundaries so a longer identifier is not silently treated as a supported
// credential, while recognized credentials cannot escape local redaction.
func TestCredentialFormatV1Boundaries(t *testing.T) {
	github := "ghp_" + strings.Repeat("a", 36)
	cases := []struct {
		name, text string
		found      bool
	}{
		{"ordinary text", "Send the public invoice status", false},
		{"short key", "ghp_" + strings.Repeat("a", 35), false},
		{"longer token", github + "a", false},
		{"identifier prefix", "_" + github, false},
		{"identifier suffix", github + "_", false},
		{"bounded token", "token=(" + github + ")", true},
		{"unicode boundary", "é" + github + "é", true},
		{"fine grained", "github_pat_" + strings.Repeat("A_", 41), true},
		{"aws", "ASIA" + strings.Repeat("9", 16), true},
		{"aws lowercase", "AKIA" + strings.Repeat("a", 16), false},
		{"later token", "_" + github + " then " + github, true},
	}
	for _, prefix := range []string{"gho_", "ghu_", "ghs_", "ghr_"} {
		cases = append(cases, struct {
			name, text string
			found      bool
		}{prefix, prefix + strings.Repeat("7", 36), true})
	}
	for _, kind := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"} {
		cases = append(cases, struct {
			name, text string
			found      bool
		}{kind, "before\n-----BEGIN " + kind + "-----\nafter", true})
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			if credentialFormatV1(example.text) != example.found {
				t.Fatal("credential classification differs from pinned format")
			}
			output, err := credentialRedactionHandler().Process(context.Background(), example.text)
			expected := example.text
			if example.found {
				expected = "[REDACTED]"
			}
			if err != nil || output != expected {
				t.Fatal("credential processing did not preserve the reviewed whole-field behavior")
			}
		})
	}
}

func TestBuiltinGuardCannotBeReplaced(t *testing.T) {
	for _, kind := range []string{"sanitize", "transform"} {
		_, err := registeredGuardHandlers([]GuardHandler{{ID: credentialRedactionHandlerID,
			Version: strings.Repeat("a", 64), Kind: kind,
			Process: func(_ context.Context, text string) (string, error) { return text, nil }}})
		if err == nil {
			t.Fatal("application handler replaced reserved built-in identity")
		}
	}
}

// Exercise the default Enforce path: no customer handler registration may be
// needed, and neither the callback nor the caller may receive the raw field.
func TestEnforceBuiltinRedactsCallAndResultWithoutRegistration(t *testing.T) {
	credential := "ghp_" + strings.Repeat("x", 36)
	plans, checks := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/contextual-requirements":
			http.NotFound(w, r)
		case "/guard-requirements":
			plans++
			phase := r.URL.Query().Get("phase")
			root := "arguments"
			if phase == "tool_result" {
				root = "result"
			}
			responseJSON(w, 200, guardPlan{FormatVersion: 1, OperationVersionID: enforceOperation().VersionID,
				Phase: phase, BundleID: testPermitID, Sequence: 1, Coverage: "evaluated",
				Requirements: []GuardRequirement{{RailVersionID: testActionID, RuleID: "redact",
					Kind: "sanitize", HandlerID: credentialRedactionHandlerID, HandlerVersion: credentialRedactionHandlerVersion,
					Target: GuardTarget{Root: root, Path: []string{"text"}}}}})
		case "/evaluate":
			checks++
			var request struct {
				RequestID string          `json:"requestId"`
				Phase     string          `json:"phase"`
				Arguments map[string]any  `json:"arguments"`
				Result    map[string]any  `json:"result"`
				Evidence  []GuardEvidence `json:"guardEvidence"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Arguments["text"] != "[REDACTED]" {
				t.Error("raw argument reached evaluation")
			}
			if request.Phase == "tool_result" && request.Result["text"] != "[REDACTED]" {
				t.Error("raw result reached evaluation")
			}
			for _, evidence := range request.Evidence {
				if evidence.HandlerID != credentialRedactionHandlerID || evidence.HandlerVersion != credentialRedactionHandlerVersion ||
					evidence.InputSHA256 != guardStringDigest(credential) || evidence.OutputSHA256 != guardStringDigest("[REDACTED]") {
					t.Error("built-in evidence did not bind the exact processing")
				}
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce", "enforced": false,
				"coverage": "evaluated", "outcome": "allow", "recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
		case "/execution-receipts":
			var receipt struct {
				Event string `json:"event"`
			}
			_ = json.NewDecoder(r.Body).Decode(&receipt)
			state := "succeeded"
			if receipt.Event == "started" {
				state = "executing"
			}
			responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": state, "replayed": false})
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"text": credential, "kept": true}
	result, _, _, err := Enforce(context.Background(), client, enforceOperation(), input,
		func(_ context.Context, processed map[string]any, _ ExecutionContext) (map[string]any, error) {
			if processed["text"] != "[REDACTED]" || processed["kept"] != true {
				t.Error("callback did not receive only the reviewed transformation")
			}
			return map[string]any{"text": credential}, nil
		})
	if err != nil || plans != 2 || checks != 2 || result["text"] != "[REDACTED]" || input["text"] != credential {
		t.Fatalf("automatic built-in processing failed: %v, plans=%d checks=%d", err, plans, checks)
	}
}
