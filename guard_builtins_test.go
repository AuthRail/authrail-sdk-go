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

// The exact reviewed target is processed; invalid or unsupported formats stay
// unchanged, and application code cannot replace a reserved implementation.
func TestSensitiveDataBuiltinProcessing(t *testing.T) {
	cases := []struct {
		text        string
		email, card bool
	}{
		{"Contact jane.doe+test@example.co.uk.", true, false}, {"a@EXAMPLE.COM", true, false},
		{"a..b@example.com", false, false}, {"a.@example.com", false, false}, {"a@example.c", false, false},
		{"_name@example.com", false, false}, {"name@example.com_", false, false},
		{strings.Repeat("a", 65) + "@example.com", false, false},
		{"Card 4111 1111 1111 1111.", false, true}, {"378282246310005", false, true},
		{"4242-4242-4242-4242", false, true}, {"4111111111111112", false, false},
		{"0000000000000000", false, false}, {"41111111111111111111", false, false},
		{"４１１１１１１１１１１１１１１１", false, false}, {"ordinary reply", false, false},
	}
	handlers, err := registeredGuardHandlers(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range cases {
		if emailAddressV1(sample.text) != sample.email || paymentCardV1(sample.text) != sample.card {
			t.Fatalf("sensitive-data classification mismatch for %q", sample.text)
		}
		for _, handler := range handlers {
			expected := sample.text
			if handler.ID == emailRedactionHandlerID && sample.email || handler.ID == paymentCardRedactionHandlerID && sample.card {
				expected = "[REDACTED]"
			}
			if handler.ID == fieldWithholdingHandlerID {
				expected = "[WITHHELD]"
			}
			output, err := handler.Process(context.Background(), sample.text)
			if err != nil || output != expected {
				t.Fatal("reserved processor did not apply the reviewed whole-field transformation")
			}
		}
	}
	for _, id := range []string{emailRedactionHandlerID, paymentCardRedactionHandlerID, fieldWithholdingHandlerID} {
		if _, err := registeredGuardHandlers([]GuardHandler{{ID: id, Version: strings.Repeat("f", 64), Kind: "sanitize", Process: func(_ context.Context, text string) (string, error) { return text, nil }}}); err == nil {
			t.Fatal("reserved sensitive-data processor was replaced")
		}
	}
}

func TestSensitiveDataPlanBindsExactWholeFieldOutput(t *testing.T) {
	for _, example := range []struct{ id, version, input, output string }{
		{emailRedactionHandlerID, emailRedactionHandlerVersion, "reply to jane@example.com", "[REDACTED]"},
		{paymentCardRedactionHandlerID, paymentCardRedactionHandlerVersion, "4111 1111 1111 1111", "[REDACTED]"},
		{fieldWithholdingHandlerID, fieldWithholdingHandlerVersion, "arbitrary private content", "[WITHHELD]"},
	} {
		t.Run(example.id, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				phase := r.URL.Query().Get("phase")
				root := "arguments"
				if phase == "tool_result" {
					root = "result"
				}
				responseJSON(w, 200, guardPlan{FormatVersion: 1, OperationVersionID: enforceOperation().VersionID, Phase: phase, BundleID: testPermitID, Sequence: 1, Coverage: "evaluated", Requirements: []GuardRequirement{{RailVersionID: testActionID, RuleID: "protect", Kind: "sanitize", HandlerID: example.id, HandlerVersion: example.version, Target: GuardTarget{Root: root, Path: []string{"text"}}}}})
			}))
			defer server.Close()
			client, err := NewClient(testConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(map[string]any{"text": example.input, "kept": true})
			for _, phase := range []string{"tool_call", "tool_result"} {
				call := Call{OperationVersionID: enforceOperation().VersionID, Arguments: raw}
				processed, result, err := client.processGuardPhase(context.Background(), call, phase, raw)
				if err != nil {
					t.Fatal(err)
				}
				output := processed.Arguments
				if phase == "tool_result" {
					output = result
				}
				var value map[string]any
				if json.Unmarshal(output, &value) != nil || value["text"] != example.output || value["kept"] != true {
					t.Fatal("processed plan released the wrong field value")
				}
				if len(processed.GuardEvidence) != 1 || processed.GuardEvidence[0].InputSHA256 != guardStringDigest(example.input) || processed.GuardEvidence[0].OutputSHA256 != guardStringDigest(example.output) {
					t.Fatal("processing proof lost exact input/output binding")
				}
			}
		})
	}
}
