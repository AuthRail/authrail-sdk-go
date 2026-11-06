package authrail

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// A contextual request must disclose only the selected fields and authenticate
// that material, phase and caller independently of the ordinary execution proof.
func TestContextualAutomaticRequestsBindSelectedMaterialAndIdentity(t *testing.T) {
	call := sampleCall()
	call.Arguments = json.RawMessage(`{"diff":"- requireAuth()\n+ allowGuest() <review>","credential":"not-selected"}`)
	const bundle = "11111111-1111-4111-8111-111111111111"
	const rail = "22222222-2222-4222-8222-222222222222"
	var phases []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testConfig("").AdapterToken {
			t.Error("local adapter credential missing")
		}
		switch r.URL.Path {
		case "/contextual-requirements":
			phase := r.URL.Query().Get("phase")
			field := GuardTarget{Root: "arguments", Path: []string{"diff"}}
			if phase == "tool_result" {
				field = GuardTarget{Root: "result", Path: []string{"classification"}}
			}
			responseJSON(w, 200, contextualPlan{FormatVersion: 1, OperationVersionID: call.OperationVersionID,
				Phase: phase, BundleID: bundle, Sequence: 1, Coverage: "evaluated",
				Requirements: []contextualRequirement{{RailVersionID: rail, Assessment: contextualAssessment{
					ID: "review_change", Phase: phase, Question: "Does this change weaken authentication?",
					Fields: []GuardTarget{field}, Answer: json.RawMessage(`{"type":"boolean"}`)}}}})
		case "/contextual-readings":
			var reading contextualRequest
			if err := json.NewDecoder(r.Body).Decode(&reading); err != nil {
				t.Error(err)
				return
			}
			phases = append(phases, reading.Phase)
			material, err := base64.RawURLEncoding.DecodeString(reading.Material)
			if err != nil || strings.Contains(string(material), "not-selected") || strings.Contains(string(material), "credential") {
				t.Error("an unselected field was disclosed")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var selected []string
			if json.Unmarshal(material, &selected) != nil {
				t.Error("material is invalid")
			}
			expected := []string{"- requireAuth()\n+ allowGuest() <review>"}
			if reading.Phase == "tool_result" {
				expected = []string{"authentication change"}
			}
			if !reflect.DeepEqual(selected, expected) {
				t.Errorf("selected material=%q", selected)
			}
			materialDigest := sha256.Sum256(material)
			attributeDigest := sha256.Sum256([]byte(`{"principalId":"staff_123","sessionId":"task_123","resourceId":null,"principalSource":"application_session","resourceSource":"not_applicable"}`))
			if reading.AttributionSHA256 != hex.EncodeToString(attributeDigest[:]) {
				t.Error("caller identity was not bound")
			}
			statement := fmt.Sprintf(`{"type":"authrail.contextual.request.v1","organisationId":%q,"deploymentId":%q,"bundleId":%q,"railVersionId":%q,"assessmentId":%q,"operationVersionId":%q,"requestId":%q,"phase":%q,"inputSha256":%q,"attributionSha256":%q,"materialSha256":%q,"keySha256":%q,"issuedAt":%d,"expiresAt":%d}`,
				testConfig("").OrganisationID, testConfig("").DeploymentID, bundle, rail, "review_change",
				call.OperationVersionID, call.RequestID, reading.Phase, reading.InputSHA256,
				reading.AttributionSHA256, hex.EncodeToString(materialDigest[:]), reading.KeySHA256,
				reading.Proof.IssuedAt, reading.Proof.ExpiresAt)
			signature, _ := base64.RawURLEncoding.DecodeString(reading.Proof.Signature)
			key := testConfig("").ExecutorPrivateKey.Public().(ed25519.PublicKey)
			if !ed25519.Verify(key, []byte(statement), signature) {
				t.Error("contextual proof does not match shared contract")
			}
			changed := strings.Replace(statement, reading.AttributionSHA256, strings.Repeat("f", 64), 1)
			if ed25519.Verify(key, []byte(changed), signature) {
				t.Error("signature allowed caller mutation")
			}
			responseJSON(w, 200, contextualFinding{Payload: "bounded-finding", KeyID: "key", Algorithm: "ECDSA_SHA_256", Signature: "signed"})
		case "/evaluate":
			var body struct {
				Phase    string              `json:"phase"`
				Findings []contextualFinding `json:"contextualFindings"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body.Findings) != 1 || body.Findings[0].Payload != "bounded-finding" {
				t.Error("finding was not carried to the evaluator")
			}
			responseJSON(w, 200, Decision{RequestID: call.RequestID, Mode: "observe", Coverage: "evaluated", Outcome: "allow"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"tool_call", "tool_result"} {
		var result json.RawMessage
		if phase == "tool_result" {
			result = json.RawMessage(`{"classification":"authentication change","credential":"not-selected"}`)
		}
		if _, err := client.evaluate(context.Background(), call, phase, "observe", result); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(phases, []string{"tool_call", "tool_result"}) {
		t.Fatalf("missing phase checks: %v", phases)
	}
}

func TestContextualMissingOrUnprocessedMaterialNeverDiscloses(t *testing.T) {
	for _, scenario := range []string{"disabled", "missing", "unprocessed", "oversized", "uncovered", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/contextual-requirements" {
					posts++
					http.Error(w, "unexpected disclosure", 500)
					return
				}
				plan := contextualPlan{FormatVersion: 1, OperationVersionID: sampleCall().OperationVersionID,
					Phase: "tool_call", BundleID: "11111111-1111-4111-8111-111111111111", Sequence: 1,
					Coverage: "evaluated", Requirements: []contextualRequirement{}}
				if scenario != "disabled" && scenario != "uncovered" && scenario != "unavailable" {
					plan.Requirements = []contextualRequirement{{RailVersionID: plan.BundleID,
						Assessment: contextualAssessment{ID: "check_text", Phase: "tool_call", Fields: []GuardTarget{{Root: "arguments", Path: []string{"text"}}}}}}
				}
				plan.DisclosureProcessing = scenario == "unprocessed"
				if scenario == "uncovered" || scenario == "unavailable" {
					plan.Coverage, plan.BundleID = scenario, ""
				}
				responseJSON(w, 200, plan)
			}))
			defer server.Close()
			client, err := NewClient(testConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			call := sampleCall()
			if scenario != "missing" {
				text := "selected text"
				if scenario == "oversized" {
					text = strings.Repeat("x", 16385)
				}
				call.Arguments, _ = json.Marshal(map[string]string{"text": text})
			}
			findings, err := client.readContextual(context.Background(), call, "tool_call", nil)
			if err != nil || len(findings) != 0 || posts != 0 {
				t.Fatalf("unsafe disclosure: posts=%d findings=%v err=%v", posts, findings, err)
			}
		})
	}
}

func TestContextualDisclosureRequiresEveryExactProcessedField(t *testing.T) {
	const bundle = "11111111-1111-4111-8111-111111111111"
	requirement := GuardRequirement{RailVersionID: bundle, RuleID: "remove_credentials", Kind: "sanitize",
		HandlerID: "credential_filter", HandlerVersion: strings.Repeat("a", 64), Target: GuardTarget{Root: "arguments", Path: []string{"text"}}}
	for _, scenario := range []string{"processed", "old_bundle", "unrelated", "changed_text", "duplicate", "missing_second"} {
		t.Run(scenario, func(t *testing.T) {
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/contextual-readings" {
					posts++
					responseJSON(w, 200,
						contextualFinding{Payload: "bounded", KeyID: "key", Algorithm: "ECDSA_SHA_256", Signature: "signature"})
					return
				}
				plan := contextualPlan{FormatVersion: 1, OperationVersionID: sampleCall().OperationVersionID, Phase: "tool_call",
					BundleID: bundle, Coverage: "evaluated", Sequence: 1, DisclosureProcessing: true,
					DisclosureRequirements: []GuardRequirement{requirement}, Requirements: []contextualRequirement{{RailVersionID: bundle,
						Assessment: contextualAssessment{ID: "check_text", Phase: "tool_call", Fields: []GuardTarget{requirement.Target}}}}}
				if scenario == "missing_second" {
					other := requirement
					other.HandlerID = "second_filter"
					plan.DisclosureRequirements = append(plan.DisclosureRequirements, other)
				}
				responseJSON(w, 200, plan)
			}))
			defer server.Close()
			client, err := NewClient(testConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			call := sampleCall()
			call.Arguments = json.RawMessage(`{"text":"permitted text"}`)
			evidence := GuardEvidence{Phase: "tool_call", BundleID: bundle, Kind: requirement.Kind, HandlerID: requirement.HandlerID,
				HandlerVersion: requirement.HandlerVersion, Target: requirement.Target, OutputSHA256: guardStringDigest("permitted text")}
			switch scenario {
			case "old_bundle":
				evidence.BundleID = "22222222-2222-4222-8222-222222222222"
			case "unrelated":
				evidence.Target.Path = []string{"other"}
			case "changed_text":
				evidence.OutputSHA256 = guardStringDigest("earlier text")
			}
			call.GuardEvidence = []GuardEvidence{evidence}
			if scenario == "duplicate" {
				call.GuardEvidence = append(call.GuardEvidence, evidence)
			}
			findings, err := client.readContextual(context.Background(), call, "tool_call", nil)
			expected := 0
			if scenario == "processed" {
				expected = 1
			}
			if err != nil || posts != expected || len(findings) != expected {
				t.Fatalf("disclosure=%d findings=%d err=%v", posts, len(findings), err)
			}
		})
	}
}

func TestEmptyResultRemainsInSignedInput(t *testing.T) {
	call := sampleCall()
	encoded, err := encodeIdentityInput(call, "tool_result", json.RawMessage(`{}`))
	if err != nil || string(encoded) != `{"arguments":{"amount":101},"result":{}}` {
		t.Fatalf("empty result missing from checked input: %s %v", encoded, err)
	}
}
