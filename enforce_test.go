package authrail

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testActionID = "11111111-1111-4111-8111-111111111111"
const testApprovalID = "22222222-2222-4222-8222-222222222222"
const testPermitID = "33333333-3333-4333-8333-333333333333"

func enforceFixture(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	client, err := NewClient(Config{SidecarURL: server.URL,
		AdapterToken:       "adapter-token-123456789012345678901234567890",
		OrganisationID:     "44444444-4444-4444-8444-444444444444",
		DeploymentID:       "55555555-5555-4555-8555-555555555555",
		ExecutorPrivateKey: private})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server.Close
}

func enforceOperation() Operation {
	return Operation{VersionID: "66666666-6666-4666-8666-666666666666",
		ActionKey: "invoice-123", PrincipalID: "staff-1", SessionID: "task-1",
		PrincipalSource: "application_session", ResourceSource: "application_lookup",
		ResourceID: "invoice-123"}
}

func responseJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func TestEnforceRetainsReceiptsAndChecksResult(t *testing.T) {
	const trace = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	var paths []string
	var requestID string
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("traceparent") != trace {
			t.Error("trace context was not propagated")
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/evaluate":
			var request struct {
				RequestID     string        `json:"requestId"`
				Phase         string        `json:"phase"`
				IdentityProof identityProof `json:"identityProof"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.IdentityProof.Signature == "" {
				t.Error("unsigned check")
			}
			if requestID == "" {
				requestID = request.RequestID
			} else if requestID != request.RequestID {
				t.Error("call/result ID mismatch")
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce",
				"enforced": false, "coverage": "evaluated", "outcome": "allow",
				"recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
		case "/execution-receipts":
			var receipt struct {
				ActionID    string        `json:"actionId"`
				AttemptID   string        `json:"attemptId"`
				Event       string        `json:"event"`
				ProviderKey string        `json:"providerIdempotencyKey"`
				Proof       identityProof `json:"proof"`
			}
			if json.NewDecoder(r.Body).Decode(&receipt) != nil || receipt.Proof.Signature == "" ||
				receipt.AttemptID != requestID || receipt.ProviderKey != "ar-"+testActionID ||
				r.Header.Get("Idempotency-Key") != testActionID+":"+requestID+":"+receipt.Event {
				t.Error("receipt binding mismatch")
			}
			responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": map[string]string{"started": "executing", "succeeded": "succeeded"}[receipt.Event], "replayed": false})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	defer closeServer()
	called := 0
	operation := enforceOperation()
	operation.Traceparent = trace
	result, callDecision, resultDecision, err := Enforce(context.Background(), client, operation,
		map[string]any{"invoiceId": "invoice-123"}, func(_ context.Context, _ map[string]any, recovery ExecutionContext) (map[string]any, error) {
			called++
			if recovery.ProviderIdempotencyKey != "ar-"+testActionID {
				t.Error("provider key mismatch")
			}
			return map[string]any{"ok": true}, nil
		})
	if err != nil || called != 1 || result["ok"] != true || callDecision == nil || resultDecision == nil ||
		!reflect.DeepEqual(paths, []string{"/evaluate", "/execution-receipts", "/execution-receipts", "/evaluate"}) {
		t.Fatalf("unexpected enforcement result: %v %v %v", err, called, paths)
	}
}

func TestEnforceBlocksUnprovenStartAndUnknownOutcome(t *testing.T) {
	for _, lostStart := range []bool{true, false} {
		t.Run(map[bool]string{true: "lost start", false: "provider unknown"}[lostStart], func(t *testing.T) {
			called := 0
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/evaluate" {
					var request struct {
						RequestID string `json:"requestId"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce",
						"enforced": false, "coverage": "evaluated", "outcome": "allow",
						"recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
					return
				}
				if lostStart {
					w.WriteHeader(503)
					return
				}
				responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": "executing", "replayed": false})
			})
			defer closeServer()
			_, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{},
				func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
					called++
					return nil, errors.New("provider timed out")
				})
			if lostStart {
				var blocked *EnforceBlockedError
				if !errors.As(err, &blocked) || called != 0 {
					t.Fatalf("start should block: %v, %d", err, called)
				}
			} else {
				var unknown *OutcomeUnknownError
				if !errors.As(err, &unknown) || called != 1 || unknown.Recovery.ProviderIdempotencyKey != "ar-"+testActionID {
					t.Fatalf("unknown outcome lost: %v, %d", err, called)
				}
			}
		})
	}
}

func TestEnforceApprovalClaimIsSingleUse(t *testing.T) {
	called := 0
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/evaluate":
			var request struct {
				RequestID string `json:"requestId"`
				Phase     string `json:"phase"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			outcome := "approval_required"
			if request.Phase == "tool_result" {
				outcome = "allow"
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce", "enforced": false,
				"coverage": "evaluated", "outcome": outcome, "recordingStatus": "retained",
				"reportReplayed": false, "actionId": testActionID, "approvalRequestId": testApprovalID})
		case "/approval-permits/claim":
			responseJSON(w, 201, map[string]any{"permitId": testPermitID, "actionId": testActionID,
				"expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
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
		}
	})
	defer closeServer()
	operation := enforceOperation()
	operation.ReviewSummary = &ReviewSummary{Title: "Pay invoice", Fields: []ReviewField{{Label: "Amount", Value: "400"}}}
	_, _, _, err := Enforce(context.Background(), client, operation, map[string]any{"amount": 400},
		func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
			called++
			return map[string]any{}, nil
		})
	var pending *ApprovalRequired
	if !errors.As(err, &pending) || called != 0 {
		t.Fatalf("approval should pause: %v", err)
	}
	_, _, err = ResumeApproval(context.Background(), pending,
		func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
			called++
			return map[string]any{"ok": true}, nil
		})
	if err != nil || called != 1 {
		t.Fatalf("approval did not resume: %v, %d", err, called)
	}
	_, _, err = ResumeApproval(context.Background(), pending,
		func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
			called++
			return map[string]any{}, nil
		})
	if err == nil || called != 1 {
		t.Fatalf("approval replay ran callback: %v, %d", err, called)
	}
}

func TestClaimAndReceiptSignServerStatements(t *testing.T) {
	var client *Client
	var captured []struct {
		path string
		body []byte
	}
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid signed request")
		}
		captured = append(captured, struct {
			path string
			body []byte
		}{r.URL.Path, body})
		if r.URL.Path == "/approval-permits/claim" {
			responseJSON(w, 201, map[string]any{"permitId": testPermitID,
				"actionId": testActionID, "expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
		} else {
			responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": "executing", "replayed": false})
		}
	})
	defer closeServer()
	call := Call{Arguments: json.RawMessage(`{"amount":400}`)}
	digest, err := callInputDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.claimApproval(context.Background(), call, &Decision{
		ActionID: testActionID, ApprovalRequestID: testApprovalID})
	if err != nil {
		t.Fatal(err)
	}
	permitID := testPermitID
	_, err = client.reportExecution(context.Background(), Recovery{
		ActionID: testActionID, AttemptID: testApprovalID, PermitID: &permitID,
		InputSHA256: digest, ProviderIdempotencyKey: "ar-" + testActionID}, "started", nil)
	if err != nil || len(captured) != 2 {
		t.Fatalf("signed requests missing: %v, %d", err, len(captured))
	}
	key := client.executorPrivateKey.Public().(ed25519.PublicKey)
	keyDigest := sha256.Sum256(key)
	keySHA := hex.EncodeToString(keyDigest[:])
	for _, request := range captured {
		var payload struct {
			Proof identityProof `json:"proof"`
		}
		if json.Unmarshal(request.body, &payload) != nil {
			t.Fatal("invalid signed payload")
		}
		var statement string
		switch request.path {
		case "/approval-permits/claim":
			statement = fmt.Sprintf(`{"type":"authrail.approval.claim.v1","organisationId":"%s","deploymentId":"%s","approvalRequestId":"%s","actionId":"%s","inputSha256":"%s","keySha256":"%s","issuedAt":%d,"expiresAt":%d}`,
				client.organisationID, client.deploymentID, testApprovalID, testActionID, digest, keySHA,
				payload.Proof.IssuedAt, payload.Proof.ExpiresAt)
		case "/execution-receipts":
			statement = fmt.Sprintf(`{"type":"authrail.execution.receipt.v1","organisationId":"%s","deploymentId":"%s","actionId":"%s","attemptId":"%s","permitId":"%s","event":"started","inputSha256":"%s","providerIdempotencyKey":"ar-%s","providerReference":null,"keySha256":"%s","issuedAt":%d,"expiresAt":%d}`,
				client.organisationID, client.deploymentID, testActionID, testApprovalID, testPermitID,
				digest, testActionID, keySHA, payload.Proof.IssuedAt, payload.Proof.ExpiresAt)
		default:
			t.Fatalf("unexpected request %s", request.path)
		}
		signature, err := base64.RawURLEncoding.DecodeString(payload.Proof.Signature)
		if err != nil || !ed25519.Verify(key, []byte(statement), signature) {
			t.Fatalf("%s signature does not match the server statement", request.path)
		}
	}
}

func TestSharedDecisionConformance(t *testing.T) {
	data, err := os.ReadFile("conformance/v1/decision-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int `json:"formatVersion"`
		Cases         []struct {
			Name            string `json:"name"`
			Mode            string `json:"mode"`
			Coverage        string `json:"coverage"`
			Outcome         string `json:"outcome"`
			RecordingStatus string `json:"recordingStatus"`
			ReportReplayed  *bool  `json:"reportReplayed"`
			EffectRuns      bool   `json:"effectRuns"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.FormatVersion != 1 || len(corpus.Cases) < 8 {
		t.Fatal("invalid conformance corpus")
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			called := 0
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/evaluate" {
					var request struct {
						RequestID string `json:"requestId"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					responseJSON(w, 200, map[string]any{"requestId": request.RequestID,
						"mode": fixture.Mode, "coverage": fixture.Coverage, "outcome": fixture.Outcome,
						"enforced": false, "recordingStatus": fixture.RecordingStatus,
						"reportReplayed": fixture.ReportReplayed, "actionId": testActionID})
					return
				}
				var receipt struct {
					Event string `json:"event"`
				}
				_ = json.NewDecoder(r.Body).Decode(&receipt)
				state := "succeeded"
				if receipt.Event == "started" {
					state = "executing"
				}
				responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": state, "replayed": false})
			})
			defer closeServer()
			_, _, _, _ = Enforce(context.Background(), client, enforceOperation(), map[string]any{},
				func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
					called++
					return map[string]any{}, nil
				})
			if (called == 1) != fixture.EffectRuns {
				t.Fatalf("effect runs=%v, expected %v", called == 1, fixture.EffectRuns)
			}
		})
	}
}

func TestSharedCanonicalInput(t *testing.T) {
	data, err := os.ReadFile("conformance/v1/canonical-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int `json:"formatVersion"`
		Cases         []struct {
			Name            string              `json:"name"`
			Phase           string              `json:"phase"`
			Arguments       json.RawMessage     `json:"arguments"`
			Result          json.RawMessage     `json:"result"`
			FactResolutions []FactResolution    `json:"factResolutions"`
			Trajectory      *TrajectorySnapshot `json:"trajectory"`
			CanonicalInput  string              `json:"canonicalInput"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.FormatVersion != 1 {
		t.Fatal("invalid canonical corpus")
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			encoded, err := encodeIdentityInput(Call{Arguments: fixture.Arguments,
				FactResolutions: fixture.FactResolutions, Trajectory: fixture.Trajectory},
				fixture.Phase, fixture.Result)
			if err != nil || string(encoded) != fixture.CanonicalInput {
				t.Fatalf("canonical mismatch: %v\nactual: %s\nexpected: %s", err, encoded, fixture.CanonicalInput)
			}
		})
	}
}

func TestSignedGoSidecarVector(t *testing.T) {
	data, err := os.ReadFile("conformance/v1/signed-go-evaluation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ExecutorSeedHex string `json:"executorSeedHex"`
		ActionKey       string `json:"actionKey"`
		Request         struct {
			RequestID          string          `json:"requestId"`
			OperationVersionID string          `json:"operationVersionId"`
			Phase              string          `json:"phase"`
			Arguments          json.RawMessage `json:"arguments"`
			Attribution        struct {
				PrincipalID     string `json:"principalId"`
				SessionID       string `json:"sessionId"`
				PrincipalSource string `json:"principalSource"`
				ResourceSource  string `json:"resourceSource"`
			} `json:"attribution"`
			IdentityProof identityProof `json:"identityProof"`
		} `json:"request"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(fixture.ExecutorSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{SidecarURL: "http://127.0.0.1:7078",
		AdapterToken:       "abcdefghijklmnopqrstuvwxyz012345",
		OrganisationID:     "00000000-0000-4000-8000-000000000001",
		DeploymentID:       "00000000-0000-4000-8000-000000000002",
		ExecutorPrivateKey: ed25519.NewKeyFromSeed(seed)})
	if err != nil {
		t.Fatal(err)
	}
	client.clock = func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }
	proof, err := client.signIdentityProof(Call{RequestID: fixture.Request.RequestID,
		OperationVersionID: fixture.Request.OperationVersionID, ActionKey: fixture.ActionKey,
		PrincipalID:     fixture.Request.Attribution.PrincipalID,
		SessionID:       fixture.Request.Attribution.SessionID,
		PrincipalSource: fixture.Request.Attribution.PrincipalSource,
		ResourceSource:  fixture.Request.Attribution.ResourceSource,
		Arguments:       fixture.Request.Arguments}, fixture.Request.Phase, nil)
	if err != nil || proof != fixture.Request.IdentityProof {
		t.Fatalf("Go proof differs from sidecar vector: %+v %v", proof, err)
	}
}

func TestSharedFailureConformance(t *testing.T) {
	data, err := os.ReadFile("conformance/v1/failure-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int `json:"formatVersion"`
		Cases         []struct {
			Name       string `json:"name"`
			Stage      string `json:"stage"`
			EffectRuns bool   `json:"effectRuns"`
			Error      string `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.FormatVersion != 1 {
		t.Fatal("invalid failure corpus")
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			effects := 0
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/evaluate" {
					if fixture.Stage == "decision_unavailable" {
						w.WriteHeader(503)
						return
					}
					if fixture.Stage == "decision_malformed" {
						responseJSON(w, 200, map[string]any{})
						return
					}
					var request struct {
						RequestID string `json:"requestId"`
						Phase     string `json:"phase"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					if request.Phase == "tool_result" && fixture.Stage == "result_unavailable" {
						w.WriteHeader(503)
						return
					}
					outcome := "allow"
					if request.Phase == "tool_result" && fixture.Stage == "result_denied" {
						outcome = "deny"
					}
					responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce",
						"enforced": false, "coverage": "evaluated", "outcome": outcome,
						"recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
					return
				}
				var receipt struct {
					Event string `json:"event"`
				}
				_ = json.NewDecoder(r.Body).Decode(&receipt)
				if receipt.Event == "started" && fixture.Stage == "start_unavailable" ||
					receipt.Event == "succeeded" && fixture.Stage == "completion_unavailable" {
					w.WriteHeader(503)
					return
				}
				state := "succeeded"
				if receipt.Event == "started" {
					state = "executing"
				}
				replayed := receipt.Event == "started" && fixture.Stage == "start_replayed"
				responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": state, "replayed": replayed})
			})
			defer closeServer()
			_, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{},
				func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
					effects++
					if fixture.Stage == "provider_unknown" {
						return nil, errors.New("provider timeout")
					}
					return map[string]any{"ok": true}, nil
				})
			if (effects == 1) != fixture.EffectRuns {
				t.Fatalf("effect count %d differs from fixture", effects)
			}
			var blocked *EnforceBlockedError
			var unknown *OutcomeUnknownError
			switch fixture.Error {
			case "outcome_unknown":
				if !errors.As(err, &unknown) {
					t.Fatalf("expected unknown outcome: %v", err)
				}
			case "blocked_call":
				if !errors.As(err, &blocked) || blocked.Phase != "tool_call" || blocked.EffectMayHaveOccurred {
					t.Fatalf("expected call block: %v", err)
				}
			case "blocked_result":
				if !errors.As(err, &blocked) || blocked.Phase != "tool_result" || !blocked.EffectMayHaveOccurred {
					t.Fatalf("expected result block: %v", err)
				}
			default:
				t.Fatalf("unknown fixture error %s", fixture.Error)
			}
		})
	}
}

func TestEnforceRejectsOversizedResultBeforeSidecarEvaluation(t *testing.T) {
	resultEvaluations := 0
	effects := 0
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evaluate" {
			var request struct {
				RequestID string `json:"requestId"`
				Phase     string `json:"phase"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode evaluation: %v", err)
				return
			}
			if request.Phase == "tool_result" {
				resultEvaluations++
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID,
				"mode": "enforce", "enforced": false, "coverage": "evaluated",
				"outcome": "allow", "recordingStatus": "retained",
				"reportReplayed": false, "actionId": testActionID})
			return
		}
		var receipt struct {
			Event string `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
			t.Errorf("decode receipt: %v", err)
			return
		}
		state := "succeeded"
		if receipt.Event == "started" {
			state = "executing"
		}
		responseJSON(w, 201, map[string]any{"receiptId": testPermitID,
			"state": state, "replayed": false})
	})
	defer closeServer()
	_, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{},
		func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
			effects++
			return map[string]any{"payload": strings.Repeat("x", 64*1024)}, nil
		})
	var blocked *EnforceBlockedError
	if !errors.As(err, &blocked) || blocked.Phase != "tool_result" ||
		!blocked.EffectMayHaveOccurred || effects != 1 || resultEvaluations != 0 {
		t.Fatalf("oversized result was not locally blocked after the effect: %v, effects=%d, evaluations=%d",
			err, effects, resultEvaluations)
	}
}

type undecodableInput struct {
	Amount int `json:"amount"`
}

func (*undecodableInput) UnmarshalJSON([]byte) error { return errors.New("cannot restore typed input") }

func TestEnforceDecodesBeforeStartAndReportsAfterCancellation(t *testing.T) {
	startCount := 0
	unknownCount := 0
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evaluate" {
			var request struct {
				RequestID string `json:"requestId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce",
				"enforced": false, "coverage": "evaluated", "outcome": "allow",
				"recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
			return
		}
		var receipt struct {
			Event string `json:"event"`
		}
		_ = json.NewDecoder(r.Body).Decode(&receipt)
		if receipt.Event == "started" {
			startCount++
		}
		if receipt.Event == "unknown" {
			unknownCount++
		}
		state := "outcome_unknown"
		if receipt.Event == "started" {
			state = "executing"
		}
		responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": state, "replayed": false})
	})
	defer closeServer()
	_, _, _, err := Enforce(context.Background(), client, enforceOperation(), undecodableInput{Amount: 40},
		func(context.Context, undecodableInput, ExecutionContext) (map[string]any, error) {
			t.Fatal("undecodable input reached protected effect")
			return nil, nil
		})
	var blocked *EnforceBlockedError
	if !errors.As(err, &blocked) || startCount != 0 {
		t.Fatalf("typed input failed after start: %v, %d", err, startCount)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, _, err = Enforce(ctx, client, enforceOperation(), map[string]any{},
		func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
			cancel()
			return nil, errors.New("provider timed out")
		})
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) || startCount != 1 || unknownCount != 1 {
		t.Fatalf("unknown outcome lost after cancel: %v, starts=%d unknowns=%d", err, startCount, unknownCount)
	}
}
