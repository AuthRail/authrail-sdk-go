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

func TestGuardProcessingHonoursCancellationEvenWhenHandlerDoesNot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer close(release)
	go func() {
		_, err := runGuardHandler(ctx, GuardHandler{Process: func(context.Context, string) (string, error) {
			close(started)
			<-release
			return "unsafe late output", nil
		}}, "private")
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handler output escaped cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("non-cooperative handler held the caller after cancellation")
	}
}

func enforceFixture(t *testing.T, handler http.HandlerFunc, handlers ...GuardHandler) (*Client, func()) {
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
		ExecutorPrivateKey: private, GuardHandlers: handlers})
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
	for _, resume := range []string{"memory", "persisted", "recover"} {
		t.Run(resume, func(t *testing.T) { testApprovalResume(t, resume) })
	}
}

// Restart recovery must preserve the processed input and original attempt,
// and read an existing permit instead of issuing another permit after uncertainty.
func testApprovalResume(t *testing.T, resume string) {
	called := 0
	processed := 0
	var originalRequestID string
	var permits []string
	version := strings.Repeat("a", 64)
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/guard-requirements":
			phase := r.URL.Query().Get("phase")
			requirements := []GuardRequirement{}
			if phase == "tool_call" {
				requirements = append(requirements, GuardRequirement{RailVersionID: testActionID, RuleID: "content", Kind: "sanitize", HandlerID: "redact", HandlerVersion: version, Target: GuardTarget{Root: "arguments", Path: []string{"memo"}}})
			}
			responseJSON(w, 200, guardPlan{FormatVersion: 1, OperationVersionID: enforceOperation().VersionID, Phase: phase, BundleID: testPermitID, Sequence: 1, Coverage: "evaluated", Requirements: requirements})
		case "/evaluate":
			var request struct {
				RequestID string `json:"requestId"`
				Phase     string `json:"phase"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if originalRequestID == "" {
				originalRequestID = request.RequestID
			} else if originalRequestID != request.RequestID {
				t.Error("restart changed original call identity")
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce", "enforced": false,
				"coverage": "evaluated", "outcome": "approval_required", "recordingStatus": "retained",
				"reportReplayed": false, "actionId": testActionID, "approvalRequestId": testApprovalID, "bundleId": testPermitID, "sequence": 1})
		case "/approval-permits/claim", "/approval-permits/recover":
			permits = append(permits, r.URL.Path)
			status := http.StatusCreated
			if r.URL.Path == "/approval-permits/recover" {
				status = http.StatusOK
			}
			responseJSON(w, status, map[string]any{"permitId": testPermitID, "actionId": testActionID,
				"expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
		case "/execution-receipts":
			var receipt struct {
				Event     string `json:"event"`
				AttemptID string `json:"attemptId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&receipt)
			if receipt.AttemptID != originalRequestID {
				t.Error("restart changed execution attempt")
			}
			state := "succeeded"
			if receipt.Event == "started" {
				state = "executing"
			}
			responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": state, "replayed": false})
		}
	}, GuardHandler{ID: "redact", Version: version, Kind: "sanitize", Process: func(_ context.Context, input string) (string, error) { processed++; return "safe", nil }})
	defer closeServer()
	operation := enforceOperation()
	operation.ReviewSummary = &ReviewSummary{Title: "Pay invoice", Fields: []ReviewField{{Label: "Amount", Value: "400"}}}
	_, _, _, err := Enforce(context.Background(), client, operation, map[string]any{"amount": 400, "memo": "private"},
		func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
			called++
			return map[string]any{}, nil
		})
	var pending *ApprovalRequired
	if !errors.As(err, &pending) || called != 0 {
		t.Fatalf("approval should pause: %v", err)
	}
	execute := func(_ context.Context, checked map[string]any, _ ExecutionContext) (map[string]any, error) {
		called++
		if checked["memo"] != "safe" {
			t.Error("approval resumed unprocessed arguments")
		}
		return map[string]any{"ok": true}, nil
	}
	if resume == "memory" {
		_, _, err = ResumeApproval(context.Background(), pending, execute)
	} else {
		continuation, snapshotErr := pending.Continuation()
		if snapshotErr != nil {
			t.Fatal(snapshotErr)
		}
		// Persisted data crosses a real JSON boundary and is loaded by a new client
		// holding the same customer identity and executor key, with no pending map.
		encoded, marshalErr := json.Marshal(continuation)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var restored ApprovalContinuation
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		clientCopy := *client
		pending = nil
		if resume == "recover" {
			_, _, err = RecoverApprovalFrom(context.Background(), &clientCopy, restored, execute)
		} else {
			_, _, err = ResumeApprovalFrom(context.Background(), &clientCopy, restored, execute)
		}
	}
	if err != nil || called != 1 || processed != 1 {
		t.Fatalf("approval did not resume: %v, %d", err, called)
	}
	if resume != "memory" {
		want := "/approval-permits/claim"
		if resume == "recover" {
			want = "/approval-permits/recover"
		}
		if !reflect.DeepEqual(permits, []string{want}) {
			t.Fatalf("unexpected permit paths: %v", permits)
		}
		return
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

// A lost claim response is not permission: only the existing exact permit and
// a fresh start acknowledgement may cross the business-effect boundary.
func TestApprovalRestartRecoveryBlocksUnprovenPermitOrStart(t *testing.T) {
	for _, failure := range []string{"unavailable", "wrong action", "expired", "duplicate start", "invalid continuation"} {
		t.Run(failure, func(t *testing.T) {
			var client *Client
			requests, effects := 0, 0
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path == "/execution-receipts" {
					responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": "executing", "replayed": true})
					return
				}
				if r.URL.Path != "/approval-permits/recover" {
					t.Errorf("recovery attempted a new claim: %s", r.URL.Path)
				}
				var payload struct {
					InputSHA256 string        `json:"inputSha256"`
					KeySHA256   string        `json:"keySha256"`
					Proof       identityProof `json:"proof"`
				}
				if json.NewDecoder(r.Body).Decode(&payload) != nil {
					t.Fatal("invalid recovery proof")
				}
				statement := fmt.Sprintf(`{"type":"authrail.approval.claim.v1","organisationId":"%s","deploymentId":"%s","approvalRequestId":"%s","actionId":"%s","inputSha256":"%s","keySha256":"%s","issuedAt":%d,"expiresAt":%d}`,
					client.organisationID, client.deploymentID, testApprovalID, testActionID, payload.InputSHA256,
					payload.KeySHA256, payload.Proof.IssuedAt, payload.Proof.ExpiresAt)
				signature, err := base64.RawURLEncoding.DecodeString(payload.Proof.Signature)
				if err != nil || !ed25519.Verify(client.executorPrivateKey.Public().(ed25519.PublicKey), []byte(statement), signature) {
					t.Error("recovery did not sign the existing protocol statement")
				}
				if failure == "unavailable" {
					w.WriteHeader(503)
					return
				}
				action, expires := testActionID, time.Now().Add(time.Minute)
				if failure == "wrong action" {
					action = testApprovalID
				}
				if failure == "expired" {
					expires = time.Now().Add(-time.Minute)
				}
				responseJSON(w, 200, map[string]any{"permitId": testPermitID, "actionId": action, "expiresAt": expires.UTC().Format(time.RFC3339)})
			})
			defer closeServer()
			op := enforceOperation()
			replayed := false
			continuation := ApprovalContinuation{Call: Call{RequestID: testApprovalID, OperationVersionID: op.VersionID,
				ActionKey: op.ActionKey, PrincipalID: op.PrincipalID, SessionID: op.SessionID, ResourceID: op.ResourceID,
				PrincipalSource: op.PrincipalSource, ResourceSource: op.ResourceSource, Arguments: json.RawMessage(`{"amount":400}`)},
				Decision: Decision{RequestID: testApprovalID, Mode: "enforce", Coverage: "evaluated", Outcome: "approval_required",
					RecordingStatus: "retained", ReportReplayed: &replayed, ActionID: testActionID, ApprovalRequestID: testApprovalID}}
			if failure == "invalid continuation" {
				continuation.Decision.Mode = "observe"
			}
			_, _, err := RecoverApprovalFrom(context.Background(), client, continuation,
				func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
					effects++
					return map[string]any{}, nil
				})
			if err == nil || effects != 0 {
				t.Fatalf("unproven recovery ran callback: err=%v effects=%d", err, effects)
			}
			if failure == "invalid continuation" && requests != 0 {
				t.Fatal("invalid continuation reached sidecar")
			}
		})
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
			GuardEvidence   []GuardEvidence     `json:"guardEvidence"`
			CanonicalInput  string              `json:"canonicalInput"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.FormatVersion != 1 {
		t.Fatal("invalid canonical corpus")
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			encoded, err := encodeIdentityInput(Call{Arguments: fixture.Arguments,
				FactResolutions: fixture.FactResolutions, Trajectory: fixture.Trajectory, GuardEvidence: fixture.GuardEvidence},
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

// Guard processing must change only reviewed fields before permission and never
// expose the original result. Duplicate requirements must not process twice.
func TestEnforceGuardProcessingBindsCallAndResult(t *testing.T) {
	version := strings.Repeat("a", 64)
	processedCalls, processedResults := 0, 0
	var retainedEvidence GuardEvidence
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/guard-requirements":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" || r.URL.Query().Get("operationVersionId") != enforceOperation().VersionID {
				t.Error("requirements lookup was not authenticated and operation-bound")
			}
			phase := r.URL.Query().Get("phase")
			root, field, kind, id := "arguments", "message", "sanitize", "redact"
			if phase == "tool_result" {
				root, field, kind, id = "result", "text", "transform", "release"
			}
			item := GuardRequirement{RailVersionID: testApprovalID, RuleID: "content", Kind: kind, HandlerID: id, HandlerVersion: version, Target: GuardTarget{Root: root, Path: []string{field}}}
			duplicate := item
			duplicate.RailVersionID = testActionID
			responseJSON(w, 200, guardPlan{FormatVersion: 1, OperationVersionID: enforceOperation().VersionID, Phase: phase, BundleID: testPermitID, Sequence: 1, Coverage: "evaluated", Requirements: []GuardRequirement{item, duplicate}})
		case "/evaluate":
			var request struct {
				RequestID string          `json:"requestId"`
				Phase     string          `json:"phase"`
				Arguments map[string]any  `json:"arguments"`
				Result    map[string]any  `json:"result"`
				Evidence  []GuardEvidence `json:"guardEvidence"`
				Proof     identityProof   `json:"identityProof"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Proof.Signature == "" {
				t.Error("processed evaluation was unsigned")
			}
			if request.Arguments["message"] != "safe input" || request.Arguments["invoiceId"] != "invoice-123" {
				t.Error("wrong call fields processed")
			}
			if request.Phase == "tool_call" {
				if len(request.Evidence) != 1 {
					t.Errorf("call evidence count %d", len(request.Evidence))
					return
				}
				retainedEvidence = request.Evidence[0]
			} else if len(request.Evidence) != 2 || !reflect.DeepEqual(retainedEvidence, request.Evidence[0]) || request.Result["text"] != "safe output" || request.Result["kept"] != true {
				t.Error("result processing lost call evidence or released private output")
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce", "enforced": false, "coverage": "evaluated", "outcome": "allow", "bundleId": testPermitID, "sequence": 1, "recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
		case "/execution-receipts":
			var receipt struct {
				Event  string `json:"event"`
				Digest string `json:"inputSha256"`
			}
			_ = json.NewDecoder(r.Body).Decode(&receipt)
			evidence, _ := json.Marshal(retainedEvidence)
			canonical := `{"arguments":{"invoiceId":"invoice-123","message":"safe input"},"guardEvidence":[` + string(evidence) + `]}`
			digest := sha256.Sum256([]byte(canonical))
			if receipt.Digest != hex.EncodeToString(digest[:]) {
				t.Error("effect digest lost call evidence")
			}
			state := "succeeded"
			if receipt.Event == "started" {
				state = "executing"
			}
			responseJSON(w, 201, map[string]any{"receiptId": testPermitID, "state": state, "replayed": false})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, GuardHandler{ID: "redact", Version: version, Kind: "sanitize", Process: func(_ context.Context, input string) (string, error) {
		processedCalls++
		if input != "private input" {
			t.Error("wrong call processor input")
		}
		return "safe input", nil
	}}, GuardHandler{ID: "release", Version: version, Kind: "transform", Process: func(_ context.Context, input string) (string, error) {
		processedResults++
		if input != "private output" {
			t.Error("wrong result processor input")
		}
		return "safe output", nil
	}})
	defer closeServer()
	input := map[string]any{"invoiceId": "invoice-123", "message": "private input"}
	result, _, _, err := Enforce(context.Background(), client, enforceOperation(), input, func(_ context.Context, checked map[string]any, _ ExecutionContext) (map[string]any, error) {
		if checked["message"] != "safe input" {
			t.Error("protected tool saw private input")
		}
		return map[string]any{"text": "private output", "kept": true}, nil
	})
	if err != nil || processedCalls != 1 || processedResults != 1 || result["text"] != "safe output" || input["message"] != "private input" {
		t.Fatalf("Guard processing boundary failed: %v %v calls=%d results=%d", result, err, processedCalls, processedResults)
	}
	before := sha256.Sum256([]byte(`"private input"`))
	after := sha256.Sum256([]byte(`"safe input"`))
	if retainedEvidence.InputSHA256 != hex.EncodeToString(before[:]) || retainedEvidence.OutputSHA256 != hex.EncodeToString(after[:]) {
		t.Fatal("evidence is not a canonical JSON string digest")
	}
}

// An unavailable, substituted, stale, or conflicting requirement must never reach
// the protected effect, even if another endpoint would return allow.
func TestEnforceGuardPlanFailuresStopBeforeEffect(t *testing.T) {
	version := strings.Repeat("a", 64)
	for _, failure := range []string{"unavailable", "wrong operation", "wrong phase", "wrong version", "isolation", "overlap", "stale bundle"} {
		t.Run(failure, func(t *testing.T) {
			processed, executed := 0, 0
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/guard-requirements" {
					if failure == "unavailable" {
						w.WriteHeader(503)
						return
					}
					plan := guardPlan{FormatVersion: 1, OperationVersionID: enforceOperation().VersionID, Phase: "tool_call", BundleID: testPermitID, Sequence: 1, Coverage: "evaluated", Requirements: []GuardRequirement{{RailVersionID: testApprovalID, RuleID: "content", Kind: "sanitize", HandlerID: "redact", HandlerVersion: version, Target: GuardTarget{Root: "arguments", Path: []string{"message"}}}}}
					switch failure {
					case "wrong operation":
						plan.OperationVersionID = testActionID
					case "wrong phase":
						plan.Phase = "tool_result"
					case "wrong version":
						plan.Requirements[0].HandlerVersion = strings.Repeat("b", 64)
					case "isolation":
						plan.Requirements[0].Kind = "isolate"
					case "overlap":
						other := plan.Requirements[0]
						other.Target.Path = []string{"message", "nested"}
						plan.Requirements = append(plan.Requirements, other)
					}
					responseJSON(w, 200, plan)
					return
				}
				if r.URL.Path != "/evaluate" || failure != "stale bundle" {
					t.Error("invalid plan reached execution path")
				}
				var request struct {
					RequestID string `json:"requestId"`
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce", "enforced": false, "coverage": "evaluated", "outcome": "allow", "bundleId": testActionID, "sequence": 2, "recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
			}, GuardHandler{ID: "redact", Version: version, Kind: "sanitize", Process: func(_ context.Context, input string) (string, error) { processed++; return input, nil }})
			defer closeServer()
			_, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{"message": "private"}, func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
				executed++
				return nil, nil
			})
			var blocked *EnforceBlockedError
			if !errors.As(err, &blocked) || blocked.Phase != "tool_call" || executed != 0 || (failure != "stale bundle" && processed != 0) {
				t.Fatalf("Guard failure did not stop safely: %v processors=%d effects=%d", err, processed, executed)
			}
		})
	}
}

// Failed result processing follows a possible effect but must release no raw data.
func TestEnforceGuardResultFailureWithholdsOutput(t *testing.T) {
	version := strings.Repeat("a", 64)
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/guard-requirements":
			phase := r.URL.Query().Get("phase")
			requirements := []GuardRequirement{}
			if phase == "tool_result" {
				requirements = append(requirements, GuardRequirement{RailVersionID: testApprovalID, RuleID: "output", Kind: "sanitize", HandlerID: "redact", HandlerVersion: version, Target: GuardTarget{Root: "result", Path: []string{"text"}}})
			}
			responseJSON(w, 200, guardPlan{FormatVersion: 1, OperationVersionID: enforceOperation().VersionID, Phase: phase, BundleID: testPermitID, Sequence: 1, Coverage: "evaluated", Requirements: requirements})
		case "/evaluate":
			var request struct {
				RequestID string `json:"requestId"`
				Phase     string `json:"phase"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.Phase != "tool_call" {
				t.Error("failed result processing reached evaluation")
			}
			responseJSON(w, 200, map[string]any{"requestId": request.RequestID, "mode": "enforce", "enforced": false, "coverage": "evaluated", "outcome": "allow", "bundleId": testPermitID, "sequence": 1, "recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
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
	}, GuardHandler{ID: "redact", Version: version, Kind: "sanitize", Process: func(context.Context, string) (string, error) { return "", errors.New("processor unavailable") }})
	defer closeServer()
	result, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{}, func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
		return map[string]any{"text": "private"}, nil
	})
	var blocked *EnforceBlockedError
	if !errors.As(err, &blocked) || blocked.Phase != "tool_result" || !blocked.EffectMayHaveOccurred || result != nil {
		t.Fatalf("raw output leaked or effect uncertainty lost: %v %v", result, err)
	}
}

// Outcome reporting must retain the original signed attempt without issuing permission.
func TestObservedExecutionSignsExactAttemptWithoutPermit(t *testing.T) {
	var client *Client
	var call Call
	sends := 0
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		sends++
		if r.URL.Path != "/execution/observed-receipts" {
			t.Error("unexpected permission path")
		}
		var body struct {
			OperationVersionID     string        `json:"operationVersionId"`
			ActionKey              string        `json:"actionKey"`
			AttemptID              string        `json:"attemptId"`
			Event                  string        `json:"event"`
			InputSHA256            string        `json:"inputSha256"`
			ProviderIdempotencyKey string        `json:"providerIdempotencyKey"`
			ProviderReference      *string       `json:"providerReference"`
			KeySHA256              string        `json:"keySha256"`
			Proof                  identityProof `json:"proof"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("invalid outcome body")
		}
		if body.AttemptID != call.RequestID || body.OperationVersionID != call.OperationVersionID {
			t.Error("wrong original attempt")
		}
		input, _ := encodeIdentityInput(call, "tool_call", nil)
		digest := sha256.Sum256(input)
		if body.InputSHA256 != hex.EncodeToString(digest[:]) {
			t.Error("wrong exact input")
		}
		statement := fmt.Sprintf(`{"type":"authrail.execution.receipt.observe.v1","organisationId":"%s","deploymentId":"%s","operationVersionId":"%s","actionKey":"%s","attemptId":"%s","event":"succeeded","inputSha256":"%s","providerIdempotencyKey":"effect-key","providerReference":null,"keySha256":"%s","issuedAt":%d,"expiresAt":%d}`, client.organisationID, client.deploymentID, body.OperationVersionID, body.ActionKey, body.AttemptID, body.InputSHA256, body.KeySHA256, body.Proof.IssuedAt, body.Proof.ExpiresAt)
		signature, _ := base64.RawURLEncoding.DecodeString(body.Proof.Signature)
		if !ed25519.Verify(client.executorPrivateKey.Public().(ed25519.PublicKey), []byte(statement), signature) {
			t.Error("outcome signature is invalid")
		}
		if ed25519.Verify(client.executorPrivateKey.Public().(ed25519.PublicKey), []byte(strings.Replace(statement, "succeeded", "failed", 1)), signature) {
			t.Error("altered outcome signature accepted")
		}
		responseJSON(w, http.StatusAccepted, map[string]string{"recordingStatus": "queued"})
	})
	defer closeServer()
	var err error
	call = sampleCall()
	result, err := client.ReportObservedExecution(context.Background(), call, ObservedExecutionOutcome{Event: "succeeded", ProviderIdempotencyKey: "effect-key"})
	if err != nil || result.RecordingStatus != "queued" {
		t.Fatalf("valid receipt rejected: %+v %v", result, err)
	}
	_, err = client.ReportObservedExecution(context.Background(), call, ObservedExecutionOutcome{Event: "started", ProviderIdempotencyKey: "effect-key"})
	if err == nil || sends != 1 {
		t.Fatal("observed outcome accepted a start or issued another request")
	}
}
