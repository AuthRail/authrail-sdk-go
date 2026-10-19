package authrail

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func testConfig(url string) Config {
	return Config{SidecarURL: url, AdapterToken: "abcdefghijklmnopqrstuvwxyz012345",
		OrganisationID:     "00000000-0000-4000-8000-000000000002",
		DeploymentID:       "00000000-0000-4000-8000-000000000003",
		ExecutorPrivateKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
}

func sampleCall() Call {
	return Call{RequestID: "00000000-0000-4000-8000-000000000009",
		OperationVersionID: "00000000-0000-4000-8000-000000000008",
		ActionKey:          "invoice-123", PrincipalID: "staff_123", SessionID: "task_123",
		PrincipalSource: "application_session", ResourceSource: "not_applicable",
		Arguments: json.RawMessage(`{"amount":101}`)}
}

func TestObserveChecksCallAndResultWithoutBlocking(t *testing.T) {
	var phases []string
	var phaseMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/evaluate" ||
			r.Header.Get("Authorization") != "Bearer abcdefghijklmnopqrstuvwxyz012345" ||
			r.Header.Get("Idempotency-Key") != "invoice-123" {
			t.Errorf("incorrect adapter request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var body struct {
			Phase       string              `json:"phase"`
			Result      json.RawMessage     `json:"result"`
			Trajectory  *TrajectorySnapshot `json:"trajectory"`
			Attribution struct {
				PrincipalID     string  `json:"principalId"`
				SessionID       string  `json:"sessionId"`
				ResourceID      *string `json:"resourceId"`
				PrincipalSource string  `json:"principalSource"`
				ResourceSource  string  `json:"resourceSource"`
			} `json:"attribution"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		phaseMu.Lock()
		phases = append(phases, body.Phase)
		phaseMu.Unlock()
		if body.Phase == "tool_result" && string(body.Result) != `{"status":"done"}` {
			t.Errorf("result was not checked: %s", body.Result)
		}
		if body.Attribution.PrincipalID != "staff_123" ||
			body.Attribution.SessionID != "task_123" || body.Attribution.ResourceID != nil ||
			body.Attribution.PrincipalSource != "application_session" ||
			body.Attribution.ResourceSource != "not_applicable" {
			t.Errorf("adapter attribution was lost: %+v", body.Attribution)
		}
		if body.Trajectory == nil || body.Trajectory.SessionID != "task_123" ||
			!body.Trajectory.Complete || len(body.Trajectory.PriorReadOperationVersionIDs) != 1 ||
			body.Trajectory.Values["sensitiveDataSeen"] != true {
			t.Errorf("signed session snapshot was lost at %s: %+v", body.Phase, body.Trajectory)
		}
		outcome := "deny"
		if body.Phase == "tool_result" {
			outcome = "allow"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"requestId": sampleCall().RequestID,
			"mode": "observe", "enforced": false, "coverage": "evaluated", "outcome": outcome})
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	executed := 0
	call := sampleCall()
	call.Trajectory = &TrajectorySnapshot{SessionID: call.SessionID, Complete: true,
		PriorReadOperationVersionIDs: []string{"00000000-0000-4000-8000-000000000070"},
		Values:                       map[string]any{"sensitiveDataSeen": true}}
	result, completed, err := client.observeRaw(context.Background(), call, func(context.Context) (json.RawMessage, error) {
		executed++
		return json.RawMessage(`{"status":"done"}`), nil
	})
	observed := <-completed
	if err != nil || executed != 1 || string(result) != `{"status":"done"}` ||
		observed.CallError != nil || observed.ResultError != nil ||
		observed.CallDecision.Outcome != "deny" || observed.ResultDecision.Outcome != "allow" ||
		len(phases) != 2 || phases[0] == phases[1] {
		t.Fatalf("Observe changed execution or missed a hook: result=%s observed=%+v err=%v phases=%v", result, observed, err, phases)
	}
}

func TestObserveKeepsToolBehaviorWhenSidecarUnavailable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	client, err := NewClient(testConfig(url))
	if err != nil {
		t.Fatal(err)
	}
	toolError := errors.New("provider failed")
	count := 0
	_, completed, gotError := client.observeRaw(context.Background(), sampleCall(), func(context.Context) (json.RawMessage, error) {
		count++
		return nil, toolError
	})
	observed := <-completed
	if count != 1 || !errors.Is(gotError, toolError) || observed.CallError == nil ||
		observed.CallDecision != nil || observed.ResultError == nil {
		t.Fatalf("tool behavior changed during sidecar failure: %+v %v", observed, gotError)
	}
}

func TestObserveDoesNotWaitForSidecar(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"requestId": sampleCall().RequestID,
			"mode": "observe", "enforced": false, "coverage": "uncovered", "outcome": "indeterminate"})
	}))
	defer server.Close()
	defer close(release)
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	go func() {
		_, _, _ = client.observeRaw(context.Background(), sampleCall(), func(context.Context) (json.RawMessage, error) {
			return json.RawMessage(`{"status":"done"}`), nil
		})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("Observe waited for the sidecar before returning the tool result")
	}
}

func TestClientRejectsRemoteSidecar(t *testing.T) {
	if _, err := NewClient(Config{SidecarURL: "https://example.com", AdapterToken: "abcdefghijklmnopqrstuvwxyz012345"}); err == nil {
		t.Fatal("remote decision endpoint was accepted")
	}
}

func TestTypedObserveKeepsGoValuesAndGeneratesRequestID(t *testing.T) {
	seenIDs := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			RequestID string `json:"requestId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		seenIDs <- request.RequestID
		_ = json.NewEncoder(w).Encode(map[string]any{"requestId": request.RequestID,
			"mode": "observe", "enforced": false, "coverage": "uncovered", "outcome": "indeterminate"})
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	type invoice struct {
		ID string `json:"id"`
	}
	result, completed, toolError := Observe(context.Background(), client,
		Operation{VersionID: sampleCall().OperationVersionID, ActionKey: "invoice-123",
			PrincipalID: "staff_123", SessionID: "task_123"},
		invoice{ID: "inv_123"}, func(context.Context) (invoice, error) {
			return invoice{ID: "inv_123"}, nil
		})
	observed := <-completed
	seenID := <-seenIDs
	if toolError != nil || result.ID != "inv_123" || observed.CallError != nil ||
		observed.ResultError != nil || !uuidPattern.MatchString(seenID) {
		t.Fatalf("typed Observe failed: result=%+v observed=%+v err=%v request=%s", result, observed, toolError, seenID)
	}
}

func TestInvalidObserveSetupStillRunsTool(t *testing.T) {
	count := 0
	result, completed, toolError := Observe(context.Background(), (*Client)(nil),
		Operation{}, struct{}{}, func(context.Context) (int, error) {
			count++
			return 42, nil
		})
	observed := <-completed
	if toolError != nil || result != 42 || count != 1 || observed.CallError == nil {
		t.Fatalf("invalid setup blocked the tool: result=%d observed=%+v err=%v", result, observed, toolError)
	}
}

func TestInvalidOperationStillRunsTool(t *testing.T) {
	client, err := NewClient(testConfig("http://127.0.0.1:7078"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	result, completed, toolError := Observe(context.Background(), client,
		Operation{VersionID: "invalid", ActionKey: "invoice-123"},
		struct{ Amount int }{Amount: 10}, func(context.Context) (int, error) {
			count++
			return 42, nil
		})
	observed := <-completed
	if toolError != nil || result != 42 || count != 1 || observed.CallError == nil {
		t.Fatalf("invalid Operation blocked the tool: result=%d observed=%+v err=%v", result, observed, toolError)
	}
}
