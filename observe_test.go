package authrail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func sampleCall() Call {
	return Call{RequestID: "00000000-0000-4000-8000-000000000009",
		OperationVersionID: "00000000-0000-4000-8000-000000000008",
		ActionKey:          "invoice-123", Arguments: json.RawMessage(`{"amount":101}`)}
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
			Phase  string          `json:"phase"`
			Result json.RawMessage `json:"result"`
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
		outcome := "deny"
		if body.Phase == "tool_result" {
			outcome = "allow"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"requestId": sampleCall().RequestID,
			"mode": "observe", "enforced": false, "coverage": "evaluated", "outcome": outcome})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "abcdefghijklmnopqrstuvwxyz012345", nil)
	if err != nil {
		t.Fatal(err)
	}
	executed := 0
	result, completed, err := client.Observe(context.Background(), sampleCall(), func(context.Context) (json.RawMessage, error) {
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
	client, err := NewClient(url, "abcdefghijklmnopqrstuvwxyz012345", nil)
	if err != nil {
		t.Fatal(err)
	}
	toolError := errors.New("provider failed")
	count := 0
	_, completed, gotError := client.Observe(context.Background(), sampleCall(), func(context.Context) (json.RawMessage, error) {
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
	client, err := NewClient(server.URL, "abcdefghijklmnopqrstuvwxyz012345", nil)
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	go func() {
		_, _, _ = client.Observe(context.Background(), sampleCall(), func(context.Context) (json.RawMessage, error) {
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
	if _, err := NewClient("https://example.com", "abcdefghijklmnopqrstuvwxyz012345", nil); err == nil {
		t.Fatal("remote decision endpoint was accepted")
	}
}
