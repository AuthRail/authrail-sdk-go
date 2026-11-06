package authrail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testDataSourceID = "77777777-7777-4777-8777-777777777777"

func testDataContract() map[string]any {
	return map[string]any{"formatVersion": 4, "kind": "sdk", "sourceIdentity": "billing.read", "accountBoundary": "account_1", "lookup": "invoice.read", "queryField": map[string]any{"root": "arguments", "path": []string{"invoiceId"}}, "factKey": "balance", "resultPath": []string{"balance"}, "valueType": "number", "maxAgeSeconds": 60, "timeoutMs": 100, "failure": "unavailable"}
}
func testDataBinding(reads *atomic.Int32) DataSourceBinding {
	return DataSourceBinding{SourceVersionID: testDataSourceID, Kind: "sdk", SourceIdentity: "billing.read", AccountBoundary: "account_1", Lookup: "invoice.read", ResolveResource: func(_ context.Context, identity DataResourceContext) (string, error) {
		if identity.ResourceID != "invoice-123" {
			return "", errors.New("wrong identity")
		}
		return "invoice_123", nil
	}, Read: func(_ context.Context, key string) (CustomerReadResult, error) {
		reads.Add(1)
		return CustomerReadResult{SourceIdentity: "billing.read", AccountBoundary: "account_1", Lookup: "invoice.read", LookupKey: key, ObservedAt: time.Now(), Value: map[string]any{"balance": 80}}, nil
	}}
}

// This exercises real SDK signing/receipt preparation so an auto-read cannot be
// omitted from an execution hash or replaced when result facts are refreshed.
func TestDataSourcesBindExecutionReceiptsAndRefreshResult(t *testing.T) {
	var reads atomic.Int32
	var callHash string
	var phases []string
	client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/data-requirements":
			responseJSON(w, 200, map[string]any{"formatVersion": 1, "operationVersionId": enforceOperation().VersionID, "phase": r.URL.Query().Get("phase"), "bundleId": testPermitID, "sequence": 1, "coverage": "evaluated", "requirements": []map[string]any{{"sourceVersionId": testDataSourceID, "contract": testDataContract()}}})
		case "/evaluate":
			var body struct {
				RequestID, Phase string
				Arguments        json.RawMessage
				FactResolutions  []FactResolution `json:"factResolutions"`
				GuardEvidence    []GuardEvidence  `json:"guardEvidence"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("invalid request")
			}
			phases = append(phases, body.Phase)
			if len(body.FactResolutions) != 1 || body.FactResolutions[0].Status != "ok" {
				t.Errorf("missing automatic facts: %+v", body.FactResolutions)
			}
			if body.Phase == "tool_call" {
				encoded, err := encodeIdentityInput(Call{Arguments: body.Arguments, FactResolutions: body.FactResolutions, GuardEvidence: body.GuardEvidence}, "tool_call", nil)
				if err != nil {
					t.Error(err)
				}
				sum := sha256.Sum256(encoded)
				callHash = hex.EncodeToString(sum[:])
			}
			responseJSON(w, 200, map[string]any{"requestId": body.RequestID, "mode": "enforce", "enforced": false, "coverage": "evaluated", "outcome": "allow", "recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID})
		case "/execution-receipts":
			var body struct {
				Event       string
				InputSHA256 string `json:"inputSha256"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.InputSHA256 != callHash {
				t.Errorf("receipt omitted checked facts: %s != %s", body.InputSHA256, callHash)
			}
			state := "succeeded"
			if body.Event == "started" {
				state = "executing"
			}
			responseJSON(w, 201, map[string]any{"receiptId": testActionID, "state": state, "replayed": false})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	defer closeServer()
	client.dataSources = []DataSourceBinding{testDataBinding(&reads)}
	output, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{"invoiceId": "invoice_123"}, func(_ context.Context, input map[string]any, recovery ExecutionContext) (map[string]any, error) {
		if reads.Load() != 1 || input["invoiceId"] != "invoice_123" || recovery.InputSHA256 != callHash {
			t.Error("effect did not retain original checked facts")
		}
		return map[string]any{"done": true}, nil
	})
	if err != nil || output["done"] != true || reads.Load() != 2 || strings.Join(phases, ",") != "tool_call,tool_result" {
		t.Fatalf("automatic phases failed: %+v %v reads=%d phases=%v", output, err, reads.Load(), phases)
	}
}
func TestDataBindingMismatchUnavailableDeadlineAndDrift(t *testing.T) {
	for _, scenario := range []string{"resource", "account", "missing", "timeout", "success", "manual"} {
		t.Run(scenario, func(t *testing.T) {
			var reads atomic.Int32
			binding := testDataBinding(&reads)
			if scenario == "resource" {
				binding.ResolveResource = func(context.Context, DataResourceContext) (string, error) { return "other", nil }
			}
			if scenario == "account" {
				binding.AccountBoundary = "other"
			}
			if scenario == "timeout" {
				binding.Read = func(ctx context.Context, _ string) (CustomerReadResult, error) {
					<-ctx.Done()
					return CustomerReadResult{}, ctx.Err()
				}
			}
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/data-requirements" {
					responseJSON(w, 200, map[string]any{"formatVersion": 1, "operationVersionId": enforceOperation().VersionID, "phase": "tool_call", "bundleId": testPermitID, "sequence": 1, "coverage": "evaluated", "requirements": []map[string]any{{"sourceVersionId": testDataSourceID, "contract": testDataContract()}}})
					return
				}
				t.Errorf("unexpected network %s", r.URL.Path)
				http.NotFound(w, r)
			})
			defer closeServer()
			client.dataSources = []DataSourceBinding{binding}
			if scenario == "missing" {
				client.dataSources = []DataSourceBinding{}
			}
			call := Call{RequestID: testActionID, OperationVersionID: enforceOperation().VersionID, Arguments: json.RawMessage(`{"invoiceId":"invoice_123"}`), ResourceID: "invoice-123"}
			if scenario == "manual" {
				call.FactResolutions = []FactResolution{{SourceVersionID: testDataSourceID}}
			}
			start := time.Now()
			prepared, err := client.prepareDataCall(context.Background(), call, "tool_call")
			if scenario == "manual" {
				if err == nil {
					t.Fatal("manual/auto conflict accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("source timeout did not bound the read")
			}
			want := "unavailable"
			if scenario == "account" || scenario == "resource" {
				want = "untrusted"
			}
			if scenario == "success" {
				want = "ok"
			}
			if len(prepared.FactResolutions) != 1 || prepared.FactResolutions[0].Status != want {
				t.Fatalf("unexpected result %+v", prepared.FactResolutions)
			}
			if scenario != "success" && reads.Load() != 0 {
				t.Fatal("mismatched source reached reader")
			}
			if len(call.FactResolutions) != 0 {
				t.Fatal("original call mutated")
			}
		})
	}
	var reads atomic.Int32
	b := testDataBinding(&reads)
	if _, err := registerDataSources([]DataSourceBinding{b, b}); err == nil {
		t.Fatal("duplicate bindings accepted")
	}
}

// Bundle drift must stop permission even if the cached fact itself is fresh.
func TestAutomaticDataRejectsMissingPlanAndBundleDrift(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "drift"}[missing], func(t *testing.T) {
			var reads atomic.Int32
			executed := false
			client, closeServer := enforceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/data-requirements" {
					if missing {
						http.NotFound(w, r)
						return
					}
					responseJSON(w, 200, map[string]any{"formatVersion": 1, "operationVersionId": enforceOperation().VersionID, "phase": "tool_call", "bundleId": testPermitID, "sequence": 1, "coverage": "evaluated", "requirements": []map[string]any{{"sourceVersionId": testDataSourceID, "contract": testDataContract()}}})
					return
				}
				if r.URL.Path == "/evaluate" {
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					responseJSON(w, 200, map[string]any{"requestId": body["requestId"], "mode": "enforce", "enforced": false, "coverage": "evaluated", "outcome": "allow", "recordingStatus": "retained", "reportReplayed": false, "actionId": testActionID, "bundleId": testPermitID, "sequence": 2})
					return
				}
				t.Errorf("unexpected request %s", r.URL.Path)
			})
			defer closeServer()
			client.dataSources = []DataSourceBinding{testDataBinding(&reads)}
			_, _, _, err := Enforce(context.Background(), client, enforceOperation(), map[string]any{"invoiceId": "invoice_123"}, func(context.Context, map[string]any, ExecutionContext) (map[string]any, error) {
				executed = true
				return nil, nil
			})
			if err == nil || executed {
				t.Fatal("unavailable/drifting Data configuration permitted an effect")
			}
		})
	}
}
