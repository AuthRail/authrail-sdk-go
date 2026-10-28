//go:build ignore

// This executable connects both SDK source trees to the actual sidecar HTTP
// handlers. Its signed control plane is a fixture, not central persistence proof.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	authrail "github.com/AuthRail/authrail-sdk-go"
	"github.com/AuthRail/authrail-sidecar/sidecar"
)

const organisationID = "00000000-0000-4000-8000-000000000001"
const deploymentID = "00000000-0000-4000-8000-000000000002"
const operationID = "00000000-0000-4000-8000-000000000008"
const actionID = "00000000-0000-4000-8000-000000000009"
const approvalID = "00000000-0000-4000-8000-000000000010"
const permitID = "00000000-0000-4000-8000-000000000011"
const bundleID = "00000000-0000-4000-8000-000000000012"
const adapterToken = "isolated-adapter-token-01234567890123456789"

func must(err error) {
	if err != nil {
		var blocked *authrail.EnforceBlockedError
		if errors.As(err, &blocked) {
			fmt.Fprintf(os.Stderr, "Blocked phase=%s decision=%+v cause=%v\n", blocked.Phase, blocked.Decision, blocked.Cause)
		}
		panic(err)
	}
}
func check(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	must(json.NewEncoder(w).Encode(value))
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, executor, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	configuration, pin := signedConfiguration()
	var mutex sync.Mutex
	starts := make(map[string]bool)
	reports, recoveries := 0, 0
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		check(r.Header.Get("Authorization") == "Bearer isolated-deployment-token", "wrong deployment credential")
		mutex.Lock()
		defer mutex.Unlock()
		switch r.URL.Path {
		case "/runtime/deployment/configuration":
			respond(w, 200, configuration)
		case "/runtime/deployment/observations":
			reports++
			respond(w, 201, map[string]any{"actionId": actionID, "certificateId": approvalID,
				"approvalRequestId": approvalID, "replayed": false})
		case "/runtime/deployment/approval-permits/recover":
			recoveries++
			verifyStatement(r, executor.Public().(ed25519.PublicKey), "authrail.approval.claim.v1")
			respond(w, 200, map[string]any{"permitId": permitID, "actionId": actionID,
				"expiresAt": time.Now().Add(time.Minute).UTC()})
		case "/runtime/deployment/execution-receipts":
			body := verifyStatement(r, executor.Public().(ed25519.PublicKey), "authrail.execution.receipt.v1")
			key := body["attemptId"].(string)
			event := body["event"].(string)
			check(r.Header.Get("Idempotency-Key") == actionID+":"+key+":"+event, "wrong receipt idempotency")
			check(body["providerIdempotencyKey"] == "ar-"+actionID, "wrong provider key")
			state, replayed := "succeeded", false
			if event == "started" {
				state, replayed = "executing", starts[key]
				starts[key] = true
			}
			respond(w, 201, map[string]any{"receiptId": permitID, "state": state, "replayed": replayed})
		default:
			w.WriteHeader(404)
		}
	}))
	defer controlPlane.Close()
	directory, err := os.MkdirTemp("", "authrail-sdk-sidecar-state-")
	must(err)
	defer os.RemoveAll(directory)
	syncer, err := sidecar.NewSynchronizer(sidecar.Options{ControlPlaneURL: controlPlane.URL,
		Token: "isolated-deployment-token", OrganisationID: organisationID, DeploymentID: deploymentID,
		TrustedPins: map[string]struct{}{pin: {}}, ExecutorPublicKey: executor.Public().(ed25519.PublicKey),
		StateFile: filepath.Join(directory, "state.json")})
	must(err)
	must(syncer.Sync(ctx))
	mux := http.NewServeMux()
	mux.Handle("/evaluate", sidecar.EvaluationHandler(syncer, adapterToken))
	mux.Handle("/guard-requirements", sidecar.GuardRequirementsHandler(syncer, adapterToken))
	mux.Handle("/approval-permits/recover", sidecar.ApprovalPermitRecoveryHandler(syncer, adapterToken))
	mux.Handle("/execution-receipts", sidecar.ExecutionReceiptHandler(syncer, adapterToken))
	local := httptest.NewServer(mux)
	defer local.Close()
	client, err := authrail.NewClient(authrail.Config{SidecarURL: local.URL, AdapterToken: adapterToken,
		OrganisationID: organisationID, DeploymentID: deploymentID, ExecutorPrivateKey: executor})
	must(err)
	operation := authrail.Operation{VersionID: operationID, ActionKey: "go-allowed", PrincipalID: "staff-1",
		SessionID: "session-1", PrincipalSource: "application_session", ResourceSource: "not_applicable",
		ReviewSummary: &authrail.ReviewSummary{Title: "Pay invoice", Fields: []authrail.ReviewField{{Label: "Amount", Value: "70 units"}}}}
	effects := 0
	execute := func(_ context.Context, input map[string]any, execution authrail.ExecutionContext) (map[string]any, error) {
		check(execution.ProviderIdempotencyKey == "ar-"+actionID, "Go provider key changed")
		effects++
		input["amount"] = 999
		return map[string]any{"status": "paid"}, nil
	}
	result, call, after, err := authrail.Enforce(ctx, client, operation, map[string]any{"amount": 80}, execute)
	must(err)
	check(result["status"] == "paid" && call.RecordingStatus == "retained" && after.Outcome == "allow", "Go allow failed")
	operation.ActionKey = "go-denied"
	_, _, _, err = authrail.Enforce(ctx, client, operation, map[string]any{"amount": 150}, execute)
	var blocked *authrail.EnforceBlockedError
	check(errors.As(err, &blocked) && effects == 1, "Go denial crossed effect boundary")
	operation.ActionKey = "go-approved"
	_, _, _, err = authrail.Enforce(ctx, client, operation, map[string]any{"amount": 70}, execute)
	var pending *authrail.ApprovalRequired
	check(errors.As(err, &pending), "Go approval did not pause")
	continuation, err := pending.Continuation()
	must(err)
	encoded, err := json.Marshal(continuation)
	must(err)
	var restored authrail.ApprovalContinuation
	must(json.Unmarshal(encoded, &restored))
	restarted, err := authrail.NewClient(authrail.Config{SidecarURL: local.URL, AdapterToken: adapterToken,
		OrganisationID: organisationID, DeploymentID: deploymentID, ExecutorPrivateKey: executor})
	must(err)
	_, after, err = authrail.RecoverApprovalFrom(ctx, restarted, restored, execute)
	must(err)
	check(after.Outcome == "approval_required" && effects == 2, "Go restart recovery failed")
	_, _, err = authrail.RecoverApprovalFrom(ctx, restarted, restored, execute)
	check(errors.As(err, &blocked) && effects == 2, "Go duplicate start crossed effect boundary")
	fmt.Println("Go: real sidecar allowed call/result, denial with no effect, persisted permit recovery, and duplicate-start blocking passed.")
	privateDER, err := x509.MarshalPKCS8PrivateKey(executor)
	must(err)
	input, err := json.Marshal(map[string]any{"actionId": actionID, "client": map[string]any{
		"sidecarUrl": local.URL, "adapterToken": adapterToken, "organisationId": organisationID,
		"deploymentId": deploymentID, "executorPrivateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))},
		"operation": map[string]any{"operationVersionId": operationID, "principalId": "staff-1", "sessionId": "session-1",
			"principalSource": "application_session", "resourceSource": "not_applicable",
			"reviewSummary": map[string]any{"title": "Pay invoice", "fields": []map[string]string{{"label": "Amount", "value": "70 units"}}}}})
	must(err)
	node := exec.CommandContext(ctx, "node", "../authrail-sdk-node/scripts/sidecar-check.mjs")
	node.Stdin, node.Stdout, node.Stderr = bytes.NewReader(input), os.Stdout, os.Stderr
	must(node.Run())
	mutex.Lock()
	defer mutex.Unlock()
	check(reports == 10 && recoveries == 4 && len(starts) == 4, fmt.Sprintf("unexpected fixture transitions reports=%d recoveries=%d starts=%d", reports, recoveries, len(starts)))
	fmt.Println("Isolated signed control-plane fixture only: no central persistence or provider-effect acceptance is claimed.")
}

func signedConfiguration() (sidecar.Configuration, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(err)
	fingerprint := sha256.Sum256(der)
	pin := hex.EncodeToString(fingerprint[:])
	field := map[string]any{"root": "arguments", "path": []string{"amount"}}
	condition := func(comparison string, amount int) map[string]any {
		return map[string]any{"kind": "compare", "left": field, "comparison": comparison, "right": map[string]any{"kind": "literal", "value": amount}}
	}
	rail := map[string]any{"railId": approvalID, "versionId": permitID, "operationVersionId": operationID, "kind": "policy",
		"operationContract": map[string]any{"requiredCoverage": []string{"tool_call", "tool_result"}},
		"content": map[string]any{"formatVersion": 2, "rules": []map[string]any{
			{"id": "approve", "when": condition("eq", 70), "outcome": "approval_required"},
			{"id": "ordinary", "when": condition("lte", 100), "outcome": "allow"},
			{"id": "large", "when": condition("gt", 100), "outcome": "deny"}}}}
	now := time.Now().UTC()
	manifest := map[string]any{"formatVersion": 1, "bundleId": bundleID, "organisationId": organisationID, "deploymentId": deploymentID,
		"inventoryItemId": actionID, "inventoryRevisionId": approvalID, "sequence": 1, "mode": "enforce",
		"issuedAt": now.Add(-time.Minute), "activeFrom": now.Add(-time.Minute), "expiresAt": now.Add(time.Hour), "rails": []any{rail}}
	payload, err := json.Marshal(manifest)
	must(err)
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	must(err)
	config := sidecar.Configuration{}
	config.Deployment.OrganisationID, config.Deployment.DeploymentID = organisationID, deploymentID
	config.Deployment.InventoryItemID, config.Deployment.InventoryRevision = actionID, approvalID
	config.Deployment.Mode, config.Deployment.Sequence, config.Deployment.ActiveBundleID = "enforce", 1, new(bundleID)
	config.Bundle = &sidecar.SignedBundle{Payload: base64.RawURLEncoding.EncodeToString(payload), KeyID: "isolated-key", Algorithm: "ECDSA_SHA_256", Signature: base64.StdEncoding.EncodeToString(signature)}
	config.Bundle.VerificationKey.Format, config.Bundle.VerificationKey.Base64, config.Bundle.VerificationKey.SHA256 = "spki-der", base64.StdEncoding.EncodeToString(der), pin
	return config, pin
}

func verifyStatement(r *http.Request, key ed25519.PublicKey, kind string) map[string]any {
	var body map[string]any
	must(json.NewDecoder(r.Body).Decode(&body))
	proof := body["proof"].(map[string]any)
	fields := []string{"approvalRequestId", "actionId", "inputSha256", "keySha256"}
	if strings.HasPrefix(kind, "authrail.execution") {
		fields = []string{"actionId", "attemptId", "permitId", "event", "inputSha256", "providerIdempotencyKey", "providerReference", "keySha256"}
	}
	statement := fmt.Sprintf(`{"type":%q,"organisationId":%q,"deploymentId":%q`, kind, organisationID, deploymentID)
	for _, field := range fields {
		encoded, err := json.Marshal(body[field])
		must(err)
		statement += fmt.Sprintf(",%q:%s", field, encoded)
	}
	statement += fmt.Sprintf(",\"issuedAt\":%.0f,\"expiresAt\":%.0f}", proof["issuedAt"], proof["expiresAt"])
	signature, err := base64.RawURLEncoding.DecodeString(proof["signature"].(string))
	must(err)
	check(ed25519.Verify(key, []byte(statement), signature), "SDK signature did not match control-plane statement")
	return body
}
