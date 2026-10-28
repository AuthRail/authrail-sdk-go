package authrail

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// ObservedExecutionOutcome records executor knowledge without authorizing an advisory attempt.
// Use unknown when an error cannot establish whether the effect happened.
type ObservedExecutionOutcome struct {
	Event                  string
	ProviderIdempotencyKey string
	ProviderReference      *string
}

// ObservedExecutionRecording distinguishes local durable delivery from central retention.
type ObservedExecutionRecording struct {
	RecordingStatus string `json:"recordingStatus"`
	ReceiptID       string `json:"receiptId,omitempty"`
	ActionID        string `json:"actionId,omitempty"`
	State           string `json:"state,omitempty"`
	Replayed        bool   `json:"replayed,omitempty"`
}

// ReportObservedExecution uses the original prepared call and exact signed input.
// Calling it is separate from running the tool; its failure must not retry the effect.
func (c *Client) ReportObservedExecution(ctx context.Context, call Call, outcome ObservedExecutionOutcome) (ObservedExecutionRecording, error) {
	var recorded ObservedExecutionRecording
	validEvent := outcome.Event == "succeeded" || outcome.Event == "failed" || outcome.Event == "unknown" || outcome.Event == "reconciled_succeeded" || outcome.Event == "reconciled_failed"
	if !uuidPattern.MatchString(call.RequestID) || !uuidPattern.MatchString(call.OperationVersionID) || !keyPattern.MatchString(call.ActionKey) || !validTraceparent(call.Traceparent) ||
		!validEvent || !keyPattern.MatchString(outcome.ProviderIdempotencyKey) || (outcome.ProviderReference != nil && !keyPattern.MatchString(*outcome.ProviderReference)) ||
		((outcome.Event == "reconciled_succeeded" || outcome.Event == "reconciled_failed") && outcome.ProviderReference == nil) {
		return recorded, errors.New("observed execution outcome is invalid")
	}
	input, err := encodeIdentityInput(call, "tool_call", nil)
	if err != nil {
		return recorded, err
	}
	inputDigest := sha256.Sum256(input)
	keyDigest := sha256.Sum256(c.executorPrivateKey.Public().(ed25519.PublicKey))
	clock := c.clock
	if clock == nil {
		clock = time.Now
	}
	issuedAt := clock().Unix()
	expiresAt := issuedAt + 30
	statement := struct {
		Type                   string  `json:"type"`
		OrganisationID         string  `json:"organisationId"`
		DeploymentID           string  `json:"deploymentId"`
		OperationVersionID     string  `json:"operationVersionId"`
		ActionKey              string  `json:"actionKey"`
		AttemptID              string  `json:"attemptId"`
		Event                  string  `json:"event"`
		InputSHA256            string  `json:"inputSha256"`
		ProviderIdempotencyKey string  `json:"providerIdempotencyKey"`
		ProviderReference      *string `json:"providerReference"`
		KeySHA256              string  `json:"keySha256"`
		IssuedAt               int64   `json:"issuedAt"`
		ExpiresAt              int64   `json:"expiresAt"`
	}{"authrail.execution.receipt.observe.v1", c.organisationID, c.deploymentID, call.OperationVersionID, call.ActionKey, call.RequestID, outcome.Event,
		hex.EncodeToString(inputDigest[:]), outcome.ProviderIdempotencyKey, outcome.ProviderReference, hex.EncodeToString(keyDigest[:]), issuedAt, expiresAt}
	encoded, err := json.Marshal(statement)
	if err != nil {
		return recorded, err
	}
	body := struct {
		OperationVersionID     string        `json:"operationVersionId"`
		ActionKey              string        `json:"actionKey"`
		AttemptID              string        `json:"attemptId"`
		Event                  string        `json:"event"`
		InputSHA256            string        `json:"inputSha256"`
		ProviderIdempotencyKey string        `json:"providerIdempotencyKey"`
		ProviderReference      *string       `json:"providerReference"`
		KeySHA256              string        `json:"keySha256"`
		Proof                  identityProof `json:"proof"`
	}{call.OperationVersionID, call.ActionKey, call.RequestID, outcome.Event, statement.InputSHA256, outcome.ProviderIdempotencyKey, outcome.ProviderReference, statement.KeySHA256,
		identityProof{IssuedAt: issuedAt, ExpiresAt: expiresAt, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.executorPrivateKey, encoded))}}
	delivery, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	status, err := c.postLocal(delivery, "/execution/observed-receipts", call.OperationVersionID+":"+call.ActionKey+":"+call.RequestID+":"+outcome.Event, body, &recorded, call.Traceparent)
	if err != nil {
		return recorded, err
	}
	if status == http.StatusAccepted && recorded.RecordingStatus == "queued" {
		return recorded, nil
	}
	if status != http.StatusCreated || recorded.RecordingStatus != "retained" || !uuidPattern.MatchString(recorded.ReceiptID) || !uuidPattern.MatchString(recorded.ActionID) ||
		(recorded.State != "succeeded" && recorded.State != "failed" && recorded.State != "outcome_unknown") {
		return ObservedExecutionRecording{}, errors.New("observed outcome response is invalid")
	}
	return recorded, nil
}
