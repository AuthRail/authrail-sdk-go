package authrail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// EnforceBlockedError means the protected function was not called for a call
// block. A result block may follow a completed external effect.
type EnforceBlockedError struct {
	Phase                 string
	EffectMayHaveOccurred bool
	Decision              *Decision
	Cause                 error
}

func (e *EnforceBlockedError) Error() string { return "AuthRail blocked the " + e.Phase }
func (e *EnforceBlockedError) Unwrap() error { return e.Cause }

// Recovery identifies an attempt whose provider outcome must be checked by
// the protected application before it can send a reconciliation receipt.
type Recovery struct {
	ActionID               string
	AttemptID              string
	PermitID               *string
	InputSHA256            string
	ProviderIdempotencyKey string
	Traceparent            string
}

// OutcomeUnknownError never authorizes a retry of the business effect.
type OutcomeUnknownError struct {
	Cause    error
	Recovery Recovery
}

func (e *OutcomeUnknownError) Error() string {
	return "protected tool outcome is unknown; reconcile before retrying"
}
func (e *OutcomeUnknownError) Unwrap() error { return e.Cause }

// ApprovalRequired retains the original checked call in memory. A restart
// requires application-owned recovery, not a blind permit claim or effect.
type ApprovalRequired struct {
	Decision *Decision
	client   *Client
	call     Call
	mu       sync.Mutex
	used     bool
}

func (e *ApprovalRequired) Error() string { return "AuthRail approval is required" }

// ExecutionContext must be persisted with the provider request for recovery.
type ExecutionContext = Recovery

// Enforce checks the call before invoking the protected function, retains a
// signed start receipt, and checks the result before returning it to the agent.
func Enforce[Input, Output any](ctx context.Context, client *Client, operation Operation,
	input Input, execute func(context.Context, Input, ExecutionContext) (Output, error)) (Output, *Decision, *Decision, error) {
	var zero Output
	if client == nil || execute == nil {
		return zero, nil, nil, &EnforceBlockedError{Phase: "tool_call", Cause: errors.New("protected executor is missing")}
	}
	requestID, err := newRequestID()
	if err != nil {
		return zero, nil, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	arguments, err := json.Marshal(input)
	if err != nil || !jsonObject(arguments) || !validEnforceOperation(operation) {
		return zero, nil, nil, &EnforceBlockedError{Phase: "tool_call", Cause: errors.New("action contract is invalid")}
	}
	call, err := freezeObserveCall(Call{RequestID: requestID, OperationVersionID: operation.VersionID,
		ActionKey: operation.ActionKey, PrincipalID: operation.PrincipalID, SessionID: operation.SessionID,
		ResourceID: operation.ResourceID, PrincipalSource: operation.PrincipalSource,
		ResourceSource: operation.ResourceSource, Arguments: arguments,
		FactResolutions: operation.FactResolutions, Trajectory: operation.Trajectory,
		ReviewSummary: operation.ReviewSummary})
	call.Traceparent = operation.Traceparent
	if err != nil {
		return zero, nil, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	decision, err := client.evaluate(ctx, call, "tool_call", "enforce", nil)
	if err != nil {
		return zero, nil, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	if !permitted(decision) {
		if decision.Outcome == "approval_required" && decision.RecordingStatus == "retained" &&
			decision.ReportReplayed != nil && !*decision.ReportReplayed && uuidPattern.MatchString(decision.ActionID) &&
			uuidPattern.MatchString(decision.ApprovalRequestID) {
			return zero, decision, nil, &ApprovalRequired{Decision: decision, client: client, call: call}
		}
		return zero, decision, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision}
	}
	result, resultDecision, err := executePermitted(ctx, client, call, decision, nil, execute)
	return result, decision, resultDecision, err
}

// ResumeApproval consumes one pending call and claims its one-use permit.
// The caller must supply the same protected operation; no callback runs if
// the permit claim is uncertain, expired, or rejected.
func ResumeApproval[Input, Output any](ctx context.Context, pending *ApprovalRequired,
	execute func(context.Context, Input, ExecutionContext) (Output, error)) (Output, *Decision, error) {
	var zero Output
	if pending == nil || execute == nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call"}
	}
	pending.mu.Lock()
	if pending.used {
		pending.mu.Unlock()
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: pending.Decision}
	}
	pending.used = true
	pending.mu.Unlock()
	var input Input
	if err := json.Unmarshal(pending.call.Arguments, &input); err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: pending.Decision, Cause: err}
	}
	permit, err := pending.client.claimApproval(ctx, pending.call, pending.Decision)
	if err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: pending.Decision, Cause: err}
	}
	return executePermitted(ctx, pending.client, pending.call, pending.Decision, &permit.PermitID, execute)
}

func validEnforceOperation(op Operation) bool {
	return uuidPattern.MatchString(op.VersionID) && keyPattern.MatchString(op.ActionKey) &&
		keyPattern.MatchString(op.PrincipalID) && keyPattern.MatchString(op.SessionID) &&
		(op.ResourceID == "" || keyPattern.MatchString(op.ResourceID)) &&
		(op.PrincipalSource == "application_session" || op.PrincipalSource == "service_identity") &&
		(op.ResourceSource == "application_lookup" || op.ResourceSource == "not_applicable") &&
		validReviewSummary(op.ReviewSummary) && validTraceparent(op.Traceparent)
}

func validReviewSummary(summary *ReviewSummary) bool {
	if summary == nil {
		return true
	}
	if !safeReviewText(summary.Title, 120) || len(summary.Fields) < 1 || len(summary.Fields) > 8 {
		return false
	}
	for _, field := range summary.Fields {
		if !safeReviewText(field.Label, 60) || !safeReviewText(field.Value, 200) {
			return false
		}
	}
	return true
}

func safeReviewText(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 || r == '<' || r == '>' || r == '&' || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

func permitted(decision *Decision) bool {
	return decision != nil && decision.Mode == "enforce" && !decision.Enforced &&
		decision.Coverage == "evaluated" && decision.Outcome == "allow" &&
		decision.RecordingStatus == "retained" && decision.ReportReplayed != nil && !*decision.ReportReplayed
}

func executePermitted[Input, Output any](ctx context.Context, client *Client, call Call,
	decision *Decision, permitID *string,
	execute func(context.Context, Input, ExecutionContext) (Output, error)) (Output, *Decision, error) {
	var zero Output
	if !uuidPattern.MatchString(decision.ActionID) {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision}
	}
	inputDigest, err := callInputDigest(call)
	if err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision, Cause: err}
	}
	recovery := Recovery{ActionID: decision.ActionID, AttemptID: call.RequestID, PermitID: permitID,
		InputSHA256: inputDigest, ProviderIdempotencyKey: "ar-" + decision.ActionID}
	recovery.Traceparent = call.Traceparent
	var input Input
	if err := json.Unmarshal(call.Arguments, &input); err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision, Cause: err}
	}
	start, err := client.reportExecution(ctx, recovery, "started", nil)
	if err != nil || start.State != "executing" || start.Replayed == nil || *start.Replayed {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision, Cause: err}
	}
	result, toolErr := execute(ctx, input, recovery)
	if toolErr != nil {
		_, _ = client.reportExecution(context.WithoutCancel(ctx), recovery, "unknown", nil)
		return zero, nil, &OutcomeUnknownError{Cause: toolErr, Recovery: recovery}
	}
	completed, err := client.reportExecution(context.WithoutCancel(ctx), recovery, "succeeded", nil)
	if err != nil || completed.State != "succeeded" {
		if err == nil {
			err = errors.New("completion was not retained as succeeded")
		}
		return zero, nil, &OutcomeUnknownError{Cause: err, Recovery: recovery}
	}
	encoded, err := json.Marshal(result)
	if err != nil || !jsonObject(encoded) || len(encoded) > 64*1024 {
		return zero, nil, &EnforceBlockedError{Phase: "tool_result", EffectMayHaveOccurred: true, Cause: errors.New("tool result is not a bounded JSON object")}
	}
	resultDecision, err := client.evaluate(ctx, call, "tool_result", "enforce", encoded)
	if err != nil || !permitted(resultDecision) {
		return zero, resultDecision, &EnforceBlockedError{Phase: "tool_result", EffectMayHaveOccurred: true, Decision: resultDecision, Cause: err}
	}
	return result, resultDecision, nil
}

func callInputDigest(call Call) (string, error) {
	var arguments map[string]any
	if json.Unmarshal(call.Arguments, &arguments) != nil || arguments == nil {
		return "", errors.New("call arguments are invalid")
	}
	encoded, err := json.Marshal(struct {
		Arguments       map[string]any      `json:"arguments"`
		FactResolutions []FactResolution    `json:"factResolutions,omitempty"`
		Trajectory      *TrajectorySnapshot `json:"trajectory,omitempty"`
	}{arguments, call.FactResolutions, call.Trajectory})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

type permitResponse struct {
	PermitID  string    `json:"permitId"`
	ActionID  string    `json:"actionId"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type receiptResponse struct {
	ReceiptID string `json:"receiptId"`
	State     string `json:"state"`
	Replayed  *bool  `json:"replayed"`
}

func (c *Client) claimApproval(ctx context.Context, call Call, decision *Decision) (permitResponse, error) {
	var permit permitResponse
	if decision == nil || !uuidPattern.MatchString(decision.ActionID) || !uuidPattern.MatchString(decision.ApprovalRequestID) {
		return permit, errors.New("retained approval request is required")
	}
	digest, err := callInputDigest(call)
	if err != nil {
		return permit, err
	}
	key := sha256.Sum256(c.executorPrivateKey.Public().(ed25519.PublicKey))
	keyDigest := hex.EncodeToString(key[:])
	now := c.clock().Unix()
	statement := struct {
		Type              string `json:"type"`
		OrganisationID    string `json:"organisationId"`
		DeploymentID      string `json:"deploymentId"`
		ApprovalRequestID string `json:"approvalRequestId"`
		ActionID          string `json:"actionId"`
		InputSHA256       string `json:"inputSha256"`
		KeySHA256         string `json:"keySha256"`
		IssuedAt          int64  `json:"issuedAt"`
		ExpiresAt         int64  `json:"expiresAt"`
	}{"authrail.approval.claim.v1", c.organisationID, c.deploymentID, decision.ApprovalRequestID,
		decision.ActionID, digest, keyDigest, now, now + 30}
	proof, err := c.signStatement(statement)
	if err != nil {
		return permit, err
	}
	status, err := c.postLocal(ctx, "/approval-permits/claim", "", struct {
		ApprovalRequestID string        `json:"approvalRequestId"`
		ActionID          string        `json:"actionId"`
		InputSHA256       string        `json:"inputSha256"`
		KeySHA256         string        `json:"keySha256"`
		Proof             identityProof `json:"proof"`
	}{decision.ApprovalRequestID, decision.ActionID, digest, keyDigest, proof}, &permit, call.Traceparent)
	if err != nil || status != http.StatusCreated || !uuidPattern.MatchString(permit.PermitID) ||
		permit.ActionID != decision.ActionID || !permit.ExpiresAt.After(time.Now()) {
		return permitResponse{}, errors.New("approval claim was unavailable or invalid")
	}
	return permit, nil
}

// Reconcile reports only the outcome established by the protected executor's
// provider lookup using the original idempotency key.
func (c *Client) Reconcile(ctx context.Context, recovery Recovery, providerReference, outcome string) (string, error) {
	if !keyPattern.MatchString(providerReference) || (outcome != "succeeded" && outcome != "failed") {
		return "", errors.New("reconciliation evidence is invalid")
	}
	reference := providerReference
	receipt, err := c.reportExecution(ctx, recovery, "reconciled_"+outcome, &reference)
	return receipt.State, err
}

func (c *Client) reportExecution(ctx context.Context, recovery Recovery, event string, providerReference *string) (receiptResponse, error) {
	var receipt receiptResponse
	if !uuidPattern.MatchString(recovery.ActionID) || !uuidPattern.MatchString(recovery.AttemptID) ||
		(recovery.PermitID != nil && !uuidPattern.MatchString(*recovery.PermitID)) ||
		!digestPattern.MatchString(recovery.InputSHA256) || !keyPattern.MatchString(recovery.ProviderIdempotencyKey) {
		return receipt, errors.New("execution receipt is invalid")
	}
	key := sha256.Sum256(c.executorPrivateKey.Public().(ed25519.PublicKey))
	keyDigest := hex.EncodeToString(key[:])
	now := c.clock().Unix()
	statement := struct {
		Type                   string  `json:"type"`
		OrganisationID         string  `json:"organisationId"`
		DeploymentID           string  `json:"deploymentId"`
		ActionID               string  `json:"actionId"`
		AttemptID              string  `json:"attemptId"`
		PermitID               *string `json:"permitId"`
		Event                  string  `json:"event"`
		InputSHA256            string  `json:"inputSha256"`
		ProviderIdempotencyKey string  `json:"providerIdempotencyKey"`
		ProviderReference      *string `json:"providerReference"`
		KeySHA256              string  `json:"keySha256"`
		IssuedAt               int64   `json:"issuedAt"`
		ExpiresAt              int64   `json:"expiresAt"`
	}{"authrail.execution.receipt.v1", c.organisationID, c.deploymentID, recovery.ActionID,
		recovery.AttemptID, recovery.PermitID, event, recovery.InputSHA256,
		recovery.ProviderIdempotencyKey, providerReference, keyDigest, now, now + 30}
	proof, err := c.signStatement(statement)
	if err != nil {
		return receipt, err
	}
	status, err := c.postLocal(ctx, "/execution-receipts", recovery.ActionID+":"+recovery.AttemptID+":"+event,
		struct {
			ActionID               string        `json:"actionId"`
			AttemptID              string        `json:"attemptId"`
			PermitID               *string       `json:"permitId"`
			Event                  string        `json:"event"`
			InputSHA256            string        `json:"inputSha256"`
			ProviderIdempotencyKey string        `json:"providerIdempotencyKey"`
			ProviderReference      *string       `json:"providerReference"`
			KeySHA256              string        `json:"keySha256"`
			Proof                  identityProof `json:"proof"`
		}{recovery.ActionID, recovery.AttemptID, recovery.PermitID, event, recovery.InputSHA256,
			recovery.ProviderIdempotencyKey, providerReference, keyDigest, proof}, &receipt, recovery.Traceparent)
	if err != nil || status != http.StatusCreated || !uuidPattern.MatchString(receipt.ReceiptID) || receipt.Replayed == nil {
		return receiptResponse{}, errors.New("execution receipt was unavailable or invalid")
	}
	return receipt, nil
}

func (c *Client) signStatement(statement any) (identityProof, error) {
	message, err := json.Marshal(statement)
	if err != nil {
		return identityProof{}, err
	}
	var times struct {
		IssuedAt  int64 `json:"issuedAt"`
		ExpiresAt int64 `json:"expiresAt"`
	}
	if err := json.Unmarshal(message, &times); err != nil {
		return identityProof{}, err
	}
	return identityProof{IssuedAt: times.IssuedAt, ExpiresAt: times.ExpiresAt,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.executorPrivateKey, message))}, nil
}

func (c *Client) postLocal(ctx context.Context, path, idempotencyKey string, body any, target any, traceparent string) (int, error) {
	if !validTraceparent(traceparent) {
		return 0, errors.New("trace context is invalid")
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost,
		c.endpoint[:len(c.endpoint)-len("/evaluate")]+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if traceparent != "" {
		request.Header.Set("traceparent", traceparent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return response.StatusCode, fmt.Errorf("sidecar returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 128*1024))
	if err := decoder.Decode(target); err != nil {
		return response.StatusCode, errors.New("sidecar response is invalid")
	}
	return response.StatusCode, nil
}
