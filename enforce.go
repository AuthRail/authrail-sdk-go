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
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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

// OutcomeUnknownError retains uncertain execution ownership or outcome. It never
// authorizes a retry of the business effect, including after a replayed start.
type OutcomeUnknownError struct {
	Cause    error
	Recovery Recovery
}

func (e *OutcomeUnknownError) Error() string {
	return "protected tool outcome is unknown; reconcile before retrying"
}
func (e *OutcomeUnknownError) Unwrap() error { return e.Cause }

// ApprovalRequired retains the original checked call in memory. Persist its
// Continuation in protected application storage before crossing a restart.
type ApprovalRequired struct {
	Decision          *Decision
	client            *Client
	call              Call
	originalArguments json.RawMessage
	mu                sync.Mutex
	used              bool
}

func (e *ApprovalRequired) Error() string { return "AuthRail approval is required" }

// ApprovalContinuation retains an exact pending call and its retained decision.
// Encrypt and scope it to the authenticated customer and operation in application
// storage. It contains private arguments and must never be accepted from an agent.
type ApprovalContinuation struct {
	Call              Call            `json:"call"`
	Decision          Decision        `json:"decision"`
	OriginalArguments json.RawMessage `json:"originalArguments,omitempty"`
}

// Continuation returns an independent snapshot for application-owned persistence.
// Store it before claiming a permit so a lost response can use RecoverApprovalFrom.
func (e *ApprovalRequired) Continuation() (ApprovalContinuation, error) {
	if e == nil {
		return ApprovalContinuation{}, errors.New("pending approval is missing")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.used || e.Decision == nil {
		return ApprovalContinuation{}, errors.New("pending approval was consumed")
	}
	return freezeApprovalContinuation(ApprovalContinuation{Call: e.call, Decision: *e.Decision, OriginalArguments: e.originalArguments})
}

func freezeApprovalContinuation(value ApprovalContinuation) (ApprovalContinuation, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 256*1024 {
		return ApprovalContinuation{}, errors.New("approval continuation is invalid")
	}
	var frozen ApprovalContinuation
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&frozen) != nil || !uuidPattern.MatchString(frozen.Call.RequestID) ||
		!validEnforceOperation(Operation{VersionID: frozen.Call.OperationVersionID,
			ActionKey: frozen.Call.ActionKey, PrincipalID: frozen.Call.PrincipalID,
			SessionID: frozen.Call.SessionID, ResourceID: frozen.Call.ResourceID,
			PrincipalSource: frozen.Call.PrincipalSource, ResourceSource: frozen.Call.ResourceSource,
			ReviewSummary: frozen.Call.ReviewSummary, Traceparent: frozen.Call.Traceparent}) ||
		!retainedApproval(&frozen.Decision) || frozen.Decision.RequestID != frozen.Call.RequestID {
		return ApprovalContinuation{}, errors.New("approval continuation is invalid")
	}
	if _, err := callInputDigest(frozen.Call); err != nil {
		return ApprovalContinuation{}, err
	}
	if len(frozen.OriginalArguments) > 0 {
		if _, err := decodeInputObject(frozen.OriginalArguments); err != nil {
			return ApprovalContinuation{}, err
		}
	}
	return frozen, nil
}

// ResumeApprovalFrom claims the original approved call after a request or process
// boundary. An uncertain claim requires RecoverApprovalFrom, never a blind retry.
func ResumeApprovalFrom[Input, Output any](ctx context.Context, client *Client,
	continuation ApprovalContinuation,
	execute func(context.Context, Input, ExecutionContext) (Output, error)) (Output, *Decision, error) {
	return resumeApprovalFrom(ctx, client, continuation, false, execute)
}

// RecoverApprovalFrom reads only the exact existing unexpired, unstarted permit.
// It never issues a replacement permit or retries an uncertain business effect.
func RecoverApprovalFrom[Input, Output any](ctx context.Context, client *Client,
	continuation ApprovalContinuation,
	execute func(context.Context, Input, ExecutionContext) (Output, error)) (Output, *Decision, error) {
	return resumeApprovalFrom(ctx, client, continuation, true, execute)
}

func resumeApprovalFrom[Input, Output any](ctx context.Context, client *Client,
	continuation ApprovalContinuation, recoverExisting bool,
	execute func(context.Context, Input, ExecutionContext) (Output, error)) (Output, *Decision, error) {
	var zero Output
	if client == nil || execute == nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call"}
	}
	frozen, err := freezeApprovalContinuation(continuation)
	if err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	// Decode before consuming a permit; incompatible application input cannot
	// become permission to invoke a callback with partially decoded arguments.
	var input Input
	if err := json.Unmarshal(frozen.Call.Arguments, &input); err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	permit, err := client.approvalPermit(ctx, frozen.Call, &frozen.Decision, recoverExisting)
	if err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: &frozen.Decision, Cause: err}
	}
	return executePermitted(ctx, client, frozen.Call, &frozen.Decision, &permit.PermitID, execute, frozen.OriginalArguments)
}

func retainedApproval(decision *Decision) bool {
	return decision != nil && decision.Mode == "enforce" && !decision.Enforced &&
		decision.Coverage == "evaluated" && decision.Outcome == "approval_required" &&
		decision.RecordingStatus == "retained" && decision.ReportReplayed != nil && !*decision.ReportReplayed &&
		uuidPattern.MatchString(decision.ActionID) && uuidPattern.MatchString(decision.ApprovalRequestID)
}

// ExecutionContext must be persisted with the provider request for recovery.
type ExecutionContext = Recovery

// WithExecutionCheckpoint binds a private durable save to this execution without
// changing the shared client. A failed checkpoint prevents execution start.
func (c *Client) WithExecutionCheckpoint(checkpoint func(context.Context, Recovery) error) *Client {
	if c == nil {
		return nil
	}
	copy := *c
	copy.executionCheckpoint = checkpoint
	return &copy
}

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
	originalArguments := append(json.RawMessage(nil), call.Arguments...)
	call, decision, err := client.checkEnforceCall(ctx, call, originalArguments, nil)
	if err != nil {
		return zero, nil, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	if !permitted(decision) {
		if retainedApproval(decision) {
			return zero, decision, nil, &ApprovalRequired{Decision: decision, client: client, call: call, originalArguments: originalArguments}
		}
		return zero, decision, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision}
	}
	result, resultDecision, err := executePermitted(ctx, client, call, decision, nil, execute, originalArguments)
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
	return executePermitted(ctx, pending.client, pending.call, pending.Decision, &permit.PermitID, execute, pending.originalArguments)
}

func equalJSONObject(left, right json.RawMessage) bool {
	a, err := decodeInputObject(left)
	if err != nil {
		return false
	}
	b, err := decodeInputObject(right)
	if err != nil {
		return false
	}
	encodedA, errA := json.Marshal(a)
	encodedB, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(encodedA, encodedB)
}
func (c *Client) checkEnforceCall(ctx context.Context, base Call, original, expected json.RawMessage) (Call, *Decision, error) {
	for attempt := 0; attempt < 2; attempt++ {
		call := base
		call.Arguments = append(json.RawMessage(nil), original...)
		call.GuardEvidence = nil
		call.guardBundleID = ""
		call.dataBundleID = ""
		call.dataPhase = ""
		prepared, _, err := c.processGuardPhase(ctx, call, "tool_call", nil)
		if err == nil && len(expected) > 0 && !equalJSONObject(prepared.Arguments, expected) {
			return Call{}, nil, errors.New("fresh processing changed the business input")
		}
		if err == nil {
			prepared, err = c.prepareDataCall(ctx, prepared, "tool_call", len(expected) > 0)
		}
		var decision *Decision
		if err == nil {
			decision, err = c.evaluate(ctx, prepared, "tool_call", "enforce", nil)
		}
		if err == nil {
			return prepared, decision, nil
		}
		if !errors.Is(err, errConfigurationChanged) || attempt == 1 {
			return Call{}, nil, err
		}
	}
	return Call{}, nil, errConfigurationChanged
}

// ApprovalStatus separates durable waiting from short-lived review freshness.
type ApprovalStatus struct {
	ActionID          string    `json:"actionId"`
	ApprovalRequestID string    `json:"approvalRequestId"`
	State             string    `json:"state"`
	RequiresRefresh   bool      `json:"requiresRefresh"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

// ApprovalStatus reads the exact retained review; it never claims permission.
func (c *Client) ApprovalStatus(ctx context.Context, continuation ApprovalContinuation) (ApprovalStatus, error) {
	frozen, err := freezeApprovalContinuation(continuation)
	if err != nil {
		return ApprovalStatus{}, err
	}
	raw, err := c.approvalRequest(ctx, frozen.Call, &frozen.Decision, "status")
	if err != nil {
		return ApprovalStatus{}, err
	}
	var status struct {
		ActionID          string    `json:"actionId"`
		ApprovalRequestID string    `json:"approvalRequestId"`
		State             string    `json:"state"`
		RequiresRefresh   *bool     `json:"requiresRefresh"`
		ExpiresAt         time.Time `json:"expiresAt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&status) != nil || status.ActionID != frozen.Decision.ActionID || status.ApprovalRequestID != frozen.Decision.ApprovalRequestID || status.RequiresRefresh == nil || status.ExpiresAt.IsZero() {
		return ApprovalStatus{}, errors.New("approval status is invalid")
	}
	switch status.State {
	case "pending", "approved", "rejected", "cancelled", "expired", "consumed", "superseded", "permit_issued":
	default:
		return ApprovalStatus{}, errors.New("approval status is invalid")
	}
	return ApprovalStatus{status.ActionID, status.ApprovalRequestID, status.State, *status.RequiresRefresh, status.ExpiresAt}, nil
}

// RefreshApprovalFrom requests a fresh exact decision. Prior votes never approve it.
// RefreshApprovalOptions supplies explicit current manual context; automatic sources are reread.
type RefreshApprovalOptions struct {
	FactResolutions []FactResolution
	Trajectory      *TrajectorySnapshot
}

func RefreshApprovalFrom[Input, Output any](ctx context.Context, client *Client, continuation ApprovalContinuation, execute func(context.Context, Input, ExecutionContext) (Output, error), options ...RefreshApprovalOptions) (Output, *Decision, error) {
	var zero Output
	if len(options) > 1 {
		return zero, nil, errors.New("provide one refresh context")
	}
	if client == nil || execute == nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call"}
	}
	frozen, err := freezeApprovalContinuation(continuation)
	if err != nil {
		return zero, nil, err
	}
	status, err := client.ApprovalStatus(ctx, frozen)
	if err != nil {
		return zero, nil, err
	}
	if !status.RequiresRefresh || (status.State != "pending" && status.State != "approved" && status.State != "permit_issued") {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: &frozen.Decision}
	}
	original := frozen.OriginalArguments
	if len(original) == 0 {
		if len(frozen.Call.GuardEvidence) > 0 {
			return zero, nil, errors.New("original input is required for fresh Guard processing")
		}
		original = frozen.Call.Arguments
	}
	frozen.Call.RequestID, err = newRequestID()
	if err != nil {
		return zero, nil, err
	}
	if len(options) > 0 {
		if options[0].FactResolutions != nil {
			frozen.Call.FactResolutions = options[0].FactResolutions
		}
		if options[0].Trajectory != nil {
			frozen.Call.Trajectory = options[0].Trajectory
		}
	}
	call, decision, err := client.checkEnforceCall(ctx, frozen.Call, original, frozen.Call.Arguments)
	if err != nil {
		return zero, nil, &EnforceBlockedError{Phase: "tool_call", Cause: err}
	}
	if !permitted(decision) {
		if retainedApproval(decision) {
			return zero, decision, &ApprovalRequired{Decision: decision, client: client, call: call, originalArguments: original}
		}
		return zero, decision, &EnforceBlockedError{Phase: "tool_call", Decision: decision}
	}
	return executePermitted(ctx, client, call, decision, nil, execute, original)
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

func permittedResult(result, call *Decision, permitID *string) bool {
	if permitted(result) {
		return call != nil && result.ActionID == call.ActionID
	}
	// Policy approval is re-evaluated at the result hook. Only a previously
	// claimed permit for this exact Action can release that result.
	return permitID != nil && *permitID != "" && call != nil &&
		call.Outcome == "approval_required" && result != nil &&
		result.Mode == "enforce" && !result.Enforced &&
		result.Coverage == "evaluated" && result.Outcome == "approval_required" &&
		result.RecordingStatus == "retained" && result.ReportReplayed != nil &&
		!*result.ReportReplayed && call.ActionID != "" && result.ActionID == call.ActionID
}

func executePermitted[Input, Output any](ctx context.Context, client *Client, call Call,
	decision *Decision, permitID *string,
	execute func(context.Context, Input, ExecutionContext) (Output, error), originalArguments ...json.RawMessage) (Output, *Decision, error) {
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
	if client.executionCheckpoint != nil {
		checkpoint := recovery
		if recovery.PermitID != nil {
			permit := *recovery.PermitID
			checkpoint.PermitID = &permit
		}
		if err := client.executionCheckpoint(ctx, checkpoint); err != nil {
			return zero, nil, &EnforceBlockedError{Phase: "tool_call", Decision: decision, Cause: err}
		}
	}
	start, err := client.reportExecution(ctx, recovery, "started", nil)
	if err != nil || start.State != "executing" || start.Replayed == nil || *start.Replayed {
		if err == nil {
			err = errors.New("execution start was not freshly acknowledged")
		}
		// A missing or replayed acknowledgement cannot dispatch, but may describe
		// retained work owned by an earlier attempt. Keep its exact recovery identity.
		return zero, nil, &OutcomeUnknownError{Cause: err, Recovery: recovery}
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
	rawResult := append(json.RawMessage(nil), encoded...)
	var resultDecision *Decision
	for attempt := 0; attempt < 2; attempt++ {
		prepared, processedResult, prepareErr := client.processGuardPhase(ctx, call, "tool_result", rawResult)
		encoded, err = processedResult, prepareErr
		if err == nil && len(originalArguments) > 0 && len(originalArguments[0]) > 0 && decision.BundleID != nil && (prepared.guardBundleID != *decision.BundleID || prepared.guardSequence != decision.Sequence) {
			freshCall := call
			freshCall.Arguments = originalArguments[0]
			freshCall.GuardEvidence = nil
			freshCall, _, err = client.processGuardPhase(ctx, freshCall, "tool_call", nil)
			if err == nil && (freshCall.guardBundleID != prepared.guardBundleID || freshCall.guardSequence != prepared.guardSequence) {
				err = errConfigurationChanged
			}
			if err == nil && !equalJSONObject(freshCall.Arguments, call.Arguments) {
				err = errors.New("current processing changed the executed input")
			}
			if err == nil {
				evidence := freshCall.GuardEvidence
				for _, item := range prepared.GuardEvidence {
					if item.Phase == "tool_result" {
						evidence = append(evidence, item)
					}
				}
				prepared.GuardEvidence = evidence
			}
		}
		if err == nil {
			resultDecision, err = client.evaluate(ctx, prepared, "tool_result", "enforce", encoded)
		}
		if err == nil {
			break
		}
		if !errors.Is(err, errConfigurationChanged) || attempt == 1 {
			return zero, resultDecision, &EnforceBlockedError{Phase: "tool_result", EffectMayHaveOccurred: true, Decision: resultDecision, Cause: err}
		}
		err = nil
	}
	if !permittedResult(resultDecision, decision, permitID) {
		return zero, resultDecision, &EnforceBlockedError{Phase: "tool_result", EffectMayHaveOccurred: true, Decision: resultDecision}
	}
	if len(client.guardHandlers) > 0 {
		// Return only the processed representation after its retained result check.
		// The tool's original object must never bypass a result transformation.
		var processed Output
		if err := json.Unmarshal(encoded, &processed); err != nil {
			return zero, resultDecision, &EnforceBlockedError{Phase: "tool_result", EffectMayHaveOccurred: true, Decision: resultDecision, Cause: err}
		}
		return processed, resultDecision, nil
	}
	return result, resultDecision, nil
}

func callInputDigest(call Call) (string, error) {
	arguments, err := decodeInputObject(call.Arguments)
	if err != nil {
		return "", errors.New("call arguments are invalid")
	}
	encoded, err := json.Marshal(struct {
		Arguments       map[string]any      `json:"arguments"`
		FactResolutions []FactResolution    `json:"factResolutions,omitempty"`
		Trajectory      *TrajectorySnapshot `json:"trajectory,omitempty"`
		GuardEvidence   []GuardEvidence     `json:"guardEvidence,omitempty"`
	}{arguments, call.FactResolutions, call.Trajectory, callGuardEvidence(call.GuardEvidence)})
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
	return c.approvalPermit(ctx, call, decision, false)
}

func (c *Client) approvalRequest(ctx context.Context, call Call, decision *Decision, operation string) (json.RawMessage, error) {
	var raw json.RawMessage
	if decision == nil || !uuidPattern.MatchString(decision.ActionID) || !uuidPattern.MatchString(decision.ApprovalRequestID) {
		return nil, errors.New("retained approval request is required")
	}
	digest, err := callInputDigest(call)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(c.executorPrivateKey.Public().(ed25519.PublicKey))
	keyDigest := hex.EncodeToString(key[:])
	purpose := "authrail.approval.claim.v1"
	if operation == "status" {
		purpose = "authrail.approval.status.v1"
	}
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
	}{purpose, c.organisationID, c.deploymentID, decision.ApprovalRequestID,
		decision.ActionID, digest, keyDigest, now, now + 30}
	proof, err := c.signStatement(statement)
	if err != nil {
		return nil, err
	}
	path, expectedStatus := "/approval-permits/"+operation, http.StatusOK
	if operation == "claim" {
		expectedStatus = http.StatusCreated
	}
	status, err := c.postLocal(ctx, path, "", struct {
		ApprovalRequestID string        `json:"approvalRequestId"`
		ActionID          string        `json:"actionId"`
		InputSHA256       string        `json:"inputSha256"`
		KeySHA256         string        `json:"keySha256"`
		Proof             identityProof `json:"proof"`
	}{decision.ApprovalRequestID, decision.ActionID, digest, keyDigest, proof}, &raw, call.Traceparent)
	if err != nil || status != expectedStatus {
		return nil, errors.New("approval request unavailable")
	}
	return raw, nil
}
func (c *Client) approvalPermit(ctx context.Context, call Call, decision *Decision, recoverExisting bool) (permitResponse, error) {
	operation := "claim"
	if recoverExisting {
		operation = "recover"
	}
	raw, err := c.approvalRequest(ctx, call, decision, operation)
	var permit permitResponse
	if err != nil || json.Unmarshal(raw, &permit) != nil || !uuidPattern.MatchString(permit.PermitID) || permit.ActionID != decision.ActionID || !permit.ExpiresAt.After(c.clock()) {
		return permitResponse{}, errors.New("approval claim unavailable or invalid")
	}
	return permit, nil
}

// Reconcile reports only the outcome established by the protected executor's
// provider lookup using the original idempotency key.
func (c *Client) Reconcile(ctx context.Context, recovery Recovery, providerReference, outcome string) (string, error) {
	if !validProviderReference(providerReference) || (outcome != "succeeded" && outcome != "failed") {
		return "", errors.New("reconciliation evidence is invalid")
	}
	reference := providerReference
	receipt, err := c.reportExecution(ctx, recovery, "reconciled_"+outcome, &reference)
	return receipt.State, err
}

func validProviderReference(value string) bool {
	if len(value) < 1 || len(value) > 4000 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 32 || character == 127 {
			return false
		}
	}
	return true
}

func (c *Client) reportExecution(ctx context.Context, recovery Recovery, event string, providerReference *string) (receiptResponse, error) {
	var receipt receiptResponse
	if !uuidPattern.MatchString(recovery.ActionID) || !uuidPattern.MatchString(recovery.AttemptID) ||
		(recovery.PermitID != nil && !uuidPattern.MatchString(*recovery.PermitID)) ||
		!digestPattern.MatchString(recovery.InputSHA256) || !keyPattern.MatchString(recovery.ProviderIdempotencyKey) {
		return receipt, errors.New("execution receipt is invalid")
	}
	validEvent := event == "started" || event == "succeeded" || event == "failed" || event == "unknown" || event == "reconciled_succeeded" || event == "reconciled_failed"
	if !validEvent || (providerReference != nil && !validProviderReference(*providerReference)) || (event == "started" && providerReference != nil) || (strings.HasPrefix(event, "reconciled_") && providerReference == nil) {
		return receipt, errors.New("execution evidence is invalid")
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
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusAccepted {
		return response.StatusCode, fmt.Errorf("sidecar returned HTTP %d", response.StatusCode)
	}
	if err := decodeBoundedResponse(response.Body, 128*1024, target); err != nil {
		return response.StatusCode, errors.New("sidecar response is invalid")
	}
	return response.StatusCode, nil
}
