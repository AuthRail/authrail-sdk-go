package authrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Client talks only to a sidecar on the same host. It has no deployment credential.
type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

type Call struct {
	RequestID          string
	OperationVersionID string
	ActionKey          string
	Arguments          json.RawMessage
}

type Decision struct {
	RequestID      string   `json:"requestId"`
	Mode           string   `json:"mode"`
	Enforced       bool     `json:"enforced"`
	Coverage       string   `json:"coverage"`
	Outcome        string   `json:"outcome"`
	Sequence       int64    `json:"sequence"`
	BundleID       *string  `json:"bundleId"`
	RailVersionIDs []string `json:"railVersionIds"`
	MatchedRuleIDs []string `json:"matchedRuleIds"`
	ReasonCodes    []string `json:"reasonCodes"`
	Unresolved     []struct {
		Root   string   `json:"root"`
		Path   []string `json:"path"`
		Reason string   `json:"reason"`
	} `json:"unresolved"`
}

// Observation reports both decision checks. Errors are coverage gaps, not tool errors.
type Observation struct {
	CallDecision   *Decision
	ResultDecision *Decision
	CallError      error
	ResultError    error
}

func NewClient(sidecarURL, adapterToken string, transport *http.Client) (*Client, error) {
	u, err := url.Parse(sidecarURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" || u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return nil, errors.New("sidecar URL must be a local HTTP address")
	}
	if len(adapterToken) < 32 {
		return nil, errors.New("adapter token must have at least 32 characters")
	}
	if transport == nil {
		transport = &http.Client{}
	}
	copyClient := *transport
	if copyClient.Timeout == 0 || copyClient.Timeout > 2*time.Second {
		copyClient.Timeout = 2 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: strings.TrimRight(sidecarURL, "/") + "/evaluate", token: adapterToken, http: &copyClient}, nil
}

// Observe starts advisory checks, runs the tool once, and returns its result
// without waiting for the sidecar. The buffered channel delivers diagnostics
// after the call and result checks finish.
func (c *Client) Observe(ctx context.Context, call Call,
	execute func(context.Context) (json.RawMessage, error)) (json.RawMessage, <-chan Observation, error) {
	if execute == nil || !uuidPattern.MatchString(call.RequestID) ||
		!uuidPattern.MatchString(call.OperationVersionID) || !keyPattern.MatchString(call.ActionKey) ||
		!jsonObject(call.Arguments) {
		return nil, nil, errors.New("call contract is invalid")
	}
	observation := make(chan Observation, 1)
	checkContext := context.WithoutCancel(ctx)
	callCheck := make(chan Observation, 1)
	go func() {
		decision, err := c.evaluate(checkContext, call, "tool_call", nil)
		callCheck <- Observation{CallDecision: decision, CallError: err}
	}()
	result, toolError := execute(ctx)
	resultCheck := make(chan Observation, 1)
	if toolError == nil {
		if jsonObject(result) {
			go func() {
				decision, err := c.evaluate(checkContext, call, "tool_result", result)
				resultCheck <- Observation{ResultDecision: decision, ResultError: err}
			}()
		} else {
			resultCheck <- Observation{ResultError: errors.New("tool result is not a JSON object")}
		}
	} else {
		resultCheck <- Observation{ResultError: errors.New("tool result unavailable after tool error")}
	}
	go func() {
		callObservation := <-callCheck
		resultObservation := <-resultCheck
		callObservation.ResultDecision = resultObservation.ResultDecision
		callObservation.ResultError = resultObservation.ResultError
		observation <- callObservation
		close(observation)
	}()
	return result, observation, toolError
}

func (c *Client) evaluate(ctx context.Context, call Call, phase string, result json.RawMessage) (*Decision, error) {
	body, err := json.Marshal(struct {
		FormatVersion      int             `json:"formatVersion"`
		RequestID          string          `json:"requestId"`
		OperationVersionID string          `json:"operationVersionId"`
		Phase              string          `json:"phase"`
		Arguments          json.RawMessage `json:"arguments"`
		Result             json.RawMessage `json:"result,omitempty"`
	}{1, call.RequestID, call.OperationVersionID, phase, call.Arguments, result})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Idempotency-Key", call.ActionKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sidecar unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sidecar returned HTTP %d", response.StatusCode)
	}
	var decision Decision
	if err := json.NewDecoder(io.LimitReader(response.Body, 128*1024)).Decode(&decision); err != nil {
		return nil, errors.New("sidecar decision is invalid")
	}
	if decision.RequestID != call.RequestID || decision.Mode != "observe" || decision.Enforced ||
		(decision.Coverage != "evaluated" && decision.Coverage != "uncovered" && decision.Coverage != "unavailable") ||
		!validOutcome(decision.Outcome) {
		return nil, errors.New("sidecar decision contract is invalid")
	}
	return &decision, nil
}

func validOutcome(value string) bool {
	switch value {
	case "allow", "deny", "approval_required", "additional_context_required", "indeterminate":
		return true
	default:
		return false
	}
}

func jsonObject(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return false
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return false
	}
	return true
}
