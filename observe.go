package authrail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
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
	endpoint           string
	token              string
	http               *http.Client
	organisationID     string
	deploymentID       string
	executorPrivateKey ed25519.PrivateKey
}

type Config struct {
	SidecarURL         string
	AdapterToken       string
	HTTPClient         *http.Client
	OrganisationID     string
	DeploymentID       string
	ExecutorPrivateKey ed25519.PrivateKey
}

// Operation identifies the reviewed action and a stable key from the workflow.
type Operation struct {
	VersionID       string
	ActionKey       string
	PrincipalID     string
	SessionID       string
	ResourceID      string
	PrincipalSource string
	ResourceSource  string
}

type Call struct {
	RequestID          string
	OperationVersionID string
	ActionKey          string
	PrincipalID        string
	SessionID          string
	ResourceID         string
	PrincipalSource    string
	ResourceSource     string
	Arguments          json.RawMessage
}

type attribution struct {
	PrincipalID     string  `json:"principalId"`
	SessionID       string  `json:"sessionId"`
	ResourceID      *string `json:"resourceId"`
	PrincipalSource string  `json:"principalSource,omitempty"`
	ResourceSource  string  `json:"resourceSource,omitempty"`
}

type Decision struct {
	RequestID       string   `json:"requestId"`
	Mode            string   `json:"mode"`
	Enforced        bool     `json:"enforced"`
	Coverage        string   `json:"coverage"`
	Outcome         string   `json:"outcome"`
	Sequence        int64    `json:"sequence"`
	BundleID        *string  `json:"bundleId"`
	RailVersionIDs  []string `json:"railVersionIds"`
	MatchedRuleIDs  []string `json:"matchedRuleIds"`
	ReasonCodes     []string `json:"reasonCodes"`
	RecordingStatus string   `json:"recordingStatus"`
	ActionID        string   `json:"actionId"`
	CertificateID   string   `json:"certificateId"`
	Unresolved      []struct {
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

func NewClient(config Config) (*Client, error) {
	u, err := url.Parse(config.SidecarURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" || u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return nil, errors.New("sidecar URL must be a local HTTP address")
	}
	if len(config.AdapterToken) < 32 {
		return nil, errors.New("adapter token must have at least 32 characters")
	}
	if !uuidPattern.MatchString(config.OrganisationID) || !uuidPattern.MatchString(config.DeploymentID) ||
		len(config.ExecutorPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("deployment identity and executor signing key are required")
	}
	derived := ed25519.NewKeyFromSeed(config.ExecutorPrivateKey.Seed())
	if subtle.ConstantTimeCompare(derived, config.ExecutorPrivateKey) != 1 {
		return nil, errors.New("executor signing key is invalid")
	}
	transport := config.HTTPClient
	if transport == nil {
		transport = &http.Client{}
	}
	copyClient := *transport
	if copyClient.Timeout == 0 || copyClient.Timeout > 2*time.Second {
		copyClient.Timeout = 2 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: strings.TrimRight(config.SidecarURL, "/") + "/evaluate", token: config.AdapterToken, http: &copyClient,
		organisationID: config.OrganisationID, deploymentID: config.DeploymentID,
		executorPrivateKey: append(ed25519.PrivateKey(nil), config.ExecutorPrivateKey...)}, nil
}

// Observe wraps a function while preserving its Go result and error. The
// buffered channel reports advisory checks after the function returns.
func Observe[Input, Output any](ctx context.Context, client *Client, operation Operation,
	input Input, execute func(context.Context) (Output, error)) (Output, <-chan Observation, error) {
	var output Output
	if execute == nil {
		return output, nil, errors.New("tool function is required")
	}
	if client == nil {
		output, toolError := execute(ctx)
		completed := make(chan Observation, 1)
		completed <- Observation{CallError: errors.New("sidecar client is missing"),
			ResultError: errors.New("sidecar client is missing")}
		close(completed)
		return output, completed, toolError
	}
	requestID, requestError := newRequestID()
	arguments, argumentError := json.Marshal(input)
	if requestError != nil || argumentError != nil {
		arguments = nil
	}
	call := Call{RequestID: requestID, OperationVersionID: operation.VersionID,
		ActionKey: operation.ActionKey, PrincipalID: operation.PrincipalID,
		SessionID: operation.SessionID, ResourceID: operation.ResourceID,
		PrincipalSource: operation.PrincipalSource, ResourceSource: operation.ResourceSource,
		Arguments: arguments}
	raw, completed, toolError := client.observeRaw(ctx, call, func(ctx context.Context) (json.RawMessage, error) {
		var err error
		output, err = execute(ctx)
		if err != nil {
			return nil, err
		}
		encoded, marshalError := json.Marshal(output)
		if marshalError != nil {
			return nil, nil
		}
		return encoded, nil
	})
	_ = raw
	return output, completed, toolError
}

// observeRaw starts checks without delaying or changing the tool's execution.
func (c *Client) observeRaw(ctx context.Context, call Call,
	execute func(context.Context) (json.RawMessage, error)) (json.RawMessage, <-chan Observation, error) {
	if execute == nil {
		return nil, nil, errors.New("tool function is required")
	}
	if !uuidPattern.MatchString(call.RequestID) ||
		!uuidPattern.MatchString(call.OperationVersionID) || !keyPattern.MatchString(call.ActionKey) ||
		!keyPattern.MatchString(call.PrincipalID) || !keyPattern.MatchString(call.SessionID) ||
		(call.ResourceID != "" && !keyPattern.MatchString(call.ResourceID)) ||
		!jsonObject(call.Arguments) {
		result, toolError := execute(ctx)
		completed := make(chan Observation, 1)
		completed <- Observation{CallError: errors.New("Observe call contract is invalid"),
			ResultError: errors.New("Observe call contract is invalid")}
		close(completed)
		return result, completed, toolError
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

func newRequestID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

func (c *Client) evaluate(ctx context.Context, call Call, phase string, result json.RawMessage) (*Decision, error) {
	proof, err := c.signIdentityProof(call, phase, result)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		FormatVersion      int             `json:"formatVersion"`
		RequestID          string          `json:"requestId"`
		OperationVersionID string          `json:"operationVersionId"`
		Phase              string          `json:"phase"`
		Arguments          json.RawMessage `json:"arguments"`
		Result             json.RawMessage `json:"result,omitempty"`
		Attribution        attribution     `json:"attribution"`
		IdentityProof      identityProof   `json:"identityProof"`
	}{FormatVersion: 1, RequestID: call.RequestID, OperationVersionID: call.OperationVersionID,
		Phase: phase, Arguments: call.Arguments, Result: result,
		Attribution: attribution{PrincipalID: call.PrincipalID,
			SessionID: call.SessionID, ResourceID: optionalRef(call.ResourceID),
			PrincipalSource: call.PrincipalSource, ResourceSource: call.ResourceSource}, IdentityProof: proof})
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

func optionalRef(value string) *string {
	if value == "" {
		return nil
	}
	return &value
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
