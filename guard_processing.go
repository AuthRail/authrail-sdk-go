package authrail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var guardIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,79}$`)
var guardPathSegment = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)

// GuardHandler is application-owned processing for one exact reviewed handler
// version. Process receives only its target string and must honour cancellation.
// Registering a handler does not establish independent code or isolation proof.
type GuardHandler struct {
	ID      string
	Version string
	Kind    string
	Process func(context.Context, string) (string, error)
}

// GuardTarget identifies one reviewed string field in the call or result.
type GuardTarget struct {
	Root string   `json:"root"`
	Path []string `json:"path"`
}

// GuardEvidence binds the executor's processing assertion to the exact bundle
// and before/after values. It is not business permission or handler-code proof.
type GuardEvidence struct {
	Phase          string      `json:"phase"`
	BundleID       string      `json:"bundleId"`
	Kind           string      `json:"kind"`
	HandlerID      string      `json:"handlerId"`
	HandlerVersion string      `json:"handlerVersion"`
	Target         GuardTarget `json:"target"`
	InputSHA256    string      `json:"inputSha256"`
	OutputSHA256   string      `json:"outputSha256"`
}

// MarshalJSON preserves canonical sorted keys inside signed evidence arrays.
func (e GuardEvidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"phase": e.Phase, "bundleId": e.BundleID,
		"kind": e.Kind, "handlerId": e.HandlerID, "handlerVersion": e.HandlerVersion,
		"target":      map[string]any{"root": e.Target.Root, "path": e.Target.Path},
		"inputSha256": e.InputSHA256, "outputSha256": e.OutputSHA256})
}

// GuardRequirement names one exact published rule and its required processing.
type GuardRequirement struct {
	RailVersionID  string      `json:"railVersionId"`
	RuleID         string      `json:"ruleId"`
	Kind           string      `json:"kind"`
	HandlerID      string      `json:"handlerId"`
	HandlerVersion string      `json:"handlerVersion"`
	Target         GuardTarget `json:"target"`
}

// GuardObligationStatus reports whether a requirement was fulfilled by the
// executor evidence; this assertion does not independently verify handler code.
type GuardObligationStatus struct {
	GuardRequirement
	Status       string `json:"status"`
	InputSHA256  string `json:"inputSha256,omitempty"`
	OutputSHA256 string `json:"outputSha256,omitempty"`
}

type guardPlan struct {
	FormatVersion      int                `json:"formatVersion"`
	OperationVersionID string             `json:"operationVersionId"`
	Phase              string             `json:"phase"`
	BundleID           string             `json:"bundleId"`
	Sequence           int64              `json:"sequence"`
	Coverage           string             `json:"coverage"`
	Requirements       []GuardRequirement `json:"requirements"`
}

func registeredGuardHandlers(handlers []GuardHandler) ([]GuardHandler, error) {
	if len(handlers) > 64 {
		return nil, errors.New("too many Guard handlers")
	}
	seen := make(map[string]bool)
	for _, handler := range handlers {
		key := handler.Kind + ":" + handler.ID + ":" + handler.Version
		if !guardIdentifier.MatchString(handler.ID) || !digestPattern.MatchString(handler.Version) ||
			(handler.Kind != "sanitize" && handler.Kind != "transform") || handler.Process == nil || seen[key] {
			return nil, errors.New("Guard handler registration is invalid")
		}
		seen[key] = true
	}
	return append([]GuardHandler(nil), handlers...), nil
}

func (c *Client) guardRequirements(ctx context.Context, call Call, phase string) (guardPlan, error) {
	var plan guardPlan
	query := url.Values{"operationVersionId": {call.OperationVersionID}, "phase": {phase}}
	requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet,
		strings.TrimSuffix(c.endpoint, "/evaluate")+"/guard-requirements?"+query.Encode(), nil)
	if err != nil {
		return plan, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if !validTraceparent(call.Traceparent) {
		return plan, errors.New("trace context is invalid")
	}
	if call.Traceparent != "" {
		request.Header.Set("traceparent", call.Traceparent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return plan, errors.New("Guard requirements are unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return plan, errors.New("Guard requirements are unavailable")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(encoded) > 64*1024 {
		return plan, errors.New("Guard requirements exceed their bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF ||
		plan.FormatVersion != 1 || plan.OperationVersionID != call.OperationVersionID || plan.Phase != phase ||
		!uuidPattern.MatchString(plan.BundleID) || plan.Sequence < 1 || plan.Coverage != "evaluated" ||
		plan.Requirements == nil || len(plan.Requirements) > 64 {
		return guardPlan{}, errors.New("Guard requirements contract is invalid")
	}
	for _, requirement := range plan.Requirements {
		if !uuidPattern.MatchString(requirement.RailVersionID) || !guardIdentifier.MatchString(requirement.RuleID) ||
			!guardIdentifier.MatchString(requirement.HandlerID) || !digestPattern.MatchString(requirement.HandlerVersion) ||
			(requirement.Kind != "sanitize" && requirement.Kind != "transform" && requirement.Kind != "isolate") ||
			!validGuardTarget(requirement.Target, phase) {
			return guardPlan{}, errors.New("Guard requirement is invalid")
		}
	}
	return plan, nil
}

func validGuardTarget(target GuardTarget, phase string) bool {
	if (phase == "tool_call" && target.Root != "arguments") ||
		(phase == "tool_result" && target.Root != "result") || len(target.Path) < 1 || len(target.Path) > 8 {
		return false
	}
	for _, segment := range target.Path {
		if !guardPathSegment.MatchString(segment) || segment == "__proto__" || segment == "prototype" || segment == "constructor" {
			return false
		}
	}
	return true
}

func guardRequirementsEqual(left, right GuardRequirement) bool {
	return left.Kind == right.Kind && left.HandlerID == right.HandlerID && left.HandlerVersion == right.HandlerVersion &&
		left.Target.Root == right.Target.Root && strings.Join(left.Target.Path, ".") == strings.Join(right.Target.Path, ".")
}

func guardTargetsOverlap(left, right GuardTarget) bool {
	if left.Root != right.Root {
		return false
	}
	for index := 0; index < len(left.Path) && index < len(right.Path); index++ {
		if left.Path[index] != right.Path[index] {
			return false
		}
	}
	return true
}

func (c *Client) processGuardPhase(ctx context.Context, call Call, phase string, result json.RawMessage) (Call, json.RawMessage, error) {
	if len(c.guardHandlers) == 0 {
		return call, result, nil
	}
	plan, err := c.guardRequirements(ctx, call, phase)
	if err != nil {
		return call, nil, err
	}
	unique := make([]GuardRequirement, 0, len(plan.Requirements))
	for _, requirement := range plan.Requirements {
		duplicate := false
		for _, prior := range unique {
			if guardRequirementsEqual(prior, requirement) {
				duplicate = true
				break
			}
			if guardTargetsOverlap(prior.Target, requirement.Target) {
				return call, nil, errors.New("Guard processing targets conflict")
			}
		}
		if !duplicate {
			unique = append(unique, requirement)
		}
	}
	// Resolve every handler before processing any value. An unsupported isolation
	// request can never be represented as successful string processing.
	handlers := make([]GuardHandler, 0, len(unique))
	for _, requirement := range unique {
		var matched *GuardHandler
		for _, handler := range c.guardHandlers {
			if requirement.Kind == handler.Kind && requirement.HandlerID == handler.ID && requirement.HandlerVersion == handler.Version {
				copy := handler
				matched = &copy
				break
			}
		}
		if matched == nil {
			return call, nil, errors.New("required Guard handler is unsupported")
		}
		handlers = append(handlers, *matched)
	}
	raw := call.Arguments
	if phase == "tool_result" {
		raw = result
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil || object == nil {
		return call, nil, errors.New("Guard target is not a JSON object")
	}
	evidence := append([]GuardEvidence(nil), call.GuardEvidence...)
	for index, requirement := range unique {
		parent := object
		for _, segment := range requirement.Target.Path[:len(requirement.Target.Path)-1] {
			child, ok := parent[segment].(map[string]any)
			if !ok {
				return call, nil, errors.New("Guard target is unavailable")
			}
			parent = child
		}
		field := requirement.Target.Path[len(requirement.Target.Path)-1]
		before, ok := parent[field].(string)
		if !ok || !utf8.ValidString(before) {
			return call, nil, errors.New("Guard target is not a string")
		}
		after, err := runGuardHandler(ctx, handlers[index], before)
		if err != nil || !utf8.ValidString(after) || len(after) > 64*1024 {
			return call, nil, errors.New("Guard processing failed")
		}
		parent[field] = after
		evidence = append(evidence, GuardEvidence{Phase: phase, BundleID: plan.BundleID,
			Kind: requirement.Kind, HandlerID: requirement.HandlerID, HandlerVersion: requirement.HandlerVersion,
			Target: requirement.Target, InputSHA256: guardStringDigest(before), OutputSHA256: guardStringDigest(after)})
	}
	encoded, err := json.Marshal(object)
	if err != nil || len(encoded) > 64*1024 || len(evidence) > 128 {
		return call, nil, errors.New("processed Guard input exceeds its bound")
	}
	call.GuardEvidence = evidence
	call.guardBundleID, call.guardSequence = plan.BundleID, plan.Sequence
	if phase == "tool_call" {
		call.Arguments = encoded
	} else {
		result = encoded
	}
	return call, result, nil
}

func runGuardHandler(ctx context.Context, handler GuardHandler, input string) (output string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	type result struct {
		output string
		err    error
	}
	done := make(chan result, 1)
	// A broken handler cannot hold the protected caller past cancellation. It
	// may continue locally, so processors must never perform business effects.
	go func() {
		value := result{}
		defer func() {
			if recover() != nil {
				value.err = errors.New("Guard handler failed")
			}
			done <- value
		}()
		value.output, value.err = handler.Process(bounded, input)
	}()
	select {
	case <-bounded.Done():
		return "", bounded.Err()
	case value := <-done:
		if bounded.Err() != nil {
			return "", bounded.Err()
		}
		return value.output, value.err
	}
}

func guardStringDigest(value string) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func callGuardEvidence(evidence []GuardEvidence) []GuardEvidence {
	var filtered []GuardEvidence
	for _, entry := range evidence {
		if entry.Phase == "tool_call" {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
