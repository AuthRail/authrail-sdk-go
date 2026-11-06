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
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// contextualFinding carries an AuthRail interpretation to the local evaluator.
// The evaluator verifies its signature and exact call binding before using it.
type contextualFinding struct {
	Payload   string `json:"payload"`
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

type contextualAssessment struct {
	ID       string          `json:"id"`
	Phase    string          `json:"phase"`
	Question string          `json:"question"`
	Fields   []GuardTarget   `json:"fields"`
	Answer   json.RawMessage `json:"answer"`
}
type contextualRequirement struct {
	RailVersionID string               `json:"railVersionId"`
	Assessment    contextualAssessment `json:"assessment"`
}
type contextualPlan struct {
	FormatVersion          int                     `json:"formatVersion"`
	OperationVersionID     string                  `json:"operationVersionId"`
	Phase                  string                  `json:"phase"`
	BundleID               string                  `json:"bundleId"`
	Sequence               int64                   `json:"sequence"`
	Coverage               string                  `json:"coverage"`
	Requirements           []contextualRequirement `json:"requirements"`
	DisclosureProcessing   bool                    `json:"disclosureProcessing"`
	DisclosureRequirements []GuardRequirement      `json:"disclosureRequirements"`
}
type contextualRequest struct {
	FormatVersion      int           `json:"formatVersion"`
	BundleID           string        `json:"bundleId"`
	RailVersionID      string        `json:"railVersionId"`
	AssessmentID       string        `json:"assessmentId"`
	OperationVersionID string        `json:"operationVersionId"`
	RequestID          string        `json:"requestId"`
	Phase              string        `json:"phase"`
	InputSHA256        string        `json:"inputSha256"`
	AttributionSHA256  string        `json:"attributionSha256"`
	Material           string        `json:"material"`
	KeySHA256          string        `json:"keySha256"`
	Proof              identityProof `json:"proof"`
}

// readContextual selects only reviewed fields. Interpretation failure leaves the
// finding absent; the deterministic rule handles that absence rather than a guessed answer.
func (c *Client) readContextual(ctx context.Context, call Call, phase string, result json.RawMessage) ([]contextualFinding, error) {
	query := url.Values{"operationVersionId": {call.OperationVersionID}, "phase": {phase}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(c.endpoint, "/evaluate")+"/contextual-requirements?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if !validTraceparent(call.Traceparent) {
		return nil, errors.New("trace context is invalid")
	}
	if call.Traceparent != "" {
		request.Header.Set("traceparent", call.Traceparent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, errors.New("Contextual AI requirements are unavailable")
	}
	defer response.Body.Close()
	// Older runtimes cannot satisfy contextual conditions and do not expose this route.
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("Contextual AI requirements are unavailable")
	}
	var plan contextualPlan
	if decodeContextualResponse(response.Body, 64*1024, &plan) != nil || plan.FormatVersion != 1 ||
		plan.OperationVersionID != call.OperationVersionID || plan.Phase != phase ||
		plan.Requirements == nil || len(plan.Requirements) > 8 {
		return nil, errors.New("Contextual AI requirements are invalid")
	}
	if (plan.Coverage == "uncovered" || plan.Coverage == "unavailable") && len(plan.Requirements) == 0 {
		return nil, nil
	}
	if !uuidPattern.MatchString(plan.BundleID) || plan.Coverage != "evaluated" {
		return nil, errors.New("Contextual AI requirements are invalid")
	}
	if plan.DisclosureProcessing || len(plan.DisclosureRequirements) > 0 {
		if !contextualDisclosureReady(plan, call, phase, result) {
			return nil, nil
		}
	}
	input, err := encodeIdentityInput(call, phase, result)
	if err != nil {
		return nil, err
	}
	inputDigest := sha256.Sum256(input)
	attributionBytes, err := json.Marshal(attribution{PrincipalID: call.PrincipalID, SessionID: call.SessionID,
		ResourceID: optionalRef(call.ResourceID), PrincipalSource: call.PrincipalSource, ResourceSource: call.ResourceSource})
	if err != nil {
		return nil, err
	}
	attributionDigest := sha256.Sum256(attributionBytes)
	keyDigest := sha256.Sum256(c.executorPrivateKey.Public().(ed25519.PublicKey))
	seen := map[string]bool{}
	findings := []contextualFinding{}
	for _, requirement := range plan.Requirements {
		assessment := requirement.Assessment
		identity := requirement.RailVersionID + ":" + assessment.ID
		if !uuidPattern.MatchString(requirement.RailVersionID) || !guardPathSegment.MatchString(assessment.ID) ||
			(assessment.Phase != "tool_call" && assessment.Phase != "tool_result") ||
			len(assessment.Fields) < 1 || len(assessment.Fields) > 4 || seen[identity] {
			return nil, errors.New("Contextual AI assessment is invalid")
		}
		seen[identity] = true
		selected, complete, err := contextualMaterial(assessment.Fields, call.Arguments, result, phase)
		if err != nil {
			return nil, err
		}
		if !complete {
			continue
		}
		material, err := json.Marshal(selected)
		if err != nil || len(material) > 16384 {
			continue
		}
		materialDigest := sha256.Sum256(material)
		now := c.clock().Unix()
		reading := contextualRequest{FormatVersion: 1, BundleID: plan.BundleID,
			RailVersionID: requirement.RailVersionID, AssessmentID: assessment.ID,
			OperationVersionID: call.OperationVersionID, RequestID: call.RequestID, Phase: phase,
			InputSHA256: hex.EncodeToString(inputDigest[:]), AttributionSHA256: hex.EncodeToString(attributionDigest[:]),
			Material: base64.RawURLEncoding.EncodeToString(material), KeySHA256: hex.EncodeToString(keyDigest[:]),
			Proof: identityProof{IssuedAt: now, ExpiresAt: now + 30}}
		statement := struct {
			Type               string `json:"type"`
			OrganisationID     string `json:"organisationId"`
			DeploymentID       string `json:"deploymentId"`
			BundleID           string `json:"bundleId"`
			RailVersionID      string `json:"railVersionId"`
			AssessmentID       string `json:"assessmentId"`
			OperationVersionID string `json:"operationVersionId"`
			RequestID          string `json:"requestId"`
			Phase              string `json:"phase"`
			InputSHA256        string `json:"inputSha256"`
			AttributionSHA256  string `json:"attributionSha256"`
			MaterialSHA256     string `json:"materialSha256"`
			KeySHA256          string `json:"keySha256"`
			IssuedAt           int64  `json:"issuedAt"`
			ExpiresAt          int64  `json:"expiresAt"`
		}{"authrail.contextual.request.v1", c.organisationID, c.deploymentID, reading.BundleID,
			reading.RailVersionID, reading.AssessmentID, reading.OperationVersionID, reading.RequestID,
			phase, reading.InputSHA256, reading.AttributionSHA256, hex.EncodeToString(materialDigest[:]), reading.KeySHA256, now, now + 30}
		message, err := json.Marshal(statement)
		if err != nil {
			return nil, err
		}
		reading.Proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.executorPrivateKey, message))
		finding, err := c.requestContextual(ctx, call, reading)
		if err == nil {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// A contextual disclosure must use the output of every required local processor
// for this exact bundle, rather than unrelated or stale processing evidence.
func contextualDisclosureReady(plan contextualPlan, call Call, phase string, result json.RawMessage) bool {
	if !plan.DisclosureProcessing || len(plan.DisclosureRequirements) == 0 || len(plan.DisclosureRequirements) > 128 {
		return false
	}
	for _, requirement := range plan.DisclosureRequirements {
		processingPhase := "tool_call"
		if requirement.Target.Root == "result" {
			processingPhase = "tool_result"
		}
		if phase == "tool_call" && processingPhase == "tool_result" {
			return false
		}
		if !uuidPattern.MatchString(requirement.RailVersionID) || !guardIdentifier.MatchString(requirement.RuleID) ||
			!guardIdentifier.MatchString(requirement.HandlerID) || !digestPattern.MatchString(requirement.HandlerVersion) ||
			(requirement.Kind != "sanitize" && requirement.Kind != "transform" && requirement.Kind != "isolate") ||
			!validGuardTarget(requirement.Target, processingPhase) {
			return false
		}
		selected, complete, err := contextualMaterial([]GuardTarget{requirement.Target}, call.Arguments, result, phase)
		if err != nil || !complete {
			return false
		}
		matches := 0
		for _, evidence := range call.GuardEvidence {
			candidate := GuardRequirement{Kind: evidence.Kind, HandlerID: evidence.HandlerID,
				HandlerVersion: evidence.HandlerVersion, Target: evidence.Target}
			if evidence.Phase == processingPhase && evidence.BundleID == plan.BundleID && guardRequirementsEqual(requirement, candidate) &&
				evidence.OutputSHA256 == guardStringDigest(selected[0]) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func contextualMaterial(fields []GuardTarget, arguments, result json.RawMessage, phase string) ([]string, bool, error) {
	selected := []string{}
	for _, target := range fields {
		if (target.Root != "arguments" && target.Root != "result") || phase == "tool_call" && target.Root == "result" ||
			len(target.Path) < 1 || len(target.Path) > 8 {
			return nil, false, errors.New("Contextual AI field is invalid")
		}
		for _, part := range target.Path {
			if !guardPathSegment.MatchString(part) || part == "__proto__" || part == "prototype" || part == "constructor" {
				return nil, false, errors.New("Contextual AI field is invalid")
			}
		}
		source := arguments
		if target.Root == "result" {
			source = result
		}
		var value any
		if json.Unmarshal(source, &value) != nil {
			return nil, false, nil
		}
		for _, part := range target.Path {
			object, ok := value.(map[string]any)
			if !ok {
				return nil, false, nil
			}
			value = object[part]
		}
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, false, nil
		}
		selected = append(selected, text)
	}
	return selected, true, nil
}

func (c *Client) requestContextual(ctx context.Context, call Call, reading contextualRequest) (contextualFinding, error) {
	var finding contextualFinding
	body, err := json.Marshal(reading)
	if err != nil {
		return finding, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost,
		strings.TrimSuffix(c.endpoint, "/evaluate")+"/contextual-readings", bytes.NewReader(body))
	if err != nil {
		return finding, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	if call.Traceparent != "" {
		request.Header.Set("traceparent", call.Traceparent)
	}
	// Hosted interpretation has its own bounded deadline; ordinary local checks retain theirs.
	client := *c.http
	client.Timeout = 12 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return finding, errors.New("Contextual AI reading is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || decodeContextualResponse(response.Body, 8192, &finding) != nil ||
		finding.Payload == "" || len(finding.Payload) > 4096 || finding.KeyID == "" ||
		finding.Algorithm != "ECDSA_SHA_256" || finding.Signature == "" {
		return contextualFinding{}, errors.New("Contextual AI finding is unavailable")
	}
	return finding, nil
}

func decodeContextualResponse(body io.Reader, maximum int64, target any) error {
	encoded, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil || int64(len(encoded)) > maximum {
		return errors.New("Contextual AI response exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("Contextual AI response is invalid")
	}
	return nil
}
