package authrail

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type identityProof struct {
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Signature string `json:"signature"`
}

type identityStatement struct {
	Type                string      `json:"type"`
	OrganisationID      string      `json:"organisationId"`
	DeploymentID        string      `json:"deploymentId"`
	RequestID           string      `json:"requestId"`
	ActionKey           string      `json:"actionKey"`
	OperationVersionID  string      `json:"operationVersionId"`
	Phase               string      `json:"phase"`
	InputSHA256         string      `json:"inputSha256"`
	Attribution         attribution `json:"attribution"`
	ReviewSummarySHA256 string      `json:"reviewSummarySha256,omitempty"`
	IssuedAt            int64       `json:"issuedAt"`
	ExpiresAt           int64       `json:"expiresAt"`
}

// signIdentityProof binds the phase, canonical input digest, and application
// identity claims to one deployment and action; it does not verify those claims.
func (c *Client) signIdentityProof(call Call, phase string, result json.RawMessage) (identityProof, error) {
	encoded, err := encodeIdentityInput(call, phase, result)
	if err != nil {
		return identityProof{}, err
	}
	digest := sha256.Sum256(encoded)
	clock := c.clock
	if clock == nil {
		clock = time.Now
	}
	now := clock().Unix()
	proof := identityProof{IssuedAt: now, ExpiresAt: now + 30}
	statement := identityStatement{Type: "authrail.observe.executor.v1",
		OrganisationID: c.organisationID, DeploymentID: c.deploymentID,
		RequestID: call.RequestID, ActionKey: call.ActionKey,
		OperationVersionID: call.OperationVersionID, Phase: phase,
		InputSHA256: hex.EncodeToString(digest[:]),
		Attribution: attribution{PrincipalID: call.PrincipalID, SessionID: call.SessionID,
			ResourceID: optionalRef(call.ResourceID), PrincipalSource: call.PrincipalSource,
			ResourceSource: call.ResourceSource}, IssuedAt: now, ExpiresAt: now + 30}
	if call.ReviewSummary != nil && phase == "tool_call" {
		summary, err := json.Marshal(call.ReviewSummary)
		if err != nil {
			return identityProof{}, err
		}
		summaryDigest := sha256.Sum256(summary)
		statement.ReviewSummarySHA256 = hex.EncodeToString(summaryDigest[:])
	}
	message, err := json.Marshal(statement)
	if err != nil {
		return identityProof{}, err
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.executorPrivateKey, message))
	return proof, nil
}

// encodeIdentityInput matches the language-neutral signed call/result bytes.
func encodeIdentityInput(call Call, phase string, result json.RawMessage) ([]byte, error) {
	var args map[string]any
	if json.Unmarshal(call.Arguments, &args) != nil || args == nil {
		return nil, errors.New("Observe arguments are invalid")
	}
	input := struct {
		Arguments       map[string]any      `json:"arguments"`
		Result          map[string]any      `json:"result,omitempty"`
		FactResolutions []FactResolution    `json:"factResolutions,omitempty"`
		Trajectory      *TrajectorySnapshot `json:"trajectory,omitempty"`
	}{Arguments: args, FactResolutions: call.FactResolutions, Trajectory: call.Trajectory}
	if phase == "tool_result" {
		if json.Unmarshal(result, &input.Result) != nil || input.Result == nil {
			return nil, errors.New("Observe result is invalid")
		}
	}
	return json.Marshal(input)
}
