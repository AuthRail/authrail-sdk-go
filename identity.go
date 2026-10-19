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
	Type               string      `json:"type"`
	OrganisationID     string      `json:"organisationId"`
	DeploymentID       string      `json:"deploymentId"`
	RequestID          string      `json:"requestId"`
	ActionKey          string      `json:"actionKey"`
	OperationVersionID string      `json:"operationVersionId"`
	Phase              string      `json:"phase"`
	InputSHA256        string      `json:"inputSha256"`
	Attribution        attribution `json:"attribution"`
	IssuedAt           int64       `json:"issuedAt"`
	ExpiresAt          int64       `json:"expiresAt"`
}

func (c *Client) signIdentityProof(call Call, phase string, result json.RawMessage) (identityProof, error) {
	var args map[string]any
	if json.Unmarshal(call.Arguments, &args) != nil || args == nil {
		return identityProof{}, errors.New("Observe arguments are invalid")
	}
	input := struct {
		Arguments       map[string]any   `json:"arguments"`
		Result          map[string]any   `json:"result,omitempty"`
		FactResolutions []FactResolution `json:"factResolutions,omitempty"`
	}{Arguments: args, FactResolutions: call.FactResolutions}
	if phase == "tool_result" {
		if json.Unmarshal(result, &input.Result) != nil || input.Result == nil {
			return identityProof{}, errors.New("Observe result is invalid")
		}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return identityProof{}, err
	}
	digest := sha256.Sum256(encoded)
	now := time.Now().Unix()
	proof := identityProof{IssuedAt: now, ExpiresAt: now + 30}
	statement := identityStatement{Type: "authrail.observe.executor.v1",
		OrganisationID: c.organisationID, DeploymentID: c.deploymentID,
		RequestID: call.RequestID, ActionKey: call.ActionKey,
		OperationVersionID: call.OperationVersionID, Phase: phase,
		InputSHA256: hex.EncodeToString(digest[:]),
		Attribution: attribution{PrincipalID: call.PrincipalID, SessionID: call.SessionID,
			ResourceID: optionalRef(call.ResourceID), PrincipalSource: call.PrincipalSource,
			ResourceSource: call.ResourceSource}, IssuedAt: now, ExpiresAt: now + 30}
	message, err := json.Marshal(statement)
	if err != nil {
		return identityProof{}, err
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.executorPrivateKey, message))
	return proof, nil
}
