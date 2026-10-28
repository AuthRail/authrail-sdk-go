package authrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DiscoveryConfig holds a short-lived setup key, separate from sidecar and deployment credentials.
type DiscoveryConfig struct {
	ControlPlaneURL string
	SetupKey        string
	AgentKey        string
	HTTPClient      *http.Client
}

// Discovery identifies the unconfirmed or confirmed Inventory item and its Observe deployment.
type Discovery struct {
	InventoryItemID     string `json:"inventoryItemId"`
	InventoryRevisionID string `json:"inventoryRevisionId"`
	DeploymentID        string `json:"deploymentId"`
	ConfirmationStatus  string `json:"confirmationStatus"`
}

// Discover resolves a scoped agent key. The setup key authenticates only discovery;
// it is never passed to the sidecar and cannot authorize a protected operation.
func Discover(ctx context.Context, config DiscoveryConfig) (Discovery, error) {
	var result Discovery
	endpoint, err := url.Parse(config.ControlPlaneURL)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "" || endpoint.Host == "" ||
		(endpoint.Scheme != "https" && !(endpoint.Scheme == "http" &&
			(endpoint.Hostname() == "127.0.0.1" || endpoint.Hostname() == "::1"))) {
		return result, errors.New("control plane URL must use HTTPS or local loopback HTTP")
	}
	if !keyPattern.MatchString(config.AgentKey) || config.SetupKey == "" {
		return result, errors.New("setup key and valid agent key are required")
	}
	body, err := json.Marshal(struct {
		AgentKey string `json:"agentKey"`
	}{AgentKey: config.AgentKey})
	if err != nil {
		return result, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(config.ControlPlaneURL, "/")+"/runtime/discovery", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	request.Header.Set("Authorization", "Bearer "+config.SetupKey)
	request.Header.Set("Content-Type", "application/json")
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	copyClient := *client
	if copyClient.Timeout == 0 || copyClient.Timeout > 5*time.Second {
		copyClient.Timeout = 5 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return result, errors.New("AI system discovery was not accepted; check the setup key and deployment status")
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&result); err != nil {
		return Discovery{}, errors.New("AI system discovery returned an invalid response")
	}
	if !uuidPattern.MatchString(result.InventoryItemID) ||
		!uuidPattern.MatchString(result.InventoryRevisionID) ||
		!uuidPattern.MatchString(result.DeploymentID) ||
		(result.ConfirmationStatus != "discovered" && result.ConfirmationStatus != "confirmed") {
		return Discovery{}, errors.New("AI system discovery returned an invalid response")
	}
	return result, nil
}
