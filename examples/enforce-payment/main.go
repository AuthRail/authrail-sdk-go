package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	authrail "github.com/AuthRail/authrail-sdk-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Go protected HTTP handler Enforce call and result retained")
}

func run() error {
	privatePEM, err := os.ReadFile(os.Getenv("AUTHRAIL_EXECUTOR_PRIVATE_KEY_FILE"))
	if err != nil {
		return err
	}
	privateKey, err := authrail.ParseExecutorPrivateKeyPEM(privatePEM)
	if err != nil {
		return err
	}
	client, err := authrail.NewClient(authrail.Config{
		SidecarURL:         os.Getenv("AUTHRAIL_SIDECAR_URL"),
		AdapterToken:       os.Getenv("AUTHRAIL_ADAPTER_TOKEN"),
		OrganisationID:     os.Getenv("AUTHRAIL_ORGANISATION_ID"),
		DeploymentID:       os.Getenv("AUTHRAIL_DEPLOYMENT_ID"),
		ExecutorPrivateKey: privateKey,
	})
	if err != nil {
		return err
	}
	// This ledger stands in for an idempotent provider behind the protected handler.
	providerLedger := map[string]bool{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input map[string]any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid input", http.StatusBadRequest)
			return
		}
		output, call, result, err := authrail.Enforce(r.Context(), client, authrail.Operation{
			VersionID: os.Getenv("AUTHRAIL_OPERATION_VERSION_ID"),
			ActionKey: "go-slice9-enforce", PrincipalID: "staff_123",
			PrincipalSource: "application_session", SessionID: "go_http_123",
			ResourceSource: "not_applicable",
		}, input, func(_ context.Context, checked map[string]any,
			recovery authrail.ExecutionContext) (map[string]any, error) {
			if checked["amount"] != float64(20) || recovery.ProviderIdempotencyKey == "" {
				return nil, fmt.Errorf("protected input or provider key changed")
			}
			providerLedger[recovery.ProviderIdempotencyKey] = true
			return map[string]any{"accepted": true}, nil
		})
		if err != nil || call == nil || result == nil ||
			call.RecordingStatus != "retained" || result.RecordingStatus != "retained" {
			http.Error(w, "protected operation unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(output)
	})
	request := httptest.NewRequest(http.MethodPost, "/payments",
		strings.NewReader(`{"amount":20}`))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(providerLedger) != 1 {
		return fmt.Errorf("protected HTTP request failed: %d", response.Code)
	}
	return nil
}
