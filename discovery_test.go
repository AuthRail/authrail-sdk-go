package authrail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverUsesScopedSetupKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/runtime/discovery" ||
			request.Header.Get("Authorization") != "Bearer setup-key" {
			t.Errorf("unexpected discovery request")
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"inventoryItemId":"11111111-1111-4111-8111-111111111111","inventoryRevisionId":"22222222-2222-4222-8222-222222222222","deploymentId":"33333333-3333-4333-8333-333333333333","confirmationStatus":"discovered"}`))
	}))
	defer server.Close()
	result, err := Discover(context.Background(), DiscoveryConfig{
		ControlPlaneURL: server.URL, SetupKey: "setup-key", AgentKey: "support.agent",
	})
	if err != nil || result.ConfirmationStatus != "discovered" {
		t.Fatalf("unexpected result: %#v, %v", result, err)
	}
}

func TestDiscoverRejectsRedirectAndUntrustedURL(t *testing.T) {
	_, err := Discover(context.Background(), DiscoveryConfig{
		ControlPlaneURL: "http://example.com", SetupKey: "setup-key", AgentKey: "agent",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected URL rejection, got %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://example.com", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	_, err = Discover(context.Background(), DiscoveryConfig{
		ControlPlaneURL: server.URL, SetupKey: "setup-key", AgentKey: "agent",
	})
	if err == nil {
		t.Fatal("redirect must not succeed")
	}
}

func TestDiscoverRejectsRevokedKeyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := Discover(context.Background(), DiscoveryConfig{
		ControlPlaneURL: server.URL, SetupKey: "revoked-key", AgentKey: "agent",
	})
	if err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("expected rejected discovery, got %v", err)
	}
}
