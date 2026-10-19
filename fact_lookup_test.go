package authrail

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type factTransport func(*http.Request) (*http.Response, error)

func (transport factTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func stripeSource(transport factTransport) StripeInvoiceSource {
	return StripeInvoiceSource{SourceVersionID: "00000000-0000-4000-8000-000000000008",
		ProviderAccountID: "acct_12345678", ConnectedAccount: true, Timeout: time.Second,
		SecretKey: "sk_test_private", HTTPClient: &http.Client{Transport: transport}}
}

func TestStripeDirectAccountVerifiesCredentialBeforeInvoice(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		accountID string
		expected  string
		calls     int
	}{{"matching account", "acct_12345678", "ok", 2},
		{"wrong account", "acct_87654321", "untrusted", 1}} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			source := stripeSource(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Header.Get("Stripe-Account") != "" {
					t.Fatal("direct account request used a Connect header")
				}
				if request.URL.Path == "/v1/account" {
					return stripeResponse(http.StatusOK, `{"id":"`+scenario.accountID+`","object":"account"}`), nil
				}
				if request.URL.Path != "/v1/invoices/in_1234" || calls != 2 {
					t.Fatalf("unexpected Stripe request: %s", request.URL)
				}
				return stripeResponse(http.StatusOK, `{"id":"in_1234","object":"invoice","status":"paid"}`), nil
			})
			source.ConnectedAccount = false
			resolution, err := LookupStripeInvoiceStatus(context.Background(), source, "in_1234")
			if err != nil || resolution.Status != scenario.expected || calls != scenario.calls {
				t.Fatalf("direct account boundary failed: %+v, %v; calls=%d", resolution, err, calls)
			}
		})
	}
}

func TestStripeDirectAccountFailureNeverReadsInvoice(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		status   int
		body     string
		expected string
	}{{"provider outage", http.StatusServiceUnavailable, `{}`, "unavailable"},
		{"redirect", http.StatusFound, `{}`, "unavailable"},
		{"malformed account", http.StatusOK, `{"id":"acct_12345678","object":"customer"}`, "untrusted"}} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			source := stripeSource(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Path != "/v1/account" {
					t.Fatal("invoice was read without verified direct account")
				}
				response := stripeResponse(scenario.status, scenario.body)
				response.Header = make(http.Header)
				response.Header.Set("Location", "https://elsewhere.example/account")
				return response, nil
			})
			source.ConnectedAccount = false
			resolution, err := LookupStripeInvoiceStatus(context.Background(), source, "in_1234")
			if err != nil || resolution.Status != scenario.expected || calls != 1 {
				t.Fatalf("failed account check was trusted: %+v, %v; calls=%d", resolution, err, calls)
			}
		})
	}
}

func stripeResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestStripeInvoiceLookupPinsAccountAndInvoice(t *testing.T) {
	source := stripeSource(func(request *http.Request) (*http.Response, error) {
		secret, _, authenticated := request.BasicAuth()
		if request.Method != http.MethodGet || request.URL.String() != "https://api.stripe.com/v1/invoices/in_1234" ||
			request.Header.Get("Stripe-Account") != "acct_12345678" || !authenticated || secret != "sk_test_private" {
			t.Errorf("wrong provider lookup boundary: %s %s", request.Method, request.URL)
		}
		return stripeResponse(http.StatusOK, `{"id":"in_1234","object":"invoice","status":"paid"}`), nil
	})
	resolution, err := LookupStripeInvoiceStatus(context.Background(), source, "in_1234")
	if err != nil || resolution.Status != "ok" || resolution.Value["status"] != "paid" ||
		resolution.Lookup != "invoice.retrieve" || resolution.LookupKey != "in_1234" ||
		resolution.ProviderAccountID != "acct_12345678" || resolution.ObservedAt == "" {
		t.Fatalf("incorrect invoice fact: %+v, %v", resolution, err)
	}
}

func TestStripeInvoiceLookupDoesNotTrustMismatchOrRedirect(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		status   int
		body     string
		expected string
	}{{"wrong invoice", http.StatusOK, `{"id":"in_other","object":"invoice","status":"paid"}`, "untrusted"},
		{"wrong type", http.StatusOK, `{"id":"in_1234","object":"customer","status":"paid"}`, "untrusted"},
		{"invalid status", http.StatusOK, `{"id":"in_1234","object":"invoice","status":"unknown"}`, "untrusted"},
		{"provider unavailable", http.StatusServiceUnavailable, `{}`, "unavailable"},
		{"redirect", http.StatusFound, `{}`, "unavailable"}} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			source := stripeSource(func(*http.Request) (*http.Response, error) {
				calls++
				response := stripeResponse(scenario.status, scenario.body)
				response.Header = make(http.Header)
				response.Header.Set("Location", "https://elsewhere.example/invoice")
				return response, nil
			})
			resolution, err := LookupStripeInvoiceStatus(context.Background(), source, "in_1234")
			if err != nil || resolution.Status != scenario.expected || resolution.Value != nil || calls != 1 {
				t.Fatalf("unsafe provider fact: %+v, %v; calls=%d", resolution, err, calls)
			}
		})
	}
}

func TestStripeInvoiceLookupRejectsInvalidBoundaryWithoutNetwork(t *testing.T) {
	source := stripeSource(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid lookup reached provider")
		return nil, errors.New("unexpected request")
	})
	source.ProviderAccountID = "other"
	if _, err := LookupStripeInvoiceStatus(context.Background(), source, "in_1234"); err == nil {
		t.Fatal("account boundary was not validated")
	}
	source.ProviderAccountID = "acct_12345678"
	if _, err := LookupStripeInvoiceStatus(context.Background(), source, "other"); err == nil {
		t.Fatal("invoice key was not validated")
	}
}

func TestCustomerLookupPreservesAccountAndUnavailable(t *testing.T) {
	source := CustomerSource{SourceVersionID: "00000000-0000-4000-8000-000000000008",
		SourceIdentity: "billing.production", AccountBoundary: "tenant_123",
		Lookup: "invoice.read", Timeout: time.Second}
	resolution, err := LookupCustomerFact(context.Background(), source, "invoice_123",
		func(_ context.Context, key string) (CustomerReadResult, error) {
			if key != "invoice_123" {
				t.Fatal("wrong lookup key")
			}
			return CustomerReadResult{SourceIdentity: "billing.production", AccountBoundary: "tenant_123",
				Lookup: "invoice.read", LookupKey: "invoice_123", ObservedAt: time.Now().Add(-time.Minute),
				Value: map[string]any{"invoice": map[string]any{"paid": true}}}, nil
		})
	if err != nil || resolution.Status != "ok" || resolution.SourceIdentity != "billing.production" ||
		resolution.AccountBoundary != "tenant_123" || resolution.ObservedAt == "" {
		t.Fatalf("incorrect customer fact: %+v, %v", resolution, err)
	}
	resolution, err = LookupCustomerFact(context.Background(), source, "invoice_123",
		func(context.Context, string) (CustomerReadResult, error) {
			return CustomerReadResult{}, errors.New("database unavailable")
		})
	if err != nil || resolution.Status != "unavailable" || resolution.Value != nil {
		t.Fatalf("failed lookup was trusted: %+v, %v", resolution, err)
	}
	resolution, err = LookupCustomerFact(context.Background(), source, "invoice_123",
		func(context.Context, string) (CustomerReadResult, error) {
			return CustomerReadResult{SourceIdentity: "billing.production", AccountBoundary: "another_tenant",
				Lookup: "invoice.read", LookupKey: "invoice_123", ObservedAt: time.Now(),
				Value: map[string]any{"paid": true}}, nil
		})
	if err != nil || resolution.Status != "untrusted" || resolution.Value != nil {
		t.Fatalf("cross-account result was accepted: %+v, %v", resolution, err)
	}
	source.Timeout = 100 * time.Millisecond
	resolution, err = LookupCustomerFact(context.Background(), source, "invoice_123",
		func(ctx context.Context, _ string) (CustomerReadResult, error) {
			<-ctx.Done()
			return CustomerReadResult{}, ctx.Err()
		})
	if err != nil || resolution.Status != "unavailable" {
		t.Fatalf("timed-out customer read was trusted: %+v, %v", resolution, err)
	}
}

func TestObserveSignatureBindsFactResolution(t *testing.T) {
	client, err := NewClient(testConfig("http://127.0.0.1:7078"))
	if err != nil {
		t.Fatal(err)
	}
	call := sampleCall()
	call.FactResolutions = []FactResolution{{SourceVersionID: "00000000-0000-4000-8000-000000000030",
		ProviderAccountID: "acct_12345678", Lookup: "invoice.retrieve", LookupKey: "in_1234",
		AuthenticatedExecutor: true, Status: "ok", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Value: map[string]any{"status": "paid"}}}
	call.Trajectory = &TrajectorySnapshot{SessionID: call.SessionID, Complete: true,
		PriorReadOperationVersionIDs: []string{"00000000-0000-4000-8000-000000000070"}}
	proof, err := client.signIdentityProof(call, "tool_call", nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := func(value Call) bool {
		var arguments map[string]any
		if json.Unmarshal(value.Arguments, &arguments) != nil {
			t.Fatal("arguments are invalid")
		}
		input, err := json.Marshal(struct {
			Arguments       map[string]any      `json:"arguments"`
			FactResolutions []FactResolution    `json:"factResolutions,omitempty"`
			Trajectory      *TrajectorySnapshot `json:"trajectory,omitempty"`
		}{arguments, value.FactResolutions, value.Trajectory})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(input)
		statement := identityStatement{Type: "authrail.observe.executor.v1",
			OrganisationID: client.organisationID, DeploymentID: client.deploymentID,
			RequestID: value.RequestID, ActionKey: value.ActionKey,
			OperationVersionID: value.OperationVersionID, Phase: "tool_call",
			InputSHA256: hex.EncodeToString(digest[:]), Attribution: attribution{
				PrincipalID: value.PrincipalID, SessionID: value.SessionID,
				ResourceID: optionalRef(value.ResourceID), PrincipalSource: value.PrincipalSource,
				ResourceSource: value.ResourceSource},
			IssuedAt: proof.IssuedAt, ExpiresAt: proof.ExpiresAt}
		message, err := json.Marshal(statement)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
		if err != nil {
			t.Fatal(err)
		}
		return ed25519.Verify(client.executorPrivateKey.Public().(ed25519.PublicKey), message, signature)
	}
	if !valid(call) {
		t.Fatal("fact resolution was not signed")
	}
	call.FactResolutions[0].ProviderAccountID = "acct_87654321"
	if valid(call) {
		t.Fatal("changed fact account passed the signature")
	}
	call.FactResolutions[0].ProviderAccountID = "acct_12345678"
	call.Trajectory.PriorReadOperationVersionIDs = nil
	if valid(call) {
		t.Fatal("changed session history passed the signature")
	}
}
