package authrail

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func customerAPISource() CustomerSource {
	return CustomerSource{SourceVersionID: "00000000-0000-4000-8000-000000000040",
		SourceIdentity: "billing.production", AccountBoundary: "tenant_123",
		Lookup: "invoice.read", Timeout: time.Second}
}

func customerAPIConfig(transport factTransport) CustomerAPIConfig {
	return CustomerAPIConfig{Endpoint: "https://billing.example/accounts/tenant_123/invoices",
		BearerToken: "protected-application-token", SourceIdentity: "billing.production",
		AccountBoundary: "tenant_123", Lookup: "invoice.read",
		HTTPClient: &http.Client{Transport: transport}}
}

func TestCustomerAPIReaderBindsCredentialAccountAndRecord(t *testing.T) {
	observedAt := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	reader, err := NewCustomerAPIReader(customerAPIConfig(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet ||
			request.URL.String() != "https://billing.example/accounts/tenant_123/invoices/invoice_123" ||
			request.Header.Get("Authorization") != "Bearer protected-application-token" {
			t.Errorf("wrong customer read boundary: %s %s", request.Method, request.URL)
		}
		return stripeResponse(http.StatusOK, `{"accountId":"tenant_123","recordId":"invoice_123",`+
			`"observedAt":"`+observedAt+`","data":{"invoice":{"paid":true}}}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := LookupCustomerFact(context.Background(), customerAPISource(), "invoice_123", reader)
	if err != nil || resolution.Status != "ok" || resolution.AccountBoundary != "tenant_123" ||
		resolution.Value["invoice"] == nil || resolution.ObservedAt != observedAt {
		t.Fatalf("customer API fact was not bound: %+v %v", resolution, err)
	}
}

func TestCustomerAPIReaderDoesNotTrustCrossAccountOrRedirect(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		status   int
		body     string
		expected string
	}{{"wrong account", http.StatusOK, `{"accountId":"tenant_456","recordId":"invoice_123","observedAt":"2026-10-19T09:00:00Z","data":{"paid":true}}`, "untrusted"},
		{"wrong record", http.StatusOK, `{"accountId":"tenant_123","recordId":"invoice_456","observedAt":"2026-10-19T09:00:00Z","data":{"paid":true}}`, "untrusted"},
		{"malformed response", http.StatusOK, `{"paid":true}`, "untrusted"},
		{"provider error", http.StatusServiceUnavailable, `{}`, "unavailable"},
		{"redirect", http.StatusFound, `{}`, "unavailable"}} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			reader, err := NewCustomerAPIReader(customerAPIConfig(func(*http.Request) (*http.Response, error) {
				calls++
				response := stripeResponse(scenario.status, scenario.body)
				response.Header = make(http.Header)
				response.Header.Set("Location", "https://elsewhere.example/record")
				return response, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := LookupCustomerFact(context.Background(), customerAPISource(), "invoice_123", reader)
			if err != nil || resolution.Status != scenario.expected || resolution.Value != nil || calls != 1 {
				t.Fatalf("unsafe customer fact: %+v %v calls=%d", resolution, err, calls)
			}
		})
	}
}

func TestCustomerAPIReaderRejectsUnsafeConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://billing.example/invoices", "https://user:pass@billing.example/invoices",
		"https://billing.example/invoices?account=other", "https://billing.example/invoices#other"} {
		config := customerAPIConfig(nil)
		config.Endpoint = endpoint
		if _, err := NewCustomerAPIReader(config); err == nil {
			t.Fatalf("unsafe customer API endpoint accepted: %s", endpoint)
		}
	}
}
