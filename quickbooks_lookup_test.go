package authrail

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type quickBooksTransport func(*http.Request) (*http.Response, error)

func (transport quickBooksTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func quickBooksResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)),
		Header: make(http.Header)}
}

func quickBooksSource(roundTrip quickBooksTransport) QuickBooksInvoiceSource {
	return QuickBooksInvoiceSource{SourceVersionID: "00000000-0000-4000-8000-000000000040",
		ProviderAccountID: "1234567890", Sandbox: true, Timeout: time.Second,
		AccessToken: "protected-oauth", HTTPClient: &http.Client{Transport: roundTrip}}
}

func TestQuickBooksInvoiceBalanceBindsRealmInvoiceAndShape(t *testing.T) {
	source := quickBooksSource(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://sandbox-quickbooks.api.intuit.com/v3/company/1234567890/invoice/42" ||
			request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer protected-oauth" {
			t.Fatalf("unreviewed QuickBooks request: %s %s", request.Method, request.URL)
		}
		return quickBooksResponse(http.StatusOK, `{"Invoice":{"Id":"42","Balance":12.5}}`), nil
	})
	fact, err := LookupQuickBooksInvoiceBalance(context.Background(), source, "42")
	if err != nil || fact.Status != "ok" || fact.ProviderAccountID != "1234567890" ||
		fact.LookupKey != "42" || fact.Value["Invoice"].(map[string]any)["Balance"] != 12.5 ||
		fact.ObservedAt == "" {
		t.Fatalf("unbound QuickBooks fact: %+v %v", fact, err)
	}
}

func TestQuickBooksInvoiceBalanceRejectsMismatchAndRedirect(t *testing.T) {
	for _, testCase := range []struct {
		name string
		code int
		body string
		want string
	}{
		{"wrong invoice", 200, `{"Invoice":{"Id":"43","Balance":0}}`, "untrusted"},
		{"missing balance", 200, `{"Invoice":{"Id":"42"}}`, "untrusted"},
		{"negative balance", 200, `{"Invoice":{"Id":"42","Balance":-1}}`, "untrusted"},
		{"oversized body", 200, strings.Repeat("x", 64*1024+1), "unavailable"},
		{"redirect", 302, "", "unavailable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			source := quickBooksSource(func(*http.Request) (*http.Response, error) {
				return quickBooksResponse(testCase.code, testCase.body), nil
			})
			fact, err := LookupQuickBooksInvoiceBalance(context.Background(), source, "42")
			if err != nil || fact.Status != testCase.want || fact.Value != nil {
				t.Fatalf("unsafe QuickBooks fact: %+v %v", fact, err)
			}
		})
	}
	invalid := quickBooksSource(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid key reached the provider")
		return nil, nil
	})
	if _, err := LookupQuickBooksInvoiceBalance(context.Background(), invalid, "../other"); err == nil {
		t.Fatal("unsafe invoice ID accepted")
	}
}
