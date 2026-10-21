package authrail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var stripeAccountPattern = regexp.MustCompile(`^acct_[A-Za-z0-9]{8,80}$`)
var stripeInvoicePattern = regexp.MustCompile(`^in_[A-Za-z0-9]{4,100}$`)
var quickBooksRealmPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var quickBooksInvoicePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var sourceNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{2,159}$`)
var accountBoundaryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$`)

// FactResolution is a signed source observation for Data Rails, never permission
// to execute the business action.
type FactResolution struct {
	SourceVersionID       string                `json:"sourceVersionId"`
	ProviderAccountID     string                `json:"providerAccountId,omitempty"`
	SourceIdentity        string                `json:"sourceIdentity,omitempty"`
	AccountBoundary       string                `json:"accountBoundary,omitempty"`
	Lookup                string                `json:"lookup"`
	LookupKey             string                `json:"lookupKey"`
	AuthenticatedExecutor bool                  `json:"authenticatedExecutor"`
	Status                string                `json:"status"`
	ObservedAt            string                `json:"observedAt,omitempty"`
	Value                 map[string]any        `json:"value,omitempty"`
	Extraction            *ExtractionProvenance `json:"extraction,omitempty"`
}

type ExtractionProvenance struct {
	SourceSHA256      string `json:"sourceSha256"`
	SourceBytes       int    `json:"sourceBytes"`
	SourceLocation    string `json:"sourceLocation"`
	ModelID           string `json:"modelId"`
	ModelConfigSHA256 string `json:"modelConfigSha256"`
	PromptVersion     string `json:"promptVersion"`
	ExtractedAt       string `json:"extractedAt"`
}

type FactSummary struct {
	SourceVersionID   string  `json:"sourceVersionId"`
	FactKey           string  `json:"factKey"`
	ProviderAccountID string  `json:"providerAccountId,omitempty"`
	SourceIdentity    string  `json:"sourceIdentity,omitempty"`
	AccountBoundary   string  `json:"accountBoundary,omitempty"`
	Lookup            string  `json:"lookup"`
	LookupKeySHA256   string  `json:"lookupKeySha256,omitempty"`
	Status            string  `json:"status"`
	Uncertainty       string  `json:"uncertainty,omitempty"`
	ObservedAt        string  `json:"observedAt,omitempty"`
	AgeSeconds        float64 `json:"ageSeconds,omitempty"`
}

type StripeInvoiceSource struct {
	SourceVersionID   string
	ProviderAccountID string
	ConnectedAccount  bool
	Timeout           time.Duration
	SecretKey         string
	HTTPClient        *http.Client
}

// LookupStripeInvoiceStatus checks the reviewed account before reading one
// invoice; provider failures return unavailable context, not a guessed value.
func LookupStripeInvoiceStatus(ctx context.Context, source StripeInvoiceSource, invoiceID string) (FactResolution, error) {
	if !uuidPattern.MatchString(source.SourceVersionID) || !stripeAccountPattern.MatchString(source.ProviderAccountID) ||
		!stripeInvoicePattern.MatchString(invoiceID) || source.Timeout < 100*time.Millisecond ||
		source.Timeout > 10*time.Second || strings.TrimSpace(source.SecretKey) == "" ||
		strings.ContainsAny(source.SecretKey, "\r\n") {
		return FactResolution{}, errors.New("Stripe fact lookup configuration is invalid")
	}
	resolution := FactResolution{SourceVersionID: source.SourceVersionID,
		ProviderAccountID: source.ProviderAccountID, Lookup: "invoice.retrieve",
		LookupKey: invoiceID, AuthenticatedExecutor: true, Status: "unavailable"}
	requestContext, cancel := context.WithTimeout(ctx, source.Timeout)
	defer cancel()
	client := source.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Verify the account in the same Stripe context used for the invoice read.
	{
		accountRequest, err := http.NewRequestWithContext(requestContext, http.MethodGet,
			"https://api.stripe.com/v1/account", nil)
		if err != nil {
			return resolution, nil
		}
		accountRequest.SetBasicAuth(source.SecretKey, "")
		if source.ConnectedAccount {
			accountRequest.Header.Set("Stripe-Account", source.ProviderAccountID)
		}
		accountResponse, err := boundedClient.Do(accountRequest)
		if err != nil {
			return resolution, nil
		}
		if accountResponse.StatusCode != http.StatusOK {
			accountResponse.Body.Close()
			return resolution, nil
		}
		if accountResponse.ContentLength > 64*1024 {
			accountResponse.Body.Close()
			resolution.Status = "untrusted"
			return resolution, nil
		}
		accountBody, readErr := io.ReadAll(io.LimitReader(accountResponse.Body, 64*1024+1))
		accountResponse.Body.Close()
		if readErr != nil || len(accountBody) > 64*1024 {
			resolution.Status = "untrusted"
			return resolution, nil
		}
		var account struct {
			ID     string `json:"id"`
			Object string `json:"object"`
		}
		if json.Unmarshal(accountBody, &account) != nil || account.Object != "account" ||
			account.ID != source.ProviderAccountID {
			resolution.Status = "untrusted"
			return resolution, nil
		}
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet,
		"https://api.stripe.com/v1/invoices/"+invoiceID, nil)
	if err != nil {
		return resolution, nil
	}
	request.SetBasicAuth(source.SecretKey, "")
	if source.ConnectedAccount {
		request.Header.Set("Stripe-Account", source.ProviderAccountID)
	}
	response, err := boundedClient.Do(request)
	if err != nil {
		return resolution, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resolution, nil
	}
	resolution.Status = "untrusted"
	if response.ContentLength > 64*1024 {
		return resolution, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return resolution, nil
	}
	var invoice struct {
		ID     string `json:"id"`
		Object string `json:"object"`
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &invoice) != nil || invoice.ID != invoiceID || invoice.Object != "invoice" ||
		!validStripeInvoiceStatus(invoice.Status) {
		return resolution, nil
	}
	resolution.Status = "ok"
	resolution.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	resolution.Value = map[string]any{"status": invoice.Status}
	return resolution, nil
}

func validStripeInvoiceStatus(value string) bool {
	switch value {
	case "draft", "open", "paid", "uncollectible", "void":
		return true
	default:
		return false
	}
}

type QuickBooksInvoiceSource struct {
	SourceVersionID   string
	ProviderAccountID string
	Sandbox           bool
	Timeout           time.Duration
	AccessToken       string
	HTTPClient        *http.Client
}

// LookupQuickBooksInvoiceBalance reads one invoice in the reviewed realm.
// The protected application owns the OAuth token; a failed read never supplies a value.
func LookupQuickBooksInvoiceBalance(ctx context.Context, source QuickBooksInvoiceSource,
	invoiceID string) (FactResolution, error) {
	if !uuidPattern.MatchString(source.SourceVersionID) ||
		!quickBooksRealmPattern.MatchString(source.ProviderAccountID) ||
		!quickBooksInvoicePattern.MatchString(invoiceID) || source.Timeout < 100*time.Millisecond ||
		source.Timeout > 10*time.Second || strings.TrimSpace(source.AccessToken) == "" ||
		strings.ContainsAny(source.AccessToken, "\r\n") {
		return FactResolution{}, errors.New("QuickBooks fact lookup configuration is invalid")
	}
	resolution := FactResolution{SourceVersionID: source.SourceVersionID,
		ProviderAccountID: source.ProviderAccountID, Lookup: "invoice.read",
		LookupKey: invoiceID, AuthenticatedExecutor: true, Status: "unavailable"}
	host := "quickbooks.api.intuit.com"
	if source.Sandbox {
		host = "sandbox-quickbooks.api.intuit.com"
	}
	requestContext, cancel := context.WithTimeout(ctx, source.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet,
		"https://"+host+"/v3/company/"+source.ProviderAccountID+"/invoice/"+invoiceID, nil)
	if err != nil {
		return resolution, nil
	}
	request.Header.Set("Authorization", "Bearer "+source.AccessToken)
	request.Header.Set("Accept", "application/json")
	client := source.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := boundedClient.Do(request)
	if err != nil {
		return resolution, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resolution, nil
	}
	if response.ContentLength > 64*1024 {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || requestContext.Err() != nil {
		return resolution, nil
	}
	var value struct {
		Invoice struct {
			ID      string   `json:"Id"`
			Balance *float64 `json:"Balance"`
		} `json:"Invoice"`
	}
	resolution.Status = "untrusted"
	if json.Unmarshal(body, &value) != nil || value.Invoice.ID != invoiceID ||
		value.Invoice.Balance == nil || *value.Invoice.Balance < 0 {
		return resolution, nil
	}
	resolution.Status = "ok"
	resolution.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	resolution.Value = map[string]any{"Invoice": map[string]any{"Balance": *value.Invoice.Balance}}
	return resolution, nil
}

type CustomerSource struct {
	SourceVersionID string
	SourceIdentity  string
	AccountBoundary string
	Lookup          string
	Timeout         time.Duration
}

type CustomerReadResult struct {
	SourceIdentity  string
	AccountBoundary string
	Lookup          string
	LookupKey       string
	ObservedAt      time.Time
	Value           map[string]any
}

type CustomerRead func(context.Context, string) (CustomerReadResult, error)

// LookupCustomerFact accepts only a matching protected source and account;
// callers must keep lookup credentials outside the agent.
func LookupCustomerFact(ctx context.Context, source CustomerSource, lookupKey string,
	read CustomerRead) (FactResolution, error) {
	if !uuidPattern.MatchString(source.SourceVersionID) || !sourceNamePattern.MatchString(source.SourceIdentity) ||
		!accountBoundaryPattern.MatchString(source.AccountBoundary) || !sourceNamePattern.MatchString(source.Lookup) ||
		lookupKey == "" || len(lookupKey) > 256 || source.Timeout < 100*time.Millisecond ||
		source.Timeout > 10*time.Second || read == nil {
		return FactResolution{}, errors.New("customer fact lookup configuration is invalid")
	}
	resolution := FactResolution{SourceVersionID: source.SourceVersionID,
		SourceIdentity: source.SourceIdentity, AccountBoundary: source.AccountBoundary,
		Lookup: source.Lookup, LookupKey: lookupKey, AuthenticatedExecutor: true, Status: "unavailable"}
	requestContext, cancel := context.WithTimeout(ctx, source.Timeout)
	defer cancel()
	result, err := read(requestContext, lookupKey)
	if err != nil || requestContext.Err() != nil {
		return resolution, nil
	}
	if result.SourceIdentity != source.SourceIdentity || result.AccountBoundary != source.AccountBoundary ||
		result.Lookup != source.Lookup || result.LookupKey != lookupKey {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	if result.ObservedAt.IsZero() || result.ObservedAt.After(time.Now().Add(5*time.Second)) || result.Value == nil {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	encoded, err := json.Marshal(result.Value)
	if err != nil || len(encoded) > 16*1024 {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	resolution.Status = "ok"
	resolution.ObservedAt = result.ObservedAt.UTC().Format(time.RFC3339Nano)
	resolution.Value = result.Value
	return resolution, nil
}
