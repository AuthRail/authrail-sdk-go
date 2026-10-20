package authrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var customerRecordPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type CustomerAPIConfig struct {
	Endpoint        string
	BearerToken     string
	SourceIdentity  string
	AccountBoundary string
	Lookup          string
	HTTPClient      *http.Client
}

// NewCustomerAPIReader creates a fixed HTTPS read-only lookup and rejects
// redirects so a provider credential cannot follow an unreviewed endpoint.
func NewCustomerAPIReader(config CustomerAPIConfig) (CustomerRead, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" ||
		endpoint.RawPath != "" || endpoint.RawFragment != "" ||
		!sourceNamePattern.MatchString(config.SourceIdentity) ||
		!sourceNamePattern.MatchString(config.Lookup) ||
		!accountBoundaryPattern.MatchString(config.AccountBoundary) ||
		config.BearerToken == "" || strings.ContainsAny(config.BearerToken, "\r\n") {
		return nil, errors.New("customer API reader configuration is invalid")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/")
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return func(ctx context.Context, lookupKey string) (CustomerReadResult, error) {
		if !customerRecordPattern.MatchString(lookupKey) || lookupKey == "." || lookupKey == ".." {
			return CustomerReadResult{}, errors.New("customer record key is invalid")
		}
		requestURL := *endpoint
		requestURL.Path = endpoint.Path + "/" + lookupKey
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return CustomerReadResult{}, errors.New("customer API lookup unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+config.BearerToken)
		request.Header.Set("Accept", "application/json")
		response, err := boundedClient.Do(request)
		if err != nil {
			return CustomerReadResult{}, errors.New("customer API lookup unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return CustomerReadResult{}, errors.New("customer API lookup unavailable")
		}
		if response.ContentLength > 32*1024 {
			return CustomerReadResult{}, nil
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 32*1024+1))
		if err != nil || len(body) > 32*1024 {
			return CustomerReadResult{}, nil
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var value struct {
			AccountID  string         `json:"accountId"`
			RecordID   string         `json:"recordId"`
			ObservedAt string         `json:"observedAt"`
			Data       map[string]any `json:"data"`
		}
		if decoder.Decode(&value) != nil {
			return CustomerReadResult{}, nil
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return CustomerReadResult{}, nil
		}
		observedAt, err := time.Parse(time.RFC3339Nano, value.ObservedAt)
		if err != nil {
			return CustomerReadResult{}, nil
		}
		return CustomerReadResult{SourceIdentity: config.SourceIdentity,
			AccountBoundary: value.AccountID, Lookup: config.Lookup,
			LookupKey: value.RecordID, ObservedAt: observedAt, Value: value.Data}, nil
	}, nil
}
