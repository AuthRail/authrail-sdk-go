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
	"sync"
	"time"
)

// DataResourceContext contains trusted application identity, never agent arguments.
type DataResourceContext struct{ PrincipalID, SessionID, ResourceID, OperationVersionID string }

// DataSourceBinding connects one exact reviewed source to private credentials and
// an application-owned resource resolver. Read is a named read-only callback for
// customer_api, database, mcp and sdk sources, not arbitrary agent-provided code.
type DataSourceBinding struct {
	SourceVersionID     string
	Kind                string
	ProviderAccountID   string
	SourceIdentity      string
	AccountBoundary     string
	Lookup              string
	ResolveResource     func(context.Context, DataResourceContext) (string, error)
	Read                CustomerRead
	SecretKey           string
	SecretKeyProvider   func(context.Context) (string, error)
	AccessToken         string
	AccessTokenProvider func(context.Context) (string, error)
	ConnectedAccount    bool
	Sandbox             bool
	HTTPClient          *http.Client
}

type dataSourceContract struct {
	FormatVersion     int         `json:"formatVersion"`
	Provider          string      `json:"provider"`
	Kind              string      `json:"kind"`
	ProviderAccountID string      `json:"providerAccountId"`
	SourceIdentity    string      `json:"sourceIdentity"`
	AccountBoundary   string      `json:"accountBoundary"`
	Lookup            string      `json:"lookup"`
	QueryField        GuardTarget `json:"queryField"`
	FactKey           string      `json:"factKey"`
	ResultField       string      `json:"resultField"`
	ResultPath        []string    `json:"resultPath"`
	ValueType         string      `json:"valueType"`
	MaxAgeSeconds     int         `json:"maxAgeSeconds"`
	TimeoutMS         int         `json:"timeoutMs"`
	Failure           string      `json:"failure"`
}
type dataRequirement struct {
	SourceVersionID string          `json:"sourceVersionId"`
	Contract        json.RawMessage `json:"contract"`
}
type dataPlan struct {
	FormatVersion      int               `json:"formatVersion"`
	OperationVersionID string            `json:"operationVersionId"`
	Phase              string            `json:"phase"`
	BundleID           *string           `json:"bundleId"`
	Sequence           int64             `json:"sequence"`
	Coverage           string            `json:"coverage"`
	Requirements       []dataRequirement `json:"requirements"`
}

func invalidData() error { return errors.New("Data source requirements or bindings are invalid") }
func registerDataSources(input []DataSourceBinding) ([]DataSourceBinding, error) {
	if input == nil {
		return nil, nil
	}
	if len(input) > 32 {
		return nil, invalidData()
	}
	output := make([]DataSourceBinding, len(input))
	seen := map[string]bool{}
	for i, b := range input {
		if !uuidPattern.MatchString(b.SourceVersionID) || seen[b.SourceVersionID] || b.ResolveResource == nil {
			return nil, invalidData()
		}
		seen[b.SourceVersionID] = true
		switch b.Kind {
		case "stripe":
			if !stripeAccountPattern.MatchString(b.ProviderAccountID) || (b.SecretKeyProvider == nil && (strings.TrimSpace(b.SecretKey) == "" || strings.ContainsAny(b.SecretKey, "\r\n"))) || (b.SecretKeyProvider != nil && b.SecretKey != "") {
				return nil, invalidData()
			}
		case "quickbooks":
			if !quickBooksRealmPattern.MatchString(b.ProviderAccountID) || (b.AccessTokenProvider == nil && (strings.TrimSpace(b.AccessToken) == "" || strings.ContainsAny(b.AccessToken, "\r\n"))) || (b.AccessTokenProvider != nil && b.AccessToken != "") {
				return nil, invalidData()
			}
		case "customer_api", "database", "mcp", "sdk":
			if !sourceNamePattern.MatchString(b.SourceIdentity) || !accountBoundaryPattern.MatchString(b.AccountBoundary) || !sourceNamePattern.MatchString(b.Lookup) || b.Read == nil {
				return nil, invalidData()
			}
		default:
			return nil, invalidData()
		}
		output[i] = b
	}
	return output, nil
}
func parseDataContract(raw json.RawMessage) (dataSourceContract, error) {
	var c dataSourceContract
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return c, invalidData()
	}
	names := []string{"formatVersion", "queryField", "factKey", "maxAgeSeconds", "timeoutMs", "failure"}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, invalidData()
	}
	if c.FormatVersion == 1 || c.FormatVersion == 3 {
		names = append(names, "provider", "lookup", "providerAccountId", "resultField")
	} else if c.FormatVersion == 4 {
		names = append(names, "kind", "sourceIdentity", "lookup", "accountBoundary", "resultPath", "valueType")
	} else {
		return c, invalidData()
	}
	if len(fields) != len(names) {
		return c, invalidData()
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return c, invalidData()
		}
	}
	var query map[string]json.RawMessage
	if json.Unmarshal(fields["queryField"], &query) != nil || len(query) != 2 || query["root"] == nil || query["path"] == nil {
		return c, invalidData()
	}
	if c.QueryField.Root != "arguments" || len(c.QueryField.Path) < 1 || len(c.QueryField.Path) > 12 || !guardIdentifier.MatchString(c.FactKey) || c.MaxAgeSeconds < 1 || c.MaxAgeSeconds > 3600 || c.TimeoutMS < 100 || c.TimeoutMS > 10000 || c.Failure != "unavailable" {
		return c, invalidData()
	}
	for _, p := range c.QueryField.Path {
		if len(p) < 1 || len(p) > 80 || p == "__proto__" || p == "prototype" || p == "constructor" {
			return c, invalidData()
		}
	}
	switch c.FormatVersion {
	case 1:
		if c.Provider != "stripe" || c.Lookup != "invoice.retrieve" || c.ResultField != "status" || !stripeAccountPattern.MatchString(c.ProviderAccountID) {
			return c, invalidData()
		}
	case 3:
		if c.Provider != "quickbooks" || c.Lookup != "invoice.read" || c.ResultField != "Balance" || !quickBooksRealmPattern.MatchString(c.ProviderAccountID) {
			return c, invalidData()
		}
	case 4:
		if (c.Kind != "customer_api" && c.Kind != "database" && c.Kind != "mcp" && c.Kind != "sdk") || !sourceNamePattern.MatchString(c.SourceIdentity) || !accountBoundaryPattern.MatchString(c.AccountBoundary) || !sourceNamePattern.MatchString(c.Lookup) || (c.ValueType != "string" && c.ValueType != "number" && c.ValueType != "boolean") || len(c.ResultPath) < 1 || len(c.ResultPath) > 8 {
			return c, invalidData()
		}
		for _, p := range c.ResultPath {
			if !guardPathSegment.MatchString(p) || p == "__proto__" || p == "prototype" || p == "constructor" {
				return c, invalidData()
			}
		}
	}
	return c, nil
}
func dataUnavailable(id string, c dataSourceContract, key string) FactResolution {
	return FactResolution{SourceVersionID: id, ProviderAccountID: c.ProviderAccountID, SourceIdentity: c.SourceIdentity, AccountBoundary: c.AccountBoundary, Lookup: c.Lookup, LookupKey: key, AuthenticatedExecutor: true, Status: "unavailable"}
}

// prepareDataCall returns a detached call so permission claims and receipts retain
// the exact facts signed for the original request, including across approval resume.
func (c *Client) prepareDataCall(ctx context.Context, call Call, phase string) (Call, error) {
	if c.dataSources == nil {
		return call, nil
	}
	query := url.Values{"operationVersionId": {call.OperationVersionID}, "phase": {phase}}
	requestCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, strings.TrimSuffix(c.endpoint, "/evaluate")+"/data-requirements?"+query.Encode(), nil)
	if err != nil {
		return call, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if call.Traceparent != "" {
		request.Header.Set("traceparent", call.Traceparent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return call, errors.New("Data requirements unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return call, errors.New("Data requirements unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if err != nil || len(body) > 128*1024 {
		return call, invalidData()
	}
	var plan dataPlan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || plan.FormatVersion != 1 || plan.OperationVersionID != call.OperationVersionID || plan.Phase != phase || plan.Coverage != "evaluated" || plan.BundleID == nil || !uuidPattern.MatchString(*plan.BundleID) || plan.Sequence < 1 || plan.Requirements == nil || len(plan.Requirements) > 32 {
		return call, invalidData()
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil || len(top) != 7 {
		return call, invalidData()
	}
	contracts := make([]dataSourceContract, len(plan.Requirements))
	ids := map[string]bool{}
	for i, r := range plan.Requirements {
		if !uuidPattern.MatchString(r.SourceVersionID) || ids[r.SourceVersionID] {
			return call, invalidData()
		}
		ids[r.SourceVersionID] = true
		contracts[i], err = parseDataContract(r.Contract)
		if err != nil {
			return call, err
		}
	}
	manual := []FactResolution{}
	seen := map[string]bool{}
	for _, fact := range call.FactResolutions {
		if seen[fact.SourceVersionID] || (phase == "tool_call" && ids[fact.SourceVersionID]) {
			return call, invalidData()
		}
		seen[fact.SourceVersionID] = true
		if !ids[fact.SourceVersionID] {
			manual = append(manual, fact)
		}
	}
	readsCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	results := make([]FactResolution, len(contracts))
	for i, contract := range contracts {
		results[i] = dataUnavailableForCall(call, plan.Requirements[i].SourceVersionID, contract)
	}
	jobs := make(chan int, len(contracts))
	for i := range contracts {
		jobs <- i
	}
	close(jobs)
	var wait sync.WaitGroup
	workers := min(4, len(contracts))
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for i := range jobs {
				if readsCtx.Err() != nil {
					return
				}
				sourceCtx, sourceCancel := context.WithTimeout(readsCtx, time.Duration(contracts[i].TimeoutMS)*time.Millisecond)
				answer := make(chan FactResolution, 1)
				go func(index int) {
					answer <- c.readDataSource(sourceCtx, call, plan.Requirements[index].SourceVersionID, contracts[index])
				}(i)
				select {
				case results[i] = <-answer:
				case <-sourceCtx.Done():
				}
				sourceCancel()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wait.Wait(); close(done) }()
	select {
	case <-done:
	case <-readsCtx.Done():
		// Abandon incomplete reads without accepting late callback results.
		fresh := make([]FactResolution, len(contracts))
		for i, contract := range contracts {
			fresh[i] = dataUnavailableForCall(call, plan.Requirements[i].SourceVersionID, contract)
		}
		call.FactResolutions = append(manual, fresh...)
		call.dataBundleID = *plan.BundleID
		call.dataSequence = plan.Sequence
		call.dataPhase = phase
		return call, nil
	}
	call.FactResolutions = append(manual, results...)
	call.dataBundleID = *plan.BundleID
	call.dataSequence = plan.Sequence
	call.dataPhase = phase
	return call, nil
}
func (c *Client) readDataSource(ctx context.Context, call Call, id string, contract dataSourceContract) FactResolution {
	sourceCtx, sourceCancel := context.WithTimeout(ctx, time.Duration(contract.TimeoutMS)*time.Millisecond)
	defer sourceCancel()
	ctx = sourceCtx
	var args map[string]any
	if json.Unmarshal(call.Arguments, &args) != nil {
		return dataUnavailable(id, contract, "")
	}
	var value any = args
	for _, part := range contract.QueryField.Path {
		item, ok := value.(map[string]any)
		if !ok {
			value = nil
			break
		}
		value = item[part]
	}
	key, ok := value.(string)
	base := dataUnavailable(id, contract, key)
	if !ok || key == "" || len(key) > 256 {
		return base
	}
	var binding *DataSourceBinding
	for i := range c.dataSources {
		if c.dataSources[i].SourceVersionID == id {
			binding = &c.dataSources[i]
			break
		}
	}
	if binding == nil {
		return base
	}
	matches := binding.Kind == contract.Provider && binding.ProviderAccountID == contract.ProviderAccountID
	if contract.FormatVersion == 4 {
		matches = binding.Kind == contract.Kind && binding.SourceIdentity == contract.SourceIdentity && binding.AccountBoundary == contract.AccountBoundary && binding.Lookup == contract.Lookup
	}
	if !matches {
		base.Status = "untrusted"
		return base
	}
	timeout := time.Duration(contract.TimeoutMS) * time.Millisecond
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type resolved struct {
		key string
		err error
	}
	done := make(chan resolved, 1)
	go func() {
		key, err := binding.ResolveResource(resolveCtx, DataResourceContext{call.PrincipalID, call.SessionID, call.ResourceID, call.OperationVersionID})
		done <- resolved{key, err}
	}()
	select {
	case <-resolveCtx.Done():
		return base
	case selected := <-done:
		if selected.err != nil {
			return base
		}
		if selected.key != key {
			base.Status = "untrusted"
			return base
		}
	}
	if ctx.Err() != nil {
		return base
	}
	var fact FactResolution
	var err error
	switch binding.Kind {
	case "stripe":
		secret, secretErr := dataCredential(ctx, binding.SecretKey, binding.SecretKeyProvider)
		if secretErr != nil {
			return base
		}
		fact, err = LookupStripeInvoiceStatus(ctx, StripeInvoiceSource{SourceVersionID: id, ProviderAccountID: binding.ProviderAccountID, ConnectedAccount: binding.ConnectedAccount, SecretKey: secret, Timeout: timeout, HTTPClient: binding.HTTPClient}, key)
	case "quickbooks":
		token, tokenErr := dataCredential(ctx, binding.AccessToken, binding.AccessTokenProvider)
		if tokenErr != nil {
			return base
		}
		fact, err = LookupQuickBooksInvoiceBalance(ctx, QuickBooksInvoiceSource{SourceVersionID: id, ProviderAccountID: binding.ProviderAccountID, Sandbox: binding.Sandbox, AccessToken: token, Timeout: timeout, HTTPClient: binding.HTTPClient}, key)
	default:
		fact, err = LookupCustomerFact(ctx, CustomerSource{SourceVersionID: id, SourceIdentity: binding.SourceIdentity, AccountBoundary: binding.AccountBoundary, Lookup: binding.Lookup, Timeout: timeout}, key, binding.Read)
	}
	if err != nil || ctx.Err() != nil {
		return base
	}
	encoded, cloneErr := json.Marshal(fact)
	if cloneErr != nil {
		return base
	}
	var copy FactResolution
	if json.Unmarshal(encoded, &copy) != nil {
		return base
	}
	return copy
}

func dataCredential(ctx context.Context, value string, get func(context.Context) (string, error)) (string, error) {
	if get != nil {
		type answer struct {
			value string
			err   error
		}
		done := make(chan answer, 1)
		go func() { value, err := get(ctx); done <- answer{value, err} }()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case result := <-done:
			if result.err != nil {
				return "", result.err
			}
			value = result.value
		}
	}
	if ctx.Err() != nil || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("Data credential unavailable")
	}
	return value, nil
}

func dataUnavailableForCall(call Call, id string, c dataSourceContract) FactResolution {
	var args map[string]any
	_ = json.Unmarshal(call.Arguments, &args)
	var value any = args
	for _, part := range c.QueryField.Path {
		item, ok := value.(map[string]any)
		if !ok {
			value = nil
			break
		}
		value = item[part]
	}
	key, _ := value.(string)
	return dataUnavailable(id, c, key)
}
