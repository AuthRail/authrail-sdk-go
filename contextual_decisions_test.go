package authrail

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type decisionsTransport func(*http.Request) (*http.Response, error)

func (transport decisionsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func decisionsTestSource(question DecisionsQuestion) ExtractionSource {
	source := sampleExtractionSource()
	source.ModelID = decisionsModel
	hash, _ := OpenAIDecisionsConfigSHA256(question)
	source.ModelConfigSHA256 = hash
	return source
}

func TestOpenAIDecisionsPredicateProducesReviewedFact(t *testing.T) {
	question := DecisionsQuestion{Type: "predicate", Instructions: "Does the message contain a payment card number?", MinConfidence: .8}
	source := decisionsTestSource(question)
	if source.ModelConfigSHA256 != "60df13567aaa08f8132106c431a80a0923af5d6d126b83565cfdf37d284fc27f" {
		t.Fatal("Go and Node reviewed configuration hashes differ")
	}
	requests := 0
	client := &http.Client{Transport: decisionsTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.String() != decisionsEndpoint || request.Method != http.MethodPost ||
			request.Header.Get("Authorization") != "Bearer protected-key" {
			t.Fatal("wrong protected request")
		}
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), `"input":"customer message"`) ||
			!strings.Contains(string(body), `"type":"predicate"`) {
			t.Fatal("wrong decision payload")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
			`{"model":"gpt-6-luna","answers":[{"type":"predicate","name":"fact","probability":0.94}]}`)),
			Header: make(http.Header)}, nil
	})}
	extractor, err := NewOpenAIDecisionsExtractor(OpenAIDecisionsConfig{Source: source, Question: question,
		APIKey: "protected-key", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := ExtractContextFact(context.Background(), source, "msg_123", "message:msg_123",
		time.Now(), []byte("customer message"), extractor)
	if err != nil || requests != 1 || resolution.Status != "ok" || resolution.Value["sensitive"] != true ||
		resolution.Extraction == nil || resolution.Extraction.ModelConfigSHA256 != source.ModelConfigSHA256 {
		t.Fatalf("expected reviewed fact: %+v %v", resolution, err)
	}
}

func TestOpenAIDecisionsChoiceAndScore(t *testing.T) {
	cases := []struct {
		name      string
		question  DecisionsQuestion
		valueType string
		answer    string
		want      any
	}{
		{"choice", DecisionsQuestion{Type: "choice", Instructions: "Classify the ticket.",
			Choices: []string{"billing", "other"}, MinConfidence: .8}, "string",
			`{"type":"choice","name":"fact","choice":"billing","confidence":0.91}`, "billing"},
		{"score", DecisionsQuestion{Type: "score", Instructions: "Rate urgency.",
			Levels: []string{"low", "medium", "high"}, MinConfidence: .8}, "number",
			`{"type":"score","name":"fact","score":1.4,"confidence":0.91}`, 1.4},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := decisionsTestSource(testCase.question)
			source.ValueType = testCase.valueType
			client := &http.Client{Transport: decisionsTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
					`{"model":"gpt-6-luna","answers":[` + testCase.answer + `]}`)), Header: make(http.Header)}, nil
			})}
			extractor, err := NewOpenAIDecisionsExtractor(OpenAIDecisionsConfig{Source: source,
				Question: testCase.question, APIKey: "protected-key", Client: client})
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := ExtractContextFact(context.Background(), source, "msg_123", "message:msg_123",
				time.Now(), []byte("customer message"), extractor)
			if err != nil || resolution.Status != "ok" || resolution.Value["sensitive"] != testCase.want {
				t.Fatalf("expected typed fact: %+v %v", resolution, err)
			}
		})
	}
}

func TestOpenAIDecisionsRefusalAndUncertainty(t *testing.T) {
	question := DecisionsQuestion{Type: "predicate", Instructions: "Does the message contain a payment card number?", MinConfidence: .8}
	source := decisionsTestSource(question)
	for _, answer := range []string{`{"type":"refusal","name":"fact"}`,
		`{"type":"predicate","name":"fact","probability":0.5}`} {
		client := &http.Client{Transport: decisionsTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
				`{"model":"gpt-6-luna","answers":[` + answer + `]}`)), Header: make(http.Header)}, nil
		})}
		extractor, err := NewOpenAIDecisionsExtractor(OpenAIDecisionsConfig{Source: source, Question: question,
			APIKey: "protected-key", Client: client})
		if err != nil {
			t.Fatal(err)
		}
		resolution, err := ExtractContextFact(context.Background(), source, "msg_123", "message:msg_123",
			time.Now(), []byte("customer message"), extractor)
		if err != nil || resolution.Status != "uncertain" || resolution.Value != nil {
			t.Fatalf("uncertainty became a fact: %+v %v", resolution, err)
		}
	}
}

func TestOpenAIDecisionsRejectsWrongContractAndResponse(t *testing.T) {
	question := DecisionsQuestion{Type: "choice", Instructions: "Classify the ticket.",
		Choices: []string{"billing", "other"}, MinConfidence: .8}
	source := decisionsTestSource(question)
	source.ValueType = "string"
	source.ModelConfigSHA256 = strings.Repeat("0", 64)
	if _, err := NewOpenAIDecisionsExtractor(OpenAIDecisionsConfig{Source: source, Question: question,
		APIKey: "protected-key"}); err == nil {
		t.Fatal("accepted wrong reviewed configuration")
	}
	source = decisionsTestSource(question)
	source.ValueType = "string"
	client := &http.Client{Transport: decisionsTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
			`{"model":"gpt-6-luna","answers":[{"type":"choice","name":"fact","choice":"unreviewed","confidence":0.99}]}`)),
			Header: make(http.Header)}, nil
	})}
	extractor, err := NewOpenAIDecisionsExtractor(OpenAIDecisionsConfig{Source: source, Question: question,
		APIKey: "protected-key", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := ExtractContextFact(context.Background(), source, "msg_123", "message:msg_123",
		time.Now(), []byte("customer message"), extractor)
	if err != nil || resolution.Status != "unavailable" || resolution.Value != nil {
		t.Fatalf("unreviewed output became a fact: %+v %v", resolution, err)
	}
}
