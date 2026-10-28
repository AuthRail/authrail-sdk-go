package authrail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const decisionsModel = "gpt-6-luna"
const decisionsEndpoint = "https://api.openai.com/v1/decisions"
const decisionsMaxResponseBytes = 16 * 1024

type DecisionsQuestion struct {
	Type          string
	Instructions  string
	Choices       []string
	Levels        []string
	MinConfidence float64
}

type OpenAIDecisionsConfig struct {
	Source   ExtractionSource
	Question DecisionsQuestion
	APIKey   string
	Client   *http.Client
}

type decisionsQuestionConfig struct {
	Model         string   `json:"model"`
	Type          string   `json:"type"`
	Instructions  string   `json:"instructions"`
	Entries       []string `json:"entries,omitempty"`
	MinConfidence float64  `json:"minConfidence"`
}

// OpenAIDecisionsConfigSHA256 pins the reviewed question, model, and uncertainty threshold.
func OpenAIDecisionsConfigSHA256(question DecisionsQuestion) (string, error) {
	if !validDecisionsQuestion(question) {
		return "", errors.New("contextual question configuration is invalid")
	}
	config := decisionsQuestionConfig{Model: decisionsModel, Type: question.Type,
		Instructions: question.Instructions, MinConfidence: question.MinConfidence}
	if question.Type == "choice" {
		config.Entries = question.Choices
	}
	if question.Type == "score" {
		config.Entries = question.Levels
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", errors.New("contextual question configuration is invalid")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validDecisionsQuestion(question DecisionsQuestion) bool {
	if question.Type != "predicate" && question.Type != "choice" && question.Type != "score" ||
		strings.TrimSpace(question.Instructions) == "" || len(question.Instructions) > 2048 ||
		math.IsNaN(question.MinConfidence) || question.MinConfidence < .5 || question.MinConfidence > 1 {
		return false
	}
	if question.Type == "predicate" {
		return len(question.Choices) == 0 && len(question.Levels) == 0
	}
	entries := question.Choices
	if question.Type == "score" {
		entries = question.Levels
	}
	if len(entries) < 2 || len(entries) > 16 ||
		(question.Type == "choice" && len(question.Levels) != 0) ||
		(question.Type == "score" && len(question.Choices) != 0) {
		return false
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if len(entry) == 0 || len(entry) > 80 || seen[entry] || !validDecisionLabel(entry) {
			return false
		}
		seen[entry] = true
	}
	return true
}

func validDecisionLabel(value string) bool {
	for index, letter := range value {
		if letter > 127 || !(letter >= 'A' && letter <= 'Z' || letter >= 'a' && letter <= 'z' ||
			letter >= '0' && letter <= '9' || index > 0 && (letter == '_' || letter == '.' || letter == ' ' || letter == '-')) {
			return false
		}
	}
	return true
}

// NewOpenAIDecisionsExtractor sends the selected document bytes to OpenAI.
// The caller must authorise and minimise that disclosure before invoking it;
// this client does not redact protected content. The model supplies a typed fact,
// never authorization, and ExtractContextFact validates its provenance.
func NewOpenAIDecisionsExtractor(config OpenAIDecisionsConfig) (Extractor, error) {
	digest, err := OpenAIDecisionsConfigSHA256(config.Question)
	if err != nil {
		return nil, err
	}
	source := config.Source
	if source.ModelID != decisionsModel || source.ModelConfigSHA256 != digest ||
		source.PromptVersion == "" || strings.TrimSpace(config.APIKey) == "" ||
		strings.ContainsAny(config.APIKey, "\r\n") || source.MaxInputBytes < 1 || source.MaxInputBytes > 65536 ||
		source.MaxOutputBytes < 1 || source.MaxOutputBytes > 4096 ||
		source.Timeout < 100*time.Millisecond || source.Timeout > 10*time.Second ||
		(config.Question.Type == "predicate" && source.ValueType != "boolean") ||
		(config.Question.Type == "choice" && source.ValueType != "string") ||
		(config.Question.Type == "score" && source.ValueType != "number") {
		return nil, errors.New("contextual extractor configuration is invalid")
	}
	client := config.Client
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	apiQuestion := map[string]any{"type": config.Question.Type, "name": "fact",
		"instructions": config.Question.Instructions}
	if config.Question.Type == "choice" {
		choices := make([]map[string]string, len(config.Question.Choices))
		for index, value := range config.Question.Choices {
			choices[index] = map[string]string{"value": value}
		}
		apiQuestion["choices"] = choices
	}
	if config.Question.Type == "score" {
		levels := make([]map[string]string, len(config.Question.Levels))
		for index, label := range config.Question.Levels {
			levels[index] = map[string]string{"label": label}
		}
		apiQuestion["levels"] = levels
	}
	return func(ctx context.Context, document []byte) (ExtractionResult, error) {
		unavailable := errors.New("contextual provider unavailable")
		if len(document) == 0 || len(document) > source.MaxInputBytes || !utf8.Valid(document) {
			return ExtractionResult{}, unavailable
		}
		body, _ := json.Marshal(map[string]any{"model": decisionsModel, "input": string(document),
			"questions": []any{apiQuestion}})
		requestContext, cancel := context.WithTimeout(ctx, source.Timeout)
		defer cancel()
		request, err := http.NewRequestWithContext(requestContext, http.MethodPost, decisionsEndpoint, bytes.NewReader(body))
		if err != nil {
			return ExtractionResult{}, unavailable
		}
		request.Header.Set("Authorization", "Bearer "+config.APIKey)
		request.Header.Set("Content-Type", "application/json")
		response, err := copyClient.Do(request)
		if err != nil {
			return ExtractionResult{}, unavailable
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return ExtractionResult{}, unavailable
		}
		limited, err := io.ReadAll(io.LimitReader(response.Body, decisionsMaxResponseBytes+1))
		if err != nil || len(limited) > decisionsMaxResponseBytes {
			return ExtractionResult{}, unavailable
		}
		value, uncertain, err := parseDecisionsAnswer(limited, config.Question)
		if err != nil {
			return ExtractionResult{}, unavailable
		}
		return ExtractionResult{Value: value, Uncertain: uncertain, ModelID: decisionsModel,
			ModelConfigSHA256: source.ModelConfigSHA256, PromptVersion: source.PromptVersion}, nil
	}, nil
}

type decisionsResponse struct {
	Model   string `json:"model"`
	Answers []struct {
		Type        string   `json:"type"`
		Name        string   `json:"name"`
		Probability *float64 `json:"probability"`
		Confidence  *float64 `json:"confidence"`
		Choice      *string  `json:"choice"`
		Score       *float64 `json:"score"`
	} `json:"answers"`
}

func parseDecisionsAnswer(body []byte, question DecisionsQuestion) (json.RawMessage, bool, error) {
	var response decisionsResponse
	if json.Unmarshal(body, &response) != nil || response.Model != decisionsModel ||
		len(response.Answers) != 1 || response.Answers[0].Name != "fact" {
		return nil, false, errors.New("invalid contextual answer")
	}
	answer := response.Answers[0]
	if answer.Type == "refusal" {
		return nil, true, nil
	}
	if answer.Type != question.Type {
		return nil, false, errors.New("invalid contextual answer")
	}
	if question.Type == "predicate" {
		if answer.Probability == nil || !validProbability(*answer.Probability) {
			return nil, false, errors.New("invalid contextual answer")
		}
		if *answer.Probability >= question.MinConfidence {
			return json.RawMessage(`true`), false, nil
		}
		if *answer.Probability <= 1-question.MinConfidence {
			return json.RawMessage(`false`), false, nil
		}
		return nil, true, nil
	}
	if answer.Confidence == nil || !validProbability(*answer.Confidence) {
		return nil, false, errors.New("invalid contextual answer")
	}
	if question.Type == "choice" {
		if answer.Choice == nil {
			return nil, false, errors.New("invalid contextual answer")
		}
		found := false
		for _, choice := range question.Choices {
			if choice == *answer.Choice {
				found = true
			}
		}
		if !found {
			return nil, false, errors.New("invalid contextual answer")
		}
		if *answer.Confidence < question.MinConfidence {
			return nil, true, nil
		}
		value, _ := json.Marshal(*answer.Choice)
		return value, false, nil
	}
	if answer.Score == nil || *answer.Score < 0 || *answer.Score > float64(len(question.Levels)-1) {
		return nil, false, errors.New("invalid contextual answer")
	}
	if *answer.Confidence < question.MinConfidence {
		return nil, true, nil
	}
	value, err := json.Marshal(*answer.Score)
	return value, false, err
}

func validProbability(value float64) bool { return !math.IsNaN(value) && value >= 0 && value <= 1 }
