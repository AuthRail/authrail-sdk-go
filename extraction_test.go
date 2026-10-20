package authrail

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func sampleExtractionSource() ExtractionSource {
	return ExtractionSource{SourceVersionID: "00000000-0000-4000-8000-000000000030",
		SourceIdentity: "support.messages", AccountBoundary: "tenant_123",
		Lookup: "message.read", ResultPath: []string{"sensitive"}, ValueType: "boolean",
		ModelID: "model.v1", ModelConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PromptVersion: "prompt.v1", MaxInputBytes: 4096, MaxOutputBytes: 256,
		Timeout: time.Second}
}

func TestExtractContextFactValidatesBoundedAssertion(t *testing.T) {
	source := sampleExtractionSource()
	extractor := func(_ context.Context, document []byte) (ExtractionResult, error) {
		if string(document) != "customer note" {
			t.Fatal("source bytes changed")
		}
		return ExtractionResult{Value: json.RawMessage(`true`), ModelID: source.ModelID,
			ModelConfigSHA256: source.ModelConfigSHA256, PromptVersion: source.PromptVersion}, nil
	}
	resolution, err := ExtractContextFact(context.Background(), source, "msg_123",
		"message:msg_123", time.Now().Add(-time.Second), []byte("customer note"), extractor)
	if err != nil || resolution.Status != "ok" || resolution.Value["sensitive"] != true ||
		resolution.Extraction == nil || resolution.Extraction.SourceBytes != len("customer note") {
		t.Fatalf("bounded assertion failed: %+v %v", resolution, err)
	}
	uncertain, err := ExtractContextFact(context.Background(), source, "msg_123",
		"message:msg_123", time.Now().Add(-time.Second), []byte("customer note"),
		func(ctx context.Context, document []byte) (ExtractionResult, error) {
			result, err := extractor(ctx, document)
			result.Uncertain = true
			return result, err
		})
	if err != nil || uncertain.Status != "uncertain" || uncertain.Value != nil {
		t.Fatalf("uncertain assertion became a fact: %+v %v", uncertain, err)
	}
	wrongModel, err := ExtractContextFact(context.Background(), source, "msg_123",
		"message:msg_123", time.Now().Add(-time.Second), []byte("customer note"),
		func(context.Context, []byte) (ExtractionResult, error) {
			return ExtractionResult{Value: json.RawMessage(`true`), ModelID: "other",
				ModelConfigSHA256: source.ModelConfigSHA256, PromptVersion: source.PromptVersion}, nil
		})
	if err != nil || wrongModel.Status != "untrusted" {
		t.Fatalf("wrong extractor was trusted: %+v %v", wrongModel, err)
	}
	widerOutput, err := ExtractContextFact(context.Background(), source, "msg_123",
		"message:msg_123", time.Now().Add(-time.Second), []byte("customer note"),
		func(context.Context, []byte) (ExtractionResult, error) {
			return ExtractionResult{Value: json.RawMessage(`{"decision":"allow"}`),
				ModelID: source.ModelID, ModelConfigSHA256: source.ModelConfigSHA256,
				PromptVersion: source.PromptVersion}, nil
		})
	if err != nil || widerOutput.Status != "untrusted" {
		t.Fatalf("model decision reached the fact protocol: %+v %v", widerOutput, err)
	}
	source.MaxInputBytes = 4
	tooLarge, err := ExtractContextFact(context.Background(), source, "msg_123",
		"message:msg_123", time.Now().Add(-time.Second), []byte("customer note"), extractor)
	if err != nil || tooLarge.Status != "unavailable" || tooLarge.Extraction != nil {
		t.Fatalf("oversized document reached extractor: %+v %v", tooLarge, err)
	}
	source.MaxInputBytes = 4096
	failed, err := ExtractContextFact(context.Background(), source, "msg_123",
		"message:msg_123", time.Now().Add(-time.Second), []byte("customer note"),
		func(context.Context, []byte) (ExtractionResult, error) {
			return ExtractionResult{}, errors.New("model unavailable")
		})
	if err != nil || failed.Status != "unavailable" || failed.Value != nil {
		t.Fatalf("model failure produced a fact: %+v %v", failed, err)
	}
}
