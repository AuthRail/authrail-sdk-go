package authrail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"time"
)

var extractionVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{1,159}$`)
var extractionLocationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$`)
var extractionFieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
var extractionSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type ExtractionSource struct {
	SourceVersionID   string
	SourceIdentity    string
	AccountBoundary   string
	Lookup            string
	ResultPath        []string
	ValueType         string
	ModelID           string
	ModelConfigSHA256 string
	PromptVersion     string
	MaxInputBytes     int
	MaxOutputBytes    int
	Timeout           time.Duration
}

type ExtractionResult struct {
	Value             json.RawMessage
	Uncertain         bool
	ModelID           string
	ModelConfigSHA256 string
	PromptVersion     string
}

type Extractor func(context.Context, []byte) (ExtractionResult, error)

func ExtractContextFact(ctx context.Context, source ExtractionSource, lookupKey string,
	sourceLocation string, observedAt time.Time, document []byte, extractor Extractor) (FactResolution, error) {
	if !uuidPattern.MatchString(source.SourceVersionID) || !sourceNamePattern.MatchString(source.SourceIdentity) ||
		!accountBoundaryPattern.MatchString(source.AccountBoundary) ||
		!sourceNamePattern.MatchString(source.Lookup) || lookupKey == "" || len(lookupKey) > 256 ||
		!extractionLocationPattern.MatchString(sourceLocation) ||
		!extractionVersionPattern.MatchString(source.ModelID) ||
		!extractionSHA256Pattern.MatchString(source.ModelConfigSHA256) ||
		!extractionVersionPattern.MatchString(source.PromptVersion) ||
		len(source.ResultPath) < 1 || len(source.ResultPath) > 8 ||
		(source.ValueType != "string" && source.ValueType != "number" && source.ValueType != "boolean") ||
		source.MaxInputBytes < 1 || source.MaxInputBytes > 65536 ||
		source.MaxOutputBytes < 1 || source.MaxOutputBytes > 4096 ||
		source.Timeout < 100*time.Millisecond || source.Timeout > 10*time.Second ||
		observedAt.IsZero() || observedAt.After(time.Now().Add(5*time.Second)) || extractor == nil {
		return FactResolution{}, errors.New("extraction source configuration is invalid")
	}
	for _, segment := range source.ResultPath {
		if !extractionFieldPattern.MatchString(segment) {
			return FactResolution{}, errors.New("extraction result path is invalid")
		}
	}
	resolution := FactResolution{SourceVersionID: source.SourceVersionID,
		SourceIdentity: source.SourceIdentity, AccountBoundary: source.AccountBoundary,
		Lookup: source.Lookup, LookupKey: lookupKey, AuthenticatedExecutor: true,
		Status: "unavailable"}
	if len(document) == 0 || len(document) > source.MaxInputBytes {
		return resolution, nil
	}
	requestContext, cancel := context.WithTimeout(ctx, source.Timeout)
	defer cancel()
	result, err := extractor(requestContext, append([]byte(nil), document...))
	if err != nil || requestContext.Err() != nil {
		return resolution, nil
	}
	if result.ModelID != source.ModelID || result.ModelConfigSHA256 != source.ModelConfigSHA256 ||
		result.PromptVersion != source.PromptVersion {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	digest := sha256.Sum256(document)
	resolution.ObservedAt = observedAt.UTC().Format(time.RFC3339Nano)
	resolution.Extraction = &ExtractionProvenance{SourceSHA256: hex.EncodeToString(digest[:]),
		SourceBytes: len(document), SourceLocation: sourceLocation,
		ModelID: result.ModelID, ModelConfigSHA256: result.ModelConfigSHA256,
		PromptVersion: result.PromptVersion, ExtractedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if result.Uncertain {
		resolution.Status = "uncertain"
		return resolution, nil
	}
	if len(result.Value) == 0 || len(result.Value) > source.MaxOutputBytes {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Value))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF ||
		!validExtractionValue(value, source.ValueType) {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	if number, numeric := value.(json.Number); numeric {
		value, err = strconv.ParseFloat(string(number), 64)
		if err != nil {
			resolution.Status = "untrusted"
			return resolution, nil
		}
	}
	var projected map[string]any
	for index := len(source.ResultPath) - 1; index >= 0; index-- {
		if projected == nil {
			projected = map[string]any{source.ResultPath[index]: value}
		} else {
			projected = map[string]any{source.ResultPath[index]: projected}
		}
	}
	encoded, err := json.Marshal(projected)
	if err != nil || len(encoded) > source.MaxOutputBytes {
		resolution.Status = "untrusted"
		return resolution, nil
	}
	resolution.Value = projected
	resolution.Status = "ok"
	return resolution, nil
}

func validExtractionValue(value any, valueType string) bool {
	switch valueType {
	case "string":
		_, valid := value.(string)
		return valid
	case "boolean":
		_, valid := value.(bool)
		return valid
	case "number":
		number, valid := value.(json.Number)
		if !valid {
			return false
		}
		_, err := strconv.ParseFloat(string(number), 64)
		return err == nil
	default:
		return false
	}
}
