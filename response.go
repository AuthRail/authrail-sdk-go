package authrail

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Read the extra byte before decoding: a valid prefix must not hide an oversized
// or second response after permission or receipt metadata.
func decodeBoundedResponse(body io.Reader, maximum int64, target any) error {
	encoded, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil || int64(len(encoded)) > maximum {
		return errors.New("response exceeds its size limit")
	}
	encoded = bytes.TrimSpace(encoded)
	if len(encoded) == 0 || encoded[0] != '{' || json.Unmarshal(encoded, target) != nil {
		return errors.New("response is not a complete JSON object")
	}
	return nil
}
