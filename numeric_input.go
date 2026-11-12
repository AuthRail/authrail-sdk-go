package authrail

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
)

// decodeInputObject preserves the protocol's binary64 canonical bytes while
// rejecting exact JSON values that would change when checked by the sidecar.
func decodeInputObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return nil, errors.New("input must be a bounded JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil || object == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("input must be a JSON object")
	}
	if err := normalizeInputNumbers(object); err != nil {
		return nil, err
	}
	return object, nil
}

func normalizeInputNumbers(value any) error {
	switch container := value.(type) {
	case map[string]any:
		for key, child := range container {
			if number, ok := child.(json.Number); ok {
				parsed, err := inputNumber(number)
				if err != nil {
					return err
				}
				container[key] = parsed
			} else if err := normalizeInputNumbers(child); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range container {
			if number, ok := child.(json.Number); ok {
				parsed, err := inputNumber(number)
				if err != nil {
					return err
				}
				container[index] = parsed
			} else if err := normalizeInputNumbers(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func inputNumber(number json.Number) (float64, error) {
	parsed, err := number.Float64()
	if err != nil {
		return 0, errors.New("input number is outside the supported JSON range")
	}
	// Handle zero before rational parsing: an extreme exponent on zero or an
	// underflowing value must not allocate an enormous power of ten.
	if parsed == 0 {
		mantissa := strings.FieldsFunc(string(number), func(r rune) bool { return r == 'e' || r == 'E' })[0]
		if strings.Trim(mantissa, "-0.") == "" {
			return parsed, nil
		}
		return 0, errors.New("input number loses precision; use a string for exact values")
	}
	canonical, err := json.Marshal(parsed)
	if err != nil {
		return 0, errors.New("input number is outside the supported JSON range")
	}
	original, originalOK := new(big.Rat).SetString(string(number))
	roundTrip, roundTripOK := new(big.Rat).SetString(string(canonical))
	if !originalOK || !roundTripOK || original.Cmp(roundTrip) != 0 {
		return 0, errors.New("input number loses precision; use a string for exact values")
	}
	return parsed, nil
}
