package authrail

import (
	"context"
	"regexp"
	"strings"
)

const credentialRedactionHandlerID = "authrail_redact_credentials_v1"
const credentialRedactionHandlerVersion = "cea4d8ac57cc39a33a9584742b56e412ff889026cb6b69b086bccbe4cc25d833"

var credentialTokenV1 = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|(?:AKIA|ASIA)[A-Z0-9]{16}`)

// credentialFormatV1 recognizes only the pinned credential formats. It does not
// classify arbitrary confidential text or establish whether a token is active.
func credentialFormatV1(input string) bool {
	for _, marker := range []string{
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		if strings.Contains(input, marker) {
			return true
		}
	}
	for _, match := range credentialTokenV1.FindAllStringIndex(input, -1) {
		if (match[0] == 0 || !credentialTokenByte(input[match[0]-1])) &&
			(match[1] == len(input) || !credentialTokenByte(input[match[1]])) {
			return true
		}
	}
	return false
}

func credentialTokenByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' || value == '_'
}

func credentialRedactionHandler() GuardHandler {
	return GuardHandler{ID: credentialRedactionHandlerID, Version: credentialRedactionHandlerVersion,
		Kind: "sanitize", Process: func(ctx context.Context, input string) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if credentialFormatV1(input) {
				return "[REDACTED]", nil
			}
			return input, nil
		}}
}

const emailRedactionHandlerID = "authrail_redact_email_v1"
const emailRedactionHandlerVersion = "9773bce1f804773de4e773f4fedbc3f8a15785d26e70e49ad7b600eb631ea49d"
const paymentCardRedactionHandlerID = "authrail_redact_payment_card_v1"
const paymentCardRedactionHandlerVersion = "01c828b26465d66ad89cb6a350c82d9afa1d8673ee8e167acfc33bde27c1535b"
const fieldWithholdingHandlerID = "authrail_withhold_field_v1"
const fieldWithholdingHandlerVersion = "3ebd6aaea66cbd30459938a624b0f74d6bea612e28d6638273a67145b2fe5555"

var emailCandidatesV1 = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+`)
var emailLastLabelV1 = regexp.MustCompile(`^[A-Za-z]{2,63}$`)
var cardCandidatesV1 = regexp.MustCompile(`[0-9](?:[0-9 -]*[0-9])?`)

func emailAddressV1(input string) bool {
	for _, match := range emailCandidatesV1.FindAllStringIndex(input, -1) {
		if match[0] > 0 && (credentialTokenByte(input[match[0]-1]) || strings.ContainsRune(".%+@-", rune(input[match[0]-1]))) ||
			match[1] < len(input) && (credentialTokenByte(input[match[1]]) || strings.ContainsRune("@-", rune(input[match[1]]))) {
			continue
		}
		candidate := input[match[0]:match[1]]
		local, domain, _ := strings.Cut(candidate, "@")
		last := domain[strings.LastIndex(domain, ".")+1:]
		if len(candidate) <= 254 && !strings.Contains(local, "..") && !strings.HasSuffix(local, ".") && emailLastLabelV1.MatchString(last) {
			return true
		}
	}
	return false
}

func paymentCardV1(input string) bool {
	for _, candidate := range cardCandidatesV1.FindAllString(input, -1) {
		digits := strings.NewReplacer(" ", "", "-", "").Replace(candidate)
		if len(digits) < 13 || len(digits) > 19 || strings.Count(digits, digits[:1]) == len(digits) {
			continue
		}
		sum, double := 0, false
		for index := len(digits) - 1; index >= 0; index-- {
			digit := int(digits[index] - '0')
			if double {
				digit *= 2
				if digit > 9 {
					digit -= 9
				}
			}
			sum += digit
			double = !double
		}
		if sum%10 == 0 {
			return true
		}
	}
	return false
}

func builtinGuardHandlers() []GuardHandler {
	makeRedactor := func(id, version string, detect func(string) bool) GuardHandler {
		return GuardHandler{ID: id, Version: version, Kind: "sanitize", Process: func(ctx context.Context, value string) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if detect(value) {
				return "[REDACTED]", nil
			}
			return value, nil
		}}
	}
	return []GuardHandler{credentialRedactionHandler(),
		makeRedactor(emailRedactionHandlerID, emailRedactionHandlerVersion, emailAddressV1),
		makeRedactor(paymentCardRedactionHandlerID, paymentCardRedactionHandlerVersion, paymentCardV1),
		{ID: fieldWithholdingHandlerID, Version: fieldWithholdingHandlerVersion, Kind: "sanitize", Process: func(ctx context.Context, _ string) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return "[WITHHELD]", nil
		}},
	}
}

func reservedGuardHandlerID(id string) bool {
	return id == credentialRedactionHandlerID || id == emailRedactionHandlerID || id == paymentCardRedactionHandlerID || id == fieldWithholdingHandlerID
}
