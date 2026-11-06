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
