package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// parseSASLMechanisms parses the SASL mechanism list from a PostgreSQL
// AuthenticationSASL message.
//
// The payload must contain:
//
//	4 bytes: authentication type, which must be 10 (SASL)
//	N bytes: null-terminated mechanism names
//	1 byte:  final zero byte terminating the list
//
// For example:
//
//	00 00 00 0A
//	53 43 52 41 4D 2D 53 48 41 2D 32 35 36 00
//	00
//
// represents:
//
//	[]string{"SCRAM-SHA-256"}
func parseSASLMechanisms(payload []byte) ([]string, error) {
	// An AuthenticationSASL payload must contain at least:
	//
	//   4 bytes for the authentication type
	//   1 byte for the terminating zero
	//
	// Therefore, anything shorter than 5 bytes is invalid.
	if len(payload) < 5 {
		return nil, fmt.Errorf("invalid AuthenticationSASL payload: too short")
	}

	msgType := int(binary.BigEndian.Uint32(payload[:4]))
	if msgType != AuthenticationSASL {
		return nil, fmt.Errorf(
			"invalid AuthenticationSASL message type, got %d, message type should be %d",
			msgType,
			AuthenticationSASL,
		)
	}

	// The first four bytes are the authentication request type.
	//
	// AuthenticationSASL uses the value 10:
	//
	//   00 00 00 0A
	//
	// We don't actually need this value anymore because the caller
	// has already identified the message as AuthenticationSASL.
	//
	// Skip those four bytes so that payload now points at the
	// first SASL mechanism name.
	payload = payload[4:]

	// This will contain the mechanism names that we discover.
	//
	// For example:
	//
	//   ["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"]
	var mechanisms []string

	// Continue until we encounter the zero byte that terminates
	// the mechanism list.
	for len(payload) > 0 {

		// A zero byte at the beginning means that we have reached
		// the end of the mechanism list.
		//
		// For example:
		//
		//   SCRAM-SHA-256\0\0
		//                    ^
		//                    this zero terminates the list
		if payload[0] == 0 {
			break
		}

		// Find the zero byte terminating the current mechanism name.
		//
		// For example, if payload contains:
		//
		//   SCRAM-SHA-256\0SCRAM-SHA-256-PLUS\0\0
		//
		// IndexByte returns the position of the first '\0'.
		end := bytes.IndexByte(payload, 0)

		// Every mechanism name must be null-terminated.
		//
		// If there is no zero byte, the message is malformed.
		if end == -1 {
			return nil, fmt.Errorf(
				"invalid AuthenticationSASL payload: unterminated mechanism",
			)
		}

		// Convert the bytes before the zero byte into a Go string.
		//
		// payload[:end] contains only the mechanism name.
		//
		// For example:
		//
		//   payload = "SCRAM-SHA-256\0..."
		//   end     = 14
		//
		// gives:
		//
		//   "SCRAM-SHA-256"
		mechanism := string(payload[:end])

		// Add the mechanism to our result.
		mechanisms = append(mechanisms, mechanism)

		// Move past the mechanism name AND its terminating zero byte.
		//
		// This makes payload point at the beginning of the next
		// mechanism.
		payload = payload[end+1:]
	}

	// Return every mechanism in the same order in which PostgreSQL
	// sent them.
	//
	// PostgreSQL sends mechanisms in the server's preferred order.
	return mechanisms, nil
}

type SASLData struct {
	CombinedNonce        string
	Salt                 string
	PBKDF2IterationCount int
	Raw                  string
}

func parseSASLData(payload []byte) (SASLData, error) {
	// An AuthenticationSASL payload must contain at least:
	//
	//   4 bytes for the authentication type
	//   4 byte for the sub-code identifying this as AuthenticationSASLContinue
	//
	if len(payload) < 8 {
		return SASLData{}, fmt.Errorf("invalid AuthenticationSASLContinue payload: too short")
	}

	msgType := int(binary.BigEndian.Uint32(payload[:4]))
	if msgType != AuthenticationSASLContinue {
		return SASLData{}, fmt.Errorf(
			"invalid AuthenticationSASLContinue message type, got %d, message type should be %d",
			msgType,
			AuthenticationSASLContinue,
		)
	}

	rawSaslData := strings.TrimSpace(string(payload[4:]))

	// Use strings.Split rather than strings.FieldsFunc: FieldsFunc silently
	// drops empty tokens between separators, which would let malformed
	// input like ",r=abc,s=xyz,i=4096" (leading empty field) collapse to
	// exactly 3 fields and pass the length check below undetected. Split
	// preserves empty fields, so malformed messages are caught either here
	// or by the individual field parsers.
	fields := strings.Split(rawSaslData, ",")

	if len(fields) != 3 {
		return SASLData{}, fmt.Errorf("invalid AuthenticationSASLContinue response")
	}

	combinedNonce, err := parseCombinedNonce(fields[0])
	if err != nil {
		return SASLData{}, err
	}

	salt, err := parseSalt(fields[1])
	if err != nil {
		return SASLData{}, err
	}

	pbkdf2IterationCount, err := parsePbkdf2IterationCount(fields[2])
	if err != nil {
		return SASLData{}, err
	}

	return SASLData{CombinedNonce: combinedNonce, Salt: salt, PBKDF2IterationCount: pbkdf2IterationCount, Raw: rawSaslData}, nil
}

// parseCombinedNonce parses an "r=<value>" field and validates that the
// value is a syntactically valid SCRAM nonce (RFC 5802 "printable" charset,
// i.e. any ASCII byte in 0x21-0x7E except ','; commas are excluded because
// they're the SCRAM field delimiter).
func parseCombinedNonce(field string) (string, error) {
	const key = "r"

	k, value, found := strings.Cut(field, "=")
	if !found {
		return "", fmt.Errorf("invalid raw sasl data field")
	}
	if strings.Contains(value, "=") {
		return "", fmt.Errorf("invalid raw sasl data field")
	}
	if k != key {
		return "", fmt.Errorf("invalid key, got %q, it should be %q", k, key)
	}
	if value == "" {
		return "", fmt.Errorf("invalid nonce, value is empty")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7E || c == ',' {
			return "", fmt.Errorf("invalid nonce, contains disallowed character %q", c)
		}
	}
	return value, nil
}

// parseSalt parses an "s=<base64>" field and validates that the value is
// well-formed standard base64 decoding to a reasonable salt length.
func parseSalt(field string) (string, error) {
	const key = "s"

	k, value, found := strings.Cut(field, "=")

	if !found {
		return "", fmt.Errorf("invalid raw sasl data field")
	}

	if k != key {
		return "", fmt.Errorf("invalid key, got %q, it should be %q", k, key)
	}

	if value == "" {
		return "", fmt.Errorf("invalid salt, value is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("invalid salt, not valid base64: %w", err)
	}

	const minSaltLen = 8 // bytes; Postgres default is 16
	if len(decoded) < minSaltLen {
		return "", fmt.Errorf("invalid salt, too short (%d bytes, minimum %d)", len(decoded), minSaltLen)
	}

	return value, nil
}

// parsePbkdf2IterationCount parses an "i=<count>" field from a SCRAM
// server-first-message and returns the PBKDF2 iteration count as an int.
//
// The field must have the exact form "i=<positive integer>", with no sign,
// no leading zeros, and no extraneous "=" characters. The parsed value is
// bounds-checked against a minimum of 4,096 iterations, as mandated by
// RFC 7677 for SCRAM-SHA-256, and a maximum of 1,000,000 iterations as a
// defensive ceiling against a malicious or misconfigured server forcing
// excessive client-side PBKDF2 computation (a denial-of-service vector).
//
// It returns an error if the field is malformed, the key is not "i", the
// value is not a valid non-negative integer, or the value falls outside
// the [4096, 1000000] range.
func parsePbkdf2IterationCount(field string) (int, error) {
	const key = "i"
	const minIterations = 4_096
	const maxIterations = 1_000_000

	k, value, found := strings.Cut(field, "=")
	if !found {
		return 0, fmt.Errorf("invalid pbkdf2 iteration format")
	}
	if strings.Contains(value, "=") {
		return 0, fmt.Errorf("invalid pbkdf2 iteration format")
	}
	if k != key {
		return 0, fmt.Errorf("invalid key for pbkdf2 iteration count, got %q, it should be %q", k, key)
	}
	if value == "" {
		return 0, fmt.Errorf("invalid value for pbkdf2 iteration count, value is empty")
	}
	if value[0] == '+' || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("invalid value for pbkdf2 iteration count, malformed integer")
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid value for pbkdf2 iteration count, it should be an integer")
	}
	if n < minIterations {
		return 0, fmt.Errorf("invalid value for pbkdf2 iteration count, the minimum should be %d, got %d", minIterations, n)
	}
	if n > maxIterations {
		return 0, fmt.Errorf("invalid value for pbkdf2 iteration count, is too large, got %d, it should be less than %d", n, maxIterations)
	}

	return n, nil
}

func parseServerSignature(payload []byte) (string, error) {
	const key = "v"

	if len(payload) < 4 {
		return "", fmt.Errorf("invalid AuthenticationSASLFinal payload: too short")
	}

	msgType := int(binary.BigEndian.Uint32(payload[:4]))
	if msgType != AuthenticationSASLFinal {
		return "", fmt.Errorf(
			"invalid AuthenticationSASLFinal message type, got %d, message type should be %d",
			msgType,
			AuthenticationSASLFinal,
		)
	}

	field := string(payload[4:])

	k, value, found := strings.Cut(field, "=")
	if !found {
		return "", fmt.Errorf("invalid raw sasl data field")
	}
	if k != key {
		return "", fmt.Errorf("invalid key, got %s, it should be %s", k, key)
	}
	if value == "" {
		return "", fmt.Errorf("invalid server signature, value is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("invalid server signature, not valid base64: %w", err)
	}

	const sha256Size = 32
	if len(decoded) != sha256Size {
		return "", fmt.Errorf("invalid server signature, expected %d bytes, got %d", sha256Size, len(decoded))
	}

	return value, nil
}
