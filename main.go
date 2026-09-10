package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	PROTOCOL_VERSION_MAJOR = 3
	PROTOCOL_VERSION_MINOR = 2
	PROTOCOL_VERSION       = (PROTOCOL_VERSION_MAJOR << 16) | PROTOCOL_VERSION_MINOR
)

const (
	Authentication           = 'R'
	BackendKeyData           = 'K'
	BindComplete             = '2'
	CloseComplete            = '3'
	CommandComplete          = 'C'
	CopyData                 = 'd'
	CopyInResponse           = 'G'
	CopyOutResponse          = 'H'
	CopyBothResponse         = 'W'
	DataRow                  = 'D'
	EmptyQueryResponse       = 'I'
	ErrorResponse            = 'E'
	FunctionCallResponse     = 'V'
	NegotiateProtocolVersion = 'v'
	NoData                   = 'n'
	NoticeResponse           = 'N'
	NotificationResponse     = 'A'
	ParameterDescription     = 't'
	ParameterStatus          = 'S'
	ParseComplete            = '1'
	PortalSuspended          = 's'
	ReadyForQuery            = 'Z'
	RowDescription           = 'T'
)

const (
	// Specifies that the authentication was successful.
	AuthenticationOk = 0

	// Specifies that Kerberos V5 authentication is required.
	AuthenticationKerberosV5 = 2

	// Specifies that a clear-text password is required.
	AuthenticationCleartextPassword = 3

	// Specifies that an MD5-encrypted password is required.
	AuthenticationMD5Password = 5

	// Specifies that GSSAPI authentication is required.
	AuthenticationGSS = 7

	// Specifies that this message contains GSSAPI or SSPI data.
	AuthenticationGSSContinue = 8

	// Specifies that SSPI authentication is required.
	AuthenticationSSPI = 9

	// Specifies that SASL authentication is required.
	AuthenticationSASL = 10

	// Specifies that this message contains a SASL challenge.
	AuthenticationSASLContinue = 11

	// Specifies that SASL authentication has completed.
	AuthenticationSASLFinal = 12
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: false}))

	if err := run(logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	u, err := url.Parse("postgresql://postgres:password123@127.0.0.1:5432/dvdrental?sslmode=require&application_name=myapp&connect_timeout=10")
	if err != nil {
		return fmt.Errorf("error parsing url: %w", err)
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fmt.Errorf("incorrect postgresql scheme in the url")
	}

	// Use connect_timeout from the URL (falling back to a sane default) to
	// bound how long we wait to establish the TCP connection, so a
	// hung/unreachable server can't block the client forever.
	connectTimeout := 10 * time.Second
	if raw := u.Query().Get("connect_timeout"); raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid connect_timeout %q: %w", raw, err)
		}
		connectTimeout = time.Duration(secs) * time.Second
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", u.Host)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer conn.Close()

	user := u.User.Username()
	database := u.Path[1:]

	var params bytes.Buffer
	writeParam(&params, "user", user)
	writeParam(&params, "database", database)
	params.WriteByte(0x00)

	var msg bytes.Buffer

	length := int32(4 + 4 + params.Len())

	binary.Write(&msg, binary.BigEndian, length)
	binary.Write(&msg, binary.BigEndian, int32(PROTOCOL_VERSION))

	msg.Write(params.Bytes())

	if _, err := conn.Write(msg.Bytes()); err != nil {
		return fmt.Errorf("error sending message: %w", err)
	}

	reader := bufio.NewReader(conn)

	// Per-connection SCRAM state. clientNonce and clientFirstMessageBare
	// are captured when we build the client-first-message, and are needed
	// later:
	//   - clientNonce: to verify the server's combined nonce in
	//     AuthenticationSASLContinue actually extends the nonce we sent
	//     (this is the replay/MITM protection SCRAM relies on).
	//   - clientFirstMessageBare: needed later to assemble AuthMessage for
	//     computing ClientProof / verifying ServerSignature.
	var clientNonce string
	var clientFirstMessageBare string
	var expectedServerSignature string

	for {
		msgType, payload, err := readMessage(reader)
		if err != nil {
			if err == io.EOF {
				logger.Info("connection closed by server")
				return nil
			}
			return fmt.Errorf("error reading message: %w", err)
		}

		switch msgType {
		case Authentication:
			authCode := binary.BigEndian.Uint32(payload[0:4])
			switch authCode {
			case AuthenticationOk:
				logger.Info("AuthenticationOk")

			case AuthenticationKerberosV5:
				logger.Info("AuthenticationKerberosV5")

			case AuthenticationCleartextPassword:
				logger.Info("AuthenticationCleartextPassword")

			case AuthenticationMD5Password:
				logger.Info("AuthenticationMD5Password")

			case AuthenticationGSS:
				logger.Info("AuthenticationGSS")

			case AuthenticationGSSContinue:
				logger.Info("AuthenticationGSSContinue")

			case AuthenticationSSPI:
				logger.Info("AuthenticationSSPI")

			case AuthenticationSASL:
				mechanisms, err := parseSASLMechanisms(payload)
				if err != nil {
					return fmt.Errorf("error parsing SASL mechanisms: %w", err)
				}

				if slices.Contains(mechanisms, "SCRAM-SHA-256") {
					clientNonce = rand.Text()

					var errFirst error
					clientFirstMessageBare, errFirst = GetClientFirstMessageBare(user, clientNonce)
					if errFirst != nil {
						return fmt.Errorf("error building client-first-message: %w", errFirst)
					}

					gs2header, errHeader := GetGS2Header("", "")
					if errHeader != nil {
						return fmt.Errorf("error building gs2 header: %w", errHeader)
					}

					clientFirstMessage := gs2header + clientFirstMessageBare

					// SASLInitialResponse
					var body bytes.Buffer
					body.WriteString("SCRAM-SHA-256")
					body.WriteByte(0x00)

					lenClientFirstMessage := int32(len(clientFirstMessage))
					binary.Write(&body, binary.BigEndian, lenClientFirstMessage)

					body.WriteString(clientFirstMessage)

					var msg bytes.Buffer
					msg.WriteByte('p')
					length := int32(4 + body.Len())
					binary.Write(&msg, binary.BigEndian, length)

					msg.Write(body.Bytes())

					if _, err := conn.Write(msg.Bytes()); err != nil {
						return fmt.Errorf("error sending sasl initial response message: %w", err)
					}
				}

			case AuthenticationSASLContinue:
				saslData, rawSaslData, err := parseSASLData(payload)
				if err != nil {
					return fmt.Errorf("error parsing AuthenticationSASLContinue: %w", err)
				}

				if clientNonce == "" {
					return fmt.Errorf("received AuthenticationSASLContinue before sending client-first-message")
				}

				// Verify the server's combined nonce actually extends the
				// nonce we generated. Without this check, a malicious or
				// misbehaving server could send back an unrelated nonce,
				// defeating the replay/MITM protection SCRAM depends on.
				if !strings.HasPrefix(saslData.CombinedNonce, clientNonce) {
					return fmt.Errorf(
						"server nonce does not extend client nonce: got %q, want prefix %q",
						saslData.CombinedNonce, clientNonce,
					)
				}

				password, ok := u.User.Password()
				if !ok {
					return fmt.Errorf("password is empty")
				}

				decodedSalt, err := base64.StdEncoding.DecodeString(saslData.Salt)
				if err != nil {
					return fmt.Errorf("error decoding salt: %w", err)
				}

				saltedPassword, err := pbkdf2.Key(
					sha256.New,
					password,
					decodedSalt,
					saslData.PBKDF2IterationCount,
					32,
				)
				if err != nil {
					return fmt.Errorf("error getting derived key: %w", err)
				}

				hmacHashClient := hmac.New(sha256.New, saltedPassword)
				hmacHashClient.Write([]byte("Client Key"))
				clientKey := hmacHashClient.Sum(nil)

				storedKey := sha256.Sum256(clientKey)

				hmacHashServer := hmac.New(sha256.New, saltedPassword)
				hmacHashServer.Write([]byte("Server Key"))
				serverKey := hmacHashServer.Sum(nil)

				clientFinalWithoutProof := "c=biws," + "r=" + saslData.CombinedNonce

				authMessage := clientFirstMessageBare + "," + rawSaslData + "," + clientFinalWithoutProof

				hmacHashServerSignature := hmac.New(sha256.New, serverKey)
				hmacHashServerSignature.Write([]byte(authMessage))
				expectedServerSignature = base64.StdEncoding.EncodeToString(hmacHashServerSignature.Sum(nil))

				hmacHashSignature := hmac.New(sha256.New, storedKey[:])
				hmacHashSignature.Write([]byte(authMessage))
				clientSignature := hmacHashSignature.Sum(nil)

				clientProof := make([]byte, len(clientKey))
				subtle.XORBytes(clientProof, clientKey, clientSignature)

				saslResponse := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)

				// SASLResponse
				var body bytes.Buffer
				body.WriteString(saslResponse)

				var msg bytes.Buffer
				msg.WriteByte('p')
				length := int32(4 + body.Len())
				binary.Write(&msg, binary.BigEndian, length)

				msg.Write(body.Bytes())

				if _, err := conn.Write(msg.Bytes()); err != nil {
					return fmt.Errorf("error sending sasl response message: %w", err)
				}

			case AuthenticationSASLFinal:
				serverSignature, err := parseServerSignature(payload)
				if err != nil {
					return err
				}

				if subtle.ConstantTimeCompare([]byte(serverSignature), []byte(expectedServerSignature)) != 1 {
					return fmt.Errorf("server signature from the server doesn't match the expected server signature")
				}
			}

		case BackendKeyData:
			logger.Info("BackendKeyData", "payload", string(payload))

		case ErrorResponse:
			fields := parseErrorFields(payload)
			logger.Error("server error response", "fields", fields)

		case ParameterStatus:
			logger.Info("ParameterStatus", "payload", string(payload))

		case ReadyForQuery:
			logger.Info("ReadyForQuery", "payload", string(payload))
		}
	}
}

func writeParam(params *bytes.Buffer, key, value string) {
	params.WriteString(key)
	params.WriteByte(0x00)
	params.WriteString(value)
	params.WriteByte(0x00)
}

func readMessage(r *bufio.Reader) (byte, []byte, error) {
	msgType, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)

	payloadLen := msgLen - 4
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}

	return msgType, payload, nil
}

// GetClientFirstMessageBare builds the "client-first-message-bare" portion
// of the SCRAM client-first-message (i.e. everything after the GS2 header):
//
//	n=<username>,r=<nonce>
//
// This is kept separate from the GS2 header because RFC 5802 requires the
// *bare* message (without the header) when constructing AuthMessage later.
func GetClientFirstMessageBare(username, nonce string) (string, error) {
	nAttribute, err := GetUsernameAttribute(username)
	if err != nil {
		return "", err
	}
	rAttribute := "r=" + nonce

	return nAttribute + "," + rAttribute, nil
}

func GetGS2Header(channelBinding, authzID string) (string, error) {
	var flag string

	switch channelBinding {
	case "":
		// No channel binding support.
		flag = "n"

	case "unsupported":
		// Client supports channel binding, but believes
		// the server does not.
		flag = "y"

	default:
		// A specific channel-binding type was selected.
		if !validCBName(channelBinding) {
			return "", fmt.Errorf("invalid channel binding type %q", channelBinding)
		}

		flag = "p=" + channelBinding
	}

	if authzID == "" {
		return flag + ",,", nil
	}

	return flag + ",a=" + saslName(authzID) + ",", nil
}

func validCBName(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' ||
			r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' ||
			r == '.' || r == '-') {
			return false
		}
	}

	return true
}

func saslName(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}

func GetUsernameAttribute(username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("username cannot be empty")
	}

	username = saslName(username)

	return "n=" + username, nil
}

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
}

func parseSASLData(payload []byte) (SASLData, string, error) {
	// An AuthenticationSASL payload must contain at least:
	//
	//   4 bytes for the authentication type
	//   4 byte for the sub-code identifying this as AuthenticationSASLContinue
	//
	if len(payload) < 8 {
		return SASLData{}, "", fmt.Errorf("invalid AuthenticationSASLContinue payload: too short")
	}

	msgType := int(binary.BigEndian.Uint32(payload[:4]))
	if msgType != AuthenticationSASLContinue {
		return SASLData{}, "", fmt.Errorf(
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
		return SASLData{}, "", fmt.Errorf("invalid AuthenticationSASLContinue response")
	}

	combinedNonce, err := parseCombinedNonce(fields[0])
	if err != nil {
		return SASLData{}, "", err
	}

	salt, err := parseSalt(fields[1])
	if err != nil {
		return SASLData{}, "", err
	}

	pbkdf2IterationCount, err := parsePbkdf2IterationCount(fields[2])
	if err != nil {
		return SASLData{}, "", err
	}

	return SASLData{combinedNonce, salt, pbkdf2IterationCount}, rawSaslData, nil
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

// parseErrorFields parses the field-code/String pairs from an
// ErrorResponse (or NoticeResponse) payload, per RFC/PG's
// "55.8. Error and Notice Message Fields" (field codes like
// 'S'=severity, 'M'=message, 'C'=sqlstate, 'D'=detail, 'H'=hint).
func parseErrorFields(payload []byte) map[byte]string {
	fields := make(map[byte]string)
	for len(payload) > 0 {
		code := payload[0]
		payload = payload[1:]
		if code == 0 {
			break
		}
		end := bytes.IndexByte(payload, 0)
		if end == -1 {
			break
		}
		fields[code] = string(payload[:end])
		payload = payload[end+1:]
	}
	return fields
}

func parseAuthenticationSASLFinal(payload []byte) (string, error) {
	return "", nil
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
