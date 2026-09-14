package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
)

// Conn holds the live connection plus per-connection SCRAM state.
//
// clientNonce and clientFirstBare are captured when the
// client-first-message is built and are needed later:
//   - clientNonce: to verify the server's combined nonce in
//     AuthenticationSASLContinue actually extends the nonce we sent
//     (the replay/MITM protection SCRAM relies on).
//   - clientFirstBare: needed to assemble AuthMessage for computing
//     ClientProof / verifying ServerSignature.
type Conn struct {
	raw               net.Conn
	r                 *bufio.Reader
	logger            *slog.Logger
	cfg               Config
	clientNonce       string
	clientFirstBare   string
	expectedServerSig string
}

func run(dsn string, logger *slog.Logger) error {
	cfg, err := parseDSN(dsn)
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	var dialer net.Dialer
	raw, err := dialer.DialContext(dialCtx, "tcp", cfg.Host)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer raw.Close()

	c := &Conn{raw: raw, r: bufio.NewReader(raw), logger: logger, cfg: cfg}

	if err := c.sendStartup(); err != nil {
		return err
	}

	return c.serve()
}

func (c *Conn) sendStartup() error {
	msg, err := buildStartupMessage(c.cfg)
	if err != nil {
		return err
	}
	if _, err := c.raw.Write(msg); err != nil {
		return fmt.Errorf("error sending message: %w", err)
	}
	return nil
}

func (c *Conn) serve() error {
	for {
		msg, err := readMessage(c.r)
		if err != nil {
			if err == io.EOF {
				c.logger.Info("connection closed by server")
				return nil
			}
			return fmt.Errorf("error reading message: %w", err)
		}

		if err := c.handleMessage(msg.msgType, msg.payload); err != nil {
			return err
		}
	}
}

func (c *Conn) handleMessage(msgType byte, payload []byte) error {
	switch msgType {
	case Authentication:
		return c.handleAuth(payload)

	case BackendKeyData:
		c.logger.Info("BackendKeyData", "payload", string(payload))

	case BindComplete:
		c.logger.Info("BindComplete", "payload", string(payload))

	case CloseComplete:
		c.logger.Info("CloseComplete", "payload", string(payload))

	case CommandComplete:
		c.logger.Info("CommandComplete", "payload", string(payload))

	case CopyBothResponse:
		c.logger.Info("CopyBothResponse", "payload", string(payload))

	case CopyData:
		c.logger.Info("CopyData", "payload", string(payload))

	case CopyInResponse:
		c.logger.Info("CopyInResponse", "payload", string(payload))

	case CopyOutResponse:
		c.logger.Info("CopyOutResponse", "payload", string(payload))

	case DataRow:
		c.logger.Info("DataRow", "payload", string(payload))

	case EmptyQueryResponse:
		c.logger.Info("EmptyQueryResponse", "payload", string(payload))

	case ErrorResponse:
		fields := parseErrorFields(payload)
		c.logger.Error("server error response", "fields", fields)

	case FunctionCallResponse:
		c.logger.Info("FunctionCallResponse", "payload", string(payload))

	case NegotiateProtocolVersion:
		c.logger.Info("NegotiateProtocolVersion", "payload", string(payload))

	case NoData:
		c.logger.Info("NoData", "payload", string(payload))

	case NoticeResponse:
		c.logger.Info("NoticeResponse", "payload", string(payload))

	case NotificationResponse:
		c.logger.Info("NotificationResponse", "payload", string(payload))

	case ParameterDescription:
		c.logger.Info("ParameterDescription", "payload", string(payload))

	case ParameterStatus:
		c.logger.Info("ParameterStatus", "payload", string(payload))

	case ParseComplete:
		c.logger.Info("ParseComplete", "payload", string(payload))

	case PortalSuspended:
		c.logger.Info("PortalSuspended", "payload", string(payload))

	case ReadyForQuery:
		c.logger.Info("ReadyForQuery", "payload", string(payload))

	case RowDescription:
		c.logger.Info("RowDescription", "payload", string(payload))
	}
	return nil
}

func (c *Conn) handleAuth(payload []byte) error {
	authCode := binary.BigEndian.Uint32(payload[0:4])
	switch authCode {
	case AuthenticationOk:
		c.logger.Info("AuthenticationOk")

	case AuthenticationKerberosV5:
		c.logger.Info("AuthenticationKerberosV5")

	case AuthenticationCleartextPassword:
		c.logger.Info("AuthenticationCleartextPassword")

	case AuthenticationMD5Password:
		c.logger.Info("AuthenticationMD5Password")

	case AuthenticationGSS:
		c.logger.Info("AuthenticationGSS")

	case AuthenticationGSSContinue:
		c.logger.Info("AuthenticationGSSContinue")

	case AuthenticationSSPI:
		c.logger.Info("AuthenticationSSPI")

	case AuthenticationSASL:
		return c.handleSASL(payload)

	case AuthenticationSASLContinue:
		return c.handleSASLContinue(payload)

	case AuthenticationSASLFinal:
		return c.handleSASLFinal(payload)
	}
	return nil
}

func (c *Conn) handleSASL(payload []byte) error {
	mechanisms, err := parseSASLMechanisms(payload)
	if err != nil {
		return fmt.Errorf("error parsing SASL mechanisms: %w", err)
	}

	if !slices.Contains(mechanisms, "SCRAM-SHA-256") {
		return nil
	}

	c.clientNonce = rand.Text()

	clientFirstBare, err := GetClientFirstMessageBare(c.cfg.User, c.clientNonce)
	if err != nil {
		return fmt.Errorf("error building client-first-message: %w", err)
	}
	c.clientFirstBare = clientFirstBare

	gs2header, err := GetGS2Header("", "")
	if err != nil {
		return fmt.Errorf("error building gs2 header: %w", err)
	}

	msg, err := buildSASLInitialResponse(gs2header + clientFirstBare)
	if err != nil {
		return err
	}

	if _, err := c.raw.Write(msg); err != nil {
		return fmt.Errorf("error sending sasl initial response message: %w", err)
	}
	return nil
}

func (c *Conn) handleSASLContinue(payload []byte) error {
	saslData, err := parseSASLData(payload)
	if err != nil {
		return fmt.Errorf("error parsing AuthenticationSASLContinue: %w", err)
	}

	if c.clientNonce == "" {
		return fmt.Errorf("received AuthenticationSASLContinue before sending client-first-message")
	}

	// Verify the server's combined nonce actually extends the
	// nonce we generated. Without this check, a malicious or
	// misbehaving server could send back an unrelated nonce,
	// defeating the replay/MITM protection SCRAM depends on.
	if !strings.HasPrefix(saslData.CombinedNonce, c.clientNonce) {
		return fmt.Errorf(
			"server nonce does not extend client nonce: got %q, want prefix %q",
			saslData.CombinedNonce, c.clientNonce,
		)
	}

	if c.cfg.Password == "" {
		return fmt.Errorf("password is empty")
	}

	final, err := computeClientFinal(
		c.cfg.Password,
		c.clientFirstBare,
		saslData.Raw,
		saslData.CombinedNonce,
		saslData.Salt,
		saslData.PBKDF2IterationCount,
	)
	if err != nil {
		return err
	}
	c.expectedServerSig = final.expectedServerSignature

	msg, err := buildSASLResponse(final.response)
	if err != nil {
		return err
	}

	if _, err := c.raw.Write(msg); err != nil {
		return fmt.Errorf("error sending sasl response message: %w", err)
	}
	return nil
}

func (c *Conn) handleSASLFinal(payload []byte) error {
	serverSignature, err := parseServerSignature(payload)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(serverSignature), []byte(c.expectedServerSig)) != 1 {
		return fmt.Errorf("server signature from the server doesn't match the expected server signature")
	}
	return nil
}
