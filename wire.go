package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func writeParam(params *bytes.Buffer, key, value string) {
	params.WriteString(key)
	params.WriteByte(0x00)
	params.WriteString(value)
	params.WriteByte(0x00)
}

// message is a single backend message: its type byte plus payload
// (everything after the int32 length prefix).
type message struct {
	msgType byte
	payload []byte
}

func readMessage(r *bufio.Reader) (message, error) {
	msgType, err := r.ReadByte()
	if err != nil {
		return message{}, err
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return message{}, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)

	payloadLen := msgLen - 4
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return message{}, err
		}
	}

	return message{msgType: msgType, payload: payload}, nil
}

// writeMessage frames a regular frontend message (type byte + int32
// length including itself + body) and writes it to w.
func writeMessage(w io.Writer, typ byte, body []byte) error {
	var msg bytes.Buffer
	msg.WriteByte(typ)
	if err := binary.Write(&msg, binary.BigEndian, int32(4+len(body))); err != nil {
		return fmt.Errorf("error encoding message length: %w", err)
	}
	msg.Write(body)

	if _, err := w.Write(msg.Bytes()); err != nil {
		return fmt.Errorf("error sending message: %w", err)
	}
	return nil
}

// buildStartupMessage returns the initial StartupMessage bytes
// (int32 length + int32 protocol + null-terminated params + terminator).
// Unlike regular messages it has no leading type byte.
func buildStartupMessage(cfg Config) ([]byte, error) {
	var params bytes.Buffer
	writeParam(&params, "user", cfg.User)
	writeParam(&params, "database", cfg.Database)
	params.WriteByte(0x00)

	var msg bytes.Buffer
	if err := binary.Write(&msg, binary.BigEndian, int32(4+4+params.Len())); err != nil {
		return nil, fmt.Errorf("error encoding startup message length: %w", err)
	}
	if err := binary.Write(&msg, binary.BigEndian, int32(PROTOCOL_VERSION)); err != nil {
		return nil, fmt.Errorf("error encoding protocol version: %w", err)
	}
	msg.Write(params.Bytes())

	return msg.Bytes(), nil
}

// buildSASLInitialResponse returns a framed SASLInitialResponse ('p')
// message for the given client-first-message.
func buildSASLInitialResponse(clientFirstMessage string) ([]byte, error) {
	var body bytes.Buffer
	body.WriteString("SCRAM-SHA-256")
	body.WriteByte(0x00)

	if err := binary.Write(&body, binary.BigEndian, int32(len(clientFirstMessage))); err != nil {
		return nil, fmt.Errorf("error encoding client-first-message length: %w", err)
	}
	body.WriteString(clientFirstMessage)

	var msg bytes.Buffer
	msg.WriteByte('p')
	if err := binary.Write(&msg, binary.BigEndian, int32(4+body.Len())); err != nil {
		return nil, fmt.Errorf("error encoding message length: %w", err)
	}
	msg.Write(body.Bytes())

	return msg.Bytes(), nil
}

// buildSASLResponse returns a framed SASLResponse ('p') message
// for the given client-final-message.
func buildSASLResponse(saslResponse string) ([]byte, error) {
	var msg bytes.Buffer
	msg.WriteByte('p')
	if err := binary.Write(&msg, binary.BigEndian, int32(4+len(saslResponse))); err != nil {
		return nil, fmt.Errorf("error encoding message length: %w", err)
	}
	msg.WriteString(saslResponse)

	return msg.Bytes(), nil
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
