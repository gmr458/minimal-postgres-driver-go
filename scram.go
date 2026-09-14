package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

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

// derivedKeys groups the SCRAM key material derived from the password
// (RFC 5802 / RFC 7677, SHA-256).
type derivedKeys struct {
	saltedPassword []byte
	clientKey      []byte
	storedKey      []byte
	serverKey      []byte
}

// clientFinal groups the client-final-message response together with the
// expected server signature to compare against SASLFinal.
type clientFinal struct {
	response                string
	expectedServerSignature string
}

// deriveKeys runs PBKDF2 over the password/salt and derives the SCRAM
// ClientKey, StoredKey and ServerKey (RFC 5802 / RFC 7677, SHA-256).
func deriveKeys(password string, salt []byte, iterCount int) (derivedKeys, error) {
	saltedPassword, err := pbkdf2.Key(sha256.New, password, salt, iterCount, 32)
	if err != nil {
		return derivedKeys{}, fmt.Errorf("error getting derived key: %w", err)
	}

	mac := hmac.New(sha256.New, saltedPassword)
	mac.Write([]byte("Client Key"))
	clientKey := mac.Sum(nil)

	sum := sha256.Sum256(clientKey)
	storedKey := sum[:]

	mac = hmac.New(sha256.New, saltedPassword)
	mac.Write([]byte("Server Key"))
	serverKey := mac.Sum(nil)

	return derivedKeys{
		saltedPassword: saltedPassword,
		clientKey:      clientKey,
		storedKey:      storedKey,
		serverKey:      serverKey,
	}, nil
}

// computeClientFinal builds the client-final-message and the expected
// server signature from the SCRAM exchange state.
func computeClientFinal(password string, clientFirstBare string, serverFirst string, combinedNonce string, saltB64 string, iterCount int) (clientFinal, error) {
	decodedSalt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return clientFinal{}, fmt.Errorf("error decoding salt: %w", err)
	}

	keys, err := deriveKeys(password, decodedSalt, iterCount)
	if err != nil {
		return clientFinal{}, err
	}

	clientFinalWithoutProof := "c=biws," + "r=" + combinedNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	mac := hmac.New(sha256.New, keys.serverKey)
	mac.Write([]byte(authMessage))
	expectedServerSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	mac = hmac.New(sha256.New, keys.storedKey)
	mac.Write([]byte(authMessage))
	clientSignature := mac.Sum(nil)

	clientProof := make([]byte, len(keys.clientKey))
	subtle.XORBytes(clientProof, keys.clientKey, clientSignature)

	response := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	return clientFinal{
		response:                response,
		expectedServerSignature: expectedServerSignature,
	}, nil
}
