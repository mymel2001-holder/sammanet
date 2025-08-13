package main

import (
	"encoding/base64"
	"encoding/json"
	"crypto/ed25519"
)

// ProtocolMessage represents a minimal, signed message used by the IPFS/Tor based protocol.
// It is designed to be extended by Phase 3 (CID-based messaging and content pointers).
type ProtocolMessage struct {
	Type      string `json:"type"`
	CID       string `json:"cid,omitempty"`
	Data      string `json:"data,omitempty"`
	Pub       string `json:"pub,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Sig       string `json:"sig"`
}

// SignProtocol signs a ProtocolMessage using the provided Ed25519 private key.
// It returns the base64-encoded signature string and the caller is responsible for
// attaching the resulting signature back into the message (Sig field can be set by caller after signing if needed).
func SignProtocol(priv ed25519.PrivateKey, pm ProtocolMessage) (string, error) {
	pm.Sig = ""
	b, err := json.Marshal(pm)
	if err != nil {
		return "", err
	}
	s := ed25519.Sign(priv, b)
	return base64.StdEncoding.EncodeToString(s), nil
}

// VerifyProtocol verifies the signature attached to a ProtocolMessage given the public key.
// It does not mutate theSig field of the provided message.
func VerifyProtocol(pub ed25519.PublicKey, pm ProtocolMessage) bool {
	sigBytes, err := base64.StdEncoding.DecodeString(pm.Sig)
	if err != nil {
		return false
	}
	// Build a copy with the signature removed for verification
	pm.Sig = ""
	b, err := json.Marshal(pm)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, b, sigBytes)
}