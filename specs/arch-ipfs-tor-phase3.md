# arch-ipfs-tor-phase3.md

Phase 3: Minimal decentralized protocol atop IPFS and Tor (signed blocks, CID-based messaging)

Date: 2025-08-12

Purpose
- Define a concrete, minimal protocol layer that enables signed content pointers and CID-based messaging over IPFS and Tor.
- Provide a forward-compatible design for Phase 4 enhancements (e.g., pubsub coordination, routing, and higher-level consensus).

Scope
- Implement a small, self-contained protocol for:
  - Signed content pointers (ProtocolMessage) that refer to IPFS CIDs and optionally carry application data.
  - Lightweight message exchange using a CID-based addressing pattern.
- Provide server-side support in the Go node for:
  - Accepting signed protocol messages via an HTTP API.
  - Verifying signatures using Ed25519 keys.
  - Echoing back or persisting the message for subsequent propagation to peers (in-memory or simple file store).
- Provide client support in Python (and JS) to publish and fetch protocol messages, leveraging existing IPFS nodes where applicable.

Data model
- ProtocolMessage
  - Type: string (e.g., "content_pointer", "pubsub_signal", "update")
  - CID: optional string (IPFS CID of the content being pointed to)
  - Data: optional string (arbitrary payload; encoded if binary)
  - Pub: base64-encoded Ed25519 public key of the sender
  - Timestamp: int64 (unix epoch)
  - Sig: base64-encoded Ed25519 signature of the message with Sig field cleared during signing

Security and trust model
- All messages are signed by the sender’s Ed25519 private key.
- Receivers verify the signature using the provided Pub.
- IPFS CID ensures content immutability; pointers can be invalidated by revocation mechanisms if needed (future work).

Workflow
- A node creates a ProtocolMessage and signs it with its private key.
- The node publishes the message to the HTTP endpoint /protocol/publish.
- The server verifies the signature, optionally stores the message, and returns the signed payload.
- Other peers can fetch or receive the message via the same endpoint or a pubsub pathway (to be implemented in future steps).

Endpoints
- POST /protocol/publish
  - Body: JSON-encoded ProtocolMessage (without Sig)
  - Server actions: verify signature, attach Pub and Timestamp, sign (with Sig), return the signed message
- Future: POST /protocol/fetch or /protocol/subscribe for PubSub-like flows; GET endpoints for retrieval

Implementation notes
- Reuse existing SignProtocol and VerifyProtocol helpers (node/protocol.go) for signing/verifying.
- Add minimal handler integration to node/main.go without impacting existing flows.
- Ensure compatibility with Tor/IPFS features already in place.

Planning guidance
- MVP success: Phase 3 spec exists, server accepts and returns signed ProtocolMessage, and signatures verify with the provided public key.

Next steps
- Implement the HTTP handler in node/main.go and wire it in the router.
- Ensure node/protocol.go exports SignProtocol and VerifyProtocol (already done) and is usable by the new handler.
- Create a Python client flow to produce ProtocolMessage payloads and publish them via /protocol/publish.
- Update arch-ipfs-tor.md to reference the new Phase 3 spec file and its integration with the existing MVP.

End of doc.