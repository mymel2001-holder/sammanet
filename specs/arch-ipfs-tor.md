# arch-ipfs-tor.md

Architectural blueprint for IPFS and Tor based decentralization in Sammanet

Date: 2025-08-12

Purpose
- Define a minimal, MVP-focused architecture to base decentralization on IPFS and Tor
- Provide a clear data model, flows, and security considerations

Scope and MVP
- Phase 1: IPFS integration in the Go node and Python client
  - Basic content publish to IPFS, obtaining a CID, and anchoring in the on-disk chain or manifest
- Phase 2: Tor scaffolding: SOCKS5 routing for peer requests and experimental hidden service
- Phase 3: Minimal protocol atop IPFS CID and signed blocks

High-level architecture
- Components
  - Go-based node (node/main.go)
  - Python client (client/client.py)
  - IPFS daemon (local) with a bridge via go-ipfs-api
  - Tor proxy/hidden service for privacy
  - Browser UI (browser/)
- Data model
  - CID-based content addressing using IPFS
  - DomainTx blocks with ed25519 signatures
  - Append-only chain (gzipped) for historical integrity
- Flows
  - Content publish: Client uploads raw content to node, node adds to IPFS returning CID, CID is recorded in chain
  - Content fetch: Client asks node for CID, node fetches from IPFS and renders
  - Peer discovery: DHT + optional IPFS PubSub for signaling; Tor path for privacy
- Security and privacy
  - Sign transactions with Ed25519; verify on receive
  - Use IPFS content addressing to ensure immutability
  - Route internal signaling through Tor when configured

Implementation plan (MVP-oriented)
- MVP milestones
  - Phase 1: IPFS publish/fetch integration scaffolding
  - Phase 2: Tor scaffolding and connectivity
  - Phase 3: Minimal protocol interface across components

Appendix: diagrams
Mermaid diagrams
graph TD
  A[Client Upload content] --> BGoNode[/upload handler/]
  BGoNode --> C[IPFS Add content -> CID]
  C --> D[Node stores CID in chain]
  D --> E[/chain endpoint/]
  E --> F[Browser fetch by CID]

graph TD
  subgraph Tor path
    A[Tor hidden service] --> B[Node API]
  end
  A --> C[Public network]

Security model
- Ed25519 keys, signatures, verification

MVP iterations and risks
- IPFS and Tor latency can affect UX
- Privacy and anonymity considerations
- Key management and rotation strategies

Notes and references
- Node main.go: IPFS integration and Tor routing references
- Client Python: endpoints for upload fetch and signing workflow

End of architecture document