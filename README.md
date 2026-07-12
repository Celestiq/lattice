# Celestiq Lattice

> Open infrastructure for a network where every entity — person, home, organisation, device, agent — is a sovereign node, and any two can coordinate directly.

---

## Three commitments

These shape every design decision in the protocol.

**Sovereignty is an architecture, not a policy.** Platforms that promise privacy do so by policy. Promises are revocable, monetisable, and silently changeable. Lattice removes the possibility of inspection rather than promising restraint: data flows directly between consenting parties, never touching a platform's systems.

**Typed messages, not opaque bytes.** A message bus that moves bytes is a transport. A bus that moves typed, schema-validated messages is a language. Lattice's schema system is what makes federation meaningful: two independent operators can exchange data because both interpret it under the same shared contract.

**Federation requires consent, in both directions.** Each node decides what it sends and what it accepts, independently. Either side can pause or revoke without the other's cooperation. Federation cannot be made to happen against any participant's will.

---

## Current status

`go build ./...` clean · 266 tests passing · race-detector clean

| Layer | Version | State |
|-------|---------|-------|
| Single-node bus | v0.1.1 | Complete and independently audited. Shippable. |
| Federation (QUIC peering) | v0.2 | Built and working end-to-end. Pre-production at the trust boundary (4 known blockers). |

---

## What works today

**Single-node (v0.1.1 — production-quality):**
- Typed pub/sub messaging over a named subject space (`home.sensor.temperature`, `home.>`)
- Deny-by-default ACL engine with wildcard rules, priority ordering, and delivery-time re-check
- Schema validation: dynamic registry backed by Protobuf `FileDescriptorProto`; custom field options for required, numeric range, and string length
- Request/response calls addressed by Ed25519 public key, with correlation, timeout, and server-stamped caller identity
- Entity presence layer (`lattice.system.entity.joined/left/offline`)
- Session resume with token-based subscription restoration
- Localhost admin HTTP API for schema management
- Mutual-auth TLS+Ed25519 handshake; TOFU pinning

**Federation (v0.2 — working, pre-production):**
- Two independent nodes form a persistent, mutually-authenticated QUIC peering
- Bilateral consent state machine: pair → accept → active ↔ paused → revoked
- Operator-configured forwarding policy per direction (outbound: what I send; inbound: what I accept)
- Schema propagation: schema descriptor piggybacked on first forward of any subject to a peer
- Cross-node call routing: entity on Node A calls entity on Node B transparently
- Three-layer connectivity: direct QUIC dial → address registry lookup → relay fallback
- Address registry server (`lattice-registry`) for dynamic peer address discovery
- Relay node (`lattice-relay`) for NAT/firewall traversal

**Not yet built (designed in spec):**
- Stream primitive — continuous bidirectional session (camera, audio, robot control)
- Object primitive — content-addressed blob store
- Schema DSL — compiles to Protobuf descriptors
- Durable messages — per-subject persistence with subscriber gap-fill

---

## Quick start

```sh
# Terminal 1 — start the node (generates node.key on first run)
go run ./cmd/lattice-node

# Terminal 2 — connect a client (generates client.key on first run)
go run ./cmd/lattice-client
```

See [DEMO.md](DEMO.md) for a full feature walkthrough including the federation scenario.

---

## Repository layout

```
lattice/
├── cmd/
│   ├── lattice-node/      server binary
│   ├── lattice-client/    reference CLI client
│   ├── lattice-relay/     relay node (QUIC rendezvous, v0.2)
│   └── lattice-registry/  address registry (v0.2)
├── internal/
│   ├── wire/              frame encoding + TLS cert generation
│   ├── identity/          Ed25519 keypair load/generate
│   ├── handshake/         HELLO exchange (client ↔ server)
│   ├── session/           authenticated session table + resume tokens
│   ├── bus/               subject validation + subscription registry
│   ├── schema/            dynamic schema registry + payload validation
│   ├── acl/               access-control engine (deny-by-default)
│   ├── registry/          entity liveness tracking
│   ├── call/              pending REQUEST/RESPONSE registry
│   ├── admin/             localhost-only HTTP admin API
│   ├── node/              server connection handler (owns all shared state)
│   ├── transport/         federation transport abstraction (Stream/Dialer/Listener)
│   ├── federation/        QUIC peering, consent, policy, call routing (v0.2)
│   ├── relay/             rendezvous relay (v0.2)
│   └── address/           address registry (v0.2)
├── proto/
│   ├── frames.proto       30 frame types (client 0–14, federation 15–23, relay/registry 24–30)
│   ├── federation.proto   federation-specific message types
│   ├── schemas.proto      built-in schema definitions
│   ├── lattice_options.proto  custom field options (range, max_length, required)
│   └── events.proto       system event payload types
├── 01-Claude/             architecture documents, audit reports, implementation blueprints
└── go.mod                 three dependencies: protobuf, quic-go, sqlite
```

---

## Documents

| File | Contents |
|------|----------|
| [DEMO.md](DEMO.md) | Step-by-step feature walkthrough: single-node and federation |
| [SYSTEM_STATE.md](SYSTEM_STATE.md) | Complete technical reference: all structs, flows, frame types, and test coverage |
| [DEV.md](DEV.md) | Developer guide: flags, test commands, proto regeneration |
| [01-Claude/PROJECT-AUDIT.md](01-Claude/PROJECT-AUDIT.md) | Full project audit: what remains, federation blockers, demo readiness |
| [01-Claude/SYSTEM_STATE.md → v0.2-Review.md](01-Claude/v0.2-Review.md) | Production-readiness review of v0.2 federation |

---

## Getting involved

This is an early project. The right way to engage right now is at the design and protocol level.

- If you have read the code and have feedback, open an issue.
- If you work on a project Lattice should learn from — NATS, libp2p, ActivityPub, AT Protocol, Matter, Home Assistant, the local-first software community — reach out.
- For longer-form thinking behind the project: [Substack](https://aayushessence.substack.com/)

---

## License

Protocol specification and reference implementations will be released under permissive open-source licences. Intended: Apache 2.0 for code, CC BY 4.0 for the specification, confirmed before the first tagged release.

---

Aayush Sharma · aayush20701@gmail.com
