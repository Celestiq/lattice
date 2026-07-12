# Lattice — Developer Guide

This document covers the full codebase (v0.1.1 single-node bus + v0.2 federation): how to run it, how to test it, and flag references for all binaries.

---

## Quick start

```sh
# Terminal 1 — server (generates node.key on first run)
go run ./cmd/lattice-node

# Terminal 2 — client (generates client.key on first run)
go run ./cmd/lattice-client
```

On first run each binary generates an Ed25519 keypair and writes it to a PKCS8 PEM file (`node.key` / `client.key`, mode 0600). Subsequent runs reuse the persisted key so identities survive restarts.

---

## Server flags (`lattice-node`)

```
--addr          :4222                  TCP listen address (client connections)
--key           node.key               Ed25519 private key file (created if absent)
--heartbeat     30                     Heartbeat interval communicated to clients (seconds)
--admin-addr    127.0.0.1:4223         Localhost-only HTTP admin API
--fed-addr      ""                     QUIC federation listen address (empty = federation disabled)
--fed-db        fed.db                 SQLite file for federation state (peers, consent, policy)
--registry-addr ""                     Address registry to register with (empty = disabled)
--relay-addr    ""                     Relay node address for fallback connectivity (empty = disabled)
```

Ctrl+C triggers graceful shutdown: every connected entity receives `lattice.system.entity.left`, connections drain, and the process exits cleanly.

## Client flags (`lattice-client`)

```
--addr        localhost:4222   Server address
--key         client.key       Ed25519 private key file (created if absent)
--server-key  ""               Expected server pubkey hex for TOFU pinning (optional)
```

## Relay flags (`lattice-relay`)

```
--addr   :4225   QUIC listen address for relay rendezvous
```

## Registry flags (`lattice-registry`)

```
--addr   :4226   HTTP/QUIC listen address for address registry
```

---

## Running tests

```sh
go test ./...
```

266 tests across all packages. The `TestIntegrationSequence` test in `internal/node` runs the full 10-step scenario end-to-end (pub/sub, schema validation, ACL, call primitive, entity events, graceful shutdown). The federation packages (`internal/federation`, `internal/relay`, `internal/address`, `internal/transport`) carry the v0.2 test suite.

Race detector is required before merging node or federation changes:

```sh
go test -race ./internal/node/...
go test -race ./internal/federation/...
```

---

## Proto regeneration

The compiled `*.pb.go` files are committed. To regenerate after editing a `.proto` file:

```sh
make proto
```

**Prerequisites (one-time setup):**
```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
# protoc must be ≥ v3 (brew install protobuf on macOS)
```

The script (`scripts/gen-proto.sh`) pins `protoc-gen-go` at `v1.36.11`. Regenerating with any other version will produce spurious diffs. After running `make proto`, `git diff proto/` should be empty unless you actually changed a `.proto` file.

---

## Repository layout

```
lattice/
├── cmd/
│   ├── lattice-node/       server binary
│   └── lattice-client/     CLI client binary
├── internal/
│   ├── wire/               frame encode/decode; TLS self-signed cert
│   ├── identity/           Ed25519 keypair load/generate (PKCS8 PEM)
│   ├── session/            authenticated session table (by ID + pubkey)
│   ├── handshake/          HELLO exchange — client and server sides
│   ├── bus/                subscription registry + wildcard matching
│   ├── schema/             subject-keyed payload validators
│   ├── acl/                access-control engine (deny-by-default)
│   ├── registry/           entity liveness tracking + heartbeat state
│   ├── call/               pending REQUEST/RESPONSE registry
│   └── node/               server: owns all state, handles connections
├── proto/
│   ├── frames.proto        14 frame types + all message definitions
│   ├── schemas.proto       TemperatureReading, LightCommand (dev scaffold)
│   └── events.proto        EntityJoined, EntityLeft, EntityOffline
└── go.mod                  single dependency: google.golang.org/protobuf
```

---

## Wire format

Every message is a **frame**:

```
┌──────────────────────────┬──────────┬────────────────────────┐
│  4 bytes  (uint32 BE)    │  1 byte  │  N bytes               │
│  payload length          │  type    │  Protobuf payload      │
└──────────────────────────┴──────────┴────────────────────────┘
```

Maximum payload: 256 KiB. Reads use `io.ReadFull` — never partial.

---

## Frame types

| # | Name | Direction | Purpose |
|---|------|-----------|---------|
| 1 | `HELLO` | C → S | Ed25519 pubkey + signature over TLS-exporter nonce |
| 2 | `HELLO_ACK` | S → C | Session ID, token, server pubkey, heartbeat interval |
| 3 | `HEARTBEAT` | C → S | Liveness keepalive |
| 4 | `HEARTBEAT_ACK` | S → C | Heartbeat acknowledgment |
| 5 | `SUBSCRIBE` | C → S | Register interest in a subject pattern |
| 6 | `UNSUBSCRIBE` | C → S | Remove a subscription |
| 7 | `PUBLISH` | C → S | Send a message to a subject |
| 8 | `DELIVER` | S → C | Forward a published message to a subscriber |
| 9 | `ERROR` | S → C | Rejected frame; carries code + message |
| 10 | `REQUEST` | C → S → C | Addressed call to a target pubkey |
| 11 | `RESPONSE` | C → S → C | Reply to a REQUEST |
| 12 | `DISCONNECT` | C → S | Graceful disconnect notification |
| 13 | `PING` | either | Latency probe (reserved) |
| 14 | `PONG` | either | Ping reply (reserved) |

---

## HELLO handshake

> **Security note — Trust on First Use (TOFU):** The first time a client connects to a node, it receives the server's Ed25519 public key in `HELLO_ACK` as an unsigned assertion. There is no independent verification of that key — the client trusts whatever the TLS-terminating process claims. An attacker who can intercept the first connection (e.g. a MITM on an untrusted network) can substitute their own key and impersonate the server. After the first pairing the client should pin the received server pubkey and reject any future `HELLO_ACK` that presents a different key. Decision #1 (Session 1) addresses this by having the server sign a TLS-exporter nonce with its Ed25519 private key so the client can verify the assertion.

After TLS 1.3 completes, the client sends a HELLO frame containing its Ed25519 public key and a signature. The nonce that is signed is derived identically on both sides from the TLS session:

```go
cs := conn.ConnectionState()
nonce, _ := cs.ExportKeyingMaterial("lattice-hello-v1", nil, 32)
```

The server verifies the signature, creates a session record (UUID v4 session ID + 32-byte random token), and replies with `HELLO_ACK`.

---

## Pub/sub

**Subscribe:** send a `SUBSCRIBE { subject: "home.>" }` frame. The server checks ACL first.

**Publish:** send a `PUBLISH { subject: "home.sensor.temperature", payload: <proto bytes> }` frame. The server runs: subject validation → ACL check → schema validation → fan-out to subscribers as `DELIVER` frames.

**Wildcard rules:**
- `*` — exactly one segment: `home.*.temperature` matches `home.sensor.temperature`
- `>` — one or more segments, terminal only: `home.>` matches `home.sensor.temperature` and `home.sensor`

**Subject rules:** segments match `[a-z0-9-_]+`, max 16 segments, max 256 chars. `lattice.system.*` is server-reserved.

---

## Call primitive

A client can call another entity by its Ed25519 public key:

```
Client A                    Server                     Client B
   │                           │                           │
   ├─ REQUEST {                 │                           │
   │   correlation_id,          │                           │
   │   target_pubkey=B,         │                           │
   │   payload,                 │                           │
   │   timeout_ms               │                           │
   │  } ───────────────────────►│                           │
   │                           ├─ ACL check (call, B) ─────┤
   │                           ├─ REQUEST forwarded ───────►│
   │                           │                           │
   │                           │◄── RESPONSE {             │
   │                           │     correlation_id,        │
   │                           │     payload               │
   │                           │    } ─────────────────────┤
   │◄── RESPONSE forwarded ────┤                           │
```

The server matches RESPONSE to pending REQUEST by `correlation_id` (generated by the caller). If no RESPONSE arrives within `timeout_ms`, the server sends an `ERROR { code: "TIMEOUT" }` to the requester.

ACL rule for calls: the `subject_pattern` matches the target's base32-encoded public key, or `*` for any target.

---

## ACL

Rules are evaluated in descending priority order. First match wins. Default: **deny**.

```go
srv.AddRule(acl.Rule{
    IdentityPattern: acl.EncodeIdentity(pubkey), // or "*" for any
    Action:          acl.ActionPublish,           // "publish" | "subscribe" | "call"
    SubjectPattern:  "home.>",                    // wildcards same as pub/sub
    Effect:          acl.Allow,                   // Allow | Deny
    Priority:        10,                          // higher = evaluated first
})
```

The server's own identity is pre-seeded at priority 1000 with allow-all for publish and subscribe (needed to emit system events).

---

## System events

Subscribe to `lattice.system.>` to observe the presence layer. All events are delivered as `DELIVER` frames with a Protobuf payload.

| Subject | Payload type | When |
|---------|-------------|------|
| `lattice.system.entity.joined` | `EntityJoined { pubkey, capabilities, session_id }` | Entity completes HELLO |
| `lattice.system.entity.left` | `EntityLeft { pubkey, session_id }` | Graceful disconnect or server shutdown |
| `lattice.system.entity.offline` | `EntityOffline { pubkey, session_id }` | Missed 3 × heartbeat_interval |

System events bypass ACL, subject validation, and schema validation — they are server-generated.

---

## Schema registry

Two subjects have registered schemas (hardcoded in `internal/schema/schema.go`). All other subjects are rejected at PUBLISH time.

| Subject | Message | Constraints |
|---------|---------|-------------|
| `home.sensor.temperature` | `TemperatureReading` | `value` required (float32, −50..150); `unit` optional (≤10 chars) |
| `home.light.command` | `LightCommand` | `action` required (ON/OFF/TOGGLE); `brightness` optional (0.0..1.0) |

---

## Graceful shutdown (server)

`srv.Shutdown()` is the programmatic API:
1. Signals background goroutines (heartbeat checker, call timeout checker) to stop.
2. Publishes `lattice.system.entity.left` for every still-connected entity.
3. Closes all connections (HandleConn goroutines see EOF and exit).
4. Waits for all goroutines to exit (`sync.WaitGroup`).

The CLI binary hooks SIGINT/SIGTERM to call `ln.Close()` then `srv.Shutdown()`.
