# Lattice — System State

**Scope:** Local orchestration only · **Language:** Go 1.23 · **Sessions complete:** 1–6 of 8

This document captures the current state of the Lattice codebase: what exists, how the pieces fit together, and what comes next. It is the right place to start before reading any source file.

---

## What Lattice Is

Lattice is a message bus for locally-connected entities (services, devices, agents). It runs as a single TCP+TLS server (`lattice-node`) that entities dial into. Once connected and authenticated, entities can:

- **Publish** messages to named subjects (`home.sensor.temperature`)
- **Subscribe** to subjects with wildcards (`home.>`, `home.*.temperature`)
- **Call** other entities point-to-point by public key (Session 7, not yet built)

Everything is binary, framed, and typed. All payloads are Protobuf. All connections use TLS 1.3. All identities are Ed25519 key pairs. Every SUBSCRIBE and PUBLISH is checked against an ACL engine (deny-by-default) before any other processing.

---

## Repository Layout

```
lattice/
├── cmd/
│   ├── lattice-node/      # server binary
│   └── lattice-client/    # CLI client binary
├── internal/
│   ├── wire/              # frame encoding / TLS cert generation
│   ├── identity/          # Ed25519 keypair persistence
│   ├── session/           # authenticated session table
│   ├── handshake/         # HELLO exchange (both sides)
│   ├── bus/               # subject validation + subscription registry
│   ├── schema/            # payload validators for registered subjects
│   ├── acl/               # access-control engine (Sessions 5)
│   ├── registry/          # entity liveness tracking (Session 6)
│   └── node/              # server connection handler (owns all of the above)
├── proto/
│   ├── frames.proto       # 14 frame types + message definitions
│   ├── schemas.proto      # TemperatureReading, LightCommand
│   └── events.proto       # EntityJoined, EntityLeft, EntityOffline
└── go.mod                 # single dependency: google.golang.org/protobuf
```

---

## The Wire Format

Every message on the wire is a **frame**. A frame has a 5-byte header followed by a Protobuf-encoded payload.

```
┌─────────────────────────┬──────────┬──────────────────────────┐
│  4 bytes (uint32 BE)    │  1 byte  │  N bytes                 │
│  payload length         │  type    │  Protobuf payload        │
└─────────────────────────┴──────────┴──────────────────────────┘
```

- Maximum payload: **256 KiB**. The server closes the connection if exceeded.
- The type byte maps to the `FrameType` enum defined in `proto/frames.proto`.
- Reads use `io.ReadFull` — never partial reads.

**Relevant types:** `wire.Frame{Type pb.FrameType, Payload []byte}`, `wire.Read(io.Reader)`, `wire.Write(io.Writer, FrameType, []byte)`

---

## The 14 Frame Types

All types are declared upfront in `proto/frames.proto` even if not yet used.

| # | Name | Direction | Purpose | Session |
|---|------|-----------|---------|---------|
| 1 | `HELLO` | client → server | Identity claim: pubkey + signature | 2 |
| 2 | `HELLO_ACK` | server → client | Session ID, token, heartbeat interval | 2 |
| 3 | `HEARTBEAT` | client → server | Liveness keepalive | 2 |
| 4 | `HEARTBEAT_ACK` | server → client | Heartbeat acknowledgment | 2 |
| 5 | `SUBSCRIBE` | client → server | Register interest in a subject pattern | 3 |
| 6 | `UNSUBSCRIBE` | client → server | Remove a subscription | 3 |
| 7 | `PUBLISH` | client → server | Send a message to a subject | 3 |
| 8 | `DELIVER` | server → client | Forward a published message to a subscriber | 3 |
| 9 | `ERROR` | server → client | Reject a frame; carries `code` + `message` | all |
| 10 | `REQUEST` | client → server → client | Point-to-point call by target pubkey | 7 |
| 11 | `RESPONSE` | client → server → client | Reply to a REQUEST | 7 |
| 12 | `DISCONNECT` | client → server | Graceful disconnect notification | 8 |
| 13 | `PING` | either | Explicit latency probe | reserved |
| 14 | `PONG` | either | Ping reply | reserved |

---

## Connection Lifecycle

Every connection goes through the same ordered lifecycle on the server:

```
TCP accept
    │
    ▼
TLS 1.3 handshake  (crypto/tls, self-signed Ed25519 cert)
    │
    ▼
HELLO exchange  (internal/handshake)
  client sends:  HELLO { pubkey, signature over TLS-exporter nonce }
  server checks: ed25519.Verify(pubkey, nonce, signature)
  server sends:  HELLO_ACK { session_id, session_token, server_pubkey, heartbeat_interval }
    │
    ▼
Post-handshake setup  (internal/node)
  registry.Register(sessionID, pubkey, capabilities)
  publish lattice.system.entity.joined
    │
    ▼
Frame dispatch loop  (internal/node)
  HEARTBEAT      → registry.UpdateHeartbeat → HEARTBEAT_ACK
  SUBSCRIBE      → acl.Allow(subscribe) → bus.Subscribe
  UNSUBSCRIBE    → bus.Unsubscribe
  PUBLISH        → ValidateSubject → acl.Allow(publish) → schema.Validate → bus.Fanout → DELIVER to each
  anything else  → logged, ignored
    │
    ▼
Cleanup on disconnect — two paths:

  GRACEFUL (client closes / read error):
    registry.Remove(pubkey) → returns record (non-nil)
    bus.RemoveSession(sessionID)
    conns.Delete(sessionID)
    sessions.Remove(sessionID)
    publish lattice.system.entity.left
    conn.Close()

  OFFLINE (heartbeat checker marks stale):
    registry.Remove(pubkey) → returns record (non-nil)
    bus.RemoveSession(sessionID)
    conns.LoadAndDelete(sessionID)
    sessions.Remove(sessionID)
    publish lattice.system.entity.offline
    conn.Close()
    → HandleConn defer: registry.Remove returns nil → skips entity.left (already handled)
```

The TLS nonce used in HELLO is derived from `tls.ConnectionState.ExportKeyingMaterial("lattice-hello-v1", nil, 32)`. Both sides call this on their respective ends of the same TLS session and get the identical 32 bytes — the server never sends it to the client.

---

## Core Structs

### `wire.Frame` — `internal/wire/wire.go`
```go
type Frame struct {
    Type    pb.FrameType
    Payload []byte
}
```
The fundamental unit of communication. `wire.Read` and `wire.Write` are the only functions that touch the network.

---

### `session.Record` — `internal/session/session.go`
```go
type Record struct {
    ID           string    // UUID v4, generated at HELLO time
    Pubkey       []byte    // Ed25519 public key (32 bytes)
    Token        []byte    // 32 random bytes, sent to client in HELLO_ACK
    CreatedAt    time.Time
    Capabilities []string  // declared in HELLO frame; informational only
}
```
One record per authenticated connection. Capabilities are set by `handshake.DoServer` from the HELLO frame and stored here for use in system events.

---

### `session.Table` — `internal/session/session.go`
```go
type Table struct {
    mu       sync.RWMutex
    byID     map[string]*Record
    byPubkey map[string]*Record // hex(pubkey) → record
}
```
The server's source of truth for who is connected. Dual-indexed so it can be looked up by session ID (frame routing) or by pubkey (registry lookups).

---

### `handshake.ClientSession` — `internal/handshake/handshake.go`
```go
type ClientSession struct {
    SessionID         string
    SessionToken      []byte
    ServerPubkey      []byte
    HeartbeatInterval time.Duration
}
```
What the client holds after a successful HELLO. The heartbeat goroutine uses `HeartbeatInterval` to set its ticker.

---

### `bus.Bus` — `internal/bus/bus.go`
```go
type Bus struct {
    mu   sync.RWMutex
    subs map[string]map[string]struct{} // pattern → {sessionID}
}
```
The subscription registry. Patterns come from SUBSCRIBE frames; session IDs come from `session.Record.ID`. `Fanout(subject)` walks all patterns, runs wildcard matching, and returns the deduplicated set of session IDs that should receive a DELIVER.

**Wildcard rules:**
- `*` matches exactly one segment: `home.*.temperature` matches `home.sensor.temperature`
- `>` matches one or more segments, terminal only: `home.>` matches `home.sensor.temperature` and `home.sensor`
- `>` in non-terminal position (e.g. `home.>.temperature`) is rejected at subscribe time

---

### `acl.Engine` — `internal/acl/acl.go`
```go
type Engine struct {
    mu    sync.RWMutex
    rules []Rule // kept in descending Priority order
}

type Rule struct {
    IdentityPattern string  // base32(pubkey) (no padding) or "*"
    Action          Action  // "publish" | "subscribe" | "call"
    SubjectPattern  string  // same wildcard syntax as subscription patterns
    Effect          Effect  // Allow | Deny
    Priority        int     // higher = evaluated first
}
```
Deny-by-default. `Allow(pubkey, action, subject)` walks rules in priority order; the first match decides. No match → deny.

`EncodeIdentity(pubkey []byte) string` converts a raw Ed25519 public key to the canonical base32 (no-padding) string used in identity patterns and log output.

At server startup, two rules at priority 1000 allow the server's own identity to publish and subscribe to everything (`>`). These let the server emit system events without being blocked by its own ACL.

---

### `registry.EntityRecord` — `internal/registry/registry.go`
```go
type EntityRecord struct {
    Pubkey          []byte
    Capabilities    []string
    SessionID       string
    ConnectedAt     time.Time
    LastHeartbeatAt time.Time
}
```
Runtime liveness state per entity. `LastHeartbeatAt` is initialised to `ConnectedAt` and refreshed on every HEARTBEAT frame. The heartbeat checker compares `now − LastHeartbeatAt` against `3 × heartbeatInterval` to decide whether an entity is stale.

---

### `registry.Registry` — `internal/registry/registry.go`
```go
type Registry struct {
    mu       sync.RWMutex
    entities map[string]*EntityRecord // hex(pubkey) → record
}
```
`Remove(pubkey)` returns the record if it existed, or `nil` if it was already removed. This nil-check is the mechanism that prevents both cleanup paths (graceful and offline) from running simultaneously for the same entity.

---

### `node.Server` — `internal/node/node.go`
```go
type Server struct {
    log               *slog.Logger
    sessions          *session.Table
    bus               *bus.Bus
    acl               *acl.Engine
    registry          *registry.Registry
    serverPriv        ed25519.PrivateKey
    serverPub         ed25519.PublicKey
    heartbeatInterval uint32 // seconds
    conns             sync.Map // sessionID → *lockedConn
}
```
The top-level server object. Created once; `HandleConn` is called in a goroutine per accepted connection. Owns all shared state. On creation, starts the `runHeartbeatChecker` goroutine.

---

### `node.lockedConn` — `internal/node/node.go`
```go
type lockedConn struct {
    mu   sync.Mutex
    conn net.Conn
}
```
A connection with a write mutex. Stored in `Server.conns` keyed by session ID. Needed because any connection's goroutine can write to *any other* connection during fanout — the write mutex prevents interleaved frame bytes.

---

## How a PUBLISH Reaches a Subscriber

This is the most important data flow. Tracing it end-to-end:

```
Client B sends PUBLISH { subject: "home.sensor.temperature", payload: <proto bytes> }
    │
    ▼  node.HandleConn (Client B's goroutine)
    │
    ├─ bus.ValidateSubject("home.sensor.temperature")
    │      checks: no wildcards, not lattice.system.*, ≤16 segs, ≤256 chars
    │
    ├─ acl.Allow(rec.Pubkey, "publish", "home.sensor.temperature")
    │      walks rules in priority order; first match wins; default deny
    │      → ERROR to publisher if denied; delivery stops here
    │
    ├─ schema.Validate("home.sensor.temperature", payload)
    │      unmarshals TemperatureReading, checks:
    │        value is present, value ∈ [-50, 150]
    │        unit ≤ 10 chars (if present)
    │      → ERROR to publisher if invalid; delivery stops here
    │
    ├─ bus.Fanout("home.sensor.temperature")
    │      iterates all patterns in Bus.subs
    │      Match("home.sensor.temperature", subject) → exact match → add session ID
    │      Match("home.>", subject) → wildcard match → add session ID
    │      Match("home.*.temperature", subject) → wildcard match → add session ID
    │      returns deduplicated []sessionID
    │
    └─ for each sessionID:
           conns.Load(sessionID) → *lockedConn
           lockedConn.writeFrame(DELIVER, { subject, payload })
               └─ mutex.Lock → wire.Write → mutex.Unlock
```

---

## System Events

The server publishes system events to three reserved subjects. These bypass ACL, subject validation, and schema validation — they are server-generated and trusted.

| Subject | Proto message | Trigger |
|---------|--------------|---------|
| `lattice.system.entity.joined` | `EntityJoined { pubkey, capabilities, session_id }` | Entity completes HELLO handshake |
| `lattice.system.entity.left` | `EntityLeft { pubkey, session_id }` | Entity disconnects gracefully |
| `lattice.system.entity.offline` | `EntityOffline { pubkey, session_id }` | Entity misses 3 × heartbeat_interval |

Any entity can subscribe to `lattice.system.>` to observe the presence layer. The offline entity's own subscriptions are removed *before* its offline event is published, so it cannot receive its own eviction notice.

---

## Heartbeat Checker

`runHeartbeatChecker` is a goroutine started in `node.New`. It ticks every `heartbeatInterval` seconds and calls `registry.Stale(now, 3×interval)` to find entities that have gone silent. For each stale entity it calls `markOffline`, which:

1. Calls `registry.Remove` — if nil, another goroutine already handled it; return immediately.
2. Removes the entity's subscriptions from the bus.
3. Removes and retrieves the `*lockedConn` from `conns`.
4. Removes the session from the session table.
5. Publishes `lattice.system.entity.offline` (while other subscribers are still in `conns`).
6. Closes the connection, causing `HandleConn`'s `wire.Read` to return EOF.
7. `HandleConn`'s defer runs: `registry.Remove` returns nil → skips `entity.left`.

---

## Subject Rules

**In SUBSCRIBE (patterns allowed):**
- Segments: `[a-z0-9-_]+`, max 16 segments, max 256 chars total
- `*` allowed anywhere (matches one segment)
- `>` allowed only as the final segment (matches one or more)

**In PUBLISH (concrete subjects only):**
- Same character and length rules, but no wildcards
- `lattice.system.*` is server-reserved — client PUBLISH is rejected

---

## Schema Registry

Currently two subjects have registered schemas (hardcoded in `internal/schema/schema.go`). Publishing to any other subject returns an error.

| Subject | Message type | Constraints |
|---|---|---|
| `home.sensor.temperature` | `TemperatureReading` | `value` required (float32, −50..150), `unit` optional (string, ≤10 chars) |
| `home.light.command` | `LightCommand` | `action` required (ON/OFF/TOGGLE), `brightness` optional (float32, 0.0..1.0) |

Proto3 `optional` is used for all fields so the validator can distinguish "not set" from "set to zero value".

> **Note:** In production, the schema registry would be dynamic — schemas registered at runtime using Protobuf `FileDescriptorProto` and `dynamicpb` for runtime-defined message types. The hardcoded `schemas.proto` is a development scaffold.

---

## Identity and Key Files

Both the server and client generate Ed25519 key pairs on first run and persist them as PKCS8 PEM files (mode 0600).

| Binary | Default key file | Flag |
|--------|-----------------|------|
| `lattice-node` | `node.key` | `--key` |
| `lattice-client` | `client.key` | `--key` |

The server also generates a **fresh self-signed TLS certificate at each startup** (not persisted). The certificate uses the same Ed25519 key type as the identity model. Clients skip certificate verification for now (`InsecureSkipVerify: true`); CA pinning is deferred.

---

## How to Run

```sh
# Terminal 1 — server
go run ./cmd/lattice-node

# Terminal 2 — client (generates client.key on first run)
go run ./cmd/lattice-client
```

The client connects, completes the HELLO handshake, and then sits in a read loop printing incoming frames while a goroutine sends `HEARTBEAT` every 30 seconds.

---

## Test Coverage

```
go test ./...
```

| Package | Tests | What they cover |
|---------|-------|-----------------|
| `internal/wire` | 7 | Frame encode/decode, 256 KiB boundary, concurrent clients, mid-read disconnect |
| `internal/handshake` | 6 | Valid HELLO, corrupted signature, mismatched pubkey, two concurrent sessions, HEARTBEAT round-trip, session token storage |
| `internal/bus` | 17 | Wildcard matching (exact, `*`, `>`), pattern/subject validation, subscribe/unsubscribe/fanout, deduplication, session cleanup |
| `internal/schema` | 13 | Both schemas: valid payloads, out-of-range values, missing required fields, invalid enum, string length, unknown subject |
| `internal/acl` | 7 | Deny by default, exact identity allow, wildcard identity, priority ordering, deny overrides lower-priority allow, ActionCall reserved |
| `internal/node` | 28 | Full server integration: pub/sub delivery, wildcard delivery, unsubscribe, disconnect cleanup, invalid patterns, schema rejection, ACL deny, ACL wildcard allow, priority ordering, entity.joined/left/offline events, simultaneous joins, no-delivery-after-offline |
| **Total** | **78** | |

---

## What Is Not Yet Built (Sessions 7–8)

| Session | What it adds |
|---------|-------------|
| **7 — Call primitive** | `REQUEST` addressed to a target pubkey; server forwards to target; `RESPONSE` forwarded back. Correlation ID ties pairs. ACL check `(caller, "call", target_pubkey)`. Server-side timeout with pending call registry. |
| **8 — Integration** | Full end-to-end test sequence. Graceful shutdown (publish `entity.left` for all connected entities on Ctrl+C). README and demo script. |

---

## Dependency Graph

```
cmd/lattice-node
    └── internal/node
            ├── internal/handshake
            │       ├── internal/session
            │       ├── internal/wire
            │       └── proto/
            ├── internal/bus
            ├── internal/schema  ──► proto/
            ├── internal/acl     ──► internal/bus (for Match)
            ├── internal/registry
            └── internal/wire

cmd/lattice-client
    ├── internal/handshake
    ├── internal/identity
    ├── internal/wire
    └── proto/

internal/wire     ──► proto/
internal/identity    (stdlib only)
internal/session     (stdlib only)
internal/registry    (stdlib only)
internal/acl      ──► internal/bus
```

No import cycles. The `proto/` package is a leaf — nothing in it imports internal packages.
