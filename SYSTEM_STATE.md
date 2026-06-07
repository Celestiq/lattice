# Lattice — System State

**Scope:** Local orchestration only · **Language:** Go 1.23 · **Sessions complete:** 1–8 of 8 · **Status: v0.1 done**

This document captures the complete state of the Lattice v0.1 codebase: what exists, how the pieces fit together, and the design decisions behind them. Start here before reading any source file.

---

## What Lattice Is

Lattice is a message bus for locally-connected entities (services, devices, AI agents). It runs as a single TCP+TLS server (`lattice-node`) that entities dial into. Once connected and authenticated, entities can:

- **Publish** messages to named subjects (`home.sensor.temperature`)
- **Subscribe** to subjects with wildcards (`home.>`, `home.*.temperature`)
- **Call** other entities point-to-point by public key — request/response with timeout
- **Observe** the presence layer (`lattice.system.entity.joined/left/offline`)

Everything is binary, framed, and typed. All payloads are Protobuf. All connections use TLS 1.3. All identities are Ed25519 key pairs. Every SUBSCRIBE, PUBLISH, and REQUEST is checked against an ACL engine (deny-by-default) before any other processing.

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
│   ├── acl/               # access-control engine
│   ├── registry/          # entity liveness tracking
│   ├── call/              # pending REQUEST/RESPONSE registry
│   └── node/              # server connection handler (owns all of the above)
├── proto/
│   ├── frames.proto       # 14 frame types + message definitions
│   ├── schemas.proto      # TemperatureReading, LightCommand
│   └── events.proto       # EntityJoined, EntityLeft, EntityOffline
├── DEV.md                 # developer guide: how to run, flags, architecture
├── DEMO.md                # step-by-step feature walkthrough
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
  REQUEST        → acl.Allow(call) → registry.Get(target) → calls.Add → forward REQUEST to target
  RESPONSE       → calls.Remove(correlationID) → forward RESPONSE to requester
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

The TLS nonce used in HELLO is derived from `tls.ConnectionState.ExportKeyingMaterial("lattice-hello-v1", nil, 32)`. Both sides call this on their respective ends of the same TLS session and get identical 32 bytes — the server never transmits it.

---

## Graceful Shutdown

`srv.Shutdown()` performs an ordered drain:

1. `close(s.done)` — signals background goroutines (heartbeat checker, call timeout checker) to stop.
2. Iterates `registry.All()` snapshot; calls `registry.Remove` for each (prevents HandleConn defers from double-publishing).
3. Publishes `lattice.system.entity.left` for each removed entity while connections are still open.
4. `conns.Range` — closes every active connection; HandleConn goroutines see EOF and exit.
5. `s.wg.Wait()` — blocks until all HandleConn goroutines and both background goroutines have exited.

The CLI binary hooks SIGINT/SIGTERM: closes the listener first (stops new connections), then calls `srv.Shutdown()`.

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

---

### `session.Table` — `internal/session/session.go`
```go
type Table struct {
    mu       sync.RWMutex
    byID     map[string]*Record
    byPubkey map[string]*Record // hex(pubkey) → record
}
```
Dual-indexed so it can be looked up by session ID (frame routing) or by pubkey.

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
`Fanout(subject)` walks all patterns, runs wildcard matching, and returns the deduplicated set of session IDs that should receive a DELIVER.

**Wildcard rules:**
- `*` matches exactly one segment: `home.*.temperature` matches `home.sensor.temperature`
- `>` matches one or more segments, terminal only: `home.>` matches `home.sensor.temperature` and `home.sensor`
- `>` in non-terminal position is rejected at subscribe time

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

`EncodeIdentity(pubkey []byte) string` converts a raw Ed25519 public key to the canonical base32 (no-padding) string used in identity patterns.

For call ACL: `action = "call"`, `subject = base32(targetPubkey)`. Use `"*"` or `">"` to allow calls to any target.

At server startup, two rules at priority 1000 allow the server's own identity to publish and subscribe to everything. These let the server emit system events.

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
`LastHeartbeatAt` is initialised to `ConnectedAt` and refreshed on every HEARTBEAT frame. The heartbeat checker compares `now − LastHeartbeatAt` against `3 × heartbeatInterval`.

---

### `registry.Registry` — `internal/registry/registry.go`
```go
type Registry struct {
    mu       sync.RWMutex
    entities map[string]*EntityRecord // hex(pubkey) → record
}
```
`Remove(pubkey)` returns the record if it existed, or `nil` if already removed. This nil-check is the sentinel that prevents the graceful, offline, and shutdown disconnect paths from all firing for the same entity.

`Get(pubkey)` returns the record without removing it — used by `handleRequest` for target lookup.

---

### `call.Registry` — `internal/call/call.go`
```go
type PendingCall struct {
    RequesterSessionID string
    Deadline           time.Time
}

type Registry struct {
    mu      sync.Mutex
    pending map[string]*PendingCall // correlationID → call
}
```
`Add` is called before forwarding the REQUEST to the target (prevents a race where the response arrives before the entry exists). `Remove` returns nil if not found (stale or already expired). `Expired(now)` removes and returns all entries past their deadline atomically.

---

### `node.Server` — `internal/node/node.go`
```go
type Server struct {
    log               *slog.Logger
    sessions          *session.Table
    bus               *bus.Bus
    acl               *acl.Engine
    registry          *registry.Registry
    calls             *call.Registry
    serverPriv        ed25519.PrivateKey
    serverPub         ed25519.PublicKey
    heartbeatInterval uint32
    conns             sync.Map   // sessionID → *lockedConn
    wg                sync.WaitGroup
    stopOnce          sync.Once
    done              chan struct{}
}
```
Created once; `HandleConn` is called in a goroutine per accepted connection. The `wg` tracks all HandleConn goroutines and the two background goroutines (heartbeat checker, call timeout checker). `done` is closed by `Shutdown()` to signal them. `stopOnce` prevents double-close panics.

---

### `node.lockedConn` — `internal/node/node.go`
```go
type lockedConn struct {
    mu   sync.Mutex
    conn net.Conn
}
```
A connection with a write mutex. Stored in `Server.conns` keyed by session ID. Required because any connection's goroutine can write to *any other* connection during fanout or REQUEST/RESPONSE forwarding.

---

## How a PUBLISH Reaches a Subscriber

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
    │      unmarshals TemperatureReading, checks value ∈ [-50, 150], unit ≤ 10 chars
    │      → ERROR to publisher if invalid; delivery stops here
    │
    ├─ bus.Fanout("home.sensor.temperature")
    │      walks all subscribed patterns, wildcard-matches each
    │      returns deduplicated []sessionID
    │
    └─ for each sessionID:
           conns.Load(sessionID) → *lockedConn
           lockedConn.writeFrame(DELIVER, { subject, payload })
               └─ mutex.Lock → wire.Write → mutex.Unlock
```

---

## How a REQUEST/RESPONSE Round-Trip Works

```
Client A sends REQUEST { correlation_id, target_pubkey=B, payload, timeout_ms }
    │
    ▼  node.handleRequest
    │
    ├─ acl.Allow(A.pubkey, "call", base32(B.pubkey))
    │      → ERROR PERMISSION_DENIED if denied
    │
    ├─ registry.Get(B.pubkey)
    │      → ERROR NOT_FOUND if B not connected
    │
    ├─ calls.Add(correlation_id, A.sessionID, now+timeout_ms)
    │      registered BEFORE forwarding (avoids response-arrives-first race)
    │
    └─ targetLc.writeFrame(REQUEST, payload)  ─────────────► Client B receives REQUEST

Client B sends RESPONSE { correlation_id, payload }
    │
    ▼  node.handleResponse
    │
    ├─ calls.Remove(correlation_id) → *PendingCall
    │      → ERROR NOT_FOUND if correlation_id unknown or already expired
    │
    └─ requesterLc.writeFrame(RESPONSE, payload) ──────────► Client A receives RESPONSE

(If no RESPONSE within timeout_ms, runCallTimeoutChecker fires ERROR TIMEOUT to A)
```

---

## System Events

The server publishes to three reserved subjects. These bypass ACL, subject validation, and schema validation.

| Subject | Proto message | Trigger |
|---------|--------------|---------|
| `lattice.system.entity.joined` | `EntityJoined { pubkey, capabilities, session_id }` | Entity completes HELLO handshake |
| `lattice.system.entity.left` | `EntityLeft { pubkey, session_id }` | Graceful disconnect or server shutdown |
| `lattice.system.entity.offline` | `EntityOffline { pubkey, session_id }` | Entity misses 3 × heartbeat_interval |

The offline entity's own subscriptions are removed *before* its offline event is published, so it cannot receive its own eviction notice.

---

## Heartbeat Checker

`runHeartbeatChecker` ticks every `heartbeatInterval` seconds. For each entity with `now − LastHeartbeatAt > 3 × interval`, `markOffline` is called:

1. `registry.Remove` — if nil, another goroutine already handled it; return.
2. Remove subscriptions from the bus.
3. Remove `*lockedConn` from `conns`.
4. Remove session from the session table.
5. Publish `entity.offline` (while other subscribers are still in `conns`).
6. Close the connection → HandleConn's `wire.Read` returns EOF.
7. HandleConn defer: `registry.Remove` returns nil → skips `entity.left`.

---

## Call Timeout Checker

`runCallTimeoutChecker` ticks every 1 second. Calls `calls.Expired(now)` to retrieve and atomically remove all pending calls past their deadline. For each expired call, sends `ERROR { code: "TIMEOUT" }` to the requester's session (silently drops if requester already disconnected — `conns.Load` miss).

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

Two subjects have registered schemas (hardcoded in `internal/schema/schema.go`). Publishing to any other subject returns `SCHEMA_ERROR: unknown subject`.

| Subject | Message type | Constraints |
|---|---|---|
| `home.sensor.temperature` | `TemperatureReading` | `value` required (float32, −50..150), `unit` optional (string, ≤10 chars) |
| `home.light.command` | `LightCommand` | `action` required (ON/OFF/TOGGLE), `brightness` optional (float32, 0.0..1.0) |

Proto3 `optional` is used for all fields so the validator can distinguish "not set" from "set to zero value".

> **Production note:** A real schema registry would be dynamic — schemas registered at runtime using Protobuf `FileDescriptorProto` and `dynamicpb`. The hardcoded `schemas.proto` is a development scaffold.

---

## Identity and Key Files

| Binary | Default key file | Flag |
|--------|-----------------|------|
| `lattice-node` | `node.key` | `--key` |
| `lattice-client` | `client.key` | `--key` |

The server generates a **fresh self-signed TLS certificate at each startup** (not persisted). Clients use `InsecureSkipVerify: true`; CA pinning is deferred.

---

## Test Coverage

```
go test ./...
```

| Package | Tests | What they cover |
|---------|-------|-----------------|
| `internal/wire` | 7 | Frame encode/decode, 256 KiB boundary, concurrent clients, mid-read disconnect |
| `internal/handshake` | 6 | Valid HELLO, corrupted signature, mismatched pubkey, concurrent sessions, HEARTBEAT round-trip, session token |
| `internal/bus` | 17 | Wildcard matching (`*`, `>`), pattern/subject validation, subscribe/unsubscribe/fanout, deduplication, session cleanup |
| `internal/schema` | 13 | Both schemas: valid payloads, out-of-range values, missing fields, invalid enum, string length, unknown subject |
| `internal/acl` | 7 | Deny by default, exact allow, wildcard identity, priority ordering, deny overrides lower-priority allow |
| `internal/node` | 35 | Full integration: pub/sub, wildcards, schema rejection, ACL deny/allow/priority, entity events, offline detection, call round-trip, call timeout, call ACL, requester disconnect, graceful shutdown |
| **Total** | **85** | |

The `TestIntegrationSequence` test covers all 10 steps of the Session 8 integration scenario in a single sequential test with per-step log output.

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
            ├── internal/schema    ──► proto/
            ├── internal/acl       ──► internal/bus (Match)
            ├── internal/registry
            ├── internal/call
            └── internal/wire

cmd/lattice-client
    ├── internal/handshake
    ├── internal/identity
    ├── internal/wire
    └── proto/

internal/wire       ──► proto/
internal/identity      (stdlib only)
internal/session       (stdlib only)
internal/registry      (stdlib only)
internal/call          (stdlib only)
internal/acl        ──► internal/bus
```

No import cycles. The `proto/` package is a leaf — nothing in it imports internal packages.
