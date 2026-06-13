# Lattice — System State

**Scope:** Local orchestration only · **Language:** Go 1.23 · **v0.1.1 hardening:** Sessions 0–3 complete · **Branch:** `dev/v0.1.1-hardening`

This document captures the complete state of the Lattice codebase: what exists, how the pieces fit together, and the design decisions behind them. Start here before reading any source file.

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
HELLO exchange  (internal/handshake)  — 10-second deadline enforced
  client sends:  HELLO { pubkey, signature(clientNonce), protocol_version=1, capabilities }
  server checks: ed25519.Verify(pubkey, clientNonce, signature); version check
  server sends:  HELLO_ACK { session_id, session_token, server_pubkey, server_signature, heartbeat_interval }
  client checks: ed25519.Verify(server_pubkey, serverNonce, server_signature); pinned-key check (TOFU)
    │
    ▼
Post-handshake setup  (internal/node)
  registry.Register(sessionID, pubkey, capabilities)
  publish lattice.system.entity.joined
    │
    ▼
Frame dispatch loop  (internal/node)
  HEARTBEAT      → registry.UpdateHeartbeat → HEARTBEAT_ACK (ctrl-priority lane)
  SUBSCRIBE      → acl.Allow(subscribe) → bus.Subscribe
  UNSUBSCRIBE    → bus.Unsubscribe
  PUBLISH        → ValidateSubject → acl.Allow(publish) → schema.Validate → bus.Fanout → for each subscriber: acl.AllowConcrete(subscribe, subject) → DELIVER
  REQUEST        → acl.Allow(call) → registry.Get(target) → calls.Add → forward REQUEST to target
  RESPONSE       → calls.Remove(correlationID) → forward RESPONSE to requester
  anything else  → logged, ignored
    │
    ▼
Cleanup on disconnect — three paths:

  GRACEFUL (client closes / read error):
    registry.Remove(pubkey) → returns record (non-nil)
    bus.RemoveSession(sessionID)
    conns.Delete(sessionID)
    sessions.Remove(sessionID)
    publish lattice.system.entity.left
    conn.Close()     → interrupts any pending write in sessionWriter
    sw.close()       → waits for writer goroutine to exit

  OFFLINE (heartbeat checker marks stale):
    registry.Remove(pubkey) → returns record (non-nil)
    bus.RemoveSession(sessionID)
    conns.LoadAndDelete(sessionID)
    sessions.Remove(sessionID)
    publish lattice.system.entity.offline
    sw.conn.Close()  → writer goroutine detects error, calls onWriteError (no-op: already removed), exits
    → HandleConn defer: registry.Remove returns nil → skips entity.left; sw.close() fast-returns

  WRITE TIMEOUT (5-second per-write deadline in sessionWriter):
    sessionWriter.write() detects error → conn.Close() → onWriteError closure fires
    registry.Remove(pubkey) → if nil, return (another path got here first)
    bus.RemoveSession(sessionID)
    conns.Delete(sessionID)
    sessions.Remove(sessionID)
    publish lattice.system.entity.offline
    → HandleConn read loop exits (conn closed) → defer: registry.Remove returns nil → skips entity.left
```

Both TLS exporter nonces are derived via `tls.ConnectionState.ExportKeyingMaterial`. Two distinct labels prevent the same bytes from being signed in both directions:
- Client nonce: `"lattice-hello-v1"` — signed by the client, verified by the server
- Server nonce: `"lattice-hello-server-v1"` — signed by the server, verified by the client

---

## Graceful Shutdown

`srv.Shutdown()` performs an ordered drain:

1. `close(s.done)` — signals background goroutines (heartbeat checker, call timeout checker) to stop.
2. Iterates `registry.All()` snapshot; calls `registry.Remove` for each (prevents HandleConn defers from double-publishing).
3. Publishes `lattice.system.entity.left` for each removed entity (frames are enqueued into subscriber writers' data channels while those writers are still running).
4. `conns.Range` — for each `sessionWriter`: calls `sw.close()` (drains buffered frames including entity.left, with 5-second write deadline per frame), then `sw.conn.Close()` so HandleConn's read loop exits.
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
    ID           string           // UUID v4, generated at HELLO time
    Pubkey       []byte           // Ed25519 public key (32 bytes)
    Token        []byte           // 32 random bytes, sent to client in HELLO_ACK
    CreatedAt    time.Time
    Capabilities []*pb.Capability // declared in HELLO frame; propagated to EntityJoined event
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

`PatternsIntersect(a, b string) bool` — in `internal/bus/subject.go`. Reports whether any concrete subject exists that matches both patterns. Used by the ACL engine for delivery-time correctness reasoning. Algorithm: walk segment pairs; `>` matches any remaining suffix of length ≥ 1 (returns true immediately if the other side still has segments), `*` matches any one segment, literals must be equal, length mismatch returns false.

---

### `acl.Engine` — `internal/acl/acl.go`
```go
type cacheKey struct {
    identity string
    action   Action
}

type Engine struct {
    mu    sync.RWMutex
    rules []Rule             // kept in descending Priority order
    cache map[cacheKey][]Rule // identity-indexed rule cache; protected by mu; reset on AddRule
}

type Rule struct {
    IdentityPattern string  // base32(pubkey) (no padding) or "*"
    Action          Action  // "publish" | "subscribe" | "call"
    SubjectPattern  string  // same wildcard syntax as subscription patterns
    Effect          Effect  // Allow | Deny
    Priority        int     // higher = evaluated first
}
```
Deny-by-default. Two methods check ACL:

- **`Allow(pubkey, action, subject)`** — subscribe/publish/call gate. Walks the full rule list under RLock; no caching. The `subject` argument may be a wildcard pattern (e.g., the subscription pattern `home.>`). Used in `handleSubscribe`, `handlePublish`, `handleRequest`.

- **`AllowConcrete(pubkey, action, subject)`** — delivery-time gate. Same logic as `Allow` but uses an identity-indexed cache (`cacheKey{identity, action}` → `[]Rule`) to avoid scanning all rules on every DELIVER. Cache is built lazily on first call and invalidated (replaced with a fresh map) on every `AddRule`. Uses double-checked locking: read under RLock, write under WLock on miss. The `subject` argument must be a concrete (non-wildcard) string. Used in `fanout` and `publishSystemEvent`.

`EncodeIdentity(pubkey []byte) string` converts a raw Ed25519 public key to the canonical base32 (no-padding) string used in identity patterns.

For call ACL: `action = "call"`, `subject = base32(targetPubkey)`. Use `"*"` or `">"` to allow calls to any target.

At server startup, two rules at priority 1000 allow the server's own identity to publish and subscribe to everything. These let the server emit system events.

---

### `registry.EntityRecord` — `internal/registry/registry.go`
```go
type EntityRecord struct {
    Pubkey          []byte
    Capabilities    []*pb.Capability
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
`Remove(pubkey)` returns the record if it existed, or `nil` if already removed. This nil-check is the sentinel that prevents the graceful, offline, write-timeout, and shutdown disconnect paths from all firing for the same entity.

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
    conns             sync.Map   // sessionID → *sessionWriter
    wg                sync.WaitGroup
    stopOnce          sync.Once
    done              chan struct{}
}
```
Created once; `HandleConn` is called in a goroutine per accepted connection. The `wg` tracks all HandleConn goroutines and the two background goroutines (heartbeat checker, call timeout checker). `done` is closed by `Shutdown()` to signal them. `stopOnce` prevents double-close panics.

---

### `node.sessionWriter` — `internal/node/writer.go`
```go
type sessionWriter struct {
    conn         net.Conn
    ctrl         chan writerMsg  // cap 64  — HEARTBEAT_ACK, ERROR; never dropped under data congestion
    data         chan writerMsg  // cap 128 — DELIVER, REQUEST, RESPONSE; dropped on overflow, logged
    stopOnce     sync.Once
    done         chan struct{}
    wg           sync.WaitGroup
    log          *slog.Logger
    sessionID    string
    onWriteError func()         // called after conn.Close() when a write deadline fires
}
```
One per connection, stored in `Server.conns`. A dedicated goroutine drains both channels with ctrl priority: a fast non-blocking check of `ctrl` precedes every fair select, so a pending heartbeat-ack is never starved by a flood of DELIVER frames. Every `wire.Write` call sets a 5-second deadline; a missed deadline closes the conn and fires `onWriteError`. `close()` signals stop, drains buffered frames, and blocks until the goroutine exits — safe to call multiple times.

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
           sessions.ByID(sessionID) → *session.Record (nil → skip: session cleaned up)
           acl.AllowConcrete(rec.Pubkey, "subscribe", subject)
               → skip subscriber silently if denied (no ERROR to subscriber)
               → uses identity-indexed rule cache (O(1) on hit); cache invalidated by AddRule
           conns.Load(sessionID) → *sessionWriter
           sw.enqueue(DELIVER, { subject, payload })
               └─ non-blocking send to data channel (cap 128); drops + logs on overflow
                  writer goroutine drains channel → wire.Write with 5s deadline
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
    └─ targetSw.enqueue(REQUEST, payload) ───────────────────► Client B receives REQUEST

Client B sends RESPONSE { correlation_id, payload }
    │
    ▼  node.handleResponse
    │
    ├─ calls.Remove(correlation_id) → *PendingCall
    │      → ERROR NOT_FOUND if correlation_id unknown or already expired
    │
    └─ requesterSw.enqueue(RESPONSE, payload) ───────────────► Client A receives RESPONSE

(If no RESPONSE within timeout_ms, runCallTimeoutChecker fires ERROR TIMEOUT to A via enqueueControl)
```

---

## System Events

The server publishes to three reserved subjects. These bypass publish-side ACL, subject format validation, and schema validation. **Delivery-time ACL is enforced**: a subscriber whose rules include `deny lattice.system.entity.joined` (or any covering pattern) will not receive that event.

| Subject | Proto message | Trigger |
|---------|--------------|---------|
| `lattice.system.entity.joined` | `EntityJoined { pubkey, capabilities, session_id }` | Entity completes HELLO handshake |
| `lattice.system.entity.left` | `EntityLeft { pubkey, session_id }` | Graceful disconnect or server shutdown |
| `lattice.system.entity.offline` | `EntityOffline { pubkey, session_id }` | Entity misses 3 × heartbeat_interval, or write deadline exceeded |

The offline entity's own subscriptions are removed *before* its offline event is published, so it cannot receive its own eviction notice.

---

## Heartbeat Checker

`runHeartbeatChecker` ticks every `heartbeatInterval` seconds. For each entity with `now − LastHeartbeatAt > 3 × interval`, `markOffline` is called:

1. `registry.Remove` — if nil, another goroutine already handled it; return.
2. Remove subscriptions from the bus.
3. Remove `*sessionWriter` from `conns` via `LoadAndDelete`.
4. Remove session from the session table.
5. Publish `entity.offline` (while other subscribers are still in `conns`).
6. `sw.conn.Close()` → HandleConn's `wire.Read` returns error; the sessionWriter goroutine detects the closed conn on its next write, calls `onWriteError` (which is a no-op since the entity is already removed), and exits.
7. HandleConn defer: `registry.Remove` returns nil → skips `entity.left`; `sw.close()` fast-returns (goroutine already exited).

---

## Call Timeout Checker

`runCallTimeoutChecker` ticks every 1 second. Calls `calls.Expired(now)` to retrieve and atomically remove all pending calls past their deadline. For each expired call, sends `ERROR { code: "TIMEOUT" }` to the requester via `enqueueControl` (silently drops if requester already disconnected — `conns.Load` miss).

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

The server generates a **fresh self-signed TLS certificate at each startup** (not persisted). Clients use `InsecureSkipVerify: true` — the TLS certificate is not the trust anchor; the Ed25519 mutual-auth signature exchange is. On first connection (TOFU), the client writes the server's Ed25519 pubkey to `server.pin`; subsequent connections verify against it.

---

## Test Coverage

```
go test ./...
```

| Package | Tests | What they cover |
|---------|-------|-----------------|
| `internal/wire` | 7 | Frame encode/decode, 256 KiB boundary, concurrent clients, mid-read disconnect |
| `internal/handshake` | 11 | Valid HELLO, corrupted signature, mismatched pubkey, concurrent sessions, HEARTBEAT round-trip, session token, server signature verify/forge, pin mismatch, unsupported protocol version, typed capabilities, handshake deadline (10s, skipped in short mode) |
| `internal/bus` | 26 | Wildcard matching (`*`, `>`), pattern/subject validation, subscribe/unsubscribe/fanout, deduplication, session cleanup; 9 `PatternsIntersect` cases (identical, gt-vs-exact, gt-vs-gt, broader-gt, star-vs-exact, different-prefix, private-vs-broader, disjoint-lengths, star-length-mismatch) |
| `internal/schema` | 13 | Both schemas: valid payloads, out-of-range values, missing fields, invalid enum, string length, unknown subject |
| `internal/acl` | 11 | Deny by default, exact allow, wildcard identity, priority ordering, deny overrides lower-priority allow; `AllowConcrete` empty-deny, allow, delivery-time deny (wildcard bypass fix), cache invalidation after `AddRule` |
| `internal/node` | 33 | 26 black-box integration tests (pub/sub, wildcards, schema rejection, ACL, entity events, offline detection, call round-trip/timeout/ACL, graceful shutdown, typed capabilities, delivery-time wildcard deny, system-event delivery deny); 7 white-box writer unit tests (delivery, write-error callback, idempotent close, close-waits-for-goroutine, channel overflow) |
| **Total** | **101** | |

The `TestIntegrationSequence` test covers all 10 steps of the full integration scenario in a single sequential test with per-step log output.

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
