# Lattice — System State

**Scope:** Local orchestration only · **Language:** Go 1.23 · **Sessions complete:** 1–4 of 8

This document captures the current state of the Lattice codebase: what exists, how the pieces fit together, and what comes next. It is the right place to start before reading any source file.

---

## What Lattice Is

Lattice is a message bus for locally-connected entities (services, devices, agents). It runs as a single TCP+TLS server (`lattice-node`) that entities dial into. Once connected and authenticated, entities can:

- **Publish** messages to named subjects (`home.sensor.temperature`)
- **Subscribe** to subjects with wildcards (`home.>`, `home.*.temperature`)
- **Call** other entities point-to-point by public key (Session 7, not yet built)

Everything is binary, framed, and typed. All payloads are Protobuf. All connections use TLS 1.3. All identities are Ed25519 key pairs.

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
│   └── node/              # server connection handler (owns all of the above)
├── proto/
│   ├── frames.proto       # 14 frame types + message definitions
│   └── schemas.proto      # TemperatureReading, LightCommand
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
Frame dispatch loop  (internal/node)
  HEARTBEAT      → HEARTBEAT_ACK
  SUBSCRIBE      → bus.Subscribe
  UNSUBSCRIBE    → bus.Unsubscribe
  PUBLISH        → ValidateSubject → schema.Validate → bus.Fanout → DELIVER to each
  anything else  → logged, ignored
    │
    ▼
Cleanup on disconnect (in order):
  1. session.Table.Remove(sessionID)
  2. bus.Bus.RemoveSession(sessionID)
  3. conns.Delete(sessionID)       ← prevents new fanout writes to this conn
  4. conn.Close()
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
    ID        string    // UUID v4, generated at HELLO time
    Pubkey    []byte    // Ed25519 public key (32 bytes)
    Token     []byte    // 32 random bytes, sent to client in HELLO_ACK
    CreatedAt time.Time
}
```
One record per authenticated connection. Lifetime: created in `handshake.DoServer`, removed in `node.HandleConn`'s cleanup defer.

---

### `session.Table` — `internal/session/session.go`
```go
type Table struct {
    mu       sync.RWMutex
    byID     map[string]*Record
    byPubkey map[string]*Record // hex(pubkey) → record
}
```
The server's source of truth for who is connected. Dual-indexed so it can be looked up by session ID (frame routing) or by pubkey (entity registry in Session 6).

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

### `node.Server` — `internal/node/node.go`
```go
type Server struct {
    log               *slog.Logger
    sessions          *session.Table
    bus               *bus.Bus
    serverPriv        ed25519.PrivateKey
    heartbeatInterval uint32
    conns             sync.Map // sessionID → *lockedConn
}
```
The top-level server object. Created once; `HandleConn` is called in a goroutine per accepted connection. Owns all shared state.

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

The publisher's goroutine does all of this synchronously. If a subscriber's connection is slow to write, it blocks that goroutine. Fan-out concurrency is a Session 6+ concern.

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
| `internal/node` | 16 | Full server integration: pub/sub delivery, wildcard delivery, unsubscribe, disconnect cleanup, invalid patterns, schema rejection, rejection recovery |
| **Total** | **59** | |

---

## What Is Not Yet Built (Sessions 5–8)

| Session | What it adds |
|---------|-------------|
| **5 — ACL engine** | Every SUBSCRIBE and PUBLISH checked against rules. Deny by default. Rules have identity pattern, action, subject pattern, effect, priority. |
| **6 — Entity registry + system events** | Server tracks connected entities. `lattice.system.entity.joined/left/offline` published on connect/disconnect/missed heartbeat. |
| **7 — Call primitive** | `REQUEST` addressed to a target pubkey; server forwards to target; `RESPONSE` forwarded back. Correlation ID ties pairs. Timeout on server side. |
| **8 — Integration** | Full end-to-end test sequence. Graceful shutdown. README and demo script. |

The PUBLISH handler has a comment marking where the ACL check will be inserted (before schema validation, per spec).

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
            ├── internal/schema ──► proto/
            └── internal/wire

cmd/lattice-client
    ├── internal/handshake
    ├── internal/identity
    ├── internal/wire
    └── proto/

internal/wire ──► proto/
internal/identity  (stdlib only)
internal/session   (stdlib only)
```

No import cycles. The `proto/` package is a leaf — nothing in it imports internal packages.
