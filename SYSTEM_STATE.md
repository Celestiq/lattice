# Lattice — System State

**Scope:** Local orchestration only · **Language:** Go 1.23 · **v0.1.1 hardening:** Sessions 0–7 complete · **Branch:** `dev/v0.1.1-hardening`

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
│   ├── schema/            # dynamic schema registry; payload validators
│   ├── acl/               # access-control engine
│   ├── registry/          # entity liveness tracking
│   ├── call/              # pending REQUEST/RESPONSE registry
│   ├── admin/             # localhost-only HTTP admin API (Decision #15)
│   └── node/              # server connection handler (owns all of the above)
├── proto/
│   ├── frames.proto       # 14 frame types + message definitions
│   ├── schemas.proto      # TemperatureReading, LightCommand (with lattice.* options)
│   ├── lattice_options.proto  # custom field options: range, max_length, required
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
| 7 | `PUBLISH` | client → server | Send a message to a subject; optional `message_id` for error correlation | 3 |
| 8 | `DELIVER` | server → client | Forward with provenance envelope: `id`, `publisher_identity`, `published_at`, `schema_version` | 3 |
| 9 | `ERROR` | server → client | Reject a frame; carries `code` + `message` + optional `ref_id` | all |
| 10 | `REQUEST` | client → server → client | Point-to-point call; server stamps `caller_identity` + `received_at` | 7 |
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
  client sends:  HELLO { pubkey, signature(clientNonce), protocol_version=1, capabilities, resume_token? }
  server checks: ed25519.Verify(pubkey, clientNonce, signature); version check
  server checks: if resume_token present → tokens.Consume(token, pubkey) → ResumeResult{Resumed, Patterns}
                 (mismatch/expired/not-found → Resumed=false; falls through to full registration silently)
  server sends:  HELLO_ACK { session_id, session_token, server_pubkey, server_signature, heartbeat_interval }
  client checks: ed25519.Verify(server_pubkey, serverNonce, server_signature); pinned-key check (TOFU)
    │
    ▼
Post-handshake setup  (internal/node)
  registry.RegisterAndEvict(sessionID, pubkey, capabilities) → atomically replaces any old session (Decision #12 / M-1)
    if old != nil: evictCapturedSession(old)  ← registry already updated; no CAS needed
      calls.InvalidateTarget(old.SessionID) → ERROR TARGET_DISCONNECTED to each requester (Decision #6)
      bus.RemoveSession(old.SessionID) → conns.LoadAndDelete → sw.conn.Close()
      sessions.Remove(old.SessionID)
      old HandleConn read loop exits (conn closed); its defer teardownSession CAS-Remove returns nil → no entity.left
  if resume.Resumed:                          ← Decision #2
    for each saved pattern:
      acl.AllowPattern(pubkey, subscribe, pattern)  ← re-check; wholly-denied patterns dropped (M-5)
      bus.Subscribe(sessionID, pattern)
    durableReplayHook(rec)  ← no-op stub in v0.1.1
    NO entity.joined published
  else:
    publish lattice.system.entity.joined
    │
    ▼
Frame dispatch loop  (internal/node)
  HEARTBEAT      → registry.UpdateHeartbeat → HEARTBEAT_ACK (ctrl-priority lane)
  SUBSCRIBE      → acl.AllowPattern(subscribe, pattern) → bus.Subscribe  ← wholly-denied check (Decision #11)
  UNSUBSCRIBE    → bus.Unsubscribe
  PUBLISH        → ValidateSubject → acl.Allow(publish) → s.schema.Validate → bus.Fanout → for each subscriber: acl.AllowConcrete(subscribe, subject) → DELIVER
  REQUEST        → acl.Allow(call) → registry.Get(target) → calls.Add(corrID, requesterSID, targetSID) → forward REQUEST to target
  RESPONSE       → calls.Peek(corrID) → verify sender.sessionID == pending.TargetSessionID (→ ERROR NOT_AUTHORIZED if mismatch) → calls.Remove → forward RESPONSE to requester
  DISCONNECT     → teardownSession (CAS Remove + bus/conns/sessions cleanup + entity.left) → return
  anything else  → logged, ignored
    │
    ▼
Cleanup on disconnect — four paths:

  GRACEFUL (client closes / read error / DISCONNECT):
    teardownSession(rec):
      registry.Remove(pubkey, sessionID) CAS → if nil, another path got here first; return
      patterns := bus.GetPatterns(sessionID)             ← snapshot subscriptions BEFORE removal
      tokens.Save(rec.Token, rec.Pubkey, patterns)       ← save for resume (Decision #2)
      bus.RemoveSession(sessionID)
      conns.Delete(sessionID)
      sessions.Remove(sessionID)
      publish lattice.system.entity.left
    conn.Close()     → interrupts any pending write in sessionWriter
    sw.close()       → waits for writer goroutine to exit

  EVICTION (same pubkey reconnects — Decision #12):
    evictOldSession(old):
      registry.Remove(old.Pubkey, old.SessionID) CAS → if nil, return
      calls.InvalidateTarget(old.SessionID) → ERROR TARGET_DISCONNECTED to requesters
      bus.RemoveSession(old.SessionID)
      conns.LoadAndDelete(old.SessionID) → sw.conn.Close()
      sessions.Remove(old.SessionID)
      NO entity.left published — reconnect supersedes old session
    → old HandleConn's read loop exits (conn closed) → defer teardownSession CAS-Remove → nil → no-op

  OFFLINE (heartbeat checker marks stale):
    registry.Remove(pubkey, sessionID) CAS → if nil, return
    bus.RemoveSession(sessionID)
    conns.LoadAndDelete(sessionID) → sw.conn.Close()
    sessions.Remove(sessionID)
    publish lattice.system.entity.offline
    → HandleConn defer: teardownSession CAS-Remove returns nil → skips entity.left; sw.close() fast-returns

  WRITE TIMEOUT (5-second per-write deadline in sessionWriter):
    onWriteError closure fires:
      registry.Remove(pubkey, sessionID) CAS → if nil, return
      bus.RemoveSession(sessionID)
      conns.Delete(sessionID)
      sessions.Remove(sessionID)
      publish lattice.system.entity.offline
    → HandleConn read loop exits (conn closed) → defer teardownSession CAS-Remove → nil → no-op
```

Both TLS exporter nonces are derived via `tls.ConnectionState.ExportKeyingMaterial`. Two distinct labels prevent the same bytes from being signed in both directions:
- Client nonce: `"lattice-hello-v1"` — signed by the client, verified by the server
- Server nonce: `"lattice-hello-server-v1"` — signed by the server, verified by the client

---

## Graceful Shutdown

`srv.Shutdown()` performs an ordered drain:

1. `close(s.done)` — signals background goroutines (heartbeat checker, call timeout checker) to stop.
2. Iterates `registry.All()` snapshot; calls `registry.Remove(pubkey, sessionID)` (CAS) for each (prevents HandleConn defers from double-publishing).
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

`Remove(id)` uses a CAS on the `byPubkey` entry: it only deletes `byPubkey[k]` when it still references the session being removed. This prevents evicting S1 (when the same pubkey reconnects as S2) from wiping S2's pubkey index.

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

`PatternsIntersect(a, b string) bool` — in `internal/bus/subject.go`. Reports whether any concrete subject exists that matches both patterns. Used by the ACL engine for subscribe-time and delivery-time correctness reasoning. Algorithm: walk segment pairs; `>` matches any remaining suffix of length ≥ 1 (returns true immediately if the other side still has segments), `*` matches any one segment, literals must be equal, length mismatch returns false.

`PatternSubsumedBy(inner, outer string) bool` — in `internal/bus/subject.go`. Reports whether every concrete subject matching `inner` also matches `outer` — i.e., `outer`'s subject set is a superset of `inner`'s. Used by `AllowPattern` to determine whether a higher-priority Deny rule fully blocks a subscription pattern. Algorithm: segment-by-segment; `outer`'s `>` subsumes any remaining inner segments (returns true if inner is non-empty); `inner`'s `>` is only subsumed by `outer`'s `>`; `outer`'s `*` accepts any single inner segment; literals must match exactly.

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
Deny-by-default. Three methods check ACL:

- **`AllowPattern(pubkey, action, pattern)`** — subscribe-time gate (Decision #11). Checks whether the subscription pattern is *not wholly-denied* — i.e., at least one concrete subject under the pattern would be permitted. Uses the identity-indexed rule cache (`rulesFor`). Algorithm: for each Allow rule that intersects the pattern (`PatternsIntersect`), check if any higher-priority Deny rule subsumes the entire subscription pattern (`PatternSubsumedBy(pattern, deny.SubjectPattern)`). If a non-blocked Allow exists, return true. Used in `handleSubscribe`. Replaces the old `Allow` call which incorrectly treated the subscription pattern as a concrete subject.

- **`Allow(pubkey, action, subject)`** — publish/call gate. Walks the full rule list under RLock; no caching. The `subject` argument is a concrete subject for publish, or `base32(targetPubkey)` for call. Used in `handlePublish`, `handleRequest`.

- **`AllowConcrete(pubkey, action, subject)`** — delivery-time gate. Same first-match-wins logic but uses an identity-indexed cache (`cacheKey{identity, action}` → `[]Rule`) to avoid scanning all rules on every DELIVER. Cache is built lazily on first call and invalidated (replaced with a fresh map) on every `AddRule`. Uses double-checked locking: read under RLock, write under WLock on miss. The `subject` argument must be a concrete (non-wildcard) string. Used in `fanout` and `publishSystemEvent`.

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
`Remove(pubkey, sessionID)` is a **compare-and-swap**: only removes the entry if `record.SessionID == sessionID`, returns the removed record or nil. This is the sentinel that prevents all four disconnect paths from racing.

`RegisterAndEvict(sessionID, pubkey, capabilities) *EntityRecord` — atomically replaces any existing session for `pubkey` with the new session in a single lock acquisition, returning the old `EntityRecord` (nil if none). Eliminates the TOCTOU race window between reading the old session and registering the new one when two connections with the same pubkey arrive concurrently (M-1 fix). The caller must clean up the returned old session directly — `registry.Remove` is NOT called for the old session, since it is already replaced.

`Get(pubkey)` returns the record without removing it — used by `handleRequest` for target lookup.

---

### `call.Registry` — `internal/call/call.go`
```go
type PendingCall struct {
    RequesterSessionID string
    TargetSessionID    string // the session that must send the RESPONSE (Decision #6)
    Deadline           time.Time
}

type Registry struct {
    mu      sync.Mutex
    pending map[string]*PendingCall // correlationID → call
}
```
- `Add(corrID, requesterSID, targetSID, deadline)` — registered before forwarding the REQUEST (race-prevention).
- `Peek(corrID)` — non-destructive lookup; used by `handleResponse` to verify the responder's session before committing a Remove.
- `Remove(corrID)` — returns nil if not found (stale or expired).
- `Expired(now)` — removes and returns all entries past their deadline atomically.
- `InvalidateTarget(targetSID)` — bulk-removes all calls targeting `targetSID`; used in `evictOldSession` to cancel in-flight calls when a target reconnects (returns `[]ExpiredCall` so callers can send `TARGET_DISCONNECTED` to requesters).

---

### `session.TokenStore` — `internal/session/tokenstore.go`
```go
type ResumeState struct {
    Pubkey    []byte
    Patterns  []string
    CreatedAt time.Time
}

type TokenStore struct {
    mu     sync.Mutex
    states map[string]*ResumeState // hex(token) → state
    ttl    time.Duration
}
```
Maps 32-byte session tokens to saved subscription patterns for token-based resume (Decision #2). `Consume(token, pubkey)` atomically removes and returns the patterns only if the entry is present, not expired, and the pubkey matches — preventing replay. `Save(token, pubkey, patterns)` is called in `teardownSession` before bus cleanup. `Delete` removes without returning state. `ExpireTokens` sweeps expired entries. Default TTL: 5 minutes; configurable via `node.New` variadic arg.

`bus.GetPatterns(sessionID string) []string` returns all patterns to which a session is currently subscribed by iterating over the bus's pattern map under `RLock`.

---

### `handshake.ResumeResult` — `internal/handshake/handshake.go`
```go
type ResumeResult struct {
    Resumed  bool
    Patterns []string
}
```
Returned by `DoServer` alongside `*session.Record`. `Resumed` is true only when the client presented a valid, unconsumed, non-expired token that matches the connecting pubkey. `DoServer` now takes `*session.TokenStore` as a parameter.

`DoClient` now accepts an optional `resumeToken ...[]byte` variadic. When provided (and non-empty), the token is included in the HELLO frame.

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
    tokens            *session.TokenStore  // resume tokens (Decision #2)
    schema            *schema.Registry    // dynamic schema registry (Decision #14)
    seq               subjectSequencer    // per-subject monotonic DELIVER IDs (Decision #4)
    serverPriv        ed25519.PrivateKey
    serverPub         ed25519.PublicKey
    heartbeatInterval uint32
    conns             sync.Map // sessionID → *sessionWriter
    wg                sync.WaitGroup
    stopOnce          sync.Once
    done              chan struct{}
}
```
Created once; `HandleConn` is called in a goroutine per accepted connection. The `wg` tracks all HandleConn goroutines and the three background goroutines (heartbeat checker, call timeout checker, token expirer). `done` is closed by `Shutdown()` to signal them. `stopOnce` prevents double-close panics.

`New(log, serverPriv, heartbeatInterval, tokenTTL ...time.Duration)` — the optional `tokenTTL` overrides the default 5-minute resume-token TTL.

`SchemaRegistry() *schema.Registry` — returns the server's dynamic schema registry. Used by `admin.New` to wire the admin HTTP server to the same registry instance.

`durableReplayHook(*session.Record)` — called during resume after subscriptions are restored. No-op stub in v0.1.1; durable message replay is not yet implemented.

---

### `node.subjectSequencer` — `internal/node/seq.go`
```go
type subjectSequencer struct {
    m sync.Map // subject (string) → *atomic.Uint64
}
```
`Next(subject string) uint64` returns the next monotonically increasing ID for `subject`, starting at 1. IDs are independent per concrete subject (`home.sensor.temperature` and `home.light.command` have separate counters). Uses `sync.Map.LoadOrStore` + `atomic.Uint64.Add` — no global lock contention during fanout.

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
Client B sends PUBLISH { subject: "home.sensor.temperature", payload: <proto bytes>, message_id?: "x" }
    │
    ▼  node.HandleConn (Client B's goroutine)
    │
    ├─ bus.ValidateSubject("home.sensor.temperature")
    │      checks: no wildcards, not lattice.system.*, ≤16 segs, ≤256 chars
    │      → ERROR { ref_id: message_id } if invalid
    │
    ├─ acl.Allow(rec.Pubkey, "publish", "home.sensor.temperature")
    │      walks rules in priority order; first match wins; default deny
    │      → ERROR { ref_id: message_id } if denied; delivery stops here
    │
    ├─ s.schema.Validate("home.sensor.temperature", payload)
    │      unmarshals via dynamicpb; enforces lattice.required, lattice.range, lattice.max_length options
    │      → ERROR { ref_id: message_id } if invalid; delivery stops here
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
           sw.enqueue(DELIVER, {
               id: seq.Next(subject),          ← per-subject monotonic counter
               subject, payload,
               publisher_identity: base32(B.pubkey),  ← server-stamped
               published_at: now_ms,
               schema_version: schema.Version(subject),
           })
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
    ├─ calls.Add(correlation_id, A.sessionID, B.sessionID, now+timeout_ms)
    │      registered BEFORE forwarding (avoids response-arrives-first race)
    │      B.sessionID stored so the responder can be verified
    │
    ├─ req.CallerIdentity = base32(A.pubkey)  ← server-stamps; overwrites any client value
    │  req.ReceivedAt    = now_ms
    │
    └─ targetSw.enqueue(REQUEST, re-marshaled req) ──────────► Client B receives REQUEST
           B can trust CallerIdentity and ReceivedAt — server-assigned, not client-asserted

Client B sends RESPONSE { correlation_id, payload }
    │
    ▼  node.handleResponse
    │
    ├─ calls.Peek(correlation_id) → *PendingCall
    │      → ERROR NOT_FOUND if correlation_id unknown or already expired
    │
    ├─ verify pending.TargetSessionID == sender.sessionID
    │      → ERROR NOT_AUTHORIZED if mismatch (call stays pending; legitimate target can still respond)
    │
    ├─ calls.Remove(correlation_id) → confirm still present (may have expired between Peek and Remove)
    │
    └─ requesterSw.enqueue(RESPONSE, payload) ───────────────► Client A receives RESPONSE

(If no RESPONSE within timeout_ms, runCallTimeoutChecker fires ERROR { code: TIMEOUT, ref_id: correlation_id } to A)
(If B evicted before responding, evictOldSession fires ERROR TARGET_DISCONNECTED to A immediately)
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

1. `registry.Remove(pubkey, sessionID)` (CAS) — if nil, another goroutine already handled it; return.
2. Remove subscriptions from the bus.
3. Remove `*sessionWriter` from `conns` via `LoadAndDelete`.
4. Remove session from the session table.
5. Publish `entity.offline` (while other subscribers are still in `conns`).
6. `sw.conn.Close()` → HandleConn's `wire.Read` returns error; the sessionWriter goroutine detects the closed conn on its next write, calls `onWriteError` (which is a no-op since the entity is already removed by CAS), and exits.
7. HandleConn defer: `teardownSession` calls `registry.Remove(pubkey, sessionID)` → returns nil → no-op (already cleaned up); `sw.close()` fast-returns (goroutine already exited).

---

## Token Expirer

`runTokenExpirer` ticks every minute and calls `s.tokens.ExpireTokens()`, which sweeps the token store for entries whose TTL has elapsed (default 5 minutes). Without this goroutine the map would grow without bound as disconnected entities accumulate tokens that are never consumed (M-2 fix).

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

## Schema Registry (Decision #14)

The schema registry is dynamic. Subjects are registered with a compiled `FileDescriptorProto` (binary-encoded); validation uses `google.golang.org/protobuf/types/dynamicpb` to unmarshal payloads against the stored `MessageDescriptor` and enforce custom field options.

Two built-in subjects are pre-registered by `schema.DefaultRegistry()` at server startup:

| Subject | Message type | Constraints |
|---|---|---|
| `home.sensor.temperature` | `TemperatureReading` | `value` required (float32, −50..150), `unit` optional (string, ≤10 chars) |
| `home.light.command` | `LightCommand` | `action` required, range [1,3] (enum ON/OFF/TOGGLE), `brightness` optional (float32, 0.0..1.0) |

### Custom proto options — `proto/lattice_options.proto`

Three extensions on `google.protobuf.FieldOptions`:

| Extension | Field tag | Go variable | Purpose |
|-----------|-----------|-------------|---------|
| `lattice.range` | 50001 | `pb.E_Range` | Min/max for numeric or enum field (`RangeOptions{Min, Max float32}`) |
| `lattice.max_length` | 50002 | `pb.E_MaxLength` | Max byte length for string/bytes field (`uint32`) |
| `lattice.required` | 50003 | `pb.E_Required` | Field must be present in the payload (`bool`) |

The generated `schemas.pb.go` embeds these option values in field descriptors; `extractConstraints` reads them via `proto.HasExtension` / `proto.GetExtension`.

### `schema.Registry` — `internal/schema/registry.go`

```go
type Registry struct {
    mu      sync.RWMutex
    entries map[string]*registryEntry // subject → entry
}
```

- **`NewRegistry()`** — creates an empty registry.
- **`DefaultRegistry()`** — returns a registry pre-populated with `home.sensor.temperature` → `TemperatureReading` and `home.light.command` → `LightCommand` at version 1.
- **`Register(subject, messageName string, fdBytes []byte) error`** — parses the `FileDescriptorProto`, builds a `FileDescriptor` via `protodesc.NewFile(fd, protoregistry.GlobalFiles)`, finds the named message, extracts constraints, enforces additive-only versioning, and stores the entry. Version increments by 1 on each accepted upgrade.
- **`Validate(subject string, payload []byte) error`** — unmarshals using `dynamicpb.NewMessage`, walks fields, enforces `required`, `range`, and `max_length` constraints.
- **`Version(subject string) uint32`** — returns current version (0 if not registered).
- **`List() []SubjectInfo`** — returns all subjects with versions; used by the admin GET endpoint.

**Additive-only versioning (Decision #16):** `checkAdditive` enforces four constraints (M-4 fix):
1. **No field removal** — every field in the old descriptor must exist in the new one.
2. **No type (Kind) change** — e.g., float → int is rejected.
3. **No cardinality change** — e.g., `optional` → `repeated` is rejected.
4. **No new required fields** — a newly added field with `lattice.required=true` would break existing publishers who don't set it; rejected via `fieldIsRequired` helper.

Field removal, type change, cardinality change, or a new required field returns an error — the `Register` call is rejected and the version is not bumped.

Proto3 `optional` is used for all built-in message fields so the `Has(field)` presence check distinguishes "not set" from "set to zero value".

### Admin API — `internal/admin/admin.go` (Decision #15)

A lightweight stdlib `net/http` server. Accessible via `cmd/lattice-node --admin-addr` (default `127.0.0.1:4223`). `ListenAndServe` validates that the bind address resolves to a loopback IP before binding.

**Timeouts and body limits (L-1):** `ListenAndServe` uses an `http.Server` with `ReadTimeout(10s)`, `WriteTimeout(10s)`, `IdleTimeout(60s)`, and `MaxHeaderBytes(64 KiB)`. `handleRegisterSchema` caps the request body at 512 KiB via `http.MaxBytesReader`; oversized requests return `413 Request Entity Too Large` before any parsing occurs.

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/schema` | `{"subject": "...", "message_name": "...", "descriptor": "<base64 FileDescriptorProto>"}` | `204 No Content`, `400 Bad Request`, `413 Too Large`, or `422 Unprocessable Entity` |
| `GET` | `/schema` | — | `200 JSON [{"subject":"...","schema_version":N}]` |

`admin.Server` also exposes `Serve(net.Listener)` for tests only — it bypasses the loopback address check. **Production code must use `ListenAndServe`**; serving the admin mux on a non-loopback listener exposes unauthenticated schema registration. (`internal/admin` is module-internal, so no external caller can reach it regardless.)

The server binary exposes `srv.SchemaRegistry() *schema.Registry` to pass to `admin.New`.

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
| `internal/schema` | 13 | Both schemas: valid payloads, out-of-range values, missing fields, invalid enum, string length, unknown subject (all validated via dynamic registry + custom options) |
| `internal/acl` | 13 | Deny by default, exact allow, wildcard identity, priority ordering, deny overrides lower-priority allow; `AllowConcrete` empty-deny, allow, delivery-time deny (wildcard bypass fix), cache invalidation after `AddRule`; `AllowPattern` wholly-denied rejection, broad-pattern accepted despite narrow deny |
| `internal/registry` | 9 | Register+Get, RegisterAndEvict no-prior/with-prior (M-1 atomic path), Remove CAS matching/stale session, Stale threshold, UpdateHeartbeat refreshes/no-op for unknown |
| `internal/session` | 6 | Consume happy path + single-use, wrong pubkey, expired token, ExpireTokens sweeps expired/preserves live (M-2 sweeper), Delete |
| `internal/call` | 5 | Add/Peek/Remove round-trip, Peek non-destructive, Peek/Remove unknown, Expired removes only past-deadline, InvalidateTarget bulk-removes by target |
| `internal/admin` | 6 | ListenAndServe rejects non-loopback, GET /schema returns built-ins, POST /schema registers subject, invalid base64, invalid JSON, body too large (413) |
| `internal/node` | 64 | 57 black-box integration tests (pub/sub, wildcards, schema rejection, ACL, entity events, offline detection, call round-trip/timeout/ACL, graceful shutdown, typed capabilities, delivery-time wildcard deny, system-event delivery deny, reconnect eviction, join-on-reconnect, responder verification, eviction invalidates calls, DISCONNECT teardown, monotonic DELIVER id, per-subject isolation, publisher identity stamped, timestamp populated, request caller identity, caller identity not spoofable, error ref_id, timeout error ref_id, resume restores subscriptions, token rotation prevents reuse, resume requires correct signature, resume token pubkey mismatch, expired token falls back, fresh connect unchanged, durable-replay hook no-op, **resume drops wholly-denied pattern** (M-5), runtime schema registration, custom range enforced, custom max_length enforced, additive version bump, breaking change rejected, cardinality change rejected, new required field rejected, admin localhost-only, admin GET schema, admin register schema); 7 white-box writer unit tests |
| **Total** | **160** | |

The `TestIntegrationSequence` test covers all 10 steps of the full integration scenario in a single sequential test with per-step log output.

---

## Dependency Graph

```
cmd/lattice-node
    ├── internal/node
    │       ├── internal/handshake
    │       │       ├── internal/session
    │       │       ├── internal/wire
    │       │       └── proto/
    │       ├── internal/bus
    │       ├── internal/schema    ──► proto/ (dynamicpb, protodesc, protoregistry)
    │       ├── internal/acl       ──► internal/bus (Match)
    │       ├── internal/registry
    │       ├── internal/call
    │       └── internal/wire
    └── internal/admin ──► internal/schema

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
