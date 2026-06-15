# Lattice — System State

**Scope:** Local orchestration + federation (in progress) · **Language:** Go 1.25 · **v0.1.1:** Sessions 0–7 complete · **v0.2 Federation S1–S5:** QUIC transport + FedHello handshake + SQLite persistence + Federation Manager + Bilateral Consent + Admin API + Forwarding Policy Engine + Schema Propagation + Cross-Federation Call Routing · **Branch:** `dev/v0.2`

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
│   ├── node/              # server connection handler (owns all of the above)
│   ├── transport/         # v0.2: federation transport abstraction (S1)
│   │   ├── transport.go   #   Stream / Dialer / Listener interfaces
│   │   └── quic/          #   QUIC implementation (quic-go v0.60)
│   │       ├── tls.go     #     TLS configs; ALPN "lattice-fed-v1"
│   │       ├── keepalive.go #   application-level PING/PONG keepalive
│   │       ├── quic.go    #     Listener, Dialer, quicStream, lazyServerStream
│   │       └── quic_test.go #  15 tests (topology / fault / race / e2e)
│   └── federation/        # v0.2: federation logic (S2+)
│       ├── handshake/     #   symmetric FedHello exchange (S2)
│       │   ├── handshake.go  # DoFederatedHandshake; rejectAndClose
│       │   └── handshake_test.go # 8 tests
│       ├── peer/          #   PeerConn state machine + write channels (S2/S4)
│       │   ├── peer.go    #     Pending→Active→Paused↔Active→Revoked; ctrl/data channels; RunWriteLoop
│       │   └── peer_test.go  # 4 tests
│       ├── policy/        #   first-match forwarding policy engine (S4)
│       │   ├── engine.go  #     Engine{rules}; Evaluate(subject)→Effect; NewEngine/Empty/SetRules/Rules
│       │   └── engine_test.go # 7 tests
│       ├── store/         #   SQLite peer persistence (S2)
│       │   ├── store.go   #     modernc.org/sqlite; 4 tables; CRUD + DeletePeer
│       │   └── store_test.go # 5 tests
│       ├── calls/         #   outbound cross-federation call registry (S5)
│       │   ├── calls.go   #     Registry; OutboundCall; AddOutbound/RemoveOutbound/ExpiredOutbound
│       │   └── calls_test.go # 6 tests
│       └── manager/       #   federation lifecycle + consent + forwarding + call routing (S3/S4/S5)
│           ├── manager.go #     Manager, NodeHooks, ConnectionInfo; Start/Stop/HandleIncoming/consent ops; ForwardIfNeeded; handleInboundDeliver; TryRouteRequest; ForwardResponse; handleInboundRequest/Response/Policy
│           └── manager_test.go # 39 tests (topology / fault / consent lifecycle / race / e2e / S4 forwarding / S5 call routing)
├── proto/
│   ├── frames.proto       # 23 frame types (0-14 client, 15-23 federation)
│   ├── federation.proto   # v0.2: FedHello, FedPolicy, FedDeliver, FedRequest, ...
│   ├── schemas.proto      # TemperatureReading, LightCommand (with lattice.* options)
│   ├── lattice_options.proto  # custom field options: range, max_length, required
│   └── events.proto       # EntityJoined, EntityLeft, EntityOffline
├── 01-Claude/
│   └── v0.2-IMPLEMENTATION.md  # 6-session federation blueprint
├── DEV.md                 # developer guide: how to run, flags, architecture
├── DEMO.md                # step-by-step feature walkthrough
└── go.mod                 # deps: google.golang.org/protobuf, quic-go, x/crypto, x/net, x/sys, modernc.org/sqlite
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

## Frame Types

Values 0–14 are client↔server frames (TLS-over-TCP). Values 15–23 are federation frames (QUIC peer connections only; never sent on client connections).

### Client frames (0–14)

| # | Name | Direction | Purpose | v0.1.1 session |
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
| 13 | `PING` | either | Application-level keepalive probe (used by federation Keepalive) | reserved |
| 14 | `PONG` | either | Ping reply (call `Keepalive.GotPong()` when received) | reserved |

### Federation frames (15–23) — QUIC connections only (v0.2)

| # | Name | Direction | Purpose | v0.2 session |
|---|------|-----------|---------|---------|
| 15 | `FED_HELLO` | peer → peer | Identity claim over QUIC: pubkey + Ed25519 sig over TLS exporter | S2 |
| 16 | `FED_HELLO_ACK` | peer → peer | Acknowledgment; both sides verified | S2 |
| 17 | `FED_REJECT` | peer → peer | Connection not accepted; stream closed after this | S2 |
| 18 | `FED_PENDING` | peer → peer | Unknown peer accepted for operator review | S2 |
| 19 | `FED_POLICY` | peer → peer | Forwarding policy + exported pubkeys | S3 |
| 20 | `FED_STATUS` | peer → peer | Connection state change (active/paused/revoked) | S3 |
| 21 | `FED_DELIVER` | peer → peer | Forwarded channel message with schema descriptor | S4 |
| 22 | `FED_REQUEST` | peer → peer | Forwarded call request across federation boundary | S5 |
| 23 | `FED_RESPONSE` | peer → peer | Forwarded call response | S5 |

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
    evictCapturedSession(old):  ← registry already updated by RegisterAndEvict; no CAS here
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
5. `s.wg.Wait()` — blocks until all HandleConn goroutines and three background goroutines (heartbeat checker, call timeout checker, token expirer) have exited.

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
    RequesterSessionID  string
    TargetSessionID     string // the session that must send the RESPONSE (Decision #6)
    Deadline            time.Time
    FedSourcePeerPubkey []byte // nil for local calls; set for cross-federation inbound calls (S5)
}

type Registry struct {
    mu      sync.Mutex
    pending map[string]*PendingCall // correlationID → call
}
```
- `Add(corrID, requesterSID, targetSID, deadline)` — registered before forwarding the REQUEST (race-prevention).
- `AddFed(corrID, targetSID, sourcePeerPubkey, deadline)` — S5: registers an inbound cross-federation call. `RequesterSessionID` is empty (requester is on the source peer node); `FedSourcePeerPubkey` stores the source peer's pubkey so `handleResponse` routes the RESPONSE back via `ForwardResponse`.
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
    fedManager        *manager.Manager    // nil when federation disabled (S3)
}
```
Created once; `HandleConn` is called in a goroutine per accepted connection. The `wg` tracks all HandleConn goroutines and the three background goroutines (heartbeat checker, call timeout checker, token expirer). `done` is closed by `Shutdown()` to signal them. `stopOnce` prevents double-close panics.

`New(log, serverPriv, heartbeatInterval, tokenTTL ...time.Duration)` — the optional `tokenTTL` overrides the default 5-minute resume-token TTL.

`SchemaRegistry() *schema.Registry` — returns the server's dynamic schema registry. Used by `admin.New` to wire the admin HTTP server to the same registry instance.

`SetFederationManager(mgr *manager.Manager)` — wires the federation manager (S3). nil-safe — existing 192+ tests pass when no manager is set.

`FederatedPublish(subject string, payload []byte, publisherPubkey []byte)` — implements `NodeHooks`; calls `s.fanout` directly (S3 stub, full routing in S4).

`RouteLocalRequest(corrID, targetPubkey, payload, callerIdentity, receivedAt, timeoutMs, sourcePeerPubkey)` — routes an inbound cross-federation REQUEST to the local target entity; calls `calls.AddFed` so the RESPONSE path can forward back to the source peer.
`RouteLocalResponse(corrID, payload, requesterSID)` — delivers a cross-federation RESPONSE to the local session identified by `requesterSID`.
`SendLocalError(sessionID, code, message, refID)` — sends an ERROR frame (via `enqueueControl`) to a local session; used for TIMEOUT errors on expired outbound federated calls.

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
- **`Descriptor(subject string) []byte`** — returns raw `FileDescriptorProto` bytes stored at `Register` time, or nil for built-in schemas and unknown subjects. Used by `manager.ForwardIfNeeded` to piggyback schema descriptors on the first FedDeliver for a subject to a peer.
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

**Schema endpoints:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/schema` | `{"subject": "...", "message_name": "...", "descriptor": "<base64 FileDescriptorProto>"}` | `204`, `400`, `413`, or `422` |
| `GET` | `/schema` | — | `200 JSON [{"subject":"...","schema_version":N}]` |

**Federation endpoints (registered via `SetFederationManager`, S3):**

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/federation/pair` | `{"pubkey":"<64-hex>","name":"...","addr":"..."}` | `201` (created), `400` (bad hex), `409` (already known) |
| `POST` | `/federation/accept` | `{"pubkey":"<64-hex>"}` | `204`, `400`, `409` (not pending) |
| `POST` | `/federation/reject` | `{"pubkey":"<64-hex>"}` | `204`, `400`, `409` (not pending) |
| `POST` | `/federation/pause` | `{"pubkey":"<64-hex>"}` | `204`, `400`, `409` (not active) |
| `POST` | `/federation/resume` | `{"pubkey":"<64-hex>"}` | `204`, `400`, `409` (not paused) |
| `POST` | `/federation/revoke` | `{"pubkey":"<64-hex>"}` | `204`, `400`, `500` |
| `GET` | `/federation/connections` | — | `200 JSON [ConnectionInfo]` |
| `POST` | `/federation/policy` | `{"pubkey":"...","outbound":[...],"inbound":[...]}` | `204`, `400` |
| `POST` | `/federation/export` | `{"pubkey":"...","entity_pubkeys":[...]}` | `204`, `400` |

All federation endpoints return `503 Service Unavailable` if federation is not enabled (`--fed-addr` not set). `validatePubkeyHex` rejects any string that isn't exactly 64 hex characters (32 bytes).

`admin.Server` also exposes `Handler() http.Handler` (for httptest) and `Serve(net.Listener)` (for test binding). **Production code must use `ListenAndServe`**; serving the admin mux on a non-loopback listener exposes unauthenticated endpoints.

The server binary exposes `srv.SchemaRegistry() *schema.Registry` to pass to `admin.New`.

---

## Identity and Key Files

| Binary | Default key file | Flag |
|--------|-----------------|------|
| `lattice-node` | `node.key` | `--key` |
| `lattice-client` | `client.key` | `--key` |

The server generates a **fresh self-signed TLS certificate at each startup** (not persisted). Clients use `InsecureSkipVerify: true` — the TLS certificate is not the trust anchor; the Ed25519 mutual-auth signature exchange is. On first connection (TOFU), the client writes the server's Ed25519 pubkey to `server.pin`; subsequent connections verify against it.

---

## v0.2 Federation Transport (Session 1)

### `internal/transport/transport.go` — interface definitions

```go
type Stream interface {
    Read(p []byte) (int, error)
    Write(p []byte) (int, error)
    SetDeadline(t time.Time) error
    Close() error
}
type Dialer  interface { DialPeer(ctx, peerAddr string) (Stream, error) }
type Listener interface { AcceptPeer(ctx) (Stream, error); Addr() net.Addr; Close() error }
```

The interface boundary isolates upper layers (FedHello handshake, policy engine, fanout) from the transport. A future libp2p swap needs only a new `Dialer`/`Listener` implementation.

### `internal/transport/quic/` — QUIC implementation

**`tls.go`**: `newServerTLSConfig()` generates an ephemeral Ed25519 TLS cert (via `wire.GenerateSelfSignedCert`) and configures ALPN `"lattice-fed-v1"`. `newClientTLSConfig()` sets `InsecureSkipVerify: true` — the trust anchor is the FedHello Ed25519 signature (Session 2), not the TLS cert.

**`quic.go`**: Two concrete stream types:
- `quicStream` (dialer side) — wraps `*quic.Stream` + `*quic.Conn`; `Close()` terminates both, making pending `Read`/`Write` calls return errors immediately.
- `lazyServerStream` (listener side) — wraps `*quic.Conn` and starts `AcceptStream` in a background goroutine. `AcceptPeer` returns immediately; the stream pointer is resolved on the first `Read`/`Write`/`SetDeadline` call. This is necessary because in QUIC a stream only becomes visible to the server after the client writes data (no stream frame is sent by `OpenStreamSync` alone).

**`keepalive.go`**: `Keepalive` sends `FRAME_TYPE_PING` every `interval` and expects `GotPong()` to be called within `timeout`. If no PONG arrives, `onTimeout` fires once and the goroutine exits. `Stop()` is idempotent.

**Key design decisions:**
- One QUIC connection, one bidirectional stream per peer pair.
- TLS cert is ephemeral; `InsecureSkipVerify: true`; identity trust deferred to FedHello.
- Existing `wire.Read`/`wire.Write` run unchanged on QUIC streams (same 5-byte header framing).
- `quic.Config{KeepAlivePeriod: 15s, MaxIdleTimeout: 5m}` for NAT traversal + idle eviction.
- Race-detector clean (`go test -race ./internal/transport/...`).

---

## v0.2 Federation Handshake + Persistence (Session 2)

### `internal/federation/handshake/handshake.go`

`DoFederatedHandshake(ctx, stream, nonce, localPriv) (peerPubkey []byte, err error)` — symmetric FedHello exchange. Neither side is initiator or responder; both send and receive simultaneously.

**Nonce**: 32-byte TLS keying material derived by the caller before dialing/accepting:
```go
conn.ConnectionState().TLS.ExportKeyingMaterial("lattice-fed-hello-v1", nil, 32)
```
Both sides of the same QUIC connection derive identical material, so no extra round-trip is needed. In tests, any shared 32-byte value works.

**Protocol (two concurrent-write phases):**
1. Phase 1: both sides concurrently send `FED_HELLO{pubkey, sig=Sign(localPriv, nonce), protocol_version=1}` and receive the peer's FED_HELLO.
2. Validate: check `protocol_version == 1`, pubkey length, `ed25519.Verify(peerPub, nonce, peerSig)`. On failure: write `FED_REJECT`, close stream, return error.
3. Phase 2: both sides concurrently send and receive an empty `FED_HELLO_ACK` to signal mutual verification.

**Deadline**: `min(ctx.Deadline(), now+10s)` set on the stream via `SetDeadline`. Cleared by defer on return.

**Errors**: `ErrInvalidSignature`, `ErrProtocolVersion`, `ErrHandshakeRejected` (wrapped in `errors.Is`-compatible chain).

**TLS exporter label**: `"lattice-fed-hello-v1"` (distinct from client labels `"lattice-hello-v1"` and `"lattice-hello-server-v1"` — cross-context replay is structurally impossible).

---

### `internal/federation/peer/peer.go`

`PeerConn` tracks the lifecycle of a single federation peer connection. All methods are goroutine-safe.

```
Pending ──Activate(stream)──► Active ──Pause()──► Paused
                                │                   │
                              Revoke()            Resume(stream)
                                │                   │
                                ▼                   ▼
                             Revoked           (back to Active)
```

- `New(pubkey, name, addr)` — creates a PeerConn in Pending. Copies pubkey. Initializes `ctrl` (cap 32) and `data` (cap 256) channels.
- `Activate(stream)` — Pending → Active. Returns `ErrIllegalTransition` if not Pending.
- `Pause()` — Active → Paused.
- `Resume(stream)` — Paused → Active (may attach a new stream on re-dial).
- `Revoke()` — Active/Paused → Revoked; calls `stream.Close()` after releasing the lock. Returns `ErrAlreadyRevoked` on double-revoke.
- `State()`, `PeerPubkey()`, `PeerName()`, `Addr()`, `Stream()` — accessors.

**S4 additions:**
- `SendCtrl(ft, payload) bool` — non-blocking enqueue to ctrl channel (FedPolicy, FedStatus). Returns false if full.
- `SendData(ft, payload) bool` — non-blocking enqueue to data channel (FedDeliver, FedRequest, FedResponse). Returns false if full (caller logs drop).
- `RunWriteLoop(done <-chan struct{}, log, onWriteError func())` — priority-drain goroutine: non-blocking ctrl check before every fair select on ctrl/data/done. Writes each frame with a 5-second deadline via `wire.Write`. Calls `onWriteError` once on write failure, then exits. Started by the Manager as a tracked goroutine after `Activate()`.

**Write channel design (mirrors v0.1.1 `sessionWriter` Decision #10):**
- `ctrl chan fedMsg` (cap 32) — high-priority lane for FedPolicy. FedStatus frames (pause/revoke) bypass the channel and are written directly to the stream before `pc.Revoke()` closes it — preserving send-before-close ordering.
- `data chan fedMsg` (cap 256) — data-plane lane for FedDeliver. Dropped (not back-pressured) when full.
- The Manager starts `runPeerWriteLoop(pc, peerHex, resetOnDrop)` as a wg-tracked goroutine after every `Activate()`.

---

### `internal/federation/store/store.go`

SQLite-backed persistence via `modernc.org/sqlite` (pure Go, no CGo). Four tables:

| Table | Purpose |
|-------|---------|
| `federation_peers` | Peer identity, address, consent state (`pending`/`active`/`paused`/`revoked`) |
| `federation_outbound_policy` | Subject forwarding rules (effect: `forward`/`deny`) per peer, in position order |
| `federation_inbound_policy` | Subject acceptance rules (effect: `accept`/`deny`) per peer, in position order |
| `remote_entities` | entity_pubkey_hex → peer_pubkey_hex routing index (populated from received `FedPolicy`) |

**Public API:**

| Method | Description |
|--------|-------------|
| `Open(path)` | Opens/creates DB; applies schema; WAL mode; `MaxOpenConns(1)` |
| `UpsertPeer(hex, name, addr, intro, state)` | INSERT … ON CONFLICT DO UPDATE — preserves `created_at` and `introduction_method` |
| `UpdatePeerState(hex, state)` | Updates state + `updated_at` only |
| `GetPeer(hex)` | Returns `*PeerRecord` or nil |
| `AllActivePeers()` | WHERE state = 'active' |
| `AllPeers()` | All peers regardless of state |
| `SetOutboundPolicy(hex, []PolicyRule)` | Replaces all outbound rules for peer in a transaction |
| `SetInboundPolicy(hex, []PolicyRule)` | Replaces all inbound rules for peer in a transaction |
| `GetOutboundPolicy(hex)` / `GetInboundPolicy(hex)` | Returns rules in position order |
| `SetExportList(hex, []entityHex)` | Replaces all `remote_entities` rows for peer in a transaction |
| `GetExportList(hex)` | Returns `[]entityHex` exported to this peer; used by `sendFedPolicy` to populate `FedPolicy.exported_pubkeys` |
| `GetRemoteEntityMap()` | Returns `map[entityHex]peerHex`; hydrates the in-memory routing table at startup |
| `Close()` | Closes the DB connection |

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
| `internal/call` | 5 | Add/Peek/Remove round-trip, Peek non-destructive, Peek/Remove unknown, Expired removes only past-deadline, InvalidateTarget bulk-removes by target (AddFed path covered by S5 manager integration tests) |
| `internal/federation/calls` | 6 | AddOutbound/RemoveOutbound round-trip, non-destructive peek, remove unknown, ExpiredOutbound removes expired entries, cleanup before remove, pubkey copy-on-add |
| `internal/admin` | 6 | ListenAndServe rejects non-loopback, GET /schema returns built-ins, POST /schema registers subject, invalid base64, invalid JSON, body too large (413) |
| `internal/node` | 64 | 57 black-box integration tests (pub/sub, wildcards, schema rejection, ACL, entity events, offline detection, call round-trip/timeout/ACL, graceful shutdown, typed capabilities, delivery-time wildcard deny, system-event delivery deny, reconnect eviction, join-on-reconnect, responder verification, eviction invalidates calls, DISCONNECT teardown, monotonic DELIVER id, per-subject isolation, publisher identity stamped, timestamp populated, request caller identity, caller identity not spoofable, error ref_id, timeout error ref_id, resume restores subscriptions, token rotation prevents reuse, resume requires correct signature, resume token pubkey mismatch, expired token falls back, fresh connect unchanged, durable-replay hook no-op, **resume drops wholly-denied pattern** (M-5), runtime schema registration, custom range enforced, custom max_length enforced, additive version bump, breaking change rejected, cardinality change rejected, new required field rejected, admin localhost-only, admin GET schema, admin register schema); 7 white-box writer unit tests |
| `internal/transport/quic` | 15 | **Topology:** basic frame round-trip, bidirectional frames, ALPN isolation (wrong-ALPN client rejected), 5 concurrent dials. **Fault injection:** truncated mid-frame, cancelled-context dial, closed listener. **Race conditions:** keepalive round-trip, keepalive timeout, Stop+GotPong concurrent race, race with stream close. **E2E:** all 9 FED_* frame types round-trip, 256 KiB max payload, 256 KiB+1 overflow rejection, 20-frame sequencing, listener addr non-zero |
| `internal/federation/handshake` | 8 | Mutual auth (both pubkeys correct), known-peer flow, unknown-peer flow, bad signature → ErrInvalidSignature, wrong protocol version → ErrProtocolVersion + FED_REJECT, 200ms deadline fires without goroutine leak, stream close midway returns error, 3 concurrent handshakes same peer pubkey (race-detector clean) |
| `internal/federation/peer` | 4 | All legal transitions (Pending→Active→Paused→Active→Revoked + stream.Close called), illegal transitions from Revoked return ErrIllegalTransition/ErrAlreadyRevoked, 20 goroutines concurrent Pause/Resume (race-detector clean), Revoke while writing (no panic, write returns error) |
| `internal/federation/store` | 5 | Full round-trip (write peer + 3 outbound + 2 inbound rules + 5 export entities; close; reopen; verify all), bad path returns error, 10 concurrent UpsertPeer goroutines (no SQLITE_BUSY), persist+restart (2 active peers + entity maps survive close/reopen), revoked peer absent from AllActivePeers |
| `internal/federation/policy` | 7 | DenyByDefault, FirstMatchForward, FirstMatchAccept, ExactMatch, GtWildcard, SetRules atomic replace, Rules snapshot immutability |
| `internal/federation/manager` | 39 | **Topology (S3):** Start dials 2 active peers, HandleIncoming known-active sends FedPolicy, HandleIncoming known-paused skips FedPolicy, HandleIncoming unknown stores as pending, HandleIncoming revoked sends FedReject. **Admin lifecycle (S3):** pair→accept→pause→resume→revoke via HTTP (201/204/409). **Fault injection (S3):** dial unreachable, stream drop resets to pending, Stop() during dial. **Admin validation (S3):** invalid hex → 400, accept non-pending → 409. **Race/concurrency (S3):** concurrent AcceptPeer+RejectPeer, 3 concurrent HandleIncoming from same peer, 10 Pause/Resume rounds, Stop with 4 active peers. **E2E (S3):** GetConnections policy counts. **S4 forwarding (9 tests):** deny-by-default (no outbound rule), single forward rule delivers FedDeliver, non-matching subject not forwarded, inbound accept calls FederatedPublish, inbound deny drops frame, SchemaDescriptor on first forward only (tracker key), schema auto-registered on inbound FedDeliver, UpdatePolicy refreshes in-memory engine, concurrent ForwardIfNeeded schema tracker race. **S5 call routing (12 tests):** TryRouteRequest false for unknown target, TryRouteRequest sends FED_REQUEST to correct peer, UpdateExportList add wires routing, UpdateExportList remove stops routing, inbound FED_REQUEST dispatches to RouteLocalRequest hook, inbound FED_RESPONSE dispatches to RouteLocalResponse with correct requesterSID, ForwardResponse sends FED_RESPONSE to peer, ForwardResponse for unknown peer no-panic, expired outbound calls trigger SendLocalError(TIMEOUT), inbound FedPolicy updates routing table and SQLite, sendFedPolicy includes exported pubkeys, export list persisted and in-memory consistent, 10 concurrent TryRouteRequest goroutines (race-detector clean) |
| **Total** | **245** | |

The `TestIntegrationSequence` test covers all 10 steps of the full integration scenario in a single sequential test with per-step log output.

---

## v0.2 Cross-Federation Call Routing (Session 5)

Session 5 makes point-to-point calls (REQUEST/RESPONSE) transparent across federation boundaries. From the calling entity's perspective, a cross-federation call is identical to a local call — same frame types, same timeout semantics.

### High-level flow

```
Node A (requester entity X)          Node B (target entity Y)

X sends REQUEST{target=Y.pub}
    │
    ▼ node.handleRequest (Node A)
    ├─ CallerIdentity / ReceivedAt stamped BEFORE registry.Get
    ├─ registry.Get(Y.pub) → nil (Y not local)
    ├─ fedManager.TryRouteRequest(req, X.sessionID)
    │       ├─ remoteEntities.Load(hex(Y.pub)) → peerHex = B
    │       ├─ fedCalls.AddOutbound(corrID, X.sessionID, B.pubkey, deadline)
    │       └─ pc.SendData(FED_REQUEST{corrID, target, payload, callerIdentity,
    │                                   receivedAt, timeoutMs})
    │
    │  (QUIC stream A→B)
    │
    ▼ runPeerReadLoop → handleInboundFrame (Node B)
    └─ handleInboundRequest
           └─ nodeHooks.RouteLocalRequest(corrID, Y.pub, payload,
                  callerIdentity, receivedAt, timeoutMs, A.pubkey)
                   │
                   ▼ node.Server.RouteLocalRequest (Node B)
                   ├─ registry.Get(Y.pub) → Y's EntityRecord
                   ├─ calls.AddFed(corrID, Y.sessionID, A.pubkey, deadline)
                   └─ targetSw.enqueue(REQUEST, req)
                           │
                           ▼ Y receives REQUEST (same as local)

Y sends RESPONSE{corrID, payload}
    │
    ▼ node.handleResponse (Node B)
    ├─ calls.Peek / Verify / calls.Remove → PendingCall{FedSourcePeerPubkey=A.pubkey}
    ├─ FedSourcePeerPubkey != nil → fedManager.ForwardResponse(corrID, payload, A.pubkey)
    │       └─ pc.SendData(FED_RESPONSE{corrID, payload})
    │
    │  (QUIC stream B→A)
    │
    ▼ runPeerReadLoop → handleInboundFrame (Node A)
    └─ handleInboundResponse
           ├─ fedCalls.RemoveOutbound(corrID) → OutboundCall{RequesterLocalSID=X.sessionID}
           └─ nodeHooks.RouteLocalResponse(corrID, payload, X.sessionID)
                   └─ node.Server.RouteLocalResponse
                           └─ requesterSw.enqueue(RESPONSE, payload)
                                   │
                                   ▼ X receives RESPONSE (same as local)
```

### `internal/federation/calls/calls.go` (new package)

Tracks outbound cross-federation calls by correlation ID.

```go
type OutboundCall struct {
    RequesterLocalSID string    // session ID of the local requester on this node
    TargetPeerPubkey  []byte    // peer that the request was forwarded to
    Deadline          time.Time
}

type Registry struct {
    mu       sync.Mutex
    outbound map[string]*OutboundCall
}
```

- `AddOutbound(corrID, requesterSID, peerPubkey, deadline)` — registers an outbound call; copies peerPubkey defensively.
- `RemoveOutbound(corrID)` — removes and returns the entry; nil if not found.
- `ExpiredOutbound(now)` — removes and returns all entries past deadline; used by `runFedCallTimeoutChecker`.

### S5 additions to `internal/federation/manager/manager.go`

**New Manager fields:**
- `remoteEntities sync.Map` — `entityHex → peerHex` routing table. Populated at `Start()` from SQLite via `store.GetRemoteEntityMap()` and updated on every `UpdateExportList` call and inbound `FED_POLICY` frame.
- `fedCalls *fedcalls.Registry` — outbound call registry. Initialized in `New()`.
- `stopOnce sync.Once` — makes `Stop()` idempotent (safe to call multiple times).

**`TryRouteRequest(req *pb.Request, requesterSID string) bool`**
1. Looks up `hex(req.TargetPubkey)` in `remoteEntities` → peerHex.
2. Returns false immediately if not found (caller falls through to local `NOT_FOUND` error).
3. Loads the active `*peer.PeerConn`; returns false if peer not active.
4. Registers outbound call in `fedCalls`.
5. Marshals `FedRequest{corrID, targetPubkey, payload, callerIdentity, receivedAt, timeoutMs, requesterNodePub}` and enqueues via `pc.SendData`. Returns true.

**`handleInboundRequest(pc, peerHex, *pb.FedRequest)`**
- Dispatches via `nodeHooks.RouteLocalRequest(corrID, targetPubkey, payload, callerIdentity, receivedAt, timeoutMs, pc.PeerPubkey())`.
- The hook implementation in `node.Server` calls `calls.AddFed` (not `calls.Add`) so the RESPONSE path knows to call `ForwardResponse` rather than a local session write.

**`handleInboundResponse(peerHex, *pb.FedResponse)`**
- Calls `fedCalls.RemoveOutbound(corrID)` to get `RequesterLocalSID`.
- Calls `nodeHooks.RouteLocalResponse(corrID, payload, requesterSID)`.

**`ForwardResponse(corrID string, payload []byte, peerPubkey []byte)`**
- Marshals `FedResponse{corrID, payload}`; enqueues via `pc.SendData` to the peer identified by `hex(peerPubkey)`.
- Logs a warning (no panic) if the peer is not found or no longer active.

**`handleInboundPolicy(pc, peerHex, *pb.FedPolicy)`**
- New handler for `FED_POLICY` frames received from peers.
- Extracts `pol.ExportedPubkeys`, hex-encodes each, calls `store.SetExportList(peerHex, entityHexes)` to persist.
- Updates `remoteEntities` sync.Map: clears old entries for this peer, stores new ones.
- Also updates `outPolicies`/`inPolicies` if the FedPolicy contains subject rules (future-proofing).

**`sendFedPolicy` with `ExportedPubkeys`**
- Now calls `store.GetExportList(peerHex)` and hex-decodes each entity pubkey before attaching to `FedPolicy.exported_pubkeys`.
- This means peers receive the local node's export list on activation, hydrating their routing table.

**`runFedCallTimeoutChecker()` goroutine**
- Ticks every 1 second.
- Calls `fedCalls.ExpiredOutbound(now)` and for each expired call: `nodeHooks.SendLocalError(requesterSID, "TIMEOUT", "...", corrID)`.
- Goroutine is wg-tracked; exits when `m.done` is closed.

### S5 additions to `internal/node/node.go`

**`handleRequest` — stamp before routing:**
```
CallerIdentity and ReceivedAt are stamped BEFORE registry.Get, so TryRouteRequest
forwards already-stamped values to the peer node.
```

**Federation fallback in `handleRequest`:**
```go
if targetEnt == nil {
    if s.fedManager != nil {
        if routed := s.fedManager.TryRouteRequest(&req, rec.ID); routed { return }
    }
    s.sendError(sw, "NOT_FOUND", "target entity not connected")
    return
}
```

**`handleResponse` — cross-federation return path:**
```go
if len(pending.FedSourcePeerPubkey) > 0 {
    if s.fedManager != nil {
        s.fedManager.ForwardResponse(resp.CorrelationId, resp.Payload, pending.FedSourcePeerPubkey)
    }
    return
}
// else: local path (unchanged)
```

**New `NodeHooks` method implementations:**
- `RouteLocalRequest` — finds entity in local registry, calls `calls.AddFed`, enqueues REQUEST to target session writer.
- `RouteLocalResponse` — finds requester session writer by ID, enqueues RESPONSE frame.
- `SendLocalError` — finds session writer by ID, enqueues ERROR frame via `enqueueControl`.

### `FedPolicy.exported_pubkeys` field

`FedPolicy` (frame type 19) now carries `repeated bytes exported_pubkeys` — the list of local entity pubkeys reachable via this node. Peers hydrate their `remoteEntities` routing table from this field on activation and on every subsequent `FED_POLICY` frame.

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

internal/wire                       ──► proto/
internal/identity                      (stdlib only)
internal/session                       (stdlib only)
internal/registry                      (stdlib only)
internal/call                          (stdlib only)
internal/acl                        ──► internal/bus
internal/transport/quic (v0.2)      ──► internal/transport (interfaces)
                                    ──► internal/wire (wire.Write/Read for keepalive)
                                    ──► proto/ (FrameType_FRAME_TYPE_PING)
                                    ──► github.com/quic-go/quic-go v0.60.0
internal/federation/handshake (v0.2) ──► internal/transport (Stream interface)
                                    ──► internal/wire (Read/Write)
                                    ──► proto/ (FedHello, FedHelloAck, FedReject)
internal/federation/peer (v0.2)     ──► internal/transport (Stream interface)
internal/federation/store (v0.2)    ──► modernc.org/sqlite v1.52.0
internal/federation/policy (v0.2 S4) ──► internal/bus (Match for wildcard evaluation)
internal/federation/manager (v0.2)  ──► internal/federation/handshake
                                    ──► internal/federation/peer
                                    ──► internal/federation/policy  (S4)
                                    ──► internal/federation/store
                                    ──► internal/transport (Dialer/Listener/TLSExporter)
                                    ──► internal/wire (Read/Write)
                                    ──► internal/schema (NodeHooks.SchemaRegistry, Descriptor)
                                    ──► proto/ (FED_* frame types)
                                    ──► google.golang.org/protobuf/types/descriptorpb  (S4 extractMsgName)
cmd/lattice-node (S3)               ──► internal/federation/manager
                                    ──► internal/admin (SetFederationManager)
```

No import cycles. `proto/` and `internal/transport` are leaves. `internal/federation/manager` does NOT import `internal/node` — the `NodeHooks` interface inverts the dependency direction. `internal/federation/manager` imports `node` only via the `NodeHooks` interface (no direct import of `internal/node`) — the dependency is inverted through the interface.

---

## v0.2 Federation Manager + Bilateral Consent (Session 3)

### `internal/federation/manager/manager.go`

`Manager` owns the full federation lifecycle: dialing active peers on startup, accepting incoming connections, routing bilateral consent state changes, and exposing policy/export configuration.

**`NodeHooks` interface** — callbacks from the manager into the node layer:
```go
type NodeHooks interface {
    FederatedPublish(subject string, payload []byte, publisherPubkey []byte)
    SchemaRegistry() *schema.Registry
    // S5: cross-federation call routing
    RouteLocalRequest(corrID string, targetPubkey []byte, payload []byte,
        callerIdentity string, receivedAt int64, timeoutMs uint32, sourcePeerPubkey []byte)
    RouteLocalResponse(corrID string, payload []byte, requesterSessionID string)
    SendLocalError(sessionID, code, message, refID string)
}
```
`node.Server` implements this interface. The manager holds it as a `NodeHooks` interface value — zero coupling to the concrete `node.Server` type.

**`ConnectionInfo`** — returned by `GetConnections()`:
```go
type ConnectionInfo struct {
    PubkeyHex     string `json:"pubkey_hex"`
    Name          string `json:"name"`
    Addr          string `json:"addr"`
    State         string `json:"state"`
    OutboundRules int    `json:"outbound_rules"`
    InboundRules  int    `json:"inbound_rules"`
}
```

**Key Manager methods:**

| Method | Description |
|--------|-------------|
| `New(localPriv, store, dialer, listener, nodeHooks, log)` | Constructor |
| `Start()` | Dials all active/paused peers from store; starts accept loop goroutine |
| `Stop()` | Cancels context; calls `Revoke` on all in-memory peers; closes listener; `wg.Wait()` |
| `HandleIncoming(stream)` | FedHello handshake + dispatch by DB state |
| `PairPeer(hex, name, addr)` | Stores peer as "pending"; error if already known |
| `AcceptPeer(hex)` | pending → active in DB; starts `connectPeerWithRetry` goroutine |
| `RejectPeer(hex)` | Deletes pending peer from store (and child rows) |
| `PausePeer(hex)` | Active → Paused in DB + PeerConn; sends `FED_STATUS{paused}` |
| `ResumePeer(hex)` | Paused → Active in DB + PeerConn; sends `FED_POLICY` |
| `RevokePeer(hex)` | Sends `FED_STATUS{revoked}`; calls `pc.Revoke()`; deletes from map; updates DB |
| `UpdatePolicy(hex, out, in)` | Replaces outbound + inbound policy rules in DB |
| `UpdateExportList(hex, entityHexes)` | Replaces exported entity pubkeys in DB and in-memory `remoteEntities` routing table |
| `GetConnections()` | Joins in-memory peer state with DB policy counts |
| `TryRouteRequest(req, requesterSID)` | S5: looks up `req.TargetPubkey` in `remoteEntities`; if found, sends FED_REQUEST to the owning peer and records the outbound call in `fedCalls`; returns true on success |
| `ForwardResponse(corrID, payload, peerPubkey)` | S5: sends FED_RESPONSE to the peer identified by `peerPubkey`; used by `node.handleResponse` when `PendingCall.FedSourcePeerPubkey` is set |

**`HandleIncoming` dispatch logic:**

| DB state of peer | Action |
|-----------------|--------|
| `"active"` | `getOrCreatePeer` → `pc.Activate(stream)` (reject concurrent with `FED_REJECT`); `sendFedPolicy`; `runPeerReadLoop(resetOnDrop=true)` |
| `"paused"` | Same as active but NO `sendFedPolicy` — peer is paused, keep stream open silently |
| `"revoked"` | Write `FED_REJECT{reason:"revoked"}` + close stream |
| `nil` / `"pending"` | `UpsertPeer` as pending; write `FED_PENDING{introductionId=hex[:8]}`; close stream |

**Bilateral consent flow (A accepts B, B dials back A):**
1. A operator calls `PairPeer(B)` → B stored as `"pending"` in A's DB.
2. A operator calls `AcceptPeer(B)` → B promoted to `"active"` in A's DB; A starts `connectPeerWithRetry(B, resetOnDrop=false)`.
3. A dials B. B's `HandleIncoming` sees A as unknown → sends `FED_PENDING` → closes stream.
4. `connectPeerWithRetry` exits (stream closed) but does NOT reset B to "pending" in A's DB (because `resetOnDrop=false`).
5. B operator calls `PairPeer(A)` + `AcceptPeer(A)`. B dials A.
6. A's `HandleIncoming` sees B as `"active"` → calls `pc.Activate(stream)` → `sendFedPolicy` → both nodes are now in `StateActive`.

**`consentMu sync.Mutex`** — serializes all consent state transitions (AcceptPeer, RejectPeer, PausePeer, ResumePeer, RevokePeer, UpdatePolicy, UpdateExportList) to prevent TOCTOU races like concurrent AcceptPeer+RejectPeer.

**`TLSExporter` interface** — added to `internal/transport/transport.go`:
```go
type TLSExporter interface {
    ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}
```
QUIC streams (`quicStream`, `lazyServerStream`) implement it via `conn.ConnectionState().TLS.ExportKeyingMaterial(...)` (local variable assignment required — `tls.ConnectionState` has pointer receiver in Go 1.21+). `deriveNonce` type-asserts the stream to `TLSExporter`; falls back to zero slice for non-QUIC streams (test doubles).

**`connectPeerWithRetry`** — exponential backoff (1s base, 60s cap) with `select` on `m.done` so `Stop()` cancels all retry loops immediately.

**`getOrCreatePeer`** — uses `sync.Map.LoadOrStore` atomically; handles stale Revoked entries via `CompareAndDelete`.

**`store.DeletePeer(hex)`** — added to `fedstore.Store` (S3); deletes child rows (`federation_outbound_policy`, `federation_inbound_policy`, `remote_entities`) then the peer row in a single transaction.

### `cmd/lattice-node/main.go` — federation flags (S3)

Two new flags:
- `--fed-addr ""` — QUIC federation listen address; empty = federation disabled.
- `--fed-db "./fed.db"` — SQLite database path for federation peer state.

When `--fed-addr` is non-empty, `main` creates a QUIC listener, opens the SQLite store, creates the Manager, calls `Start()`, and wires it to both `node.Server` (`SetFederationManager`) and `admin.Server` (`SetFederationManager`). `Stop()` is called in the SIGINT/SIGTERM handler before `srv.Shutdown()`.

---

## v0.2 Forwarding Policy Engine + Schema Propagation (Session 4)

### `internal/federation/policy/engine.go`

First-match forwarding policy engine used by the Manager to decide cross-peer message routing.

```go
type Effect int
const (
    EffectDeny    Effect = iota // no rule matches → deny (default)
    EffectForward               // outbound: message should cross to this peer
    EffectAccept                // inbound: message should be delivered locally
)

type Rule struct {
    SubjectPattern string
    Effect         Effect
}

type Engine struct {
    mu    sync.RWMutex
    rules []Rule
}
```

- `NewEngine(rules)` — creates Engine with initial rule set (copied).
- `Empty()` — Engine with no rules (deny all).
- `Evaluate(subject)` — returns Effect of first rule whose `SubjectPattern` matches `subject` using `bus.Match` semantics (`*`/`>` wildcards). Returns `EffectDeny` on no match.
- `SetRules(rules)` — atomically replaces all rules (thread-safe).
- `Rules()` — returns a snapshot copy (mutations don't affect the engine).

### S4 additions to `internal/federation/manager/manager.go`

**New Manager fields:**
- `outPolicies sync.Map` — `peerHex → *fedpolicy.Engine` (outbound forwarding rules). Loaded from SQLite on peer activation and on every `UpdatePolicy` or `UpdateExportList` call.
- `inPolicies sync.Map` — `peerHex → *fedpolicy.Engine` (inbound acceptance rules). Same lifecycle as `outPolicies`.
- `schemaTracker sync.Map` — key: `peerHex+":"+subject` → `struct{}`. Ensures `SchemaDescriptor` is sent at most once per peer per subject. Uses `sync.Map.LoadOrStore` atomically.

**`loadPolicies(peerHex)`** — reads outbound and inbound rules from SQLite, builds `*fedpolicy.Engine` objects, stores them in `outPolicies`/`inPolicies`. Called on activation and after `UpdatePolicy`/`UpdateExportList` to keep in-memory engines fresh without hitting SQLite on the hot forwarding path.

**`ForwardIfNeeded(subject, payload, publisherPubkey []byte)`** — called by `node.Server.handlePublish` after every successful local fanout (nil-guarded: no-op when federation is disabled). Algorithm:
1. Base32-encode `publisherPubkey` for `FedDeliver.publisher_identity`.
2. `peers.Range` over all active peers.
3. For each active peer: load `outPolicies`; if `Evaluate(subject) != EffectForward`, skip.
4. Check `schemaTracker.LoadOrStore(peerHex+":"+subject, struct{}{})` — if not loaded, attach `SchemaDescriptor = nodeHooks.SchemaRegistry().Descriptor(subject)` to the frame (nil for built-ins → no descriptor).
5. `proto.Marshal` the `FedDeliver` frame; `pc.SendData` (non-blocking); log drop if full.

**`handleInboundDeliver(pc, peerHex, *pb.FedDeliver)`** — dispatched by `handleInboundFrame` on `FED_DELIVER` frames:
1. Load `inPolicies` for `peerHex`; if `Evaluate(subject) != EffectAccept`, drop.
2. If `SchemaDescriptor` is present and `reg.Version(subject) == 0`: call `extractMsgName(fdBytes)` and `reg.Register(subject, msgName, fdBytes)` to auto-register the schema.
3. Call `nodeHooks.FederatedPublish(subject, payload, pc.PeerPubkey())` → fans out locally.

**`extractMsgName(fdBytes []byte) string`** — unmarshals `FileDescriptorProto` via `proto.Unmarshal`, returns `fdProto.MessageType[0].Name` (the first top-level message). Returns `""` on any error.

**`sendFedPolicy(pc *peer.PeerConn, peerHex string) error`** — changed from taking `transport.Stream` to taking `*peer.PeerConn`. Now uses `pc.SendCtrl` (enqueues to ctrl channel) instead of `wire.Write` (direct stream write). FedStatus frames (pause/revoke signals) remain direct writes to preserve send-before-close ordering.

**`runPeerWriteLoop(pc, peerHex, resetOnDrop)`** — Manager-tracked wrapper for `pc.RunWriteLoop`. `onWriteError` calls `dropPeer(peerHex, resetOnDrop)`.

**`dropPeer(peerHex, resetOnDrop)`** — idempotent cleanup: `peers.Delete(peerHex)`, optionally resets DB state to `"pending"`. Called from both read loop (stream error) and write loop (write error) — `sync.Map.Delete` and `store.UpdatePeerState` are both safe to call multiple times.

### S4 node.go change

Single nil-guarded call added in `handlePublish` after `s.fanout(...)`:
```go
if s.fedManager != nil {
    s.fedManager.ForwardIfNeeded(msg.Subject, msg.Payload, rec.Pubkey)
}
```

### Message flow with federation (S4)

```
Local entity PUBLISH "sensors.temperature"
    │
    ▼  node.handlePublish
    │
    ├─ ValidateSubject / ACL / schema.Validate / s.fanout  (unchanged)
    │
    └─ s.fedManager.ForwardIfNeeded("sensors.temperature", payload, pubkey)
           │
           ▼  peers.Range
           for each active peer:
               outPolicies[peer].Evaluate(subject)   == EffectForward?
               yes → build FedDeliver { subject, payload, publisher_identity, published_at }
                         if first time subject→peer: attach SchemaDescriptor
                         pc.SendData(FED_DELIVER, marshaled)  (non-blocking; drops if full)

Peer sends FED_DELIVER to us:
    │
    ▼  runPeerReadLoop → handleInboundFrame → handleInboundDeliver
    │
    ├─ inPolicies[peer].Evaluate(subject)   == EffectAccept?
    ├─ if SchemaDescriptor present and subject unregistered: auto-register schema
    └─ nodeHooks.FederatedPublish(subject, payload, peerPubkey)
           └─ node.FederatedPublish → s.fanout(subject, payload, peerPubkey)
```
