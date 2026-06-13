# Lattice v0.1.1 — Implementation Roadmap

**Scope:** Decisions 1–18 from the CTO Architecture Review (June 2026) · **Status: In progress** · **Target: v0.1.1**

This document is the single source of truth for the v0.1.1 hardening work. All sessions are implemented on a single branch: **`dev/0.1.1-hardening`**. Check off decisions as they land. Merge to `main` only when **all sessions** are complete and all tests pass.

---

## Coverage Map

All 18 decisions accounted for. Decision #13 (QUIC port) is explicitly deferred.

**Working branch:** `dev/0.1.1-hardening` (all sessions)

| Session | Decisions | Theme | Risk | Status |
|---------|-----------|-------|------|--------|
| 0 | — | Pre-flight: key hygiene + proto toolchain | Low | `[x]` |
| 1 | #1, #3, #7, #9, #17 | Handshake & identity hardening | **High** | `[x]` |
| 2 | #10 | Bus flow control — per-session writer queues | **Highest** | `[x]` |
| 3 | #11 | ACL correctness — delivery-time check + rule cache | **High** | `[x]` |
| 4 | #12, #6, #8 | Session lifecycle correctness | Med | `[ ]` |
| 5 | #4, #18, #5 | Message provenance & correlation envelopes | Med | `[ ]` |
| 6 | #2 | Token-based session resume | Med | `[ ]` |
| 7 | #14, #15, #16 | Dynamic schema registry + admin API | Med/Large | `[ ]` |

**Deferred (post-v0.1.1):** #13 QUIC port, federation, durable messages, libp2p DHT.
**Sequencing constraint to carry forward:** Session 2 (writer queues) must be complete before QUIC is started. The per-session outbound queue maps directly onto per-stream writes in quic-go — porting blocking fanout onto QUIC forfeits the head-of-line-blocking benefit.

---

## Ordering Rationale

The session order mirrors the CTO decision-queue dependency ranking:
- **#1 auth → #2 writer-queue → #3 ACL subsumption → #4 envelope** — each blocks everything below it.
- #1/#3/#7 are all wire-breaking changes to the HELLO message — batched in one session to touch `proto/frames.proto` and `internal/handshake/handshake.go` exactly once.
- #10 (writer queues) reshapes every outbound write path in `internal/node/node.go`. Sessions 3, 4, and 5 all modify the fanout/delivery path — they must be written against the final writer architecture, not the old `lockedConn` shape.
- #6↔#12 are explicitly coupled in the decisions amendments: CAS eviction (session 4) must also invalidate pending calls targeting the evicted session. They land in the same session.
- #16 depends on the `schema_version` field introduced by #4 (session 5). The schema cluster (session 7) comes after envelopes.
- #2 session resume is additive. It depends on a stable handshake (session 1) and a correct session/registry layer (session 4) and can therefore be its own late session.

---

## Global Definition of Done

Every session must pass before merge:

```
go build ./...
go test ./...
go test -race ./internal/node/...
```

Plus the session-specific new tests listed below.

---

## Session 0 — Pre-flight

**Branch:** `dev/0.1.1-hardening`

### Decisions
- [x] Verify `*.key` absent from git history: `git rev-list --all --objects | grep -i '\.key'` must produce zero output. `.gitignore` already contains `*.key` (confirmed in v0.1).
- [x] Document TOFU exposure: the first connection to a node is trust-on-first-use — the server pubkey is not independently verified on first pairing. This must be called out in `DEV.md` so operators understand what first-pairing means.
- [x] Install `protoc-gen-go` at the version matching the existing generated files: `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11`. Confirm `protoc --version` ≥ 3 (already installed at `/opt/homebrew/bin/protoc`).
- [x] Add a codegen script or `Makefile` target so every subsequent session can regenerate `*.pb.go` with one command. Pin to `protoc-gen-go v1.36.11` to keep generated output reproducible.

### Files to Create/Modify
| File | Change |
|------|--------|
| `scripts/gen-proto.sh` (new) | Shell script that runs `protoc` for all three `.proto` files |
| `Makefile` (new) | `make proto` target invoking the script; `make test` for full suite |
| `DEV.md` | Add "Proto regeneration" section; add TOFU/first-pairing security note |

### Test Plan
- `go build ./...` still green after script is added.
- `go test ./...` green (no source changes, just tooling).
- Run `make proto` → `git diff proto/` must produce zero diff (toolchain reproduces current output identically). This proves the pinned version is correct.

---

## Session 1 — Handshake & Identity Hardening

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 0 complete (codegen tooling in place).

### Decisions

- [x] **#1 — Server authentication in HELLO handshake**
  The server currently sends `HELLO_ACK { server_pubkey }` as an unsigned assertion — any process that terminates TLS can assert any identity. Fix: server derives a *separate* 32-byte nonce via `ExportKeyingMaterial("lattice-hello-server-v1", nil, 32)` and signs it with its Ed25519 private key. This signature is added to `HelloAck`. The client verifies it against the pinned server pubkey. `InsecureSkipVerify` stays — the TLS certificate is not the trust anchor, the Ed25519 signature is. The two exporter labels (`"lattice-hello-v1"` for the client nonce, `"lattice-hello-server-v1"` for the server nonce) are intentionally distinct so the same bytes are never signed in both directions.

- [x] **#3 — Protocol version field**
  Add `uint32 protocol_version = N` to the `Hello` proto message. Server rejects connections with an unrecognised major version (send `ERROR { code: "UNSUPPORTED_VERSION" }` and close). Version lives in `Hello` only — the 5-byte frame header is stable and does not need a version field.

- [x] **#7 — Typed capabilities**
  Change `repeated string capabilities` in `Hello` to `repeated Capability capabilities` where `Capability` is a new proto message. Start with the minimum fields required now. Future Entity Description extensions go into `Capability` without breaking the wire. All code that touches `rec.Capabilities` / `ent.Capabilities` must be updated to use the new type.

- [x] **#9 — Mark PING/PONG reserved**
  Add proto comments marking `FRAME_TYPE_PING` and `FRAME_TYPE_PONG` as reserved in `frames.proto`. No implementation, no handler. External developers must not build against them.

- [x] **#17 — Handshake deadline**
  In `HandleConn`, call `conn.SetDeadline(time.Now().Add(10 * time.Second))` immediately before the `handshake.DoServer` call. Clear the deadline with `conn.SetDeadline(time.Time{})` after a successful `HELLO_ACK` is sent. A client that completes TLS and never sends `HELLO` currently holds a goroutine forever — the heartbeat checker cannot reap it because nothing pre-HELLO is in the registry.

### Files to Modify
| File | Change |
|------|--------|
| `proto/frames.proto` | Add `server_signature` to `HelloAck`; add `protocol_version` to `Hello`; add `Capability` message; replace `repeated string` with `repeated Capability`; mark PING/PONG reserved in comments |
| `proto/frames.pb.go` | Regenerated via `make proto` |
| `internal/handshake/handshake.go` | Server: derive server nonce + sign + populate `server_signature`; client: verify `server_signature` against pinned pubkey; both: send/check `protocol_version`; update caps type |
| `internal/node/node.go` | `HandleConn`: add deadline before/after handshake; update all `rec.Capabilities` usages to typed `Capability` |
| `internal/registry/registry.go` | `EntityRecord.Capabilities` → `[]*pb.Capability` |
| `internal/session/session.go` | `Record.Capabilities` → `[]*pb.Capability` |
| `cmd/lattice-client/main.go` | Send `protocol_version`; add `--server-key` flag for pinning (or read from a side-channel like a `.pin` file); verify server signature |
| `cmd/lattice-node/main.go` | (Minor: flag for pinning / no structural change expected) |

### Test Plan (new tests on top of existing 6 + 35)
| Test | Asserts |
|------|---------|
| Server-sig verify success | Client completes handshake when server signs correctly |
| Forged server signature | Client rejects `HELLO_ACK` with wrong/missing `server_signature` |
| Pin mismatch | Client rejects valid signature from a different server identity |
| Unknown `protocol_version` | Server sends `ERROR UNSUPPORTED_VERSION` and closes |
| Typed capabilities round-trip | `Capability` fields survive `Hello` → `HelloAck` → `EntityJoined` event |
| Handshake deadline | A client that connects but never sends `HELLO` is reaped within ~10s |
| Regression | All existing `internal/handshake` (6) and `internal/node` (35) tests green |

---

## Session 2 — Bus Flow Control

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 1 complete.

### Decision

- [x] **#10 — Per-session writer queues with slow-consumer policy**
  Replace the synchronous `lockedConn.writeFrame` (which blocks on the publisher's goroutine holding a mutex) with a per-session bounded outbound channel drained by a dedicated writer goroutine. Fan-out enqueues a pre-serialised frame and returns immediately. Details:
  - **Write deadline:** 5 seconds on every `wire.Write` call. Exceeded → disconnect + publish `entity.offline`.
  - **Slow-consumer policy by subject class:**
    - *Ephemeral subjects:* drop on overflow, log the drop.
    - *Durable subjects (future):* drop and record the gap so the subscriber can replay on reconnect. Stub this path for v0.1.1 — the mechanism must exist even if durable messages are not implemented yet.
  - **Control-frame priority lane:** `HEARTBEAT_ACK`, `ERROR`, and `HELLO_ACK` must never be dropped under `DELIVER` congestion. A congested client that misses `HEARTBEAT_ACK`s will conclude the server is dead and reconnect, worsening congestion. Implement a reserved-slot guarantee or a separate high-priority channel in the writer queue.
  - The `Shutdown` drain must wait for all writer goroutines to flush and exit.

  **Why this is the highest-risk session:** this change replaces every outbound write path in the server. Fan-out, system events, REQUEST/RESPONSE forwarding, heartbeat acks, and error delivery all flow through the writer. The race detector is mandatory.

### Files to Modify
| File | Change |
|------|--------|
| `internal/node/node.go` | Replace `lockedConn` with new writer type; update `fanout`, `publishSystemEvent`, `handleRequest`, `handleResponse`, `markOffline`, `runCallTimeoutChecker`, `Shutdown`; add write-deadline logic |
| `internal/node/writer.go` (new, recommended) | `sessionWriter` struct: channel, goroutine, `enqueue(frameType, payload)`, `enqueueControl(...)`, `close()` |

### Test Plan
| Test | Asserts |
|------|---------|
| Slow consumer does not wedge bus | Publisher and other subscribers proceed normally while one subscriber's channel is full |
| Control frames under backpressure | `HEARTBEAT_ACK` delivered even when DELIVER queue is saturated |
| Overflow → disconnect | Slow consumer is disconnected and `entity.offline` is published on queue overflow |
| Write deadline | Simulated TCP stall triggers disconnect within ~5s |
| Graceful shutdown drain | `Shutdown()` waits for writer goroutines to flush; no writes after conn close |
| Race detector | `go test -race ./internal/node/...` clean |
| Regression | All existing `internal/node` (35) tests green |

---

## Session 3 — ACL Correctness

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 2 complete.

### Decision

- [x] **#11 — Delivery-time ACL check + subscribe-time subsumption**
  The current bug: subscribe-time ACL calls `bus.Match(rule.SubjectPattern, subscriptionPattern)` where `subscriptionPattern` is itself a wildcard pattern. A subscription to `home.>` does not string-match a deny rule on `home.private.>`, so the deny is silently skipped. There is no delivery-time re-check, so the subscriber receives every `home.private.*` message.

  **Two-layered fix:**
  1. **Subscribe-time subsumption:** reject a subscription pattern if any higher-priority deny rule's pattern *intersects* it. A subscription is safe only if every concrete subject it can match is permitted. Intersection over `*` and `>` is a small decidable function — walk segments pairwise, `*` intersects any single-segment, `>` intersects any suffix of equal or greater length. Implementation goes in `internal/bus/subject.go` or a new `intersection.go` alongside it.
  2. **Delivery-time check:** before every `DELIVER`, check the concrete subject against the subscriber's ACL rules. If a deny rule matches, skip that subscriber silently (do not send ERROR to the subscriber — the publisher has already been permitted). This check runs per-subscriber per-DELIVER, so an **identity-indexed rule cache** (invalidated on `AddRule`) is required. Without the cache, the per-message cost is O(rules) per subscriber, which is not acceptable.
  3. **System events:** `publishSystemEvent` currently bypasses ACL entirely. Route it through the delivery-time check — a deny rule on `lattice.system.>` for a specific identity must be honoured.

### Files to Modify
| File | Change |
|------|--------|
| `internal/acl/acl.go` | Add `Intersects(patternA, patternB string) bool` helper; add identity-indexed rule cache (`map[string][]Rule`, invalidated on `AddRule`); add `AllowConcrete(pubkey, action, subject)` cached path for delivery-time calls |
| `internal/bus/subject.go` | Export the pattern-intersection logic (or place it in `acl.go` — keep whichever avoids an import cycle) |
| `internal/node/node.go` | `handleSubscribe`: add subsumption check after `bus.Subscribe`; `fanout` + `publishSystemEvent`: add delivery-time ACL check per subscriber (session→pubkey lookup via `sessions.ByID`) |

### Test Plan
| Test | Asserts |
|------|---------|
| Wildcard bypass fixed | `allow home.> p10`, `deny home.private.> p100` — subscriber on `home.>` does NOT receive `home.private.sensor` |
| Subscribe-time subsumption | Subscribing to `home.private.>` when it is wholly denied is rejected at subscribe time |
| Exact-pattern subscribe still works | A subscription fully within an allow rule is accepted |
| System-event deny honoured | `deny lattice.system.> p100` for identity X — X does not receive `entity.joined` events |
| Cache invalidation | Adding a new deny rule via `AddRule` immediately takes effect on the next `DELIVER` |
| Existing `acl` suite (7) | All existing tests green |
| Existing `node` suite (35) | All existing tests green (ACL allow paths unchanged) |

---

## Session 4 — Session Lifecycle Correctness

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 3 complete.

### Decisions

- [ ] **#12 — Same-identity reconnect: compare-and-swap registry remove**
  The current race: entity K connects (S1), network blips, K reconnects (S2) before the server detects S1 dead. Registry maps K→S2. S1's read loop then errors; its `defer` calls `registry.Remove(K)` which deletes S2's record and publishes `entity.left`. S2 is still connected but invisible to heartbeat tracking, call routing, and system events.

  Fix: `registry.Remove(pubkey, sessionID string)` becomes a compare-and-swap — only deletes if `record.SessionID == sessionID`. S1's defer calls `Remove(K, S1)`, finds S2 in the registry, and does nothing.

  On new `HELLO` from an already-active pubkey: evict the old session silently (no `entity.left` — the new join supersedes it), register the new session, publish a single `entity.joined`. Document that `entity.joined` is at-least-once and does not imply a prior disconnection.

- [ ] **#6 — Call response responder verification**
  `handleResponse` forwards any `RESPONSE` whose `correlation_id` matches a pending entry, from any connected entity. Fix: store `TargetSessionID` in `PendingCall` at `Add` time. In `handleResponse`, verify the responding session ID matches before forwarding. Mismatch → send `ERROR NOT_AUTHORIZED` to the responder and drop the frame.

  **Amendment (#6 ↔ #12 coupling):** when CAS eviction displaces the old session, scan the call registry and ERROR-out all pending calls whose `TargetSessionID` matches the evicted session — send `ERROR { code: "TARGET_DISCONNECTED", … }` to each requester. The new session has a different session ID and is not bound by the old calls.

- [ ] **#8 — DISCONNECT frame: handle graceful teardown**
  `DISCONNECT` currently falls into the default-ignore branch in `HandleConn`. Fix: handle `FRAME_TYPE_DISCONNECT` with immediate clean teardown — remove from registry, remove from bus and session table, publish `entity.left`, close the connection. The entity must not remain in the registry until the heartbeat checker fires (up to 3× heartbeat interval).

### Files to Modify
| File | Change |
|------|--------|
| `internal/registry/registry.go` | `Remove(pubkey []byte, sessionID string)` — CAS; no other signature change |
| `internal/call/call.go` | Add `TargetSessionID string` to `PendingCall`; add `Add(correlationID, requesterSessionID, targetSessionID string, deadline time.Time)`; add `InvalidateTarget(targetSessionID string) []ExpiredCall` |
| `internal/node/node.go` | Update `HandleConn` defer to pass session ID to `Remove`; add HELLO eviction path; update `handleRequest` to pass `targetEnt.SessionID` to `calls.Add`; update `handleResponse` to verify responder; add `DISCONNECT` case; call `calls.InvalidateTarget` on eviction |
| `internal/handshake/handshake.go` | Expose a mechanism for the node to detect duplicate-pubkey HELLO and trigger eviction (e.g. return a signal or accept an eviction callback) |

### Test Plan
| Test | Asserts |
|------|---------|
| Reconnect-before-detect | New session (S2) remains live and tracked after S1's goroutine errors out |
| No spurious `entity.left` on eviction | Evicting S1 for S2 does not publish `entity.left`; only one `entity.joined` is published |
| CAS no-op | S1's defer with `Remove(K, S1)` when registry holds S2 is a no-op |
| Responder verification | RESPONSE from a non-target entity is rejected with ERROR |
| Eviction invalidates calls | Pending calls targeting evicted session ID get ERROR `TARGET_DISCONNECTED` |
| DISCONNECT teardown | `entity.left` published immediately; entity gone from registry; no heartbeat-checker delay |
| At-least-once join documented | Test asserts two `entity.joined` with no `entity.left` between them on reconnect |

---

## Session 5 — Message Provenance & Correlation

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 4 complete.

### Decisions

- [ ] **#4 — DELIVER envelope**
  Extend `Deliver` from `{subject, payload}` to `{id, subject, publisher_identity, published_at, schema_version, payload}`. Fields:
  - `id`: `uint64`, server-assigned per-concrete-subject **monotonic counter** (not global). A new sequence allocator maps subject → atomic counter.
  - `publisher_identity`: base32 pubkey of the publishing entity, server-stamped (not client-asserted).
  - `published_at`: server timestamp (int64 Unix milliseconds or `google.protobuf.Timestamp`).
  - `schema_version`: `uint32`, populated from the schema registry (0 for subjects with no registered schema).

  **Amendment:** the per-subject `id` creates a conflict with `subscriber_offsets` keyed by pattern. A wildcard subscriber on `home.>` receives interleaved per-subject sequences — a single offset per pattern is meaningless. Durable offset tracking must key per concrete subject. Update the durable-messages storage design note in `DEV.md` before implementing.

- [ ] **#18 — REQUEST caller identity**
  Server stamps `caller_identity` (base32 pubkey of the requesting entity) and `received_at` (server timestamp) onto the `Request` proto before forwarding to the target. These fields are server-assigned — the target can trust them. The requesting client cannot assert them.

- [ ] **#5 — ERROR frame correlation**
  Add optional `ref_id string` to `Error`. Add optional `message_id string` to `Publish` — client-assigned. Server echoes `message_id` in any resulting ERROR (`ref_id = message_id`). For call timeouts, `runCallTimeoutChecker` echoes the expired `correlation_id` in the ERROR's `ref_id`.

### Files to Modify
| File | Change |
|------|--------|
| `proto/frames.proto` | Extend `Deliver`; extend `Request` with `caller_identity`/`received_at`; add `ref_id` to `Error`; add `message_id` to `Publish`; regenerate |
| `proto/frames.pb.go` | Regenerated |
| `internal/node/node.go` | `fanout` + `publishSystemEvent`: build full `Deliver` envelope using sequence allocator + registry lookup; `handleRequest`: stamp `caller_identity`/`received_at`; `handlePublish`/`sendError`: echo `message_id`; `runCallTimeoutChecker`: echo `correlation_id` in ERROR |
| `internal/node/seq.go` (new) | `SubjectSequencer`: `sync.Map` of `string → *atomic.Uint64`; `Next(subject string) uint64` |
| `cmd/lattice-client/main.go` | Update read loop to parse and display the enriched `Deliver` envelope |
| `DEV.md` | Add durable-offset design note: offsets must key per concrete subject, not per pattern |

### Test Plan
| Test | Asserts |
|------|---------|
| Monotonic DELIVER id | Sequential publishes on same subject produce ids 1, 2, 3, … |
| Per-subject isolation | Ids restart per subject; `home.a` and `home.b` have independent counters |
| Publisher identity stamped | `Deliver.publisher_identity` matches the publishing entity's pubkey |
| Timestamp populated | `Deliver.published_at` is non-zero and ≤ now |
| REQUEST caller identity | Target receives `caller_identity` set to requester's pubkey, not a client-supplied value |
| Caller identity not spoofable | Client cannot override `caller_identity` in `Request` payload |
| ERROR with ref_id | PUBLISH with `message_id="x"` triggers a schema error → `Error.ref_id == "x"` |
| Timeout ERROR with corr_id | Call timeout fires `Error.ref_id == correlation_id` |

---

## Session 6 — Token-Based Session Resume

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 4 complete (stable CAS registry + session table).

### Decision

- [ ] **#2 — Session resume via token**
  The session token is generated and sent in `HELLO_ACK` but nothing consumes it. On every reconnect the client does a full re-registration — new `entity.joined` event, empty subscription state, any durable messages during the gap lost.

  Fix: token-based resume path.
  - Server: maintain a `token → sessionState` map with a TTL (e.g. 5 minutes). `sessionState` holds the session record, the subscription patterns, and a placeholder for queued durable messages.
  - Client: persist the token on disk (alongside the key file). On reconnect, include the saved token in `Hello` as a new optional field.
  - Server resume path:
    1. Validate: token exists, not expired, and the `Hello.pubkey` matches the token's session pubkey. **Ed25519 signature must still be verified** — the token alone does not authenticate.
    2. On success: restore subscription state, skip `registry.Register` / `entity.joined`, rotate the token (old token is invalid after first use), deliver any queued durable messages (stubbed in v0.1.1 — the hook must exist).
    3. On failure (expired, mismatch): fall back to full re-registration.

### Files to Modify
| File | Change |
|------|--------|
| `proto/frames.proto` | Add `bytes resume_token = N` (optional) to `Hello`; regenerate |
| `proto/frames.pb.go` | Regenerated |
| `internal/session/session.go` | Add `TokenStore`: `token → {record, subscriptions, TTL, createdAt}`; `CreateResumable`, `LookupToken`, `RotateToken`, `ExpireTokens` |
| `internal/handshake/handshake.go` | Add resume branch: if `Hello.resume_token` is set, attempt lookup before full registration; return a `ResumeResult` flag to the caller |
| `internal/node/node.go` | On resume: skip `registry.Register` + `publishEntityJoined`; restore subscriptions via `bus.Subscribe` for each saved pattern; stub durable-replay hook |
| `cmd/lattice-client/main.go` | Persist token to `<keyfile>.token`; load and present on reconnect |

### Test Plan
| Test | Asserts |
|------|---------|
| Valid resume | Subscriptions restored; no `entity.joined` published; same session semantics |
| Token rotation | Old token rejected on second resume attempt |
| Signature still required | Resume with valid token but wrong/absent Ed25519 signature is rejected |
| Token-pubkey mismatch | Token from entity A cannot resume entity B's session |
| Expired token | Falls back to full re-registration (new `entity.joined`) |
| Fresh connect unchanged | Full registration path unaffected when no token is presented |
| Durable-replay hook | Stub exists and is called (no-op output in v0.1.1) |

---

## Session 7 — Dynamic Schema Registry + Admin API

**Branch:** `dev/0.1.1-hardening`
**Prerequisite:** Session 5 complete (schema_version in DELIVER envelope).

### Decisions

- [ ] **#14 — Dynamic schema registry with raw `FileDescriptorProto`**
  Replace the two hardcoded validators in `internal/schema/schema.go` with a runtime registry backed by `google.golang.org/protobuf/types/descriptorpb.FileDescriptorProto` and `google.golang.org/protobuf/types/dynamicpb`. Developers POST compiled `.proto` descriptors to the admin endpoint to register subjects.

  **Custom proto options for field-level validation (per user decision):** define `lattice.range` and `lattice.max_length` proto extensions in a new `proto/lattice_options.proto`. The dynamic registry reads these options from the descriptor and enforces them — preserving `value ∈ [-50, 150]` and `len(unit) ≤ 10` validation semantics. This is also the compile target the v1 Lattice DSL will need: custom options are the natural extension point.

- [ ] **#15 — Admin API: localhost-only binding**
  The admin API (for schema registration and future management operations) binds to `127.0.0.1` only — not `0.0.0.0`. The API surface stays stable for when enterprise deployments require remote administration with identity-auth. Implementation: a lightweight HTTP server (stdlib `net/http`), no external dependencies.

- [ ] **#16 — Schema versioning: additive-only in-place updates**
  In-place schema version bumps are allowed only for additive changes (new optional fields with defaults). Breaking changes (new enum values, changed field types, removed fields, added required fields) require registering a new subject pattern. The `schema_version` field in `Deliver` (from session 5) carries the version tag; subscribers use it to route to the correct decoder. Clear rule documented in `DEV.md`.

### Files to Modify
| File | Change |
|------|--------|
| `proto/lattice_options.proto` (new) | Define `lattice.range` (min/max float) and `lattice.max_length` (int) custom field options |
| `proto/lattice_options.pb.go` | Generated |
| `internal/schema/schema.go` | Replace hardcode map with dynamic `Registry`; add `Register(subject, version, descriptor)`, `Validate(subject, version, payload)`; option reader for `lattice.range`/`lattice.max_length` |
| `internal/admin/` (new package) | `Server`: localhost-bound `net/http`; `POST /schema` endpoint to submit `FileDescriptorProto`; `GET /schema` to list registered subjects |
| `cmd/lattice-node/main.go` | Start admin listener on `--admin-addr` (default `127.0.0.1:4223`); wire `admin.Server` to schema registry |
| `internal/node/node.go` | `handlePublish`: pass `schema_version` from registry to `Validate`; schema.Validate call site |
| `DEV.md` / `README.md` | Developer schema-registration guide: compile `.proto` with `protoc`, POST descriptor; schema versioning rules; custom option syntax |

### Test Plan
| Test | Asserts |
|------|---------|
| Runtime registration | Register descriptor at startup → PUBLISH validated against it |
| Custom range option | `lattice.range` enforced: `value = 200.0` rejected for a field with `max = 150` |
| Custom max_length option | `lattice.max_length` enforced: string field exceeding limit rejected |
| Regression parity | Hardcoded `home.sensor.temperature` and `home.light.command` semantics exactly reproduced via dynamic + custom options |
| Unknown subject still rejected | PUBLISH to unregistered subject returns `SCHEMA_ERROR: unknown subject` |
| Additive bump accepted | New optional field added in-place → old clients unaffected; `schema_version` increments |
| Breaking change rejected | Server refuses to accept a descriptor that removes a field or changes a field type on an existing version |
| Admin localhost-only | Admin endpoint unreachable from a non-loopback address |
| Admin `GET /schema` | Lists registered subjects with their versions |

---

## Deferred / Out of Scope for v0.1.1

| Item | Reason | Constraint |
|------|--------|------------|
| **#13 QUIC port** | Explicitly deferred by decisions doc | Writer queues (Session 2) must be complete first. Map per-session outbound queue → per-stream writes in quic-go. |
| **Federation** | Post-v0.1.1 | Depends on mutual auth (#1) and DELIVER envelope (#4) being stable first. |
| **Durable messages** | Post-v0.1.1 | Session resume (session 6) stubs the replay hook. Offset table must key per concrete subject (noted in session 5). |
| **libp2p DHT** | v2 target | Flat local entity registry is correct for v1. |
| **IPv6 reachability measurement** | Pre-federation research task | Run empirical test (Jio + Airtel residential, raw QUIC over IPv6) before committing the registry's coordinated-open design. |
| **Remote admin auth** | Post v0.1.1 | Admin API surface is localhost-only. Graduate to Ed25519-signed requests when enterprise remote admin is needed. |

---

*Last updated: 2026-06-13 · Based on CTO Recommendations — v0.1 Architecture Review (June 2026)*
