# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
# Run the server (generates node.key on first run)
go run ./cmd/lattice-node

# Run the client (generates client.key on first run)
go run ./cmd/lattice-client

# Run all tests
go test ./...

# Run a single package's tests
go test ./internal/node/...

# Race-detector test (required for node package before merging)
go test -race ./internal/node/...

# Build everything
go build ./...

# Regenerate protobuf Go bindings (protoc must be ≥ v3, protoc-gen-go pinned at v1.36.11)
# No Makefile or script exists yet — Session 0 of v0.1.1 adds one
protoc --go_out=. --go_opt=paths=source_relative proto/*.proto
```

**Session flags:**
- Server: `--addr :4222`, `--key node.key`, `--heartbeat 30`
- Client: `--addr localhost:4222`, `--key client.key`

Key files (`*.key`) are gitignored. Each binary generates its Ed25519 keypair on first run and reuses it on subsequent runs.

## Architecture

Lattice is a sovereign federated coordination protocol. The current codebase is the v0.1 single-node reference implementation — a typed pub/sub message bus with identity, ACL, schema validation, and a call primitive. Federation (the core thesis) is not yet implemented.

### Package responsibilities

| Package | Role |
|---------|------|
| `internal/wire` | Frame encode/decode (4-byte BE length + 1-byte type + protobuf body). Max payload 256 KiB. Also generates the self-signed TLS cert used by the server. |
| `internal/identity` | Ed25519 keypair load/generate, persisted as PKCS8 PEM at mode 0600. |
| `internal/handshake` | HELLO exchange. Client signs a 32-byte nonce derived from the TLS session via `ExportKeyingMaterial("lattice-hello-v1")`. Server verifies and issues a session ID + token. |
| `internal/session` | In-memory session table keyed by UUID session ID and by public key. |
| `internal/bus` | Subscription registry with `*`/`>` wildcard matching. Subject rules: segments `[a-z0-9-_]+`, max 16 segments, 256 chars. `lattice.system.*` is server-reserved. |
| `internal/schema` | Subject-keyed payload validators (currently hardcoded: `home.sensor.temperature` → `TemperatureReading`, `home.light.command` → `LightCommand`). All other subjects are rejected at PUBLISH time. |
| `internal/acl` | Deny-by-default access-control engine. Rules evaluated in descending priority order; identity matched by base32-encoded Ed25519 pubkey or `"*"`. Actions: publish, subscribe, call. |
| `internal/registry` | Entity liveness tracking. Marks entity offline after 3× missed heartbeat intervals; emits system events. |
| `internal/call` | Pending REQUEST/RESPONSE correlation table with per-request timeout. Matched by `correlation_id`. |
| `internal/node` | `Server` struct — owns all shared state (session table, bus, ACL engine, registry, call registry). `HandleConn` is the per-connection goroutine. Background goroutines: heartbeat checker, call timeout checker. |
| `cmd/lattice-node` | Server binary: parses flags, loads/generates keypair, opens TLS listener, calls `srv.HandleConn` per connection, hooks SIGINT/SIGTERM for graceful shutdown. |
| `cmd/lattice-client` | CLI client binary: connects, authenticates, then exercises subscribe/publish/call via hardcoded demo flow. |
| `proto/` | Three `.proto` files (`frames.proto`, `schemas.proto`, `events.proto`). Pre-compiled `*.pb.go` files are committed. The `go_package` is `lattice/proto`. |

### Message flow for PUBLISH

```
Client sends PUBLISH
  → node: subject format validation
  → acl: ActionPublish check for sender's pubkey
  → schema: payload validation against registered schema
  → bus: fan-out as DELIVER frames to all matching subscribers
```

### System events

The server emits `lattice.system.entity.joined/left/offline` as DELIVER frames to subscribers of `lattice.system.>`. These bypass ACL, subject validation, and schema validation. The server identity is pre-seeded with priority-1000 allow-all rules so it can publish these.

### Active development: v0.1.1 hardening

The working branch is `dev/v0.1.1-hardening`. The `IMPLEMENTATION_ROADMAP.md` is the source of truth — 8 sessions (0–7), all on one branch, merged to `main` only when all sessions are complete and `go test -race ./internal/node/...` is green.

Session sequencing constraint: Session 2 (per-session writer queues, Decision #10) reshapes every outbound write path in `internal/node/node.go` — Sessions 3, 4, and 5 all modify the fanout/delivery path and must be written against the post-Session-2 architecture.

### Single dependency

`google.golang.org/protobuf v1.36.11` — the only external dependency. Everything else is stdlib.
