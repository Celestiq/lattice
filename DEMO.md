# Lattice v0.1 — Demo Walkthrough

A two-minute tour of the complete feature set. Run each command in the terminal indicated.

---

## Setup: three terminals

```
Terminal 1 — lattice-node (server)
Terminal 2 — admin client  (Client A)
Terminal 3 — sensor client (Client B)
```

---

## Step 1 — Start the server

**Terminal 1:**
```sh
go run ./cmd/lattice-node
```

Expected output:
```
time=... level=INFO msg="server identity loaded" key_file=node.key
time=... level=INFO msg="lattice-node listening" addr=:4222 tls=true
```

The server generates `node.key` (Ed25519 keypair, PKCS8 PEM) on first run. Subsequent runs reuse it so the server identity is stable across restarts.

---

## Step 2 — Connect the admin client

**Terminal 2:**
```sh
go run ./cmd/lattice-client
```

Expected output:
```
identity loaded from client.key
connected to localhost:4222
authenticated  session_id=<uuid>  heartbeat_interval=30s
```

**Terminal 1** logs:
```
msg="entity authenticated"  session_id=<uuid>
```

The client sends `HEARTBEAT` every 30 seconds. The server responds with `HEARTBEAT_ACK` and the client prints `← HEARTBEAT_ACK`.

---

## Step 3 — Connect the sensor client

**Terminal 3:**
```sh
go run ./cmd/lattice-client --key sensor.key
```

Expected output (Terminal 3):
```
identity loaded from sensor.key
connected to localhost:4222
authenticated  session_id=<uuid>  heartbeat_interval=30s
```

**Terminal 2** does NOT see an `entity.joined` event yet — the admin client has no active subscription.

---

## What you have now

- Server running with TLS, Ed25519 self-signed cert generated at startup.
- Two connected entities, each with a unique Ed25519 identity and a UUID session.
- ACL is deny-by-default — neither client can publish or subscribe until rules are added.

---

## Architecture checkpoint

```
admin-client ──TLS──► lattice-node ◄──TLS── sensor-client
                           │
                    ┌──────┴──────┐
                    │  session    │  2 records: admin, sensor
                    │  registry   │  2 entities tracked
                    │  bus (empty)│  no subscriptions yet
                    │  acl (deny) │  only server identity allowed
                    └─────────────┘
```

---

## Going further (programmatic)

The CLI binaries intentionally stay minimal — they connect and print frames. All real behaviour is wired in tests. To see every feature exercised end-to-end:

```sh
go test ./internal/node/ -run TestIntegrationSequence -v
```

This test walks through:
1. Server starts
2. Admin subscribes to `lattice.system.>`
3. Sensor connects → admin receives `entity.joined`
4. Sensor subscribes to `home.sensor.temperature`
5. Admin publishes valid temperature → sensor receives `DELIVER`
6. Admin publishes out-of-range temperature → `SCHEMA_ERROR`, sensor gets nothing
7. Third client with no rules attempts to publish → `PERMISSION_DENIED`
8. Admin calls sensor by pubkey → sensor responds → admin receives `RESPONSE`
9. Sensor disconnects → admin receives `entity.left`
10. `srv.Shutdown()` → completes in < 1s, no hanging goroutines

Each step is logged with `✓` on pass.

---

## Stopping

**Ctrl+C in Terminal 1** triggers graceful shutdown:
```
time=... level=INFO msg="signal received, shutting down"
time=... level=INFO msg="goodbye"
```

Connected entities receive `lattice.system.entity.left` for every entity before the connections are closed. Clients in Terminals 2 and 3 print `server closed the connection` and exit.
