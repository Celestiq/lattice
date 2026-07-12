# Lattice — Demo Walkthrough

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

---

---

# Section 2 — Federation Demo (v0.2)

Two independent nodes on the same machine form a mutually-authenticated QUIC peer link, exchange policy-governed messages, and route calls transparently across the node boundary.

> **Platform note:** This demo uses IPv6 loopback (`[::1]`). This is standard on macOS. On Linux, verify `::1` is assigned: `ip addr show lo`. On Windows, use WSL2 or a Linux VM.

---

## What you need

- `curl` (for admin API calls)
- `openssl` (to extract Ed25519 pubkeys from the `.key` files)
- 4 terminals: 2 for servers, 2 for client devices (optional; the connection lifecycle can be shown with curl alone)

---

## Step 1 — Start both nodes

```sh
# Terminal A — Node A
go run ./cmd/lattice-node \
  --addr :4222 \
  --key node-a.key \
  --admin-addr 127.0.0.1:4300 \
  --fed-addr [::1]:5751 \
  --fed-db fed-a.db

# Terminal B — Node B
go run ./cmd/lattice-node \
  --addr :4223 \
  --key node-b.key \
  --admin-addr 127.0.0.1:4301 \
  --fed-addr [::1]:5752 \
  --fed-db fed-b.db
```

Each node starts:
- TLS+TCP client listener (`:4222` / `:4223`)
- QUIC federation listener (`[::1]:5751` / `[::1]:5752`)
- Localhost-only HTTP admin API (`127.0.0.1:4300` / `127.0.0.1:4301`)
- SQLite state file (`fed-a.db` / `fed-b.db`)

---

## Step 2 — Extract federation pubkeys

The federation pubkey is the node's Ed25519 public key. Extract both from the generated key files:

```sh
A_PUBKEY=$(openssl pkey -in node-a.key -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 256 | tr -d '\n')
echo "A: $A_PUBKEY"

B_PUBKEY=$(openssl pkey -in node-b.key -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 256 | tr -d '\n')
echo "B: $B_PUBKEY"
```

Both should print 64 hex characters. If `xxd` is not available, `od -A n -t x1 | tr -d ' \n'` is an equivalent substitute.

---

## Step 3 — Establish bilateral consent

Lattice federation requires explicit consent from both operators. Neither node can join the other's peer set unilaterally.

> **F-7 workaround:** Always supply the peer's QUIC address in the `pair` call (not just at `accept`). If Node B learns of Node A only from an incoming connection, it stores `addr=""` and the dial-back fails. Calling `pair` with the address on both sides before `accept` avoids this.

```sh
# --- On Node A ---

# Register B as a known peer (supply B's fed-addr here — the workaround)
curl -s -X POST http://127.0.0.1:4300/federation/pair \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\",\"addr\":\"[::1]:5752\",\"name\":\"node-b\"}"
# → 201 Created

# Accept B (A is now willing to peer)
curl -s -X POST http://127.0.0.1:4300/federation/accept \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\"}"
# → 204 No Content

# --- On Node B ---

# Register A as a known peer (supply A's fed-addr — the workaround)
curl -s -X POST http://127.0.0.1:4301/federation/pair \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$A_PUBKEY\",\"addr\":\"[::1]:5751\",\"name\":\"node-a\"}"

# Accept A
curl -s -X POST http://127.0.0.1:4301/federation/accept \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$A_PUBKEY\"}"
```

Verify both sides reached `active`:

```sh
curl -s http://127.0.0.1:4300/federation/connections | python3 -m json.tool
curl -s http://127.0.0.1:4301/federation/connections | python3 -m json.tool
```

Both should show `"state": "active"`.

---

## Step 4 — Configure forwarding policy

Forwarding policy controls what subjects A sends to B (outbound) and what subjects B accepts from A (inbound). Both sides are required.

```sh
# A forwards home.> to B
curl -s -X POST http://127.0.0.1:4300/federation/policy \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\",\"outbound\":[{\"subject_pattern\":\"home.>\",\"effect\":\"forward\"}],\"inbound\":[]}"

# B accepts home.> from A
curl -s -X POST http://127.0.0.1:4301/federation/policy \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$A_PUBKEY\",\"outbound\":[],\"inbound\":[{\"subject_pattern\":\"home.>\",\"effect\":\"accept\"}]}"
```

---

## Step 5 — Cross-node message flow

Once devices are connected to each node (via `go run ./cmd/lattice-client`) with appropriate ACL rules in place:

**Cross-node pub/sub:** A device on Node A publishes `home.sensor.temperature` → Node A's forwarding policy forwards it to Node B via QUIC → Node B's inbound policy accepts it → any subscriber on Node B receives a `DELIVER` frame. The `publisher_identity` field contains the original device's pubkey (not Node A's pubkey).

**Cross-node call:** To make an entity on Node A callable from Node B, configure an export list on A:

```sh
# Replace <device-on-A-hex> with the hex pubkey of the device connected to A
curl -X POST http://127.0.0.1:4300/federation/export \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\",\"entity_pubkeys\":[\"<device-on-A-hex>\"]}"
```

An entity on Node B then sends a `REQUEST` addressed to the device on A. Node B's call router sees the target is in A's export list, routes the request over the QUIC peer link, Node A delivers it to the device, the device responds, and the response travels back. The entities on both sides see a normal request/response — the federation is transparent to them.

---

## Step 6 — Connection lifecycle

**Pause** — suspend message forwarding without closing the link:

```sh
curl -s -X POST http://127.0.0.1:4300/federation/pause \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\"}"
```

Messages published on A to `home.>` will not reach B while paused. The QUIC connection stays open. Resume with:

```sh
curl -s -X POST http://127.0.0.1:4300/federation/resume \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\"}"
```

**Revoke** — permanently close the link from A's side:

```sh
curl -s -X POST http://127.0.0.1:4300/federation/revoke \
  -H "Content-Type: application/json" \
  -d "{\"pubkey\":\"$B_PUBKEY\"}"
```

B receives a `FED_STATUS{state: revoked}` frame and closes its end. Local operation on both nodes is unaffected — their connected devices continue to pub/sub and call each other locally.

---

## Running the full scenario as a test

The automated integration test at `go test ./internal/... -run TestIntegration -v` exercises the single-node path end-to-end. Full-stack federation E2E tests are on the v0.2 backlog.
