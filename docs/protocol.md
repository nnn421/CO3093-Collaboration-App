# Protocol Specification

> **Status:** Draft — to be completed by 22/10 (full team, Phase 0).
> Confirmed: Group of 3. Deadline: **08/11/2026**.

---

## Architecture: TCP vs UDP

TCP (port 9000) is used for **login only** — exactly 3 steps:

```
Client                          Server
  │── TCP connect ──────────────>│
  │<─ X25519 server pubkey ──────│   (1) Key exchange — password never sent plaintext
  │── X25519 client pubkey ─────>│
  │   (both derive session keys via HKDF)
  │── REGISTER or LOGIN ────────>│   (2) Auth over encrypted TCP
  │<─ {conn_id, status} ─────────│
  │── TCP close (optional) ──────│   (3) TCP done — conn_id issued
  │
  │── UDP HELLO {conn_id} ───────>│  UDP transport takes over
  │<─ everything else via UDP ───│
```

After login, **all runtime traffic goes over UDP transport (port 9001)**:
chat, user list, heartbeat, file transfer, disconnect detection.

Client disconnect detection relies entirely on **heartbeat idle timeout** (A9 + B4),
since TCP is closed. A9 and B4 must both use `IDLE_TIMEOUT = 15s`.

---

## G1 — Packet Header

> Owner: Person A | Due: 22/10

**struct format:** `>BBBIHIIIIH` (big-endian, total 27 bytes)

| Field    | Size (B) | Offset | Type           | Description |
|----------|---------|--------|----------------|-------------|
| Version  | 1       | 0      | uint8          | Protocol version — currently `1` |
| Type     | 1       | 1      | uint8          | Packet type (see table below) |
| Flags    | 1       | 2      | uint8          | Bitmask (SYN=0x01, FIN=0x02, ACK=0x04, RST=0x08) |
| ConnID   | 4       | 3      | uint32 BE      | Unique connection identifier (issued by server at login) |
| StreamID | 2       | 7      | uint16 BE      | Stream multiplexing identifier |
| Seq      | 4       | 9      | uint32 BE      | Sequence number of this packet |
| Ack      | 4       | 13     | uint32 BE      | Cumulative ACK number |
| Window   | 4       | 17     | uint32 BE      | Receiver window size (flow control, per-stream) |
| Length   | 2       | 21     | uint16 BE      | Payload length in bytes |
| Checksum | 4       | 23     | uint32 BE      | CRC32 of (header with checksum=0) + payload |
| **Total**| **27**  |        |                | Fixed header size |

### Packet Types

| Name      | Value | Description |
|-----------|-------|-------------|
| DATA      | 0x01  | Data packet carrying payload |
| ACK       | 0x02  | Acknowledgment (may carry SACK ranges in payload) |
| HELLO     | 0x03  | UDP binding: client sends conn_id to associate UDP address |
| FIN       | 0x04  | Graceful connection/stream termination |
| HEARTBEAT | 0x05  | Keep-alive on Stream 2 (best-effort, no retry) |

### SACK (Selective ACK) in ACK payload

When Type=ACK, the payload may contain SACK ranges to tell the sender
which out-of-order packets have been buffered. Format (binary):

```
[1 byte: number of ranges N]
[N × 8 bytes: (start_seq uint32 BE, end_seq uint32 BE)]
```

Example: `\x02 \x00\x00\x00\x05\x00\x00\x00\x07 \x00\x00\x00\x09\x00\x00\x00\x09`
means ranges [5,7] and [9,9] have been received — sender only retransmits 3, 4, 8.

---

## G2 — Application-Layer Message Types

> Owner: Person B | Due: 22/10

All messages are JSON objects framed with a 2-byte length prefix (see G3).

| Type        | Transport | Stream | Direction     | Required Fields |
|-------------|-----------|--------|---------------|-----------------|
| REGISTER    | TCP       | —      | Client→Server | `type`, `username`, `password` |
| LOGIN       | TCP       | —      | Client→Server | `type`, `username`, `password` |
| AUTH_OK     | TCP       | —      | Server→Client | `type`, `conn_id` |
| AUTH_FAIL   | TCP       | —      | Server→Client | `type`, `code`, `message` |
| UDP_HELLO   | UDP       | 0      | Client→Server | `type`, `conn_id` |
| USER_LIST   | UDP       | 1      | Server→Client | `type`, `users` |
| MSG_BCAST   | UDP       | 1      | Client→Server | `type`, `body`, `ts` |
| MSG_DM      | UDP       | 1      | Client→Server | `type`, `to`, `body`, `ts` |
| HEARTBEAT   | UDP       | 2      | Client→Server | `type`, `conn_id` |
| FILE_OFFER  | UDP       | 0      | Client→Server | `type`, `to`, `filename`, `size`, `sha256` |
| FILE_ACCEPT | UDP       | 0      | Server→Client | `type`, `transfer_id` |
| FILE_CHUNK  | UDP       | 3+     | Client→Server | binary framing (see G3) |
| FILE_DONE   | UDP       | 3+     | Client→Server | `type`, `transfer_id`, `sha256` |
| ERROR       | UDP       | 1      | Server→Client | `type`, `code`, `message` |

### JSON Examples

```json
// LOGIN (over TCP, encrypted)
{"type": "LOGIN", "username": "alice", "password": "hunter2"}

// AUTH_OK (over TCP)
{"type": "AUTH_OK", "conn_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}

// UDP_HELLO (Stream 0) — binds UDP address to conn_id
{"type": "UDP_HELLO", "conn_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}

// USER_LIST (Stream 1)
{"type": "USER_LIST", "users": [{"name": "alice", "status": "online"}, {"name": "bob", "status": "online"}]}

// MSG_DM (Stream 1)
{"type": "MSG_DM", "to": "bob", "body": "Hey Bob!", "ts": 1730000000}

// FILE_OFFER (Stream 0)
{"type": "FILE_OFFER", "to": "bob", "filename": "report.pdf", "size": 10485760, "sha256": "abc123..."}

// FILE_ACCEPT (Stream 0)
{"type": "FILE_ACCEPT", "transfer_id": "tx-001"}

// FILE_DONE (Stream 3+)
{"type": "FILE_DONE", "transfer_id": "tx-001", "sha256": "abc123..."}

// ERROR (Stream 1)
{"type": "ERROR", "code": "USER_OFFLINE", "message": "bob is not online"}
```

---

## G3 — Stream ID Convention & Message Framing

> Owner: Person A | Due: 22/10

### Stream ID Table

| StreamID | Name      | Reliable? | Content | Notes |
|----------|-----------|-----------|---------|-------|
| 0        | Control   | Yes       | UDP_HELLO, FILE_OFFER, FILE_ACCEPT, FIN | Connection lifecycle |
| 1        | Chat      | Yes       | MSG_BCAST, MSG_DM, USER_LIST, ERROR | All text messaging |
| 2        | Heartbeat | **No**    | HEARTBEAT | Loss acceptable; no retransmit |
| 3+       | File      | Yes       | FILE_CHUNK, FILE_DONE | Dynamic: one stream per transfer |

**Why separate streams?** Avoids Head-of-Line (HoL) blocking.
File chunk retransmits on stream 5 do not delay chat on stream 1.

### Message Framing on Streams

A stream is a byte sequence with no built-in message boundaries.
**All application messages (JSON and binary) use 2-byte length prefix framing:**

```
┌──────────────────────┬──────────────────────────────┐
│  Length (2B, BE)     │  Payload (Length bytes)      │
└──────────────────────┴──────────────────────────────┘
```

- **JSON messages** (all streams except FILE_CHUNK): `[2B length][UTF-8 JSON]`
- **FILE_CHUNK** (streams 3+): `[2B length][transfer_id (16B)][offset (4B BE)][chunk data]`
  - No base64 encoding — raw binary payload for efficiency

> This framing must be implemented identically by A (transport), B (server), and C (client).
> The constant `MSG_LENGTH_PREFIX_SIZE = 2` is defined in `shared/config.py`.

---

## G4 — Configuration Reference

> Owner: Person B | See `shared/config.py` for values.

| Constant            | Value  | Purpose |
|---------------------|--------|---------|
| TCP_PORT            | 9000   | Login-only channel |
| UDP_PORT            | 9001   | All runtime traffic |
| HTTP_PORT           | 8080   | Web UI |
| CHUNK_SIZE          | 1000 B | FILE_CHUNK binary payload size |
| WINDOW_SIZE         | 16     | Sliding window default |
| MAX_RETRIES         | 5      | Max retransmissions |
| INITIAL_RTO         | 2 s    | Starting RTO (updated dynamically) |
| HEARTBEAT_INTERVAL  | 5 s    | Client heartbeat send period |
| HEARTBEAT_TIMEOUT   | 15 s   | Server marks user offline |
| IDLE_TIMEOUT        | 15 s   | A9 closes connection (= HEARTBEAT_TIMEOUT) |
| INITIAL_CWND        | 1      | Slow start initial window (connection-level) |
| INITIAL_SSTHRESH    | 64     | Slow start threshold |

**Timeout consistency rule:** `IDLE_TIMEOUT == HEARTBEAT_TIMEOUT == 15s`.
Do not use different values in different modules.

---

## G5 — Transport API Contract

> Owner: Person A | Deadline: 22/10 (blocking B and C)

```python
# Open a stream on a connection
stream: Stream = await conn.open_stream(stream_id: int)

# Send framed message on a stream (bytes, already length-prefixed)
await stream.send(data: bytes) -> None

# Receive one framed message from a stream (returns payload without length prefix)
data: bytes = await stream.recv()

# Register callback for unexpected disconnect
conn.on_disconnect(callback: Callable[[], Awaitable[None]])
```

Implementation: `transport/fake.py` — in-memory, asyncio.Queue-backed.

---

## G6 — State Diagrams

> Owner: B (login flow), C (file transfer flow) | Due: 22/10

Files to be placed in `docs/diagrams/`:
- `login_state.png` — Person B: DISCONNECTED → KEY_EXCHANGE → AUTH → UDP_BOUND → ONLINE
- `file_transfer_state.png` — Person C: IDLE → OFFERING → ACCEPTED → TRANSFERRING → VERIFYING → DONE / ABORTED

Both diagrams must include error and timeout transitions.

---

## G7 — Repository & Branch Convention

> Owner: Person C | Due: 22/10

**Branch naming:** `feature/<task-id>-<short-description>`

Examples:
```
feature/G7-repo-setup
feature/A1-packet-struct
feature/A4-stop-and-wait
feature/B3-auth
feature/C1-lossy-transport
```

**Commit message format:** `[TaskID] short description`

```
[A1] implement pack/unpack with struct
[B3] add PBKDF2 password hashing
fix: [A5] handle out-of-order packets
docs: [A10] add sliding window explanation
```

**Protected branches:** `main` (stable releases), `dev` (integration)

**Integration milestone (~26/10):** A delivers A4 (stop-and-wait over real UDP).
B and C switch from `FakeTransport` to real transport at this point.

---

## Encryption Design

> Related tasks: B5 (server), A (transport hook)

**Key Exchange:** X25519 over TCP before login. Password is never sent plaintext.

**Key Derivation:** HKDF from shared secret → **two 32-byte keys**:
- `key_c2s`: used by client to encrypt, server to decrypt
- `key_s2c`: used by server to encrypt, client to decrypt

**Cipher:** AES-256-GCM

**Nonce (12 bytes):** `stream_id (2B BE) + seq (4B BE) + \x00\x00\x00\x00\x00\x00`
- Nonce is deterministic from (stream_id, seq) — never reuse the same pair

**AAD (Additional Authenticated Data):** the 27-byte packet header (with checksum field zeroed)
- Header integrity is verified even though it is not encrypted

**Note:** Server decrypts all traffic (server-terminated encryption, not end-to-end).
The term "end-to-end" should not be used for this design.

**Hook location:** Encryption/decryption is applied at the transport layer boundary —
just before `sendto()` on send, just after `recvfrom()` on receive.
