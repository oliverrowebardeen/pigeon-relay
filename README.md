# pigeon-relay

An opaque, zero-knowledge WebSocket relay server for [Pigeon](https://github.com/oliverrowebardeen/pigeon-ios) -- an end-to-end encrypted messenger that communicates over BLE mesh, internet relay, or both.

The relay never decrypts, inspects, or logs message contents. It stores and forwards encrypted envelopes addressed by recipient public-key hash. There are no accounts, no usernames, no passwords -- identity is a Curve25519 keypair.

**Try Pigeon:** The iOS app is available on [TestFlight](https://testflight.apple.com/join/nv3UA1Hy) for the first 100 testers.

## Architecture

```
                         Internet
                            |
          +-----------------+-----------------+
          |                                   |
     Phone A                             Phone B
     (sender)                           (recipient)
          |                                   |
          |   1. auth_hello / auth_prove      |
          +----------> [ Relay ] <------------+
          |         (opaque box)              |
          |                                   |
          |   2. msg_send(envelope_b64)       |
          +----------> [ Queue ] ------------>+
          |         never decrypted       msg_deliver
          |                                   |
          |   3. msg_ack                      |
          +<----------- msg_acked <-----------+
          |                                   |
          |   If offline:                     |
          |   APNS silent push -------> wake  |
          |                                   |
     +----+----+                              |
     | BLE mesh |  (direct, no relay)         |
     +----+----+                              |
          |                                   |
          +------- BLE multi-hop ------------>+

     Bridge Mode:
     Phone C (BLE-only) --> BLE --> Phone B (bridge) --> WS --> Relay --> Phone A
```

Every message between clients is encrypted end-to-end with AES-256-GCM before it reaches the relay. The relay sees only opaque base64 blobs and identity hashes -- never plaintext, never sender names, never message content.

## Key Design Decisions

**Zero-knowledge relay.** The server cannot read messages. The `envelope_b64` field is an opaque encrypted blob. Sender-recipient correlation uses SHA-256 hashes of public keys, not human-readable identifiers.

**Accountless authentication.** Clients authenticate using their existing Curve25519 keypair via ECDH challenge-response. The server generates an ephemeral X25519 keypair per challenge, derives a shared secret via HKDF-SHA256, and the client proves possession of its private key with an HMAC proof. No registration, no email, no phone number.

**Constant-time verification.** Auth proofs are compared using `subtle::ConstantTimeEq` to prevent timing side-channel attacks.

**Bridge-transparent.** A bridge phone that relays traffic for nearby BLE-only peers doesn't need special server-side logic. Each tunneled peer authenticates as itself over its own WebSocket session. Multiple identities behind the same NAT/IP are expected and rate-limited independently.

## Authentication Flow

```
Client                          Relay
  |                               |
  |  auth_hello(client_pubkey)    |
  +------------------------------>|
  |                               |  generate ephemeral X25519 keypair
  |                               |  generate nonce
  |  auth_challenge(server_pub,   |
  |    nonce, challenge_id)       |
  |<------------------------------+
  |                               |
  |  ECDH shared secret           |
  |  HKDF-SHA256 derive auth_key  |
  |  HMAC(challenge_id || iat)    |
  |                               |
  |  auth_prove(challenge_id,     |
  |    proof)                     |
  +------------------------------>|  verify HMAC (constant-time)
  |                               |  identity = SHA-256(client_pubkey)
  |  auth_ok(identity_hash,       |
  |    session_expires_at)        |
  |<------------------------------+
  |                               |  deliver any queued messages
```

## Protocol

WebSocket endpoint: `/v1/ws`

All frames are JSON with a `type` field:

| Frame | Direction | Description |
|-------|-----------|-------------|
| `auth_hello` | client -> server | Start authentication with client public key |
| `auth_challenge` | server -> client | Ephemeral server key, nonce, challenge ID |
| `auth_prove` | client -> server | HMAC proof of shared secret |
| `auth_ok` | server -> client | Authentication succeeded, identity hash assigned |
| `msg_send` | client -> server | Send encrypted envelope to recipient hash |
| `msg_accepted` | server -> client | Envelope queued, with queue depth |
| `msg_deliver` | server -> client | Deliver envelope to recipient |
| `msg_ack` | client -> server | Acknowledge receipt of message |
| `msg_acked` | server -> client | Notify sender their message was acknowledged |
| `push_register` | client -> server | Register APNS device token |
| `ping` / `pong` | bidirectional | Keepalive |
| `error` | server -> client | Error with code and message |

## Building from Source

**Prerequisites:**
- Rust 1.85+ (this project uses edition 2024)
- Git

```bash
git clone https://github.com/oliverrowebardeen/pigeon-relay.git
cd pigeon-relay
cargo build --release
```

## Running

```bash
# Optional: configure via environment variables (see below)
source .env 2>/dev/null || true

cargo run --release
```

Default bind: `0.0.0.0:8080`

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

## Configuration

All configuration is via environment variables with sensible defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_ADDR` | `0.0.0.0:8080` | Listen address |
| `RELAY_MESSAGE_TTL` | `168h` | How long queued messages are retained |
| `RELAY_MAX_MESSAGE_BYTES` | `65536` | Maximum envelope size |
| `RELAY_MAX_QUEUE_PER_RECIPIENT` | `500` | Per-recipient queue depth cap |
| `RELAY_CHALLENGE_TTL` | `30s` | Auth challenge expiry |
| `RELAY_SESSION_TTL` | `24h` | Authenticated session expiry |
| `RELAY_RATE_LIMIT_PER_MIN` | `60` | Requests per minute per identity |
| `RELAY_PING_INTERVAL` | `25s` | Server-initiated ping interval |
| `RELAY_PONG_TIMEOUT` | `60s` | Close connection if no pong received |

### APNS Configuration

When `APNS_ENABLED=true`, the relay sends silent background pushes to wake offline recipients:

| Variable | Description |
|----------|-------------|
| `APNS_ENABLED` | `true` / `false` (default `false`) |
| `APNS_TEAM_ID` | Apple Developer Team ID |
| `APNS_KEY_ID` | Default APNS key ID (fallback for both environments) |
| `APNS_PRIVATE_KEY_PATH` | Default path to `.p8` key file |
| `APNS_SANDBOX_KEY_ID` | Sandbox-specific key ID (overrides default) |
| `APNS_SANDBOX_PRIVATE_KEY_PATH` | Sandbox-specific key path |
| `APNS_PRODUCTION_KEY_ID` | Production-specific key ID (overrides default) |
| `APNS_PRODUCTION_PRIVATE_KEY_PATH` | Production-specific key path |
| `APNS_TOPIC` | App bundle ID |
| `APNS_ENV` | `sandbox` or `production` (default `sandbox`) |

Use `production` for TestFlight and App Store builds. Use `sandbox` for debug builds installed from Xcode.

The push payload is a silent background notification:

```json
{
  "aps": { "content-available": 1 },
  "pigeon_type": "relay_message"
}
```

## Rate Limiting

Rate limiting is scoped to prevent abuse while supporting bridge mode:

- **Before authentication:** per WebSocket connection (`anon:<connection-id>`)
- **After authentication:** per identity hash

This means multiple BLE-only peers tunneled through a single bridge phone each get their own rate limit budget, rather than sharing one.

## Bridge / NAT Behavior

`pigeon-relay` does not need a separate server-side bridge mode.

- A bridge phone keeps its own normal `/v1/ws` session.
- Each BLE-only peer tunneled through that bridge opens its own `/v1/ws` session and authenticates as itself.
- The relay tracks one active session per identity, not "bridge acting on behalf of peers".
- Multiple identities from the same public IP / NAT is the expected production shape when a bridge device carries relay traffic for nearby peers.

## Message Queue

Messages are stored in an in-memory queue keyed by recipient identity hash:

- **TTL:** configurable per message (default 7 days)
- **Deduplication:** same message ID to same recipient is only queued once
- **Per-recipient cap:** oldest messages are dropped when the cap is exceeded
- **Drain on connect:** queued messages are delivered immediately when a recipient authenticates

The queue is not persisted to disk. A server restart clears all queued messages.

## Testing

```bash
cargo test --all-targets --all-features
```

Tests include integration tests that stand up a real WebSocket server and perform full ECDH authentication handshakes.

## CI

CI runs on every push and pull request:
- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`

## Deployment

The relay runs as a systemd service. Configuration and secrets live outside the repo in `/etc/pigeon-relay/`.

**Server layout:**

```
/opt/pigeon-relay/          # git clone of this repo
/etc/pigeon-relay/
  pigeon-relay.env          # environment variables (secrets, config)
  AuthKey_*.p8              # APNS signing keys (chmod 600)
```

**Update from a new push:**

```bash
cd /opt/pigeon-relay
git pull origin main
source "$HOME/.cargo/env"
cargo build --release
systemctl restart pigeon-relay
systemctl status pigeon-relay   # verify it started
```

The systemd unit uses `EnvironmentFile=/etc/pigeon-relay/pigeon-relay.env` to load secrets at startup. The `.env` file in the repo directory is for local development only and is never committed.

**Note:** Restarting the service drops all active WebSocket connections and clears the in-memory message queue. Connected clients will reconnect automatically.

## Related

- [Pigeon iOS app](https://github.com/oliverrowebardeen/pigeon-ios) -- the end-to-end encrypted messenger client

## License

[MIT](LICENSE)
