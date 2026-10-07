# pigeon-relay

A WebSocket relay server for opaque encrypted envelopes for [Pigeon](https://github.com/oliverrowebardeen/pigeon-ios) -- an end-to-end encrypted messenger that communicates over BLE mesh, internet relay, or both.

The relay forwards base64 envelopes addressed by recipient public-key hash. It has no message decryption keys and does not log envelope payloads. Clients are responsible for encrypting and authenticating their contents; the relay cannot verify that an envelope is encrypted. There are no accounts, usernames, or passwords: receive identity is a Curve25519 keypair.

**Experimental and not independently security-audited.** Do not rely on this relay for sensitive communications. See [security and deployment limits](#security-and-deployment-limits).

**Pigeon is pre-beta; no TestFlight build is currently available.** Developers can build the [iOS client](https://github.com/oliverrowebardeen/pigeon-ios) from source. Bluetooth testing requires physical iPhones.

## Architecture

```
                         Internet
                            |
          +-----------------+-----------------+
          |                                   |
     Phone A                             Phone B
     (sender)                           (recipient)
          |                                   |
          |   Receive conns (authenticated)   |
          |   auth_hello / auth_prove         |
          +----------> [ Relay ] <------------+
          |         (opaque box)              |
          |                                   |
          |   Anonymous send conn             |
          |   msg_send(envelope_b64)          |
          +----------> [ Queue ] ------------>+
          |         never decrypted       msg_deliver
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

Pigeon clients are expected to encrypt envelopes before sending them to the relay. The server also sees routing and connection metadata, including recipient hashes, network addresses, timing, and sizes. It does not validate the client encryption scheme.

## Key Design Decisions

**Opaque message transport.** The server cannot decrypt client-encrypted message content. `msg_send` does not require sender authentication, while receive connections prove the recipient identity. Network addresses, timing, sizes, and recipient routing hashes remain visible, so separate sockets do not guarantee anonymity or prevent correlation.

**Accountless authentication.** Clients authenticate using their existing Curve25519 keypair via ECDH challenge-response. The server generates an ephemeral X25519 keypair per challenge, derives a shared secret via HKDF-SHA256, and the client proves possession of its private key with an HMAC proof. No registration, no email, no phone number.

**Constant-time verification.** Auth proofs are compared using `subtle::ConstantTimeEq` for the fixed-size proof comparison.

**Sealed sender.** The send protocol omits the sender identity. Receive connections are authenticated solely for delivery routing. `msg_deliver` contains the encrypted envelope, message ID, and timestamp. This reduces exposed protocol metadata; it does not stop a relay operator or network observer from correlating traffic.

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

Connections have a **role** determined by their first non-keepalive frame: `auth_hello` assigns the **receive** role, `msg_send` assigns the **send** role. Roles are immutable for the lifetime of the connection.

All frames are JSON with a `type` field:

| Frame | Direction | Description |
|-------|-----------|-------------|
| `auth_hello` | client -> server | Start authentication with client public key |
| `auth_challenge` | server -> client | Ephemeral server key, nonce, challenge ID |
| `auth_prove` | client -> server | HMAC proof of shared secret |
| `auth_ok` | server -> client | Authentication succeeded, identity hash assigned |
| `msg_send` | client -> server | Send encrypted envelope to recipient hash |
| `msg_accepted` | server -> client | Envelope queued, with queue depth |
| `msg_deliver` | server -> client | Deliver envelope to recipient (sealed: no sender identity) |
| `push_register` | client -> server | Register APNS device token |
| `push_registered` | server -> client | APNS token registration confirmed |
| `session_replaced` | server -> client | Another session authenticated with your identity |
| `ping` / `pong` | bidirectional | Keepalive |
| `error` | server -> client | Error with code and message |

## Building from Source

**Prerequisites:**
- Rust 1.88+ (this project uses edition 2024)
- Git
- A C/C++ build toolchain and CMake for the AWS-LC cryptography dependency

```bash
git clone https://github.com/oliverrowebardeen/pigeon-relay.git
cd pigeon-relay
cargo build --release --locked
```

## Running

```bash
# Optional: copy and edit the local configuration
cp .env.example .env
./scripts/dev-run.sh
```

The development script binds to `127.0.0.1:8080` unless `RELAY_ADDR` is set and exports variables from `.env`. It sources that file as shell code: use only a file you trust.

For direct execution, export any configuration variables and run `cargo run --release --locked`. The binary itself defaults to `0.0.0.0:8080` and does not load `.env`.

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

## Configuration

All configuration is via environment variables with sensible defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_ADDR` | `0.0.0.0:8080` | Listen address |
| `RELAY_MAX_CONNECTIONS` | `1024` | Global active WebSocket cap (1–65536); excess upgrades receive HTTP 503 |
| `RELAY_MESSAGE_TTL` | `168h` | How long queued messages are retained |
| `RELAY_MAX_MESSAGE_BYTES` | `65536` | Maximum envelope size |
| `RELAY_MAX_QUEUE_PER_RECIPIENT` | `500` | Per-recipient queue depth cap |
| `RELAY_MAX_SESSION_SEND_QUEUE` | `128` | Per-websocket outbound buffer cap before the session is treated as stale |
| `RELAY_CHALLENGE_TTL` | `30s` | Auth challenge expiry |
| `RELAY_SESSION_TTL` | `24h` | Authenticated session expiry |
| `RELAY_RATE_LIMIT_PER_MIN` | `60` | Requests per minute per authenticated identity or anonymous connection (see below) |
| `RELAY_PING_INTERVAL` | `25s` | Server-initiated ping interval |
| `RELAY_PONG_TIMEOUT` | `60s` | Close connection if no pong received |
| `RELAY_MAX_CHALLENGES` | `10000` | Maximum concurrent pending auth challenges |
| `RELAY_MAX_PUSH_REGISTRATIONS` | `100000` | Maximum stored APNS device tokens |
| `RELAY_PUSH_TOKEN_TTL` | `720h` | APNS device token expiry |
| `RELAY_ALLOW_LEGACY_SEND` | `false` | Allow `msg_send` on authenticated (receive) connections for old clients |

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

- **Send connections (anonymous):** per WebSocket connection (`anon:<connection-id>`)
- **Receive connections (authenticated):** per identity hash after authentication, per connection before

This means multiple BLE-only peers tunneled through a single bridge phone each get their own rate limit budget, rather than sharing one.

## Legacy Compatibility

`RELAY_ALLOW_LEGACY_SEND` now defaults to `false`. Modern Pigeon clients use a dedicated anonymous send socket even in bridge mode, so authenticated receive sockets no longer need to accept `msg_send`.

Only set `RELAY_ALLOW_LEGACY_SEND=true` as a temporary rollback valve for older clients that have not yet migrated.

## Bridge / NAT Behavior

`pigeon-relay` does not need a separate server-side bridge mode.

- A bridge phone keeps its own normal `/v1/ws` session.
- Each BLE-only peer tunneled through that bridge opens its own `/v1/ws` session and authenticates as itself.
- The relay tracks one active session per identity, not "bridge acting on behalf of peers".
- Multiple identities from the same public IP / NAT is the expected production shape when a bridge device carries relay traffic for nearby peers.

## Message Queue

Messages are stored in an in-memory queue keyed by recipient identity hash:

- **TTL:** configured for the relay and applied when each message is queued (default 7 days)
- **Deduplication:** duplicate IDs are suppressed while queued for the same recipient; delivery removes that deduplication entry, so retries can be delivered again
- **Per-recipient cap:** oldest messages are dropped when the cap is exceeded
- **Drain on connect:** the existing backlog is drained when a recipient authenticates; messages arriving during that drain can remain queued until the next authentication

Delivery is best-effort, with no end-to-end acknowledgement or exactly-once guarantee. A completed WebSocket write does not prove that the client processed the message. The queue is not persisted to disk. A server restart clears all queued messages.

## Testing

```bash
cargo test --all-targets --all-features --locked
```

Tests include integration tests that stand up a real WebSocket server and perform full ECDH authentication handshakes.

## CI

CI runs on every push and pull request:
- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-targets --all-features --locked`
- `cargo deny check advisories bans licenses sources`
- `cargo audit --deny warnings`
- `cargo +1.88.0 check --all-targets --locked`
- `gitleaks git . --log-opts="--all" --redact`

## Deployment

On Linux, you can run the relay as a systemd service. No `.service` file is included: create one for your environment, with TLS termination and reverse-proxy limits as described below. The following paths are examples; keep configuration and signing keys outside the repository.

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
cargo build --release --locked
systemctl restart pigeon-relay
systemctl status pigeon-relay   # verify it started
```

Configure your systemd unit with `EnvironmentFile=/etc/pigeon-relay/pigeon-relay.env` to load configuration at startup. The `.env` file in the repo directory is for local development only and is never committed.

**Note:** Restarting the service drops all active WebSocket connections and clears the in-memory message queue. Clients must reconnect and retry as appropriate.

## Related

- [Pigeon iOS app](https://github.com/oliverrowebardeen/pigeon-ios) -- the end-to-end encrypted messenger client

## License

[MIT](LICENSE). Dependencies retain their respective licenses; see
[third-party notices](LICENSE-THIRD-PARTY).

## Security and deployment limits

See [SECURITY.md](SECURITY.md). This experimental implementation has automated tests and dependency checks, but no independent cryptographic audit. Public-facing deployments need TLS termination plus connection and request limits at the reverse proxy. The global WebSocket cap bounds simultaneous sessions; it does not bound pre-upgrade TCP connections or total queued data across recipients. Anonymous send budgets are per connection and can be reset by reconnecting; they are not an abuse-prevention system. Configure message/queue caps, monitor memory, and test limits for your workload. The relay currently stores queues in memory; restart loses pending messages.

CI uses the committed lockfile, checks the minimum Rust version, denies dependency advisories/warnings, and scans full Git history. APNS requests and socket delivery confirmations have bounded waits. `jsonwebtoken` uses the AWS-LC backend to avoid the unused RSA dependency previously present in the default RustCrypto backend.
