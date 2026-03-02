# pigeon-relay

Minimal authenticated websocket relay for Pigeon encrypted message envelopes.

## Features

- Auth challenge-response using existing Curve25519 keypairs (no accounts)
- Encrypted blob queue keyed by recipient public-key hash
- Delivery ack routing (`msg_ack` -> `msg_acked`)
- In-memory queue with TTL and dedup
- Optional APNS silent push wakeups for offline recipients

## Protocol

Websocket endpoint: `/v1/ws`

Frame types:

- `auth_hello`
- `auth_challenge`
- `auth_prove`
- `auth_ok`
- `msg_send`
- `msg_accepted`
- `msg_deliver`
- `msg_ack`
- `msg_acked`
- `push_register`
- `error`
- `ping` / `pong`

## Local Run

```bash
cp .env.example .env
# edit values as needed
source .env
cargo run --release
```

Default bind: `0.0.0.0:8080`

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

## Environment Variables

- `RELAY_ADDR` (default `0.0.0.0:8080`)
- `RELAY_MESSAGE_TTL` (default `168h`)
- `RELAY_MAX_MESSAGE_BYTES` (default `65536`)
- `RELAY_MAX_QUEUE_PER_RECIPIENT` (default `500`)
- `RELAY_CHALLENGE_TTL` (default `30s`)
- `RELAY_SESSION_TTL` (default `24h`)
- `RELAY_RATE_LIMIT_PER_MIN` (default `60`)
- `RELAY_PING_INTERVAL` (default `25s`)
- `RELAY_PONG_TIMEOUT` (default `60s`)
- `APNS_ENABLED` (`true`/`false`, default `false`)
- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- `APNS_PRIVATE_KEY_PATH`
- `APNS_TOPIC`
- `APNS_ENV` (`sandbox` or `production`, default `sandbox`)

## APNS Notes

When `APNS_ENABLED=true`, all APNS fields are required.
The server sends background silent pushes:

```json
{"aps":{"content-available":1}}
```

## License

MIT
