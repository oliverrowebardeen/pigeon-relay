# pigeon-relay

Minimal authenticated websocket relay for Pigeon encrypted message envelopes.

## Features

- Auth challenge-response using existing Curve25519 keypairs (no accounts)
- Encrypted blob queue keyed by recipient public-key hash
- Delivery ack routing (`msg_ack` -> `msg_acked`)
- In-memory queue with TTL and dedup
- Optional APNS silent background pushes for offline recipients

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

## Bridge / NAT Behavior

`pigeon-relay` does not need a separate server-side bridge mode.

- A bridge phone keeps its own normal `/v1/ws` session.
- Each BLE-only peer tunneled through that bridge opens its own normal `/v1/ws` session and authenticates as itself.
- The relay still tracks one active session per identity, not "bridge acting on behalf of peers".
- Several identities can safely connect from the same public IP / NAT. That is the expected production shape when one bridge device carries relay traffic for nearby peers.

Rate limiting is intentionally scoped this way:

- Before auth: per websocket connection (`anon:<connection-id>`)
- After auth: per authenticated identity hash

That prevents one bridged peer from consuming the authenticated budget for every other peer behind the same bridge.

## Local Run

```bash
source .env 2>/dev/null || true
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
  - Use `production` for TestFlight and App Store builds.
  - Use `sandbox` for debug builds installed directly from Xcode on a device.

## APNS Notes

When `APNS_ENABLED=true`, all APNS fields are required.

The relay now sends a silent background push for offline recipients:

```json
{
  "aps": {
    "content-available": 1
  },
  "pigeon_type": "relay_message"
}
```

The relay no longer sends a user-visible APNS alert. Recipients only get a background wake signal when iOS chooses to deliver it.

## License

MIT
