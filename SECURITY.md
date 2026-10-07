# Security Policy

`pigeon-relay` forwards opaque encrypted envelopes for an end-to-end encrypted messenger. Cryptographic and protocol-level vulnerabilities are taken seriously and handled privately.

## Reporting a Vulnerability

**Do not open public GitHub issues for security problems.**

Use GitHub's [private vulnerability reporting](https://github.com/oliverrowebardeen/pigeon-relay/security/advisories/new) with:

- A description of the issue and the impact you believe it has.
- Steps to reproduce, or a proof-of-concept if you have one.
- The affected commit hash or release tag.
- Whether the issue is exploitable against a deployed relay or only a local build.

Reports are handled on a best-effort basis without a guaranteed response time.

If the private reporting form is unavailable, open an issue asking the maintainer to enable private vulnerability reporting. Include **no vulnerability details, exploit code, personal information, or credentials** in that public request. Wait for a private channel before sending the report.

## Disclosure Process

1. Acknowledge the report.
2. Confirm or refute the issue and assess severity.
3. Develop a fix in a private branch.
4. Coordinate a disclosure timeline with the reporter (default: 90 days from acknowledgement, or sooner if a fix ships).
5. Publish a GitHub Security Advisory crediting the reporter (if they consent) when the fix is released.

There is no monetary bug bounty. Reporters who prefer attribution are credited in the advisory and the release notes.

## Scope

**In scope:**

- Anything in this repository: the relay binary, its protocol, dependencies pinned in `Cargo.lock`, CI configuration.
- Cryptographic claims made in `README.md` (opaque envelope forwarding, sealed sender, accountless ECDH challenge-response, constant-time verification).
- Issues that allow sender↔recipient correlation, identity recovery, message-content recovery, or unauthorized message delivery.
- Resource exhaustion that bypasses configured caps or introduces unbounded protocol resource use, accounting for the known limitations below.

**Out of scope (report to the respective project):**

- The Pigeon iOS client (separate repository).
- Pigeon firmware nodes (separate repository).
- Vulnerabilities in third-party services like APNS itself.
- Issues that require physical access to a deployed relay's machine, or root on the host.
- Denial of service via volumetric network attacks (these are an operator concern, not a protocol concern). DoS via protocol-level amplification or unbounded resource use **is** in scope.

## Testing

- Test against your own local build, not against any deployed relay you do not operate.
- The repository is MIT-licensed and freely buildable; spinning up a local instance for testing is the expected workflow.

## Threat Model Summary

The relay is designed under the assumption that the operator and the server itself are **untrusted by clients**. Clients do not rely on the relay for confidentiality, authenticity, or sender privacy beyond what the protocol enforces. The relay sees opaque envelopes, authentication public keys, recipient identity hashes, source network addresses, connection timing, message sizes, and APNS device tokens when push is enabled. Send sockets omit authenticated sender identity, but traffic analysis can still correlate send and receive connections. Content disclosure or violations of the documented authentication boundary are in scope.

The relay does **not** defend against:

- A global passive network adversary correlating connections by timing (mitigation belongs at the transport layer, e.g. Tor).
- Compromise of a client device (out of scope; the client is responsible for its own keys).
- Misuse of the relay's identity model by clients that re-use keys across contexts.

## Known Resource Limitations

- `RELAY_MAX_CONNECTIONS` bounds upgraded WebSocket sessions, not pre-upgrade TCP/HTTP connections. Operators need connection and request limits at a TLS reverse proxy or network edge.
- Unauthenticated (sealed-sender) send budgets are per connection and reset on reconnect. They are not a global abuse-prevention limit. Rate-limit tracking entries have time-based cleanup but no global entry-count cap, so rapid connection/identity churn can grow that map between cleanups.
- APNS requests have timeouts and per-recipient cooldowns, but spawned push tasks have no global concurrency cap.
- `RELAY_MAX_TOTAL_QUEUED_BYTES` bounds charged queue storage across recipients, including bookkeeping for empty envelopes. It is not a process RSS limit: allocator/container overhead, drained messages awaiting delivery, and per-session outbound buffers are separate. Failed backlog deliveries can be dropped if concurrent enqueues consume the released capacity before requeueing. Queues are in memory and lost on restart.

These limitations remain relevant to deployment and security reports; the queue budget does not claim to prevent all denial of service.
