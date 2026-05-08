# Security Policy

`pigeon-relay` is a zero-knowledge relay for an end-to-end encrypted messenger. Cryptographic and protocol-level vulnerabilities are taken seriously and handled privately.

## Reporting a Vulnerability

**Do not open public GitHub issues for security problems.**

Email **security@example.com** with:

- A description of the issue and the impact you believe it has.
- Steps to reproduce, or a proof-of-concept if you have one.
- The affected commit hash or release tag.
- Whether the issue is exploitable against a deployed relay or only a local build.

You will get an acknowledgement within **72 hours**. If you do not, please follow up — the email may have been missed.

GitHub's [private vulnerability reporting](https://github.com/oliverrowebardeen/pigeon-relay/security/advisories/new) is also enabled and is an acceptable alternative channel.

## Disclosure Process

1. Acknowledge the report (≤ 72 hours).
2. Confirm or refute the issue and assess severity.
3. Develop a fix in a private branch.
4. Coordinate a disclosure timeline with the reporter (default: 90 days from acknowledgement, or sooner if a fix ships).
5. Publish a GitHub Security Advisory crediting the reporter (if they consent) when the fix is released.

There is no monetary bug bounty. Reporters who prefer attribution are credited in the advisory and the release notes.

## Scope

**In scope:**

- Anything in this repository: the relay binary, its protocol, dependencies pinned in `Cargo.lock`, CI configuration.
- Cryptographic claims made in `README.md` (zero-knowledge relay, sealed sender, accountless ECDH challenge-response, constant-time verification).
- Issues that allow sender↔recipient correlation, identity recovery, message-content recovery, or unauthorized message delivery.
- Resource exhaustion that is not bounded by the configured caps.

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

The relay is designed under the assumption that the operator and the server itself are **untrusted by clients**. Clients do not rely on the relay for confidentiality, authenticity, or sender privacy beyond what the protocol enforces. The relay sees only opaque blobs and identity hashes; any vulnerability that lets the relay learn more than that is in scope.

The relay does **not** defend against:

- A global passive network adversary correlating connections by timing (mitigation belongs at the transport layer, e.g. Tor).
- Compromise of a client device (out of scope; the client is responsible for its own keys).
- Misuse of the relay's identity model by clients that re-use keys across contexts.
