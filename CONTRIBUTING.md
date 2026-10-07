# Contributing to pigeon-relay

Thank you for your interest in contributing to pigeon-relay. This document covers the basics you need to get started.

## Getting Started

**Prerequisites:**

- Rust 1.88 or later (the project uses edition 2024)
- Git
- A C/C++ build toolchain and CMake for AWS-LC

**Build from source:**

```sh
git clone https://github.com/oliverrowebardeen/pigeon-relay.git
cd pigeon-relay
cargo build --release --locked
```

## Running Locally

```sh
cp .env.example .env
./scripts/dev-run.sh
```

The development script exports `.env` assignments using `set -a` and defaults to `127.0.0.1:8080`. It sources `.env` as shell code, so only use a file you trust. [.env.example](.env.example) lists every relay and APNS setting, selects `RUST_LOG=pigeon_relay=info` for startup logs, and keeps APNS disabled. Replace its placeholder APNS identifiers, topic, and key paths before enabling push. See the [configuration reference](README.md#configuration) for defaults and limits. The binary itself does not read `.env` and defaults to `0.0.0.0:8080` when run directly. To verify it is running:

```sh
curl http://127.0.0.1:8080/healthz
```

## Running Tests

```sh
cargo test --all-targets --all-features --locked
```

## Code Style

All code must pass both of the following checks:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

CI enforces both. Please run them locally before pushing.

## Third-party notices

When `Cargo.lock` changes, regenerate the dependency notices from the locked
versions, including build/dev dependencies and all target platforms:

```sh
cargo install cargo-about --version 0.9.2 --features cli --locked
cargo about generate --locked --all-features --fail about.hbs -o LICENSE-THIRD-PARTY
```

Review and commit the resulting `LICENSE-THIRD-PARTY` with the lockfile. The
accepted license list in `about.toml` follows `deny.toml`; upstream license text
is preserved verbatim. Binary distributions must include the applicable notices.

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`.
2. Keep commits small and focused. Write descriptive commit messages.
3. Open a pull request against `main`.
4. In the PR body, describe *what* changed and *why*.
5. Make sure CI passes before requesting review.

## Reporting Bugs

Open an issue and include:

- A clear description of the problem.
- Steps to reproduce.
- Expected versus actual behavior.
- Relevant log output or error messages, if available.

## Security

If you discover a security vulnerability, please do **not** open a public issue. Use the private reporting route in [SECURITY.md](SECURITY.md).

