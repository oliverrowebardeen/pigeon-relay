# Contributing to pigeon-relay

Thank you for your interest in contributing to pigeon-relay. This document covers the basics you need to get started.

## Getting Started

**Prerequisites:**

- Rust 1.85 or later (the project uses edition 2024)
- git

**Build from source:**

```sh
git clone https://github.com/oliverrowebardeen/pigeon-relay.git
cd pigeon-relay
cargo build --release
```

## Running Locally

```sh
source .env 2>/dev/null || true && cargo run --release
```

The server binds to `0.0.0.0:8080` by default. To verify it is running:

```sh
curl http://127.0.0.1:8080/healthz
```

## Running Tests

```sh
cargo test --all-targets --all-features
```

## Code Style

All code must pass both of the following checks:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

CI enforces both. Please run them locally before pushing.

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

If you discover a security vulnerability, please do **not** open a public issue. Instead, email **security@pigeonnet.tech** with details so it can be addressed privately.

