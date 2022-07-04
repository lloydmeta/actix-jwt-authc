## actix-jwt-authc

An JWT authentication middleware for Actix that supports checking for invalidated JWTs without paying the cost for a per-request
IO call. It does this by periodically pulling a set of invalidated JWTs and storing them in memory from a reader implementation. 

This middleware is based on the assumption that since JWTs (should) have an expiry, ultimately, an in-memory set of 
explicitly invalidated JWTs that are periodically reloaded (ie trimmed) should not be overwhelmingly big.

### Uses
- [Actix](https://actix.rs)
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) for JWT encoding + validation

### Features

- `tracing` enables instrumentation by pulling in [tracing](https://github.com/tokio-rs/tracing)
- `log` enables logs (via [tracing](https://github.com/tokio-rs/tracing)) using the [compatibility layer](https://docs.rs/tracing-log/latest/tracing_log/#convert-tracing-events-to-logs)
- `session` enables [`actix-session`](https://crates.io/crates/actix-session) integration, allowing you to extract
  JWTs from a configurable session key.

### Example

The example included in this repo has

- A simple set of routes for starting and inspecting the current session
- An in-memory implementation of the invalidated JWT interface
  - In-memory loop for purging expired JWTs from the store
- [ring](https://github.com/briansmith/ring) to generate an Ed25519 keypair for [EdDSA-signed JWTs](https://www.scottbrady91.com/jose/jwts-which-signing-algorithm-should-i-use)

Both session and JWT keys are generated on the fly, so JWTs are incompatible across restarts.

It supports `tracing` and `session` as features. To run a server on 8080:

```shell
cargo run --example inmemory --features tracing,session
```

Supported endpoints

- `/login` to start a session
- `/logout` to destroy the current session (requires a session)
- `/session` to inspect the current session (requires a session)
- `/maybe_sesion` to inspect the current session if it exists

If `session` is not passed, authentication in the example is dependent on `Bearer` tokens sent as an `Authorization` header.

