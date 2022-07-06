## actix-jwt-authc 
[![Crates.io](https://img.shields.io/crates/v/actix-jwt-authc.svg)](https://crates.io/crates/actix-jwt-authc)
[![docs.rs](https://img.shields.io/docsrs/actix-jwt-authc.svg?label=docs.rs)](https://docs.rs/actix-jwt-authc)
[![Continuous integration](https://github.com/lloydmeta/actix-jwt-authc/actions/workflows/ci.yaml/badge.svg)](https://github.com/lloydmeta/actix-jwt-authc/actions/workflows/ci.yaml)
[![Coverage Status](https://coveralls.io/repos/github/lloydmeta/actix-jwt-authc/badge.svg?branch=main)](https://coveralls.io/github/lloydmeta/actix-jwt-authc?branch=main)

JWT authentication middleware for Actix that supports checking for invalidated JWTs without paying the cost of a per-request
IO call. It sources invalidated JWTs from a Stream and stores them in memory.

This middleware is based on the assumption that since JWTs (should) have an expiry, ultimately, an in-memory set of 
explicitly-invalidated-yet-unexpired JWTs that are periodically reloaded should not be overwhelmingly big enough to 
cause problems. Only testing can truly answer if this assumption works for a given usecase.

[Docs for `main`](https://beachape.com/actix-jwt-authc/actix_jwt_authc)

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
  - Channel-based Stream of invalidated JWT events for powering the invalidated JWT set used by the middleware
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

### Disclaimer

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY SPECIAL, DIRECT, 
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF 
THIS SOFTWARE.
