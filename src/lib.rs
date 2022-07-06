#![cfg_attr(docsrs, feature(doc_cfg))]
//! This crate provides an Actix Web middleware that supports authentication of requests based
//! on JWTs, with support for JWT invalidation without incurring a per-request performance hit of
//! making IO calls to an external datastore.
//!
//! # Example
//!
//! The example below demonstrates `Bearer` authentication. For a more expansive example showing
//! sessions-based authenticated sessions, refer to examples/inmemory.rs.
//!
//! ```
//! use std::collections::HashSet;
//! use std::ops::Add;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use actix_jwt_authc::*;
//! use actix_http::StatusCode;
//! use actix_web::web::Data;
//! use actix_web::dev::{Service, ServiceResponse};
//! use actix_web::{get, test, App, HttpResponse};
//! use dashmap::DashSet;
//! use futures::channel::{mpsc, mpsc::{channel, Sender}};
//! use futures::SinkExt;
//! use futures::stream::Stream;
//! use jsonwebtoken::*;
//! use ring::rand::SystemRandom;
//! use ring::signature::{Ed25519KeyPair, KeyPair};
//! use serde::{Deserialize, Serialize};
//! use time::ext::*;
//! use time::OffsetDateTime;
//! use uuid::Uuid;
//! use tokio::sync::Mutex;
//! # #[cfg(feature = "tracing")]
//! # use tracing::error;
//!
//! const JWT_SIGNING_ALGO: Algorithm = Algorithm::EdDSA;
//!
//! #[actix_web::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!   let jwt_ttl = JWTTtl(1.hours());
//!   let jwt_signing_keys = JwtSigningKeys::generate()?;
//!   let validator = Validation::new(JWT_SIGNING_ALGO);
//!
//!   let auth_middleware_settings = AuthenticateMiddlewareSettings {
//!       # #[cfg(feature = "session")]
//!       # jwt_session_key: Some(JWTSessionKey("jwt-session".to_string())),
//!       jwt_decoding_key: jwt_signing_keys.decoding_key,
//!       jwt_authorization_header_prefixes: Some(vec!["Bearer".to_string()]),
//!       jwt_validator: validator,
//!   };
//!
//!   let (invalidated_jwts_store, stream) = InvalidatedJWTStore::new_with_stream();
//!   let auth_middleware_factory = AuthenticateMiddlewareFactory::<Claims>::new(
//!     stream,
//!     auth_middleware_settings.clone(),
//!   );
//!
//!   /// To instantiate a real running app, consult Actix docs
//!   let app = {
//!      test::init_service(
//!          App::new()
//!              .app_data(Data::new(invalidated_jwts_store.clone()))
//!              .app_data(Data::new(jwt_signing_keys.encoding_key.clone()))
//!              .app_data(Data::new(jwt_ttl.clone()))
//!              .wrap(auth_middleware_factory.clone())
//!              .service(login)
//!              .service(logout)
//!              .service(session_info)
//!       )
//!     }.await;
//!
//!   let unauthenticated_session_req = test::TestRequest::get().uri("/session").to_request();
//!   let unauthenticated_resp = test::call_service(&app, unauthenticated_session_req).await;
//!   assert_eq!(StatusCode::UNAUTHORIZED, unauthenticated_resp.status());
//!
//!   let login_resp = {
//!     let req = test::TestRequest::get().uri("/login").to_request();
//!     test::call_service(&app, req).await
//!   };
//!   let login_response: LoginResponse = test::read_body_json(login_resp).await;
//!   let (login_response, session_req) = {
//!     let req = test::TestRequest::get().uri("/session").insert_header((
//!       "Authorization",
//!       format!("Bearer {}", login_response.bearer_token),
//!     ));
//!    (login_response, req)
//!   };
//!   let session_resp = test::call_service(&app, session_req.to_request()).await;
//!   assert_eq!(StatusCode::OK, session_resp.status());
//!   let session_response: Authenticated<Claims> = test::read_body_json(session_resp).await;
//!   assert_eq!(login_response.claims, session_response.claims);
//!
//!   let logout_req = test::TestRequest::get().uri("/logout").insert_header((
//!     "Authorization",
//!     format!("Bearer {}", login_response.bearer_token),
//!   ));
//!   let logout_resp = test::call_service(&app, logout_req.to_request()).await;
//!   assert_eq!(StatusCode::OK, logout_resp.status());
//!   assert!(invalidated_jwts_store.store.contains(&JWT(login_response.bearer_token.clone())));
//!
//!   // Wait until middleware reloads invalidated JWTs from central store
//!   tokio::time::sleep(Duration::from_millis(100)).await;
//!
//!   let session_resp_after_logout = {
//!     let req = test::TestRequest::get().uri("/session").insert_header((
//!       "Authorization",
//!       format!("Bearer {}", login_response.bearer_token),
//!     ));
//!     let resp: actix_web::Error = app.call(req.to_request()).await.err().unwrap();
//!     ServiceResponse::new(
//!       test::TestRequest::get().uri("/session").to_http_request(),
//!       resp.error_response(),
//!     )
//!   };
//!   assert_eq!(StatusCode::UNAUTHORIZED, session_resp_after_logout.status());
//!   Ok(())
//! }
//!
//! #[get("/login")]
//! async fn login(
//!     jwt_encoding_key: Data<EncodingKey>,
//!     jwt_ttl: Data<JWTTtl>
//! ) -> Result<HttpResponse, Error> {
//!     let sub = format!("{}", Uuid::new_v4().as_u128());
//!     let iat = OffsetDateTime::now_utc().unix_timestamp() as usize;
//!     let expires_at = OffsetDateTime::now_utc().add(jwt_ttl.0);
//!     let exp = expires_at.unix_timestamp() as usize;
//!
//!     let jwt_claims = Claims { iat, exp, sub };
//!     let jwt_token = encode(
//!         &Header::new(JWT_SIGNING_ALGO),
//!         &jwt_claims,
//!         &jwt_encoding_key,
//!     )
//!     .map_err(|_| Error::InternalError)?;
//!     let login_response = LoginResponse {
//!         bearer_token: jwt_token,
//!         claims: jwt_claims,
//!     };
//!
//!     Ok(HttpResponse::Ok().json(login_response))
//! }
//!
//! #[get("/session")]
//! async fn session_info(authenticated: Authenticated<Claims>) -> Result<HttpResponse, Error> {
//!     Ok(HttpResponse::Ok().json(authenticated))
//! }
//!
//! #[get("/logout")]
//! async fn logout(
//!     invalidated_jwts: Data<InvalidatedJWTStore>,
//!     authenticated: Authenticated<Claims>
//! ) -> Result<HttpResponse, Error> {
//!     invalidated_jwts.add_to_invalidated(authenticated).await;
//!     Ok(HttpResponse::Ok().json(EmptyResponse {}))
//! }
//!
//! #[derive(Clone)]
//! struct InvalidatedJWTStore {
//!     store: Arc<DashSet<JWT>>,
//!     tx: Arc<Mutex<Sender<InvalidatedTokensEvent>>>,
//! }
//!
//! impl InvalidatedJWTStore {
//!
//!     /// Returns a [InvalidatedJWTStore] with a Stream of [InvalidatedTokensEvent]s
//!     fn new_with_stream() -> (InvalidatedJWTStore, impl Stream<Item = InvalidatedTokensEvent>) {
//!         let invalidated = Arc::new(DashSet::new());
//!         let (tx, rx) = mpsc::channel(100);
//!         let tx_to_hold = Arc::new(Mutex::new(tx));
//!         (
//!             InvalidatedJWTStore {
//!                 store: invalidated,
//!                 tx: tx_to_hold,
//!             },
//!             rx,
//!         )
//!     }
//!
//!     async fn add_to_invalidated(&self, authenticated: Authenticated<Claims>) {
//!         self.store.insert(authenticated.jwt.clone());
//!         let mut tx = self.tx.lock().await;
//!         if let Err(_e) = tx
//!             .send(InvalidatedTokensEvent::Add(authenticated.jwt))
//!             .await
//!         {
//!             #[cfg(feature = "tracing")]
//!             error!(error = ?_e, "Failed to send update on adding to invalidated")
//!         }
//!     }
//! }
//!
//! struct JwtSigningKeys {
//!   encoding_key: EncodingKey,
//!   decoding_key: DecodingKey,
//! }
//!
//! impl JwtSigningKeys {
//!     fn generate() -> Result<Self, Box<dyn std::error::Error>> {
//!         let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
//!         let keypair = Ed25519KeyPair::from_pkcs8(doc.as_ref())?;
//!         let encoding_key = EncodingKey::from_ed_der(doc.as_ref());
//!         let decoding_key = DecodingKey::from_ed_der(keypair.public_key().as_ref());
//!         Ok(JwtSigningKeys {
//!             encoding_key,
//!             decoding_key,
//!         })
//!     }
//! }
//!
//! #[derive(Clone, Copy)]
//! struct JWTTtl(time::Duration);
//!
//! #[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
//! struct Claims {
//!     exp: usize,
//!     iat: usize,
//!     sub: String,
//! }
//!
//! #[derive(Serialize, Deserialize)]
//! struct EmptyResponse {}
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct LoginResponse {
//!     bearer_token: String,
//!     claims: Claims,
//! }
//! ```

pub use authentication::*;
pub use errors::*;

mod authentication;
mod errors;
