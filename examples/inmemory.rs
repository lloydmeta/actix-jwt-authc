use std::collections::HashSet;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "session")]
use actix_session::storage::CookieSessionStore;
#[cfg(feature = "session")]
use actix_session::{Session, SessionMiddleware};
#[cfg(feature = "session")]
use actix_web::cookie::Key;
use actix_web::web::Data;
use actix_web::{get, rt, App, HttpResponse, HttpServer};
use dashmap::DashMap;
use futures::channel::{mpsc, mpsc::Sender};
use futures::{SinkExt, Stream};
use jsonwebtoken::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use time::ext::*;
use time::OffsetDateTime;
use tokio::sync::Mutex;
#[cfg(feature = "tracing")]
use tracing::{error, trace, Level};
#[cfg(feature = "tracing")]
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

use actix_jwt_authc::*;

const JWT_SIGNING_ALGO: Algorithm = Algorithm::EdDSA;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "tracing")]
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    #[cfg(feature = "tracing")]
    tracing::subscriber::set_global_default(subscriber)?;

    let jwt_signing_keys = JwtSigningKeys::generate()?;
    #[cfg(feature = "session")]
    let jwt_session_key = JWTSessionKey("jwt-session".to_string());
    let auth_middleware_settings = {
        AuthenticateMiddlewareSettings {
            jwt_decoding_key: jwt_signing_keys.decoding_key,
            #[cfg(feature = "session")]
            jwt_session_key: Some(jwt_session_key.clone()),
            jwt_authorization_header_prefixes: Some(vec!["Bearer".to_string()]),
            jwt_validator: Validation::new(JWT_SIGNING_ALGO),
        }
    };

    let (invalidated_jwts_store, invalidation_events_stream) =
        InvalidatedJWTStore::new_with_stream();

    // This emulates a mechanism that purges expired tokens; in real life, this will probably be
    // an out-of-band thing that is called once a day or so.
    let invalidated_jwts_store_for_cleanup = invalidated_jwts_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            invalidated_jwts_store_for_cleanup.purge_expired().await;
        }
    });

    let auth_middleware_factory = AuthenticateMiddlewareFactory::<Claims>::new(
        invalidation_events_stream,
        auth_middleware_settings.clone(),
    );

    #[cfg(feature = "session")]
    let session_encryption_key = Key::generate();

    HttpServer::new(move || {
        #[cfg(feature = "session")]
        let app_t = App::new()
            .app_data(Data::new(jwt_session_key.clone()))
            .app_data(Data::new(invalidated_jwts_store.clone()))
            .app_data(Data::new(jwt_signing_keys.encoding_key.clone()))
            .wrap(auth_middleware_factory.clone())
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    session_encryption_key.clone(),
                )
                .cookie_secure(false)
                .cookie_http_only(true)
                .build(),
            );
        #[cfg(not(feature = "session"))]
        let app_t = App::new()
            .app_data(Data::new(invalidated_jwts_store.clone()))
            .app_data(Data::new(jwt_signing_keys.encoding_key.clone()))
            .wrap(auth_middleware_factory.clone());
        app_t
            .service(login)
            .service(logout)
            .service(session_info)
            .service(maybe_session_info)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}

// <-- Routes
#[get("/login")]
async fn login(
    jwt_encoding_key: Data<EncodingKey>,
    #[cfg(feature = "session")] jwt_session_key: Data<JWTSessionKey>,
    #[cfg(feature = "session")] session: Session,
) -> Result<HttpResponse, Error> {
    let sub = format!("{}", Uuid::new_v4().as_u128());
    let iat = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let expires_at = OffsetDateTime::now_utc().add(1.days());
    let exp = expires_at.unix_timestamp() as usize;

    let jwt_claims = Claims { iat, exp, sub };
    let jwt_token = encode(
        &Header::new(JWT_SIGNING_ALGO),
        &jwt_claims,
        &jwt_encoding_key,
    )
    .map_err(|_| Error::InternalError)?;
    let login_response = LoginResponse {
        bearer_token: jwt_token.as_str(),
        claims: jwt_claims,
    };
    #[cfg(feature = "session")]
    session
        .insert(&jwt_session_key.0, &jwt_token)
        .map_err(|_| Error::InternalError)?;

    Ok(HttpResponse::Ok().json(login_response))
}

#[get("/session")]
async fn session_info(authenticated: Authenticated<Claims>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(authenticated))
}

#[get("/maybe_session")]
async fn maybe_session_info(
    maybe_authenticated: MaybeAuthenticated<Claims>,
) -> Result<HttpResponse, Error> {
    if let Some(authenticated) = maybe_authenticated.into_option() {
        Ok(HttpResponse::Ok().json(authenticated))
    } else {
        Ok(HttpResponse::Ok().json(MessageResponse {
            message: "No session for you !",
        }))
    }
}

#[get("/logout")]
async fn logout(
    invalidated_jwts: Data<InvalidatedJWTStore>,
    authenticated: Authenticated<Claims>,
    #[cfg(feature = "session")] session: Session,
) -> Result<HttpResponse, Error> {
    #[cfg(feature = "session")]
    session.clear();
    invalidated_jwts.add_to_invalidated(authenticated).await;
    Ok(HttpResponse::Ok().json(EmptyResponse {}))
}

//     Routes -->

#[derive(Clone)]
struct InvalidatedJWTStore {
    store: Arc<DashMap<JWT, OffsetDateTime>>,
    tx: Arc<Mutex<Sender<InvalidatedTokensEvent>>>,
}

impl InvalidatedJWTStore {
    /// Returns a [InvalidatedJWTStore] with a Stream of [InvalidatedTokensEvent]s
    fn new_with_stream() -> (
        InvalidatedJWTStore,
        impl Stream<Item = InvalidatedTokensEvent>,
    ) {
        let invalidated: Arc<DashMap<JWT, OffsetDateTime>> = Arc::new(DashMap::new());

        // Since this is an in-memory, single server example, we use an in-memory channel to send
        // changes to the middleware. In Real Life ™, this could be powered by a pub-sub / events
        // channel for invalidated JWTs.
        let (tx, rx) = mpsc::channel(100);
        let mut tx_for_reload = tx.clone();
        let invalidated_for_reload = invalidated.clone();

        // In this implementation, every once in a while, we send a full reload from the data store
        // down the stream in case we missed on any updates.
        rt::spawn(async move {
            let mut full_reload_interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                full_reload_interval.tick().await;
                if invalidated_for_reload.is_empty() {
                    #[cfg(feature = "tracing")]
                    trace!("No invalidated tokens, skipping periodic full reload")
                } else {
                    if let Err(_e) = tx_for_reload
                        .send(InvalidatedTokensEvent::Full(
                            invalidated_for_reload
                                .iter()
                                .map(|k| k.key().clone())
                                .collect(),
                        ))
                        .await
                    {
                        #[cfg(feature = "tracing")]
                        error!(error = ?_e, "Failed to send periodic full reload")
                    }
                }
            }
        });
        let tx_to_hold = Arc::new(Mutex::new(tx));
        (
            InvalidatedJWTStore {
                store: invalidated,
                tx: tx_to_hold,
            },
            rx,
        )
    }

    async fn add_to_invalidated(&self, authenticated: Authenticated<Claims>) -> () {
        if let Ok(expiry) = OffsetDateTime::from_unix_timestamp(authenticated.claims.exp as i64) {
            self.store.insert(authenticated.jwt.clone(), expiry);
            let mut tx = self.tx.lock().await;
            if let Err(_e) = tx
                .send(InvalidatedTokensEvent::Add(authenticated.jwt))
                .await
            {
                #[cfg(feature = "tracing")]
                error!(error = ?_e, "Failed to send update on adding to invalidated")
            }
        }
    }

    async fn purge_expired(&self) {
        let expired: HashSet<JWT> = self
            .store
            .iter()
            .filter_map(|e| {
                if e.value() < &mut OffsetDateTime::now_utc() {
                    Some(e.key().clone())
                } else {
                    None
                }
            })
            .collect();
        if expired.is_empty() {
            #[cfg(feature = "tracing")]
            trace!("No expired invalidated tokens found")
        } else {
            self.store.retain(|k, _| !expired.contains(k));
            let mut tx = self.tx.lock().await;
            if let Err(_e) = tx
                .send(InvalidatedTokensEvent::Diff {
                    add: None,
                    remove: Some(expired),
                })
                .await
            {
                {
                    #[cfg(feature = "tracing")]
                    error!(error = ?_e, "Failed to send expired diff")
                }
            }
        }
    }
}

struct JwtSigningKeys {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtSigningKeys {
    fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
        let keypair = Ed25519KeyPair::from_pkcs8(doc.as_ref())?;
        let encoding_key = EncodingKey::from_ed_der(doc.as_ref());
        let decoding_key = DecodingKey::from_ed_der(keypair.public_key().as_ref());
        Ok(JwtSigningKeys {
            encoding_key,
            decoding_key,
        })
    }
}

// <-- Responses

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    exp: usize,
    iat: usize,
    sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse<'a> {
    bearer_token: &'a str,
    claims: Claims,
}

#[derive(Serialize, Deserialize)]
struct EmptyResponse {}

#[derive(Serialize, Deserialize)]
struct MessageResponse<'a> {
    message: &'a str,
}

//     Responses -->
