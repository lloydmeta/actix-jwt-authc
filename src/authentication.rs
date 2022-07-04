use std::collections::HashSet;
use std::future::{ready, Ready};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "session")]
use actix_session::SessionExt;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{rt, FromRequest, HttpMessage};
use async_trait::async_trait;
use derive_more::Display;
use futures_util::future::LocalBoxFuture;
use futures_util::FutureExt;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
#[cfg(feature = "tracing")]
use tracing::{error, info, trace};

use crate::errors::Error;

/// A "must-be-authenticated" type wrapper, which, when added as a parameter on a route
/// handler, will result in an 401 response if a given request cannot be authenticated.
///
/// It is generic on the claims type to allow developers to specify their own JWT claims type.
///
/// If [AuthenticateMiddleware] has been attached as middle to a [actix_web::App], this type will be
/// injected into authenticatable-requests.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Authenticated<T> {
    pub jwt: JWT,
    pub claims: T,
}

/// A "might-be-authenticated" type wrapper.
///
/// It is generic on the claims type to allow developers to specify their own JWT claims type.
///
/// If [AuthenticateMiddleware] has been attached as middle to a [actix_web::App], this type will be
/// injected into authenticatable-requests.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MaybeAuthenticated<T> {
    Just(Authenticated<T>),
    None,
}

impl<T> MaybeAuthenticated<T> {
    pub fn into_option(self) -> Option<Authenticated<T>> {
        self.into()
    }
}

impl<T> From<MaybeAuthenticated<T>> for Option<Authenticated<T>> {
    fn from(maybe_authenticated: MaybeAuthenticated<T>) -> Self {
        match maybe_authenticated {
            MaybeAuthenticated::Just(v) => Some(v),
            MaybeAuthenticated::None => None,
        }
    }
}

impl<T> FromRequest for Authenticated<T>
where
    T: Clone + 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let value = req.extensions().get::<Authenticated<T>>().cloned();
        let result = match value {
            Some(v) => Ok(v),
            None => Err(Error::Unauthenticated),
        };
        ready(result)
    }
}

impl<T> FromRequest for MaybeAuthenticated<T>
where
    T: Clone + 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let value = req.extensions().get::<Authenticated<T>>().cloned();
        let result = match value {
            Some(v) => Ok(MaybeAuthenticated::Just(v)),
            None => Ok(MaybeAuthenticated::None),
        };
        ready(result)
    }
}

/// A wrapper around JWTs
#[derive(Hash, PartialEq, Eq, Clone, Debug, Display, Serialize, Deserialize)]
pub struct JWT(pub String);

/// A wrapper to hold the key used for extracting a JWT from an [actix_session::Session]
#[cfg(feature = "session")]
#[cfg_attr(docsrs, doc(cfg(feature = "session")))]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct JWTSessionKey(pub String);

/// An opaque tag that can be used in [InvalidatedJWTsReader] implementations for improving
/// the efficiency of periodic reads
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct InvalidatedTokensTag<T = String>(pub T);

/// The happy-path result of [InvalidatedJWTsReader::read].
///
/// The variants allow implementations of [InvalidatedJWTsReader] to not need to return the full set
/// of invalidated JWTs depending on the current in-memory state, as described by [InvalidatedTokensTag],
/// thus allowing more efficiency.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum InvalidatedTokens<T = String> {
    NoChange(Option<InvalidatedTokensTag<T>>),

    Full {
        tag: Option<InvalidatedTokensTag<T>>,
        all: HashSet<JWT>,
    },

    Diff {
        tag: Option<InvalidatedTokensTag<T>>,
        add: HashSet<JWT>,
        remove: HashSet<JWT>,
    },
}

/// A reader for invalidated JWTs, for instance from an external shared data store.
#[async_trait]
pub trait InvalidatedJWTsReader<T = String> {
    /// Reads invalidated JWTs
    ///
    /// The read method will receive the last [InvalidatedTokensTag] that the middleware received
    /// as an argument, and must return either a variant of [InvalidatedTokens] or an IO error.
    async fn read(
        &self,
        tag: Option<&InvalidatedTokensTag<T>>,
    ) -> std::io::Result<InvalidatedTokens<T>>;
}

#[derive(Eq, PartialEq, Debug)]
struct InvalidatedJWTsState<T = String> {
    tag: Option<InvalidatedTokensTag<T>>,
    invalidated_jwts: HashSet<JWT>,
}

// <-- Middleware

/// Settings for [AuthenticateMiddlewareFactory]. These determine how the authentication middleware
/// will work.
#[derive(Clone)]
pub struct AuthenticateMiddlewareSettings {
    /// How frequently the in-memory set of invalidated JWTs should be reloaded
    pub invalidated_jwt_reload_frequency: Duration,

    /// JWT Decoding Key; used to ensure that JWTs were signed by a trusted source
    pub jwt_decoding_key: DecodingKey,

    /// JWT validation configuration options
    pub jwt_validator: Validation,

    /// Optional key for extracting a JWT out of a request's Session.
    ///
    /// If not provided, the middleware will not attempt to extract JWTs from Sessions.
    #[cfg(feature = "session")]
    #[cfg_attr(docsrs, doc(cfg(feature = "session")))]
    pub jwt_session_key: Option<JWTSessionKey>,

    /// Optional prefixes for extracting a JWT out of the Authorization header.
    ///
    /// The values provided should not have any extra leading or trailing spaces (e.g. "Bearer", or
    /// "ApiKey" will suffice if you expect headers to look like "Authorization:Bearer {JWT}" or
    /// "Authorization: ApiKey {JWT}").
    ///
    /// If not provided, the middleware will not attempt to extract JWTs from the Authorization
    /// header.
    pub jwt_authorization_header_prefixes: Option<Vec<String>>,
}

/// A factory for the authentication middleware.
///
/// This is meant to be instantiated once during bootstrap and *cloned* to the app factory
/// closure. That way, there is a single set of invalidated JWTs held in memory, refreshed by
/// a single periodic timer.
///
/// Cloning is cheap because internally this uses [Arc]s to hold state.
#[derive(Clone)]
pub struct AuthenticateMiddlewareFactory<ClaimsType> {
    invalidated_jwts_state: Arc<RwLock<InvalidatedJWTsState>>,
    jwt_decoding_key: Arc<DecodingKey>,
    #[cfg(feature = "session")]
    jwt_session_key: Option<Arc<JWTSessionKey>>,
    jwt_authorization_header_prefixes: Option<Arc<Vec<String>>>,
    jwt_validator: Arc<Validation>,
    _claims_type_marker: PhantomData<ClaimsType>,
}

impl<ClaimsType> AuthenticateMiddlewareFactory<ClaimsType>
where
    ClaimsType: DeserializeOwned + 'static,
{
    /// Takes an [InvalidatedJWTsReader] returns a [AuthenticateMiddlewareFactory] that knows how
    /// to periodically use the [InvalidatedJWTsReader]'s read method to re-load an in-memory
    /// set of invalidated JWTs that is then passed on to the [AuthenticateMiddleware] that it spawns.
    ///
    /// The current periodic refresh implementation assumes this method is called from within
    /// an Actix runtime.
    pub fn new<R>(
        reader: R,
        settings: AuthenticateMiddlewareSettings,
    ) -> AuthenticateMiddlewareFactory<ClaimsType>
    where
        R: InvalidatedJWTsReader + Sync + Send + 'static,
    {
        let invalidated_jwts_state = Arc::new(RwLock::new(InvalidatedJWTsState {
            tag: None,
            invalidated_jwts: HashSet::new(),
        }));
        let invalidated_jwts_state_reload_ref = invalidated_jwts_state.clone();

        let invalidated_jwt_reload_frequency = settings.invalidated_jwt_reload_frequency;

        #[cfg(feature = "tracing")]
        info!(
            frequency = ?invalidated_jwt_reload_frequency,
            "Kicking off invalidated JWT reload loop"
        );
        rt::spawn(async move {
            let mut interval = tokio::time::interval(invalidated_jwt_reload_frequency);
            loop {
                interval.tick().await;
                reload_invalidated(&reader, &invalidated_jwts_state_reload_ref).await;
            }
        });

        AuthenticateMiddlewareFactory::<ClaimsType> {
            invalidated_jwts_state,
            jwt_decoding_key: Arc::new(settings.jwt_decoding_key),
            #[cfg(feature = "session")]
            jwt_session_key: settings.jwt_session_key.map(Arc::new),
            jwt_authorization_header_prefixes: settings.jwt_authorization_header_prefixes.map(
                |prefixes| {
                    Arc::new(
                        prefixes
                            .iter()
                            .map(|prefix| format!("{} ", prefix))
                            .collect(),
                    )
                },
            ),
            jwt_validator: Arc::new(settings.jwt_validator),
            _claims_type_marker: PhantomData,
        }
    }
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(reader, invalidated_jwts_set_reload_ref))
)]
async fn reload_invalidated<R>(
    reader: &R,
    invalidated_jwts_set_reload_ref: &Arc<RwLock<InvalidatedJWTsState>>,
) where
    R: InvalidatedJWTsReader,
{
    #[cfg(feature = "tracing")]
    trace!("Running invalidated JWT reload reload");
    let mut invalidated_state = invalidated_jwts_set_reload_ref.write().await;
    let invalidated_jwts_result = reader.read(invalidated_state.tag.as_ref()).await;
    match invalidated_jwts_result {
        Ok(invalidated_jwts) => match invalidated_jwts {
            InvalidatedTokens::NoChange(tag) => {
                #[cfg(feature = "tracing")]
                trace!(tag =? tag, "No change from invalidated JWTs reader");
                invalidated_state.tag = tag;
            }
            InvalidatedTokens::Full { tag, all } => {
                #[cfg(feature = "tracing")]
                trace!(tag =? tag, count = all.len(), "Read invalidated JWTs, which returned a full set");
                invalidated_state.invalidated_jwts = all;
                invalidated_state.tag = tag;
            }
            InvalidatedTokens::Diff { tag, add, remove } => {
                #[cfg(feature = "tracing")]
                trace!(tag =? tag, add_count = add.len(), remove_count = remove.len(), "Read invalidated JWTs, which returned a diff");
                for to_remove in remove.iter() {
                    invalidated_state.invalidated_jwts.remove(to_remove);
                }
                invalidated_state.invalidated_jwts.extend(add);
                invalidated_state.tag = tag;
            }
        },
        Err(_e) => {
            #[cfg(feature = "tracing")]
            error!(error = ?_e, "Failed to fetch invalidated JWTs [{}]", _e)
        }
    }
}

impl<S, B, ClaimsType> Transform<S, ServiceRequest> for AuthenticateMiddlewareFactory<ClaimsType>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    ClaimsType: DeserializeOwned + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = AuthenticateMiddleware<S, ClaimsType>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticateMiddleware {
            invalidated_jwts_state: self.invalidated_jwts_state.clone(),
            service: Rc::new(service),
            jwt_decoding_key: self.jwt_decoding_key.clone(),
            #[cfg(feature = "session")]
            jwt_session_key: self.jwt_session_key.clone(),
            jwt_authorization_header_prefixes: self.jwt_authorization_header_prefixes.clone(),
            jwt_validator: self.jwt_validator.clone(),
            _claims_type_marker: PhantomData,
        }))
    }
}

/// The actual middleware that extracts JWTs from requests, validates them, and injects them into
/// a request.
pub struct AuthenticateMiddleware<S, ClaimsType> {
    invalidated_jwts_state: Arc<RwLock<InvalidatedJWTsState>>,
    service: Rc<S>,
    jwt_decoding_key: Arc<DecodingKey>,
    #[cfg(feature = "session")]
    jwt_session_key: Option<Arc<JWTSessionKey>>,
    jwt_authorization_header_prefixes: Option<Arc<Vec<String>>>,
    jwt_validator: Arc<Validation>,
    _claims_type_marker: PhantomData<ClaimsType>,
}

impl<S, B, ClaimsType> Service<ServiceRequest> for AuthenticateMiddleware<S, ClaimsType>
where
    ClaimsType: DeserializeOwned + 'static,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, req)))]
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let invalidated_jwts_state = self.invalidated_jwts_state.clone();
        let jwt_decoding_key = self.jwt_decoding_key.clone();
        #[cfg(feature = "session")]
        let jwt_session_key = self.jwt_session_key.clone();
        let jwt_authorization_header_prefixes = self.jwt_authorization_header_prefixes.clone();
        let validation = self.jwt_validator.clone();
        async move {
            authenticate::<S, B, ClaimsType>(
                svc,
                req,
                invalidated_jwts_state,
                &jwt_decoding_key,
                #[cfg(feature = "session")]
                jwt_session_key,
                jwt_authorization_header_prefixes,
                &validation,
            )
            .await
        }
        .boxed_local()
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
async fn authenticate<S, B, ClaimsType>(
    svc: Rc<S>,
    req: ServiceRequest,
    invalidated_jwts_state: Arc<RwLock<InvalidatedJWTsState>>,
    jwt_decoding_key: &DecodingKey,
    #[cfg(feature = "session")] jwt_session_key: Option<Arc<JWTSessionKey>>,
    jwt_authorization_header_prefixes: Option<Arc<Vec<String>>>,
    validation: &Validation,
) -> Result<ServiceResponse<B>, actix_web::Error>
where
    ClaimsType: DeserializeOwned + 'static,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
    #[cfg(feature = "tracing")]
    trace!("Attempting to authenticate");
    let maybe_jwt_from_auth_header =
        jwt_authorization_header_prefixes.and_then(|prefixes| extract_bearer_jwt(&req, &prefixes));
    #[cfg(feature = "session")]
    let maybe_extracted_jwt = maybe_jwt_from_auth_header
        .or_else(|| jwt_session_key.and_then(|key| extract_session_jwt(&req, &key)));
    #[cfg(not(feature = "session"))]
    let maybe_extracted_jwt = maybe_jwt_from_auth_header;
    if let Some(jwt) = maybe_extracted_jwt {
        #[cfg(feature = "tracing")]
        trace!(jwt = ?jwt, "JWT extracted");
        let jwt_str = jwt.0.as_str();
        if invalidated_jwts_state
            .read()
            .await
            .invalidated_jwts
            .contains(&jwt)
        {
            #[cfg(feature = "tracing")]
            trace!(jwt= ?jwt, "Invalidated JWT detected");
            Err(Error::InvalidSession(format!(
                "Invalidated session. JWT [{jwt}] was already invalidated"
            )))?;
        } else {
            let decoded_claims = decode::<ClaimsType>(jwt_str, jwt_decoding_key, validation)
                .map_err(|e| {
                    let error_message = e.to_string();
                    #[cfg(feature = "tracing")]
                    trace!("Claims failed decoding because of [{}]", error_message);
                    Error::InvalidSession(error_message)
                })?;
            #[cfg(feature = "tracing")]
            trace!("Claims successfully decoded");

            req.extensions_mut().insert(Authenticated {
                jwt,
                claims: decoded_claims.claims,
            });
        }
    }
    let res = svc.call(req).await?;
    Ok(res)
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace"))]
fn extract_bearer_jwt(req: &ServiceRequest, auth_prefixes: &[String]) -> Option<JWT> {
    let authorisation_header = req.headers().get("Authorization")?;
    let as_str = authorisation_header.to_str().ok()?;
    let jwt_str = auth_prefixes
        .iter()
        .filter_map(|prefix| as_str.strip_prefix(prefix))
        .next()?;
    Some(JWT(jwt_str.to_string()))
}

#[cfg(feature = "session")]
#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(jwt_session_key))
)]
fn extract_session_jwt(req: &ServiceRequest, jwt_session_key: &JWTSessionKey) -> Option<JWT> {
    let session = req.get_session();
    let jwt_str = session.get::<String>(&jwt_session_key.0).ok().flatten()?;
    Some(JWT(jwt_str))
}

//     Middleware -->
#[cfg(test)]
mod tests {
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::Duration;

    use actix_session::storage::CookieSessionStore;
    #[cfg(not(feature = "session"))]
    use actix_session::SessionMiddleware;
    #[cfg(feature = "session")]
    use actix_session::{Session, SessionMiddleware};
    use actix_web::cookie::Key;
    use actix_web::web::Data;
    use actix_web::{get, test, App, HttpResponse};
    use async_trait::async_trait;
    use dashmap::DashSet;
    use jsonwebtoken::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde::{Deserialize, Serialize};
    use time::ext::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    #[derive(Clone)]
    struct StubbedReader {
        received_tag: Arc<RwLock<Option<InvalidatedTokensTag>>>,
        to_return: Result<InvalidatedTokens, String>,
    }

    #[async_trait]
    impl InvalidatedJWTsReader for StubbedReader {
        async fn read(
            &self,
            tag: Option<&InvalidatedTokensTag>,
        ) -> std::io::Result<InvalidatedTokens> {
            match &self.to_return {
                Ok(_) => {
                    *self.received_tag.write().await = tag.cloned();
                    self.to_return
                        .clone()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                }
                Err(_) => self
                    .to_return
                    .clone()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        }
    }

    #[test]
    async fn test_reload_invalidated_full_replace() {
        let mut full_invalidated_set = HashSet::new();
        full_invalidated_set.insert(JWT("1".to_string()));
        full_invalidated_set.insert(JWT("2".to_string()));
        full_invalidated_set.insert(JWT("3".to_string()));

        let state = Arc::new(RwLock::new(InvalidatedJWTsState {
            tag: None,
            invalidated_jwts: HashSet::new(),
        }));

        let new_tag = InvalidatedTokensTag("new-state-tag".to_string());
        let stubbed_reader_with_tag = StubbedReader {
            received_tag: Arc::new(Default::default()),
            to_return: Ok(InvalidatedTokens::Full {
                tag: Some(new_tag.clone()),
                all: full_invalidated_set.clone(),
            }),
        };
        reload_invalidated(&stubbed_reader_with_tag, &state).await;

        assert_eq!(full_invalidated_set, state.read().await.invalidated_jwts);
        assert_eq!(Some(new_tag), state.read().await.tag);

        let stubbed_reader_no_tag = StubbedReader {
            received_tag: Arc::new(Default::default()),
            to_return: Ok(InvalidatedTokens::Full {
                tag: None,
                all: HashSet::new(),
            }),
        };
        reload_invalidated(&stubbed_reader_no_tag, &state).await;

        assert!(state.read().await.invalidated_jwts.is_empty());
        assert!(state.read().await.tag.is_none());
    }

    #[test]
    async fn test_reload_invalidated_diff() {
        let mut full_invalidated_set = HashSet::new();
        full_invalidated_set.insert(JWT("1".to_string()));
        full_invalidated_set.insert(JWT("2".to_string()));
        full_invalidated_set.insert(JWT("3".to_string()));

        let mut add_set = HashSet::new();
        add_set.insert(JWT("4".to_string()));

        let mut remove_set = HashSet::new();
        remove_set.insert(JWT("1".to_string()));

        let state = Arc::new(RwLock::new(InvalidatedJWTsState {
            tag: None,
            invalidated_jwts: full_invalidated_set,
        }));

        let new_tag = InvalidatedTokensTag("new-state-tag".to_string());
        let stubbed_reader_with_tag = StubbedReader {
            received_tag: Arc::new(Default::default()),
            to_return: Ok(InvalidatedTokens::Diff {
                tag: Some(new_tag.clone()),
                add: add_set.clone(),
                remove: remove_set,
            }),
        };
        reload_invalidated(&stubbed_reader_with_tag, &state).await;

        let mut expected_invalidated_set = HashSet::new();
        expected_invalidated_set.insert(JWT("2".to_string()));
        expected_invalidated_set.insert(JWT("3".to_string()));
        expected_invalidated_set.insert(JWT("4".to_string()));

        assert_eq!(
            expected_invalidated_set,
            state.read().await.invalidated_jwts
        );
        assert_eq!(Some(new_tag), state.read().await.tag);

        let mut remove_set_2 = HashSet::new();
        remove_set_2.insert(JWT("2".to_string()));
        remove_set_2.insert(JWT("3".to_string()));
        remove_set_2.insert(JWT("4".to_string()));

        let stubbed_reader_no_tag = StubbedReader {
            received_tag: Arc::new(Default::default()),
            to_return: Ok(InvalidatedTokens::Diff {
                tag: None,
                add: HashSet::new(),
                remove: remove_set_2,
            }),
        };
        reload_invalidated(&stubbed_reader_no_tag, &state).await;

        assert!(state.read().await.invalidated_jwts.is_empty());
        assert!(state.read().await.tag.is_none());
    }

    #[test]
    async fn test_reload_invalidated_no_change() {
        let mut full_invalidated_set = HashSet::new();
        full_invalidated_set.insert(JWT("1".to_string()));
        full_invalidated_set.insert(JWT("2".to_string()));
        full_invalidated_set.insert(JWT("3".to_string()));

        let state = Arc::new(RwLock::new(InvalidatedJWTsState {
            tag: None,
            invalidated_jwts: full_invalidated_set.clone(),
        }));

        let new_tag = InvalidatedTokensTag("new-state-tag".to_string());
        let stubbed_reader_with_tag = StubbedReader {
            received_tag: Arc::new(Default::default()),
            to_return: Ok(InvalidatedTokens::NoChange(Some(new_tag.clone()))),
        };
        reload_invalidated(&stubbed_reader_with_tag, &state).await;

        assert_eq!(full_invalidated_set, state.read().await.invalidated_jwts);
        assert_eq!(Some(new_tag), state.read().await.tag);

        let stubbed_reader_no_tag = StubbedReader {
            received_tag: Arc::new(Default::default()),
            to_return: Ok(InvalidatedTokens::NoChange(None)),
        };
        reload_invalidated(&stubbed_reader_no_tag, &state).await;

        assert_eq!(full_invalidated_set, state.read().await.invalidated_jwts);
        assert!(state.read().await.tag.is_none());
    }

    #[test]
    async fn test_extract_bearer_jwt_none() {
        let req = test::TestRequest::default().to_srv_request();
        let resp = extract_bearer_jwt(&req, vec!["Bearer ".to_string()].as_slice());
        assert!(resp.is_none());
    }

    #[test]
    async fn test_extract_bearer_jwt_some() {
        let req = test::TestRequest::default()
            .insert_header(("Authorization", "Bearer XYZ"))
            .to_srv_request();
        let resp = extract_bearer_jwt(&req, vec!["Bearer ".to_string()].as_slice());
        assert_eq!(Some(JWT("XYZ".to_string())), resp);
    }

    #[test]
    async fn test_extract_bearer_jwt_some_all_prefix_prefix() {
        for auth_header in ["ApiKey XYZ", "Bearer XYZ"] {
            let req = test::TestRequest::default()
                .insert_header(("Authorization", auth_header))
                .to_srv_request();
            let resp = extract_bearer_jwt(
                &req,
                vec!["Bearer ".to_string(), "ApiKey ".to_string()].as_slice(),
            );
            assert_eq!(Some(JWT("XYZ".to_string())), resp);
        }
    }

    #[test]
    async fn test_extract_bearer_jwt_wrong_prefix() {
        let req = test::TestRequest::default()
            .insert_header(("Authorization", "Bearer XYZ"))
            .to_srv_request();
        let resp = extract_bearer_jwt(&req, vec!["ApiKey ".to_string()].as_slice());
        assert!(resp.is_none());
    }

    #[cfg(feature = "session")]
    #[test]
    async fn test_extract_session_jwt_none() {
        let session_key = JWTSessionKey("sesh".to_string());
        let req = test::TestRequest::default().to_srv_request();
        let resp = extract_session_jwt(&req, &session_key);
        assert!(resp.is_none());
    }

    #[test]
    async fn integration_test_no_session_should_reject() {
        let fixture = build_fixture(JWTTtl::default()).await.unwrap();
        let app = fixture.app;
        let req = test::TestRequest::get().uri("/session").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(actix_http::StatusCode::UNAUTHORIZED, resp.status());
        let error_response: crate::errors::ErrorResponse = test::read_body_json(resp).await;
        assert_eq!(
            format!("{}", crate::errors::Error::Unauthenticated),
            error_response.message
        )
    }

    #[test]
    async fn integration_test_no_session_maybe_authenticated() {
        let fixture = build_fixture(JWTTtl::default()).await.unwrap();
        let app = fixture.app;
        let req = test::TestRequest::get().uri("/maybe_session").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(actix_http::StatusCode::OK, resp.status());
        let message_response: MessageResponse = test::read_body_json(resp).await;
        assert_eq!("No session for you !", message_response.message.as_str())
    }

    #[test]
    async fn integration_test_with_authentication() {
        let fixture = build_fixture(JWTTtl::default()).await.unwrap();
        let app = fixture.app;

        let login_resp = {
            let req = test::TestRequest::get().uri("/login").to_request();
            test::call_service(&app, req).await
        };
        assert_eq!(actix_http::StatusCode::OK, login_resp.status());
        #[cfg(feature = "session")]
        let (login_response, session_req) = {
            let mut req = test::TestRequest::get().uri("/session");
            for c in login_resp.response().cookies() {
                req = req.cookie(c);
            }

            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            (login_response, req)
        };
        #[cfg(not(feature = "session"))]
        let (login_response, session_req) = {
            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            let req = test::TestRequest::get().uri("/session").insert_header((
                "Authorization",
                format!("Bearer {}", login_response.bearer_token),
            ));
            (login_response, req)
        };
        let session_resp = test::call_service(&app, session_req.to_request()).await;
        assert_eq!(actix_http::StatusCode::OK, session_resp.status());
        let session_response: Authenticated<Claims> = test::read_body_json(session_resp).await;
        assert_eq!(login_response.claims, session_response.claims);
    }

    #[test]
    async fn integration_test_with_expired_authentication() {
        let fixture = build_fixture(JWTTtl(1.nanoseconds())).await.unwrap();
        let app = fixture.app;

        let login_resp = {
            let req = test::TestRequest::get().uri("/login").to_request();
            test::call_service(&app, req).await
        };
        assert_eq!(actix_http::StatusCode::OK, login_resp.status());
        tokio::time::sleep(Duration::from_secs(2)).await;
        #[cfg(feature = "session")]
        let (_login_response, session_resp) = {
            let mut req = test::TestRequest::get().uri("/session");
            for c in login_resp.response().cookies() {
                req = req.cookie(c);
            }
            let resp = app.call(req.to_request()).await.err().unwrap();
            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            (login_response, resp)
        };
        #[cfg(not(feature = "session"))]
        let (_login_response, session_resp) = {
            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            let req = test::TestRequest::get().uri("/session").insert_header((
                "Authorization",
                format!("Bearer {}", login_response.bearer_token),
            ));
            let resp = app.call(req.to_request()).await.err().unwrap();
            (login_response, resp)
        };
        let session_resp = ServiceResponse::new(
            test::TestRequest::get().uri("/session").to_http_request(),
            session_resp.error_response(),
        );
        assert_eq!(actix_http::StatusCode::UNAUTHORIZED, session_resp.status());
        let session_response: crate::errors::ErrorResponse =
            test::read_body_json(session_resp).await;
        assert_eq!(
            "Invalid session [ExpiredSignature]",
            session_response.message.as_str()
        )
    }

    #[test]
    async fn integration_test_with_invalidated_authentication() {
        let fixture = build_fixture(JWTTtl(1.nanoseconds())).await.unwrap();
        let app = fixture.app;

        let login_resp = {
            let req = test::TestRequest::get().uri("/login").to_request();
            test::call_service(&app, req).await
        };
        assert_eq!(actix_http::StatusCode::OK, login_resp.status());

        #[cfg(feature = "session")]
        let (logout_req, session_req) = {
            let mut logout_req = test::TestRequest::get().uri("/logout");
            for c in login_resp.response().cookies() {
                logout_req = logout_req.cookie(c);
            }

            let mut session_req = test::TestRequest::get().uri("/session");
            for c in login_resp.response().cookies() {
                session_req = session_req.cookie(c);
            }
            (logout_req, session_req)
        };
        #[cfg(not(feature = "session"))]
        let (logout_req, session_req) = {
            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            let session_req = test::TestRequest::get().uri("/session").insert_header((
                "Authorization",
                format!("Bearer {}", login_response.bearer_token),
            ));
            let logout_req = test::TestRequest::get().uri("/logout").insert_header((
                "Authorization",
                format!("Bearer {}", login_response.bearer_token),
            ));
            (logout_req, session_req)
        };
        let logout_resp = test::call_service(&app, logout_req.to_request()).await;
        assert_eq!(actix_http::StatusCode::OK, logout_resp.status());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let session_resp: actix_web::Error =
            { app.call(session_req.to_request()).await.err().unwrap() };
        let session_resp = {
            ServiceResponse::new(
                test::TestRequest::get().uri("/session").to_http_request(),
                session_resp.error_response(),
            )
        };
        assert_eq!(actix_http::StatusCode::UNAUTHORIZED, session_resp.status());

        let session_response: crate::errors::ErrorResponse =
            test::read_body_json(session_resp).await;
        assert!(session_response
            .message
            .as_str()
            .starts_with("Invalid session [Invalidated session"))
    }

    #[test]
    async fn integration_test_with_remotely_invalidated_session() {
        let fixture = build_fixture(JWTTtl(1.nanoseconds())).await.unwrap();
        let app = fixture.app;

        let login_resp = {
            let req = test::TestRequest::get().uri("/login").to_request();
            test::call_service(&app, req).await
        };
        assert_eq!(actix_http::StatusCode::OK, login_resp.status());
        #[cfg(feature = "session")]
        let (login_response, session_req) = {
            let mut req = test::TestRequest::get().uri("/session");
            for c in login_resp.response().cookies() {
                req = req.cookie(c);
            }

            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            (login_response, req)
        };
        #[cfg(not(feature = "session"))]
        let (login_response, session_req) = {
            let login_response: LoginResponse = test::read_body_json(login_resp).await;
            let req = test::TestRequest::get().uri("/session").insert_header((
                "Authorization",
                format!("Bearer {}", login_response.bearer_token),
            ));
            (login_response, req)
        };

        fixture
            .invalidated_jwts_store
            .0
            .insert(JWT(login_response.bearer_token));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let session_resp: actix_web::Error =
            { app.call(session_req.to_request()).await.err().unwrap() };
        let session_resp = {
            ServiceResponse::new(
                test::TestRequest::get().uri("/session").to_http_request(),
                session_resp.error_response(),
            )
        };

        assert_eq!(actix_http::StatusCode::UNAUTHORIZED, session_resp.status());
        let session_response: crate::errors::ErrorResponse =
            test::read_body_json(session_resp).await;
        assert!(session_response
            .message
            .as_str()
            .starts_with("Invalid session [Invalidated session"))
    }

    struct TestFixture<T> {
        invalidated_jwts_store: InvalidatedJWTStore,
        app: T,
    }

    /// Builds a server app, almost exactly the same as inmemory example, just with ultra-fast loops
    /// and no tracing
    async fn build_fixture(
        jwt_ttl: JWTTtl,
    ) -> Result<
        TestFixture<
            impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
        >,
        Box<dyn std::error::Error>,
    > {
        let jwt_signing_keys = JwtSigningKeys::generate()?;
        #[cfg(feature = "session")]
        let jwt_session_key = JWTSessionKey("jwt-session".to_string());

        let mut validator = Validation::new(JWT_SIGNING_ALGO);
        validator.leeway = 1;

        let auth_middleware_settings = AuthenticateMiddlewareSettings {
            invalidated_jwt_reload_frequency: Duration::from_nanos(1),
            jwt_decoding_key: jwt_signing_keys.decoding_key,
            #[cfg(feature = "session")]
            jwt_session_key: Some(jwt_session_key.clone()),
            jwt_authorization_header_prefixes: Some(vec!["Bearer".to_string()]),
            jwt_validator: validator,
        };

        let invalidated_jwts_store = InvalidatedJWTStore(Arc::new(DashSet::new()));
        let auth_middleware_factory = AuthenticateMiddlewareFactory::<Claims>::new(
            invalidated_jwts_store.clone(),
            auth_middleware_settings.clone(),
        );

        let session_encryption_key = Key::generate();

        let app = {
            #[cfg(feature = "session")]
            let app_t = App::new().app_data(Data::new(jwt_session_key.clone()));
            #[cfg(not(feature = "session"))]
            let app_t = App::new();
            test::init_service(
                app_t
                    .app_data(Data::new(invalidated_jwts_store.clone()))
                    .app_data(Data::new(jwt_signing_keys.encoding_key.clone()))
                    .app_data(Data::new(jwt_ttl.clone()))
                    .wrap(auth_middleware_factory.clone())
                    .wrap(
                        SessionMiddleware::builder(
                            CookieSessionStore::default(),
                            session_encryption_key.clone(),
                        )
                        .cookie_secure(false)
                        .cookie_http_only(true)
                        .build(),
                    )
                    .service(login)
                    .service(logout)
                    .service(session_info)
                    .service(maybe_session_info),
            )
        }
        .await;
        Ok(TestFixture {
            invalidated_jwts_store: invalidated_jwts_store.clone(),
            app,
        })
    }

    // <-- Routes
    #[get("/login")]
    async fn login(
        jwt_encoding_key: Data<EncodingKey>,
        #[cfg(feature = "session")] jwt_session_key: Data<JWTSessionKey>,
        jwt_ttl: Data<JWTTtl>,
        #[cfg(feature = "session")] session: Session,
    ) -> Result<HttpResponse, Error> {
        let sub = format!("{}", Uuid::new_v4().as_u128());
        let iat = OffsetDateTime::now_utc().unix_timestamp() as usize;
        let expires_at = OffsetDateTime::now_utc().add(jwt_ttl.0);
        let exp = expires_at.unix_timestamp() as usize;

        let jwt_claims = Claims { iat, exp, sub };
        let jwt_token = encode(
            &Header::new(JWT_SIGNING_ALGO),
            &jwt_claims,
            &jwt_encoding_key,
        )
        .map_err(|_| Error::InternalError)?;
        #[cfg(feature = "session")]
        session
            .insert(&jwt_session_key.0, &jwt_token)
            .map_err(|_| Error::InternalError)?;
        let login_response = LoginResponse {
            bearer_token: jwt_token,
            claims: jwt_claims,
        };

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
                message: "No session for you !".to_string(),
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
    //    Routes -->

    const JWT_SIGNING_ALGO: Algorithm = Algorithm::EdDSA;

    // Holds a map of encoded JWT -> expiries

    #[async_trait]
    trait InvalidatedJWTsWriter {
        async fn add_to_invalidated(&self, authenticated: Authenticated<Claims>) -> ();
    }

    #[derive(Clone)]
    struct InvalidatedJWTStore(Arc<DashSet<JWT>>);

    #[async_trait]
    impl InvalidatedJWTsWriter for InvalidatedJWTStore {
        async fn add_to_invalidated(&self, authenticated: Authenticated<Claims>) {
            self.0.insert(authenticated.jwt);
        }
    }

    #[async_trait]
    impl InvalidatedJWTsReader for InvalidatedJWTStore {
        async fn read(
            &self,
            _tag: Option<&InvalidatedTokensTag>,
        ) -> std::io::Result<InvalidatedTokens> {
            Ok(InvalidatedTokens::Full {
                tag: None,
                all: self.0.iter().map(|k| k.key().clone()).collect(),
            })
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

    #[derive(Clone, Copy)]
    struct JWTTtl(time::Duration);

    impl Default for JWTTtl {
        fn default() -> Self {
            JWTTtl(1.days())
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
    struct Claims {
        exp: usize,
        iat: usize,
        sub: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct LoginResponse {
        bearer_token: String,
        claims: Claims,
    }

    #[derive(Serialize, Deserialize)]
    struct EmptyResponse {}

    #[derive(Serialize, Deserialize)]
    struct MessageResponse {
        message: String,
    }

    //     Responses -->
}
