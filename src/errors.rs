use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Display, Error)]
pub enum Error {
    #[display(fmt = "Internal error")]
    InternalError,
    #[display(fmt = "Unauthenticated")]
    Unauthenticated,
    #[display(fmt = "Invalid session [{}]", _0)]
    InvalidSession(#[error(not(source))] String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let response = ErrorResponse {
            message: self.to_string(),
        };
        HttpResponse::build(self.status_code()).json(response)
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            Error::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Unauthenticated => StatusCode::UNAUTHORIZED,
            Error::InvalidSession(_) => StatusCode::UNAUTHORIZED,
        }
    }
}
