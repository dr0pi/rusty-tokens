use std::convert::From;
use super::{Token, Scope};
use client::credentials::CredentialsError;

pub mod credentials;

mod implementation;

pub use client::implementation::SelfUpdatingTokenManagerConfig;
pub use client::implementation::SelfUpdatingTokenManager;
pub use client::implementation::RequestAccessTokenError;

#[cfg(feature = "hyper")]
pub use client::implementation::hypertokenmanager::HyperTokenManager;

pub struct ManagedToken {
    pub name: String,
    pub scopes: Vec<Scope>,
    pub credentials_provider: Box<credentials::CredentialsProvider>,
}

impl ManagedToken {
    pub fn new(name: String, credentials_provider: Box<credentials::CredentialsProvider>) -> Self {
        ManagedToken {
            name: name,
            scopes: Vec::new(),
            credentials_provider: credentials_provider,
        }
    }

    pub fn with_scope(self, scope: Scope) -> Self {
        let mut x = self;
        x.scopes.push(scope);
        x
    }

    pub fn with_scopes(self, scopes: &[Scope]) -> Self {
        let mut x = self;
        for scope in scopes {
            x.scopes.push(scope.clone());
        }
        x
    }
}

pub type TokenResult = Result<Token, TokenError>;

pub trait TokenManager {
    fn get_token(&self, name: &str) -> TokenResult;
    fn stop(&self);
}

#[derive(Debug, Clone)]
pub enum TokenError {
    NoToken,
    InternalError(String),
    CredentialsError(CredentialsError),
    RequestError(RequestAccessTokenError),
}

impl From<CredentialsError> for TokenError {
    fn from(err: CredentialsError) -> Self {
        TokenError::CredentialsError(err)
    }
}

impl From<RequestAccessTokenError> for TokenError {
    fn from(err: RequestAccessTokenError) -> Self {
        TokenError::RequestError(err)
    }
}
