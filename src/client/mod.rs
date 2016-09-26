//! This module is intended to be used if you are a client of a resource server.
//!
//! You can use a `TokenManager` to manage multiple tokens.
//! A `TokenManager` is manages `Tokens` configured by using 'ManagedTokens'
//! which have a name by which you can lookup a `Token`.
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

/// Used to configure a `TokenManager`.
/// Define a name for lookup and the `Scopes` you wish to be granted.
pub struct ManagedToken {
    /// The name used for a lookup when retrieving the `Token` from a `TokenManager`.
    pub name: String,
    /// The `Scopes` you wish to be granted with the `Token`.
    pub scopes: Vec<Scope>,
}

impl ManagedToken {
    /// Create a new empty `ManagedToken` without any `Scopes`.
    pub fn new(name: String) -> Self {
        ManagedToken {
            name: name,
            scopes: Vec::new(),
        }
    }

    /// Builder method. Add a `Scope`.
    pub fn with_scope(self, scope: Scope) -> Self {
        let mut x = self;
        x.scopes.push(scope);
        x
    }

    /// Builder pattern. Add multiple `Scopes`.
    pub fn with_scopes(self, scopes: &[Scope]) -> Self {
        let mut x = self;
        for scope in scopes {
            x.scopes.push(scope.clone());
        }
        x
    }
}

/// The result returned by a `TokenManager` for queried `Tokens`.
pub type TokenResult = Result<Token, TokenError>;

/// A `TokenManager`. Manages multiple `Tokens` and refreshes them automatically.
pub trait TokenManager {
    /// Lookup a `Token`. This method may fail for multiple reasons.
    fn get_token(&self, name: &str) -> TokenResult;
    fn stop(&self);
}

/// The errors that can occure when looking up a `Token`.
#[derive(Debug, Clone)]
pub enum TokenError {
    /// There is no `Token`
    NoToken,
    /// Something that can not be further specified happended
    InternalError(String),
    /// The required `Credentials` could not be fetched
    CredentialsError(CredentialsError),
    /// The `Token` could not be requested
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
