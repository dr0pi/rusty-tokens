use super::{Token, Scope};
use std::collections::HashSet;

use client::credentials::CredentialsError;

pub mod credentials;

mod implementation;

// #[cfg(feature = "hyper")]
// pub use client::hypertokenmanager::HyperTokenManager;
//
// #[cfg(feature = "hyper")]
// pub use client::hypertokenmanager::HyperTokenManagerConfig;

pub struct ManagedToken {
    pub name: String,
    pub scopes: HashSet<Scope>,
    pub credentials_provider: Box<credentials::CredentialsProvider>,
}

impl ManagedToken {
    pub fn new(name: String, credentials_provider: Box<credentials::CredentialsProvider>) -> Self {
        ManagedToken {
            name: name,
            scopes: HashSet::new(),
            credentials_provider: credentials_provider,
        }
    }

    pub fn with_scope(self, scope: Scope) -> Self {
        let mut x = self;
        x.scopes.insert(scope);
        x
    }

    pub fn with_scopes(self, scopes: &[Scope]) -> Self {
        let mut x = self;
        for scope in scopes {
            x.scopes.insert(scope.clone());
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
    InternalProblem { message: String },
    CredentialsProblem(CredentialsError),
}
