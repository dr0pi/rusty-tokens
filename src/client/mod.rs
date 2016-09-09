use super::{Token, Scope};
use std::collections::HashSet;
use chrono::naive::datetime::NaiveDateTime;

use client::credentials::CredentialsError;

pub mod credentials;

// #[cfg(feature = "hyper")]
// mod hypertokenmanager;
//
// #[cfg(feature = "hyper")]
// pub use client::hypertokenmanager::HyperTokenProvider;
//
// #[cfg(feature = "hyper")]
// pub use client::hypertokenmanager::HyperTokenProviderConfig;
//
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

#[derive(Clone, Debug)]
struct AccessToken {
    token: Token,
    issued_at: NaiveDateTime,
    valid_until: NaiveDateTime,
}

pub trait TokenProvider {
    fn get_token(&self, name: &str) -> Result<Token, TokenError>;
}

#[derive(Clone, Debug)]
pub enum TokenError {
    NoToken,
    InternalProblem {
        message: String,
    },
    CredentialsProblem(CredentialsError),
}
