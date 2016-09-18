use std::fmt;
use std::error::Error;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use chrono::NaiveDateTime;
use {Token, Scope, InitializationError};
use super::{TokenError, TokenManager, ManagedToken, TokenResult};
use client::credentials::{CredentialsPair, CredentialsPairProvider};


mod manager_loop;

#[cfg(feature = "hyper")]
pub mod hypertokenmanager;


pub struct SelfUpdatingTokenManagerConfig {
    pub refresh_percentage_threshold: f32,
    pub warning_percentage_threshold: f32,
    pub managed_tokens: Vec<ManagedToken>,
}

pub struct AccessToken {
    pub token: Token,
    pub issued_at_utc: NaiveDateTime,
    pub valid_until_utc: NaiveDateTime,
}

pub type RequestAccessTokenResult = Result<AccessToken, RequestAccessTokenError>;

pub trait AccessTokenProvider {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        credentials: &CredentialsPair)
                        -> RequestAccessTokenResult;
}

#[derive(Clone)]
pub struct SelfUpdatingTokenManager {
    token_state: Arc<RwLock<HashMap<String, TokenResult>>>,
    stop_requested: Arc<RwLock<bool>>,
}

impl SelfUpdatingTokenManager {
    pub fn new<T, U>(conf: SelfUpdatingTokenManagerConfig,
                     credentials_provider: U,
                     access_token_provider: T)
                     -> Result<SelfUpdatingTokenManager, InitializationError>
        where T: AccessTokenProvider + Send + 'static,
              U: CredentialsPairProvider + Send + 'static
    {
        let provider = SelfUpdatingTokenManager {
            token_state: Arc::new(RwLock::new(HashMap::new())),
            stop_requested: Arc::new(RwLock::new(false)),
        };
        try!{manager_loop::start_manager(provider.token_state.clone(),
                      credentials_provider,
                      access_token_provider,
                      conf,
                      provider.stop_requested.clone())};
        Ok(provider)
    }
}

impl TokenManager for SelfUpdatingTokenManager {
    fn get_token(&self, name: &str) -> TokenResult {
        match self.token_state.read() {
            Err(err) => Err(TokenError::InternalError(err.description().to_owned())),
            Ok(lock) => {
                let the_map = lock;
                match the_map.get(name) {
                    Some(result) => result.clone(),
                    None => Err(TokenError::NoToken),
                }
            }
        }
    }

    fn stop(&self) {
        info!("Stop requested.");
        let mut stop = self.stop_requested.write().unwrap();
        *stop = true;
    }
}

#[derive(Debug, Clone)]
pub enum RequestAccessTokenError {
    InternalError(String),
    ConnectionError(String),
    RequestError {
        status: u16,
        body: String,
    },
    InvalidCredentials(String),
    ParsingError(String),
}

impl fmt::Display for RequestAccessTokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RequestAccessTokenError::InternalError(ref message) => {
                write!(f, "InternalError: {}", message)
            }
            RequestAccessTokenError::ConnectionError(ref message) => {
                write!(f, "NotAuthenticated: {}", message)
            }
            RequestAccessTokenError::RequestError { ref status, ref body } => {
                write!(f, "A request failed with status code{}: {}", status, body)
            }
            RequestAccessTokenError::InvalidCredentials(ref message) => {
                write!(f, "InvalidCredentials: {}", message)
            }
            RequestAccessTokenError::ParsingError(ref message) => {
                write!(f, "ParsingError: {}", message)
            }
        }
    }
}

impl Error for RequestAccessTokenError {
    fn description(&self) -> &str {
        match *self {
            RequestAccessTokenError::InternalError(ref message) => message.as_ref(),
            RequestAccessTokenError::ConnectionError(ref message) => message.as_ref(),
            RequestAccessTokenError::RequestError { .. } => "A request failed",
            RequestAccessTokenError::InvalidCredentials(ref message) => message.as_ref(),
            RequestAccessTokenError::ParsingError(ref message) => message.as_ref(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}
