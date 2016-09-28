use std::fmt;
use std::error::Error;
use std::thread::JoinHandle;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::convert::From;
use std::io;
use std::str::FromStr;
use std::env;

use rustc_serialize::json::DecoderError;
use chrono::NaiveDateTime;
use {Token, Scope, InitializationError};
use super::{TokenError, TokenManager, ManagedToken, TokenResult};
use client::credentials::{CredentialsPair, CredentialsPairProvider};


mod manager_loop;

#[cfg(feature = "hyper")]
pub mod hypertokenmanager;

/// Values needed to configure a `SelfUpdatingTokenManager`
pub struct SelfUpdatingTokenManagerConfig {
    pub refresh_percentage_threshold: f32,
    pub warning_percentage_threshold: f32,
    pub managed_tokens: Vec<ManagedToken>,
}

impl SelfUpdatingTokenManagerConfig {
    /// Create a new instance from scratch
    pub fn new(managed_tokens: Vec<ManagedToken>,
               refresh_percentage_threshold: f32,
               warning_percentage_threshold: f32)
               -> SelfUpdatingTokenManagerConfig {
        SelfUpdatingTokenManagerConfig {
            refresh_percentage_threshold: refresh_percentage_threshold,
            warning_percentage_threshold: warning_percentage_threshold,
            managed_tokens: managed_tokens,
        }
    }

    /// Creates a new instance with some environment variables
    ///
    /// Environment vars used:
    ///
    /// * `RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR`(mandatory): The percentage of the lifetime of the `Token` after which a new one will be requested.
    /// * `RUSTY_TOKENS_TOKEN_MANAGER_WARNING_FACTOR`(mandatory): The percentage of the lifetime of the `Token` after a warning will be logged.
    /// Should be greater than `RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR`.
    pub fn new_from_env(managed_tokens: Vec<ManagedToken>)
                        -> Result<SelfUpdatingTokenManagerConfig, InitializationError> {
        let refresh_percentage_threshold_str =
            try!{ env::var("RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR") };
        let refresh_percentage_threshold = try!{ f32::from_str(&refresh_percentage_threshold_str) };

        let warning_percentage_threshold_str =
            try!{ env::var("RUSTY_TOKENS_TOKEN_MANAGER_WARNING_FACTOR") };
        let warning_percentage_threshold = try!{ f32::from_str(&warning_percentage_threshold_str) };
        Ok(SelfUpdatingTokenManagerConfig {
            refresh_percentage_threshold: refresh_percentage_threshold,
            warning_percentage_threshold: warning_percentage_threshold,
            managed_tokens: managed_tokens,
        })
    }
}

/// Returned by an `AccessTokenProvider`
#[derive(Debug, PartialEq, Clone)]
pub struct AccessToken {
    pub token: Token,
    pub issued_at_utc: NaiveDateTime,
    pub valid_until_utc: NaiveDateTime,
}

pub type RequestAccessTokenResult = Result<AccessToken, RequestAccessTokenError>;

/// Fetches `AccessToken`s
pub trait AccessTokenProvider {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        credentials: &CredentialsPair)
                        -> RequestAccessTokenResult;
}

/// A `TokenManager` that autonomously updates its `Token`s
///
/// Internally updates its state by using a seperate thread.
#[derive(Clone)]
pub struct SelfUpdatingTokenManager {
    token_state: Arc<RwLock<HashMap<String, TokenResult>>>,
    stop_requested: Arc<RwLock<bool>>,
}

impl SelfUpdatingTokenManager {
    /// Create a new instance from scratch
    #[must_use]
    pub fn new<T, U>(conf: SelfUpdatingTokenManagerConfig,
                     credentials_provider: U,
                     access_token_provider: T)
                     -> Result<(SelfUpdatingTokenManager, JoinHandle<()>), InitializationError>
        where T: AccessTokenProvider + Send + 'static,
              U: CredentialsPairProvider + Send + 'static
    {
        let provider = SelfUpdatingTokenManager {
            token_state: Arc::new(RwLock::new(HashMap::new())),
            stop_requested: Arc::new(RwLock::new(false)),
        };
        let join_handle = try!{manager_loop::start_manager(provider.token_state.clone(),
                      credentials_provider,
                      access_token_provider,
                      conf,
                      provider.stop_requested.clone())};
        Ok((provider, join_handle))
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
    IoError(String),
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
                write!(f, "ConnectionError: {}", message)
            }
            RequestAccessTokenError::IoError(ref message) => write!(f, "IoError: {}", message),
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
            RequestAccessTokenError::InternalError(ref message) |
            RequestAccessTokenError::ConnectionError(ref message) |
            RequestAccessTokenError::InvalidCredentials(ref message) |
            RequestAccessTokenError::ParsingError(ref message) |
            RequestAccessTokenError::IoError(ref message) => message.as_ref(),
            RequestAccessTokenError::RequestError { .. } => "A request failed",
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl From<io::Error> for RequestAccessTokenError {
    fn from(err: io::Error) -> Self {
        RequestAccessTokenError::IoError(format!("{}", err))
    }
}

impl From<DecoderError> for RequestAccessTokenError {
    fn from(err: DecoderError) -> Self {
        RequestAccessTokenError::ParsingError(format!("{}", err))
    }
}

#[cfg(test)]
mod test {
    extern crate env_logger;
    use std::collections::HashMap;
    use std::thread;
    use std::sync::{Arc, RwLock};
    use std::cell::Cell;
    use std::time::Duration as TDuration;

    use Scope;
    use chrono::*;
    use Token;
    use client::{ManagedToken, TokenManager, SelfUpdatingTokenManager,
                 SelfUpdatingTokenManagerConfig, TokenResult};
    use client::credentials::{Credentials, CredentialsPair, StaticCredentialsProvider};
    use client::implementation::{AccessToken, AccessTokenProvider, RequestAccessTokenResult,
                                 RequestAccessTokenError};
    // use super::{TokenData, update_token_data, manager_loop};


    struct MultipleAccessTokensProviderMock {
        results: Vec<RequestAccessTokenResult>,
        counter: Cell<usize>,
    }

    impl MultipleAccessTokensProviderMock {
        fn new(results: Vec<RequestAccessTokenResult>) -> MultipleAccessTokensProviderMock {
            MultipleAccessTokensProviderMock {
                results: results,
                counter: Cell::new(0),
            }
        }
    }

    impl AccessTokenProvider for MultipleAccessTokensProviderMock {
        fn get_access_token(&self,
                            _scopes: &[Scope],
                            _credentials: &CredentialsPair)
                            -> RequestAccessTokenResult {
            let next: usize = self.counter.get();
            self.counter.set(next + 1);
            if next < self.results.len() {
                self.results[next].clone()
            } else {
                Err(RequestAccessTokenError::InternalError(format!("error_{}", next)))
            }
        }
    }

    #[test]
    fn basic_manager_test() {
        let _ = env_logger::init();

        let now = UTC::now();

        let refresh_percentage_threshold = 0.5f32;
        let warning_percentage_threshold = 1.0f32;
        let managed_token = ManagedToken::new("my_token".to_owned())
            .with_scope(Scope::from_str("test"));

        let config = SelfUpdatingTokenManagerConfig {
            refresh_percentage_threshold: refresh_percentage_threshold,
            warning_percentage_threshold: warning_percentage_threshold,
            managed_tokens: vec![managed_token],
        };


        let sample_access_tokens =
            vec![Ok(AccessToken {
                     token: Token(String::from("token_1")),
                     issued_at_utc: now.naive_utc() - Duration::seconds(0),
                     valid_until_utc: now.naive_utc() + Duration::seconds(10),
                 }),
                 Ok(AccessToken {
                     token: Token(String::from("token_2")),
                     issued_at_utc: now.naive_utc() - Duration::seconds(20),
                     valid_until_utc: now.naive_utc() + Duration::seconds(20),
                 }),
                 Ok(AccessToken {
                     token: Token(String::from("token_3")),
                     issued_at_utc: now.naive_utc() - Duration::seconds(30),
                     valid_until_utc: now.naive_utc() + Duration::seconds(30),
                 })];

        let access_token_provider = MultipleAccessTokensProviderMock::new(sample_access_tokens);

        let credentials_provider = StaticCredentialsProvider::new(String::new(),
                                                                  String::new(),
                                                                  String::new(),
                                                                  String::new());

        let (manager, join_handle) =
            SelfUpdatingTokenManager::new(config, credentials_provider, access_token_provider)
                .unwrap();

        let mut collected_tokens = Vec::new();

        thread::sleep(TDuration::from_secs(3));

        let token_result: TokenResult = manager.get_token("my_token");
        if token_result.is_ok() {
            collected_tokens.push(token_result.unwrap());
        }

        thread::sleep(TDuration::from_secs(5));

        let token_result: TokenResult = manager.get_token("my_token");
        if token_result.is_ok() {
            collected_tokens.push(token_result.unwrap());
        }

        thread::sleep(TDuration::from_secs(5));

        let token_result: TokenResult = manager.get_token("my_token");
        if token_result.is_ok() {
            collected_tokens.push(token_result.unwrap());
        }

        manager.stop();

        join_handle.join().unwrap();

        assert_eq!(vec![Token::new("token_1"), Token::new("token_2"), Token::new("token_3")],
                   collected_tokens);

    }
}
