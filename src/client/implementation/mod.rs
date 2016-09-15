use std::error::Error;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::Duration;
use {Token, InitializationError};
use super::{TokenError, TokenManager, ManagedToken, TokenResult};
use client::credentials::Credentials;


mod manager_loop;


pub struct SelfUpdatingTokenManagerConfig {
    update_interval: Duration,
    managed_tokens: Vec<ManagedToken>,
}

pub struct AccessToken {
    token: Token,
}

pub struct RequestAccessTokenError {
    message: String,
}

pub type RequestAccessTokenResult = Result<AccessToken, RequestAccessTokenError>;


#[derive(Clone)]
pub struct SelfUpdatingTokenManager {
    token_state: Arc<RwLock<HashMap<String, TokenResult>>>,
    stop_requested: Arc<RwLock<bool>>,
}

impl SelfUpdatingTokenManager {
    pub fn new<T>(conf: SelfUpdatingTokenManagerConfig,
                  request_access_token: Box<T>)
                  -> Result<SelfUpdatingTokenManager, InitializationError>
        where T: FnOnce(&ManagedToken, &Credentials) -> RequestAccessTokenResult + Send + 'static
    {
        let provider = SelfUpdatingTokenManager {
            token_state: Arc::new(RwLock::new(HashMap::new())),
            stop_requested: Arc::new(RwLock::new(false)),
        };
        try!{manager_loop::start_manager(provider.token_state.clone(),
                      conf.managed_tokens,
                      request_access_token,
                      conf.update_interval,
                      provider.stop_requested.clone())};
        Ok(provider)
    }
}

impl TokenManager for SelfUpdatingTokenManager {
    fn get_token(&self, name: &str) -> TokenResult {
        match self.token_state.read() {
            Err(err) => Err(TokenError::InternalProblem { message: err.description().to_string() }),
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
