use std::error::Error;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::Duration;
use InitializationError;
use super::{TokenError, TokenManager, ManagedToken, TokenResult};
use hyper;


mod manager_loop;

pub struct HyperTokenManagerConfig {
    url: String,
    update_interval: Duration,
}

#[derive(Clone)]
pub struct HyperTokenManager {
    token_state: Arc<RwLock<HashMap<String, TokenResult>>>,
    stop_requested: Arc<RwLock<bool>>,
}

impl HyperTokenManager {
    pub fn new(managed_tokens: Vec<ManagedToken>,
               http_client: hyper::Client,
               conf: HyperTokenManagerConfig)
               -> Result<HyperTokenManager, InitializationError> {
        let provider = HyperTokenManager {
            token_state: Arc::new(RwLock::new(HashMap::new())),
            stop_requested: Arc::new(RwLock::new(false)),
        };
        try!{manager_loop::start_manager(provider.clone(),
                      managed_tokens,
                      http_client,
                      conf)};
        Ok(provider)
    }
}

impl TokenManager for HyperTokenManager {
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
