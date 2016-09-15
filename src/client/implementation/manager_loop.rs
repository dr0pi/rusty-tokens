use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::thread;
use std::sync::{Arc, RwLock};
use InitializationError;
use Token;
use client::credentials::Credentials;
use client::{ManagedToken, TokenResult};
use super::RequestAccessTokenResult;


struct TokenData {
    token: Token,
    issued_at: Instant,
    valid_until: Instant,
    update_latest: Instant,
}


pub fn start_manager<T>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                        managed_tokens_vec: Vec<ManagedToken>,
                        request_access_token: Box<T>,
                        update_interval: Duration,
                        stop_requested: Arc<RwLock<bool>>)
                        -> Result<(), InitializationError>
    where T: FnOnce(&ManagedToken, &Credentials) -> RequestAccessTokenResult + Send + 'static
{
    info!("Manager loop starting.");

    let mut managed_tokens = HashMap::new();
    for mt in managed_tokens_vec.into_iter() {
        managed_tokens.insert(mt.name.clone(), mt);
    }
    let _join_handle = thread::spawn(move || {
        manager_loop(manager_state,
                     managed_tokens,
                     request_access_token,
                     update_interval,
                     stop_requested);
    });
    Ok(())
}

fn manager_loop<T>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                   managed_tokens: HashMap<String, ManagedToken>,
                   request_access_token_box: Box<T>,
                   update_interval: Duration,
                   stop_requested: Arc<RwLock<bool>>)
    where T: FnOnce(&ManagedToken, &Credentials) -> RequestAccessTokenResult
{
    let request_access_token = *request_access_token_box;

    info!("Manager loop started.");

    loop {

        let stop = stop_requested.read().unwrap();
        if *stop {
            break;
        }
        thread::sleep(update_interval);
    }

    info!("Manager loop stopped.");
}

fn query_token(managed_token: &ManagedToken,
               credentials: &Credentials)
               -> Result<TokenData, String> {
    panic!("")
}
