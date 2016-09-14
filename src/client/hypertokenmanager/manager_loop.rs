use std::collections::HashMap;
use std::time::Instant;
use std::thread;
use InitializationError;
use Token;
use client::credentials::Credentials;
use client::ManagedToken;
use super::{HyperTokenManager, HyperTokenManagerConfig};
use hyper;


struct TokenData {
    token: Token,
    issued_at: Instant,
    valid_until: Instant,
    update_latest: Instant,
}


pub fn start_manager(manager: HyperTokenManager,
                     managed_tokens_vec: Vec<ManagedToken>,
                     http_client: hyper::Client,
                     conf: HyperTokenManagerConfig)
                     -> Result<(), InitializationError> {
    info!("Manager loop starting.");
    let mut managed_tokens = HashMap::new();
    for mt in managed_tokens_vec.into_iter() {
        managed_tokens.insert(mt.name.clone(), mt);
    }
    let _join_handle = thread::spawn(move || {
        manager_loop(manager, managed_tokens, http_client, conf);
    });
    Ok(())
}

fn manager_loop(manager: HyperTokenManager,
                managed_tokens: HashMap<String, ManagedToken>,
                http_client: hyper::Client,
                conf: HyperTokenManagerConfig) {

    info!("Manager loop started.");

}

fn query_token(managed_token: &ManagedToken,
               credentials: &Credentials)
               -> Result<TokenData, String> {
    panic!("")
}
