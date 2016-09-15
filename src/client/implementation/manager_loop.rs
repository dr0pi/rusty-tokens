use std::error::Error;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::thread;
use std::sync::{Arc, RwLock};
use InitializationError;
use {Token, Scope};
use client::credentials::{Credentials, CredentialsProvider};
use client::{ManagedToken, TokenResult, TokenError};
use super::{RequestAccessTokenResult, AccessToken, AccessTokenProvider, RequestAccessTokenError};


struct TokenData {
    access_token: AccessToken,
    update_latest: Instant,
}


pub fn start_manager<T>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                        managed_tokens_vec: Vec<ManagedToken>,
                        access_token_provider: T,
                        update_interval: Duration,
                        stop_requested: Arc<RwLock<bool>>)
                        -> Result<(), InitializationError>
    where T: AccessTokenProvider + Send + 'static
{
    info!("Manager loop starting.");

    let mut managed_tokens = HashMap::new();
    for mt in managed_tokens_vec.into_iter() {
        managed_tokens.insert(mt.name.clone(), mt);
    }
    let _join_handle = thread::spawn(move || {
        manager_loop(manager_state,
                     managed_tokens,
                     access_token_provider,
                     update_interval,
                     stop_requested);
    });
    Ok(())
}

fn manager_loop<T>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                   managed_tokens: HashMap<String, ManagedToken>,
                   access_token_provider: T,
                   update_interval: Duration,
                   stop_requested: Arc<RwLock<bool>>)
    where T: AccessTokenProvider + Send
{

    info!("Manager loop started.");

    loop {
        let res = query_token_data(managed_tokens.get("0").unwrap(), &access_token_provider);
        let stop = stop_requested.read().unwrap();
        if *stop {
            break;
        }
        thread::sleep(update_interval);
    }

    info!("Manager loop stopped.");
}

fn query_token_data<T>(managed_token: &ManagedToken,
                       access_token_provider: &T)
                       -> Result<TokenData, TokenError>
    where T: AccessTokenProvider
{
    let credentials = try!{managed_token.credentials_provider.get_credentials()};
    let access_token = try!{query_access_token(&managed_token.name, &managed_token.scopes, &credentials, access_token_provider, 3, None)};
    panic!("")
}

fn query_access_token<T>(managed_token_name: &str,
                         managed_token_scopes: &Vec<Scope>,
                         credentials: &Credentials,
                         access_token_provider: &T,
                         attempts_left: u16,
                         last_error: Option<RequestAccessTokenError>)
                         -> RequestAccessTokenResult
    where T: AccessTokenProvider
{
    if attempts_left == 0 {
        match last_error {
            Some(err) => Err(err),
            None => {
                Err(RequestAccessTokenError::InternalError(String::from("No attempts were made.")))
            }
        }
    } else {
        let result = access_token_provider.request_access_token(managed_token_scopes, credentials);
        match result {
            Ok(res) => Ok(res),
            Err(err) => {
                warn!("Failed to query access token({}): {}",
                      managed_token_name,
                      err);
                query_access_token(managed_token_name,
                                   managed_token_scopes,
                                   credentials,
                                   access_token_provider,
                                   attempts_left - 1,
                                   Some(err))
            }
        }
    }
}
