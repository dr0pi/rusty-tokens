use std::error::Error;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::thread;
use std::sync::{Arc, RwLock};
use InitializationError;
use {Token, Scope};
use client::credentials::{Credentials, UserCredentialsProvider, ClientCredentialsProvider};
use client::{ManagedToken, TokenResult, TokenError};
use super::{RequestAccessTokenResult, AccessToken, AccessTokenProvider, RequestAccessTokenError,
            SelfUpdatingTokenManagerConfig};


struct TokenData {
    access_token: AccessToken,
    update_latest: Instant,
}


pub fn start_manager<T, U>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                           credentials_provider: U,
                           access_token_provider: T,
                           conf: SelfUpdatingTokenManagerConfig,
                           stop_requested: Arc<RwLock<bool>>)
                           -> Result<(), InitializationError>
    where T: AccessTokenProvider + Send + 'static,
          U: UserCredentialsProvider + ClientCredentialsProvider + Send + 'static
{
    info!("Manager loop starting.");

    let _join_handle = thread::spawn(move || {
        manager_loop(manager_state,
                     credentials_provider,
                     access_token_provider,
                     conf,
                     stop_requested);
    });
    Ok(())
}

fn manager_loop<T, U>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                      credentials_provider: U,
                      access_token_provider: T,
                      conf: SelfUpdatingTokenManagerConfig,
                      stop_requested: Arc<RwLock<bool>>)
    where T: AccessTokenProvider + Send + 'static,
          U: UserCredentialsProvider + ClientCredentialsProvider + Send + 'static
{

    info!("Manager loop started.");

    loop {
        let stop = match stop_requested.read() {
            Ok(stop) => *stop,
            Err(err) => {
                error!("Could not aquire read lock. Stopping. Error was: {}", err);
                true
            }
        };
        if stop {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    info!("Manager loop stopped.");
}

fn query_token_data<T, U>(managed_token: &ManagedToken,
                          client_credentials: &Credentials,
                          user_credentials: &Credentials,
                          access_token_provider: &T)
                          -> Result<TokenData, TokenError>
    where T: AccessTokenProvider,
          U: UserCredentialsProvider + ClientCredentialsProvider + Send + 'static
{
    let access_token = try!{query_access_token(
        &managed_token.name,
        &managed_token.scopes,
        client_credentials,
        user_credentials,
        access_token_provider,
        3,
        None)};
    panic!("")
}

fn query_access_token<T>(managed_token_name: &str,
                         managed_token_scopes: &[Scope],
                         client_credentials: &Credentials,
                         user_credentials: &Credentials,
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
        let result = access_token_provider.get_access_token(managed_token_scopes, client_credentials, user_credentials);
        match result {
            Ok(res) => Ok(res),
            Err(err) => {
                warn!("Failed to query access token({}): {}",
                      managed_token_name,
                      err);
                query_access_token(managed_token_name,
                                   managed_token_scopes,
                                   client_credentials,
                                   user_credentials,
                                   access_token_provider,
                                   attempts_left - 1,
                                   Some(err))
            }
        }
    }
}
