use std::error::Error;
use std::collections::HashMap;
use std::time::{Instant as TInstant, Duration as TDuration};
use std::thread;
use std::sync::{Arc, RwLock};
use chrono::*;
use InitializationError;
use {Token, Scope};
use client::credentials::{CredentialsPair, CredentialsPairProvider};
use client::{ManagedToken, TokenResult, TokenError};
use super::{RequestAccessTokenResult, AccessToken, AccessTokenProvider, RequestAccessTokenError,
            SelfUpdatingTokenManagerConfig};


struct TokenData {
    token: Token,
    update_latest: i64,
    warn_after: i64,
}


pub fn start_manager<T, U>(manager_state: Arc<RwLock<HashMap<String, TokenResult>>>,
                           credentials_provider: U,
                           access_token_provider: T,
                           conf: SelfUpdatingTokenManagerConfig,
                           stop_requested: Arc<RwLock<bool>>)
                           -> Result<(), InitializationError>
    where T: AccessTokenProvider + Send + 'static,
          U: CredentialsPairProvider + Send + 'static
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
          U: CredentialsPairProvider + Send + 'static
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
        thread::sleep(TDuration::from_secs(1));
    }

    info!("Manager loop stopped.");
}

fn access_token_2_token_data(access_token: AccessToken,
                             refresh_percentage_threshold: f32,
                             warning_percentage_threshold: f32)
                             -> TokenData {
    let now_utc: i64 = UTC::now().timestamp();
    let valid_until_utc: i64 = access_token.valid_until_utc.timestamp();
    let update_latest: i64 = scale_date(now_utc, valid_until_utc, refresh_percentage_threshold);
    let warn_after: i64 = scale_date(now_utc, valid_until_utc, warning_percentage_threshold);
    TokenData {
        token: access_token.token,
        update_latest: update_latest,
        warn_after: warn_after,
    }
}

fn scale_date(now: i64, later: i64, factor: f32) -> i64 {
    now + ((later - now) as f64 * factor as f64) as i64
}

fn query_access_token<T>(managed_token_name: &str,
                         managed_token_scopes: &[Scope],
                         credentials: &CredentialsPair,
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
        let result = access_token_provider.get_access_token(managed_token_scopes, credentials);
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
