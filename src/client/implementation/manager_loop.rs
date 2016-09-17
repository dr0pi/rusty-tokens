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
    token_name: String,
    token: Option<Token>,
    update_latest: i64,
    valid_until: i64,
    warn_after: i64,
    scopes: Vec<Scope>,
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
    where T: AccessTokenProvider,
          U: CredentialsPairProvider
{
    info!("Manager loop started.");

    let mut managed_token_data = Vec::new();
    let t = UTC::now().timestamp();
    for managed_token in conf.managed_tokens {
        managed_token_data.push(TokenData {
            token_name: managed_token.name.clone(),
            token: None,
            update_latest: t,
            warn_after: t,
            valid_until: t,
            scopes: managed_token.scopes,
        });
    }


    loop {
        let iteration_started = TInstant::now();

        let now = UTC::now().timestamp();

        let credentials = match credentials_provider.get_credentials_pair() {
            Ok(creds) => creds,
            Err(err) => {
                error!("Could not aquire credentials: {}", err);
                continue;
            }
        };

        let mut state_to_update: Vec<(&String, TokenResult)> = Vec::new();
        for token_data in &mut managed_token_data {
            if token_data.update_latest <= now {
                let res = update_token_data(token_data,
                                            &access_token_provider,
                                            &credentials,
                                            conf.refresh_percentage_threshold,
                                            conf.warning_percentage_threshold);
                match res {
                    Ok(()) => {
                        // let token = &token_data.token.unwrap();
                        // state_to_update.push((&token_data.token_name, Ok(token.clone())));
                    }
                    Err(err) => {
                        if token_data.update_latest - 2 > now {
                            warn!("Could not update still valid(for at least 2 seconds) token \
                                   {}: {}",
                                  token_data.token_name,
                                  err);
                        } else {
                            error!("Could not update expired token {}: {}",
                                   token_data.token_name,
                                   err);
                            state_to_update.push((&token_data.token_name, Err(TokenError::RequestError(err))));
                        }
                    }
                }
            }
            if token_data.warn_after < now {
                warn!("Token {} becomes to old.", token_data.token_name);
            }
        }

        // for token_data in managed_token_data {
        //     if token_data.update_latest >= now {
        //
        //     }
        //
        // }

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
        let iteration_ended = TInstant::now();

        thread::sleep(TDuration::from_secs(1));
    }

    info!("Manager loop stopped.");
}

fn update_token_data<T>(token_data: &mut TokenData,
                        access_token_provider: &T,
                        credentials: &CredentialsPair,
                        refresh_percentage_threshold: f32,
                        warning_percentage_threshold: f32)
                        -> Result<(), RequestAccessTokenError>
    where T: AccessTokenProvider
{
    let access_token =
        try!{query_access_token(token_data, credentials, access_token_provider, 3, None)};

    update_token_data_with_access_token(token_data,
                                        access_token,
                                        refresh_percentage_threshold,
                                        warning_percentage_threshold);
    Ok(())
}

fn update_token_data_with_access_token(token_data: &mut TokenData,
                                       access_token: AccessToken,
                                       refresh_percentage_threshold: f32,
                                       warning_percentage_threshold: f32) {
    let now_utc: i64 = UTC::now().timestamp();
    let valid_until_utc: i64 = access_token.valid_until_utc.timestamp();
    let update_latest: i64 = scale_date(now_utc, valid_until_utc, refresh_percentage_threshold);
    let warn_after: i64 = scale_date(now_utc, valid_until_utc, warning_percentage_threshold);
    token_data.update_latest = update_latest;
    token_data.warn_after = warn_after;
    token_data.valid_until = valid_until_utc;
    token_data.token = Some(access_token.token);
}

fn scale_date(now: i64, later: i64, factor: f32) -> i64 {
    now + ((later - now) as f64 * factor as f64) as i64
}

fn query_access_token<T>(token_data: &TokenData,
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
        let result = access_token_provider.get_access_token(&token_data.scopes, credentials);
        match result {
            Ok(res) => Ok(res),
            Err(err) => {
                warn!("Failed to query access token({}): {}",
                      token_data.token_name,
                      err);
                query_access_token(token_data,
                                   credentials,
                                   access_token_provider,
                                   attempts_left - 1,
                                   Some(err))
            }
        }
    }
}
