use std::collections::HashMap;
use std::time::{Instant as TInstant, Duration as TDuration};
use std::thread;
use std::sync::{Arc, RwLock};
use std::cmp::{min, max};
use chrono::*;
use InitializationError;
use {Token, Scope};
use client::credentials::{CredentialsPair, CredentialsPairProvider};
use client::{TokenResult, TokenError, ManagedToken};
use super::{RequestAccessTokenResult, AccessToken, AccessTokenProvider, RequestAccessTokenError,
            SelfUpdatingTokenManagerConfig};


#[derive(Debug, PartialEq)]
struct TokenData<'a> {
    token_name: &'a str,
    token: Option<Token>,
    update_latest: i64,
    valid_until: i64,
    warn_after: i64,
    scopes: &'a Vec<Scope>,
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

fn initialize<'a>(token_data_buffer: &mut Vec<TokenData<'a>>,
                  managed_tokens: &'a Vec<ManagedToken>) {
    let t = UTC::now().timestamp();
    for managed_token in managed_tokens {
        token_data_buffer.push(TokenData {
            token_name: &managed_token.name,
            token: None,
            update_latest: t,
            warn_after: t,
            valid_until: t,
            scopes: &managed_token.scopes,
        });
    }
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

    let mut managed_token_data = {
        let mut v = Vec::new();
        initialize(&mut v, &conf.managed_tokens);
        v
    };



    let mut token_states_to_update: Vec<(&str, TokenResult)> = Vec::new();

    loop {
        let iteration_started = TInstant::now();

        let credentials = match credentials_provider.get_credentials_pair() {
            Ok(creds) => creds,
            Err(err) => {
                error!("Could not aquire credentials: {}", err);
                thread::sleep(TDuration::from_secs(1));
                continue;
            }
        };

        let now = UTC::now().timestamp();

        let mut next_update_at = UTC::now().timestamp() + 3600;
        for ref mut token_data in &mut managed_token_data {
            if token_data.update_latest <= now {
                let res = update_token_data(token_data,
                                            &access_token_provider,
                                            &credentials,
                                            conf.refresh_percentage_threshold,
                                            conf.warning_percentage_threshold);
                match res {
                    Ok(_) => {
                        match token_data.token {
                            Some(ref token) =>
                            token_states_to_update.push((token_data.token_name.clone(), Ok(token.clone()))),
                            None =>
                            token_states_to_update.push((token_data.token_name.clone(),
                                                         Err(TokenError::NoToken))),
                        }
                    }
                    Err(err) => {
                        if token_data.valid_until > now {
                            warn!("Could not update still valid token \
                                   {}: {}",
                                  token_data.token_name,
                                  err);
                        } else {
                            error!("Could not update expired token {}: {}",
                                   token_data.token_name,
                                   err);
                            token_states_to_update.push((token_data.token_name.clone(),
                                                         Err(TokenError::RequestError(err))));
                        }
                    }
                }
            }
            if token_data.warn_after < now {
                warn!("Token {} becomes to old.", &token_data.token_name);
            }

            next_update_at = min(next_update_at, token_data.update_latest);
        }

        {
            let mut unlocked_manager_state = manager_state.write().unwrap();
            for to_update in &token_states_to_update {
                unlocked_manager_state.insert(to_update.0.to_owned(), to_update.1.clone());
            }
        }

        token_states_to_update.clear();

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
        let time_spent_in_iteration = iteration_ended - iteration_started;
        debug!("Iteration took {:?}.", time_spent_in_iteration);


        match calc_sleep_duration(UTC::now().timestamp(), next_update_at) {
            duration if duration.as_secs() == 0u64 => {
                info!("Starting token update iteration immediately.")
            }
            duration => {
                info!("Starting next token update iteration in {:?}.", duration);
                thread::sleep(duration)
            }
        };

    }

    info!("Manager loop stopped.");
}

fn calc_sleep_duration(now: i64, next_update_at: i64) -> TDuration {
    if (next_update_at - now) > 0i64 {
        let next_update_in: u64 = (next_update_at - now) as u64;
        TDuration::from_secs(next_update_in)
    } else {
        TDuration::from_secs(0u64)
    }
}

fn update_token_data<T>(token_data: &mut TokenData,
                        access_token_provider: &T,
                        credentials: &CredentialsPair,
                        refresh_percentage_threshold: f32,
                        warning_percentage_threshold: f32)
                        -> Result<DateTime<UTC>, RequestAccessTokenError>
    where T: AccessTokenProvider
{
    let access_token =
        try!{query_access_token(token_data, credentials, access_token_provider, 3, None)};

    let now_utc = UTC::now();
    let now_utc_epoch: i64 = now_utc.timestamp();

    update_token_data_with_access_token(now_utc_epoch,
                                        token_data,
                                        access_token,
                                        refresh_percentage_threshold,
                                        warning_percentage_threshold);
    Ok(now_utc)
}

fn update_token_data_with_access_token(now_utc: i64,
                                       token_data: &mut TokenData,
                                       access_token: AccessToken,
                                       refresh_percentage_threshold: f32,
                                       warning_percentage_threshold: f32) {
    let valid_until_utc: i64 = access_token.valid_until_utc.timestamp();
    let update_latest: i64 = scale_time(now_utc, valid_until_utc, refresh_percentage_threshold);
    let warn_after: i64 = scale_time(now_utc, valid_until_utc, warning_percentage_threshold);
    token_data.update_latest = update_latest;
    token_data.warn_after = warn_after;
    token_data.valid_until = valid_until_utc;
    token_data.token = Some(access_token.token);
}

fn scale_time(now: i64, later: i64, factor: f32) -> i64 {
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

#[cfg(test)]
mod test_funs;

#[cfg(test)]
mod test_loop_funs;
