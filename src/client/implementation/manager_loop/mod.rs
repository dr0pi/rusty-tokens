use std::collections::HashMap;
use std::time::{Instant as TInstant, Duration as TDuration};
use std::thread;
use std::sync::{Arc, RwLock};
use std::cmp::min;
use chrono::*;
use InitializationError;
use {Token, Scope};
use client::credentials::{CredentialsPair, CredentialsPairProvider};
use client::{TokenResult, TokenError, ManagedToken};
use super::{AccessToken, AccessTokenProvider, RequestAccessTokenError,
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
                           -> Result<thread::JoinHandle<()>, InitializationError>
    where T: AccessTokenProvider + Send + 'static,
          U: CredentialsPairProvider + Send + 'static
{
    info!("Manager starting.");

    let join_handle = thread::spawn(move || {
        let mut managed_token_data = Vec::new();
        initialize(&mut managed_token_data, &conf.managed_tokens);

        manager_loop(manager_state,
                     managed_token_data,
                     credentials_provider,
                     access_token_provider,
                     conf.refresh_percentage_threshold,
                     conf.warning_percentage_threshold,
                     stop_requested);
    });
    Ok(join_handle)
}

fn initialize<'a>(token_data_buffer: &mut Vec<TokenData<'a>>, managed_tokens: &'a [ManagedToken]) {
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
                      managed_token_data: Vec<TokenData>,
                      credentials_provider: U,
                      access_token_provider: T,
                      refresh_percentage_threshold: f32,
                      warning_percentage_threshold: f32,
                      stop_requested: Arc<RwLock<bool>>)
    where T: AccessTokenProvider,
          U: CredentialsPairProvider
{
    info!("Manager loop started.");

    let mut mutable_managed_token_data = managed_token_data;
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

        let mut next_update_at = UTC::now().timestamp() + 3600 * 3;
        for ref mut token_data in &mut mutable_managed_token_data {
            if token_data.update_latest <= now {
                let res = update_token_data(token_data,
                                            &access_token_provider,
                                            &credentials,
                                            refresh_percentage_threshold,
                                            warning_percentage_threshold);
                match res {
                    Ok(_) => {
                        match token_data.token {
                            Some(ref token) =>
                                token_states_to_update.push((token_data.token_name, Ok(token.clone()))),
                            None =>
                                token_states_to_update.push((token_data.token_name,
                                                         Err(TokenError::NoToken))),
                        }
                    }
                    Err(err) => {
                        if token_data.valid_until > now {
                            warn!("Could not update still valid token \
                                   '{}': {}",
                                  token_data.token_name,
                                  err);
                        } else {
                            error!("Could not update expired({}) token {}: {}",
                            NaiveDateTime::from_num_seconds_from_unix_epoch(token_data.valid_until, 0),
                                   token_data.token_name,
                                   err);
                            token_states_to_update.push((token_data.token_name,
                                                         Err(TokenError::RequestError(err))));
                        }
                    }
                }
            }
            if token_data.warn_after < now {
                warn!("Token {} becomes to old(valid until {}, update latest was {}).",
                      &token_data.token_name,
                      NaiveDateTime::from_num_seconds_from_unix_epoch(token_data.valid_until, 0),
                      NaiveDateTime::from_num_seconds_from_unix_epoch(token_data.update_latest, 0));
            }

            next_update_at = min(next_update_at, token_data.update_latest);
        }

        if !token_states_to_update.is_empty() {
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


        let sleep_dur = calc_sleep_duration(UTC::now().timestamp(),
                                            next_update_at,
                                            TDuration::from_secs(5));
        debug!("Starting next token update iteration in {:?}.", sleep_dur);
        thread::sleep(sleep_dur);
    }

    info!("Manager loop stopped.");
}

fn calc_sleep_duration(now: i64, next_update_at: i64, max_sleep_duration: TDuration) -> TDuration {
    if (next_update_at - now) > 0i64 {
        let next_update_in: u64 = (next_update_at - now) as u64;
        TDuration::from_secs(min(max_sleep_duration.as_secs(), next_update_in))
    } else {
        TDuration::from_millis(100u64)
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
        try!{access_token_provider.get_access_token(&token_data.scopes, credentials)};

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
    debug!("Updated token data for '{}'. Valid until: {}, Update latest: {}, Warn after: {}",
           &token_data.token_name,
           valid_until_utc,
           update_latest,
           warn_after);
}

fn scale_time(now: i64, later: i64, factor: f32) -> i64 {
    now + ((later - now) as f64 * factor as f64) as i64
}

#[cfg(test)]
mod test_funs;

#[cfg(test)]
mod test_loop_funs;
