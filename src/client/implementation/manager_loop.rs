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
                    Ok(()) => {
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
        let time_spent_in_iteration: u64 = (iteration_ended - iteration_started).as_secs();

        match calc_sleep_duration(time_spent_in_iteration,
                                  next_update_at,
                                  UTC::now().timestamp()) {
            0u64 => (),
            seconds => thread::sleep(TDuration::from_secs(seconds)),
        };

    }

    info!("Manager loop stopped.");
}

fn calc_sleep_duration(time_spent_in_iteration: u64, next_update_at: i64, now: i64) -> u64 {
    let next_update_in: u64 = max(0i64, next_update_at - now) as u64;

    if time_spent_in_iteration < next_update_in {
        next_update_in - time_spent_in_iteration
    } else {
        0u64
    }
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

    let now_utc: i64 = UTC::now().timestamp();

    update_token_data_with_access_token(now_utc,
                                        token_data,
                                        access_token,
                                        refresh_percentage_threshold,
                                        warning_percentage_threshold);
    Ok(())
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
mod test {
    use chrono::NaiveDateTime;
    use {Scope, Token};
    use client::implementation::AccessToken;
    use super::{scale_time, update_token_data_with_access_token, TokenData};

    #[test]
    fn update_token_data_with_access_token_must_create_the_correct_result() {
        let now = 100;
        let refresh_percentage_threshold = 0.6f32;
        let warning_percentage_threshold = 0.8f32;

        let scopes = vec![Scope(String::from("sc"))];

        let mut sample_token_data = TokenData {
            token_name: "token_data",
            token: None,
            update_latest: -1,
            valid_until: -2,
            warn_after: -3,
            scopes: &scopes,
        };

        let sample_access_token = AccessToken {
            token: Token(String::from("token")),
            issued_at_utc: NaiveDateTime::from_timestamp(50, 0),
            valid_until_utc: NaiveDateTime::from_timestamp(200, 0),
        };

        let expected = TokenData {
            token_name: "token_data",
            token: Some(Token(String::from("token"))),
            update_latest: 160,
            valid_until: 200,
            warn_after: 180,
            scopes: &scopes,
        };

        update_token_data_with_access_token(now,
                                            &mut sample_token_data,
                                            sample_access_token,
                                            refresh_percentage_threshold,
                                            warning_percentage_threshold);

        assert_eq!(expected, sample_token_data);

    }

    #[test]
    fn scale_time_0_percent() {
        let now = 100;
        let later = 200;
        let factor = 0.0f32;
        let expected = 100;
        assert_eq!(expected, scale_time(now, later, factor));
    }

    #[test]
    fn scale_time_30_percent() {
        let now = 100;
        let later = 200;
        let factor = 0.3f32;
        let expected = 130;
        assert_eq!(expected, scale_time(now, later, factor));
    }

    #[test]
    fn scale_time_50_percent() {
        let now = 100;
        let later = 200;
        let factor = 0.5f32;
        let expected = 150;
        assert_eq!(expected, scale_time(now, later, factor));
    }

    #[test]
    fn scale_time_70_percent_evals_to_69_percent() {
        let now = 100;
        let later = 200;
        let factor = 0.7f32;
        let expected = 169;
        assert_eq!(expected, scale_time(now, later, factor));
    }

    #[test]
    fn scale_time_100_percent() {
        let now = 100;
        let later = 200;
        let factor = 1.0f32;
        let expected = 200;
        assert_eq!(expected, scale_time(now, later, factor));
    }
}
