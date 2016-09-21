extern crate env_logger;

use std::collections::HashMap;
use std::thread;
use std::sync::{Arc, RwLock};
use std::cell::Cell;
use chrono::*;
use std::time::Duration as TDuration;
use {Scope, Token};
use client::TokenResult;
use client::credentials::{Credentials, CredentialsPair, StaticCredentialsProvider};
use client::implementation::{AccessToken, AccessTokenProvider, RequestAccessTokenResult,
                             RequestAccessTokenError};
use super::{TokenData, update_token_data, manager_loop};

struct AccessTokenProviderMock {
    result: RequestAccessTokenResult,
}

impl AccessTokenProvider for AccessTokenProviderMock {
    fn get_access_token(&self,
                        _scopes: &[Scope],
                        _credentials: &CredentialsPair)
                        -> RequestAccessTokenResult {
        self.result.clone()
    }
}



#[test]
fn update_token_data_should_update_the_token() {
    let now = UTC::now();
    let refresh_percentage_threshold = 0.5f32;
    let warning_percentage_threshold = 1.0f32;

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
        issued_at_utc: now.naive_utc() - Duration::seconds(60),
        valid_until_utc: now.naive_utc() + Duration::seconds(60),
    };

    let provider = AccessTokenProviderMock { result: Ok(sample_access_token) };


    let credentials = CredentialsPair {
        client_credentials: Credentials {
            id: String::new(),
            secret: String::new(),
        },
        user_credentials: Credentials {
            id: String::new(),
            secret: String::new(),
        },
    };

    let used_timestamp = update_token_data(&mut sample_token_data,
                                           &provider,
                                           &credentials,
                                           refresh_percentage_threshold,
                                           warning_percentage_threshold)
        .unwrap();

    let expected = TokenData {
        token_name: "token_data",
        token: Some(Token(String::from("token"))),
        update_latest: (used_timestamp.naive_utc() + Duration::seconds(30)).timestamp(),
        valid_until: (now.naive_utc() + Duration::seconds(60)).timestamp(),
        warn_after: (used_timestamp.naive_utc() + Duration::seconds(60)).timestamp(),
        scopes: &scopes,
    };


    assert_eq!(expected, sample_token_data);
}

#[test]
fn update_token_data_should_not_update_the_token_when_the_acess_token_provider_fails() {
    let refresh_percentage_threshold = 0.5f32;
    let warning_percentage_threshold = 1.0f32;

    let scopes = vec![Scope(String::from("sc"))];

    let mut sample_token_data = TokenData {
        token_name: "token_data",
        token: None,
        update_latest: -1,
        valid_until: -2,
        warn_after: -3,
        scopes: &scopes,
    };

    let provider = AccessTokenProviderMock {
        result: Err(RequestAccessTokenError::InternalError(String::from("error"))),
    };

    let credentials = CredentialsPair {
        client_credentials: Credentials {
            id: String::new(),
            secret: String::new(),
        },
        user_credentials: Credentials {
            id: String::new(),
            secret: String::new(),
        },
    };

    let result = update_token_data(&mut sample_token_data,
                                   &provider,
                                   &credentials,
                                   refresh_percentage_threshold,
                                   warning_percentage_threshold);



    assert_eq!(result.is_err(), true);
}

struct MultipleAccessTokensProviderMock {
    results: Vec<RequestAccessTokenResult>,
    counter: Cell<usize>,
}

impl MultipleAccessTokensProviderMock {
    fn new(results: Vec<RequestAccessTokenResult>) -> MultipleAccessTokensProviderMock {
        MultipleAccessTokensProviderMock {
            results: results,
            counter: Cell::new(0),
        }
    }
}

impl AccessTokenProvider for MultipleAccessTokensProviderMock {
    fn get_access_token(&self,
                        _scopes: &[Scope],
                        _credentials: &CredentialsPair)
                        -> RequestAccessTokenResult {
        let next: usize = self.counter.get();
        self.counter.set(next + 1);
        if next < self.results.len() {
            self.results[next].clone()
        } else {
            Err(RequestAccessTokenError::InternalError(format!("error_{}", next)))
        }
    }
}

#[test]
fn basic_loop_iteration() {

    let _ = env_logger::init();

    let now = UTC::now();

    let refresh_percentage_threshold = 0.5f32;
    let warning_percentage_threshold = 1.0f32;


    let sample_access_tokens = vec![Ok(AccessToken {
                                        token: Token(String::from("token_1")),
                                        issued_at_utc: now.naive_utc() - Duration::seconds(0),
                                        valid_until_utc: now.naive_utc() + Duration::seconds(10),
                                    }),
                                    Ok(AccessToken {
                                        token: Token(String::from("token_2")),
                                        issued_at_utc: now.naive_utc() - Duration::seconds(20),
                                        valid_until_utc: now.naive_utc() + Duration::seconds(20),
                                    }),
                                    Ok(AccessToken {
                                        token: Token(String::from("token_3")),
                                        issued_at_utc: now.naive_utc() - Duration::seconds(30),
                                        valid_until_utc: now.naive_utc() + Duration::seconds(30),
                                    })];

    let access_token_provider = MultipleAccessTokensProviderMock::new(sample_access_tokens);



    let credentials_provider =
        StaticCredentialsProvider::new(String::new(), String::new(), String::new(), String::new());

    let manager_state = Arc::new(RwLock::new(HashMap::<String, TokenResult>::new()));
    let manager_state_for_loop = manager_state.clone();

    let stop = Arc::new(RwLock::new(false));
    let stop_requested = stop.clone();
    let join_handle = thread::spawn(move || {
        let scopes = vec![Scope(String::from("sc"))];

        let managed_token_data = vec![TokenData {
                                          token_name: "my_token",
                                          token: None,
                                          update_latest: -1,
                                          valid_until: -2,
                                          warn_after: -3,
                                          scopes: &scopes,
                                      }];

        manager_loop(manager_state_for_loop,
                     managed_token_data,
                     credentials_provider,
                     access_token_provider,
                     refresh_percentage_threshold,
                     warning_percentage_threshold,
                     stop_requested);
    });

    let mut collected_tokens = Vec::new();
    thread::sleep(TDuration::from_secs(5));
    {
        let lock = manager_state.read().unwrap();
        let token_result: TokenResult = lock.get("my_token").unwrap().clone();
        collected_tokens.push(token_result.unwrap());
    }
    thread::sleep(TDuration::from_secs(10));
    {
        let lock = manager_state.read().unwrap();
        let token_result: TokenResult = lock.get("my_token").unwrap().clone();
        collected_tokens.push(token_result.unwrap());
    }
    thread::sleep(TDuration::from_secs(10));
    {
        let lock = manager_state.read().unwrap();
        let token_result: TokenResult = lock.get("my_token").unwrap().clone();
        collected_tokens.push(token_result.unwrap());
    }

    {
        let mut stop = stop.write().unwrap();
        *stop = true;
    }

    join_handle.join().unwrap();

    assert_eq!(vec![Token::new("token_1"), Token::new("token_2"), Token::new("token_3")],
               collected_tokens);

}
