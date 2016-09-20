use chrono::*;
use std::time::Duration as TDuration;
use {Scope, Token};
use client::credentials::{Credentials, CredentialsPair, CredentialsPairProvider};
use client::implementation::{AccessToken, AccessTokenProvider, RequestAccessTokenResult,
                             RequestAccessTokenError};
use super::{TokenData, update_token_data};

struct AccessTokenProviderMock {
    result: RequestAccessTokenResult,
}

impl AccessTokenProviderMock {
    fn new(token: Token,
           issued_at_utc: NaiveDateTime,
           valid_until_utc: NaiveDateTime)
           -> AccessTokenProviderMock {
        AccessTokenProviderMock {
            result: Ok(AccessToken {
                token: token,
                valid_until_utc: valid_until_utc,
                issued_at_utc: issued_at_utc,
            }),
        }
    }
}

impl AccessTokenProvider for AccessTokenProviderMock {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        credentials: &CredentialsPair)
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
