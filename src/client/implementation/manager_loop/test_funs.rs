use chrono::NaiveDateTime;
use std::time::Duration;
use {Scope, Token};
use client::implementation::AccessToken;
use super::{scale_time, update_token_data_with_access_token, TokenData, calc_sleep_duration};

#[test]
fn calc_sleep_duration_when_next_update_is_overdue() {
    let now = 10i64;
    let next_update_at = 0i64;

    let expected = Duration::from_millis(100u64);
    let result = calc_sleep_duration(now, next_update_at, Duration::from_secs(10));

    assert_eq!(expected, result);
}

#[test]
fn calc_sleep_duration_when_next_update_is_now() {
    let now = 10i64;
    let next_update_at = 10i64;

    let expected = Duration::from_millis(100u64);
    let result = calc_sleep_duration(now, next_update_at, Duration::from_secs(10));

    assert_eq!(expected, result);
}

#[test]
fn calc_sleep_duration_when_next_update_is_soon() {
    let now = 10i64;
    let next_update_at = 20i64;

    let expected = Duration::from_secs(10u64);
    let result = calc_sleep_duration(now, next_update_at, Duration::from_secs(10));

    assert_eq!(expected, result);
}

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
        token: Token::new("token"),
        issued_at_utc: NaiveDateTime::from_timestamp(50, 0),
        valid_until_utc: NaiveDateTime::from_timestamp(200, 0),
    };

    let expected = TokenData {
        token_name: "token_data",
        token: Some(Token::new("token")),
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
