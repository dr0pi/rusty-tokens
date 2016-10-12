//! Plan B JWT.
//!
//! A JWT Token according to [Plan B](https://github.com/zalando/planb-provider)
use std::str::FromStr;
use rustc_serialize::json::Json;
use chrono::*;
use super::*;

/// The header of JWT token as returned by Plan B
#[derive(PartialEq, Debug)]
pub struct PlanbHeader {
    pub key_id: String,
    pub algorithm: String,
}

/// The payload of JWT token as returned by Plan B
#[derive(PartialEq, Debug)]
pub struct PlanbPayload {
    pub subject: String,
    pub realm: String,
    pub scopes: Vec<String>,
    pub issuer: String,
    pub expiration_date_utc: NaiveDateTime,
    pub issue_date_utc: NaiveDateTime,
}

/// A JWT token as returned by Plan B
#[derive(PartialEq, Debug)]
pub struct PlanbToken {
    pub header: PlanbHeader,
    pub payload: PlanbPayload,
}

impl PlanbToken {
    /// Creates a new Plan B JWT token
    pub fn new(header: PlanbHeader, payload: PlanbPayload) -> PlanbToken {
        PlanbToken {
            header: header,
            payload: payload,
        }
    }

    /// Takes a JWT token and makes a Plan B token from it.
    /// May fail if the required fields for a Plan B JWT token are not supplied with the JWT token.
    pub fn from_jwt_token(jwt_token: &JsonWebToken) -> Result<PlanbToken, &'static str> {
        let kid: &str = try!{
            jwt_token.get_registered_header(RegisteredHeader::KeyId).and_then(|json|
                json.as_string()).ok_or("Custom field 'kid' is missing or not a String.") };
        let algorithm: &str = try!{
            jwt_token.get_header(&Header::Registered(RegisteredHeader::Algorithm)).and_then(|json|
                json.as_string()).ok_or("Field 'Algorithm' is missing or not a String.") };

        let header = PlanbHeader {
            key_id: String::from(kid),
            algorithm: String::from(algorithm),
        };

        let subject: &str = try!{
            jwt_token.get_registered_payload(RegisteredClaim::Subject).and_then(|json|
                json.as_string()).ok_or("Field 'Subject' is missing or not a String.") };
        let realm: &str = try!{
            jwt_token.get_payload(&Claim::Custom("realm")).and_then(|json|
                json.as_string()).ok_or("Custom field 'realm' is missing or not a String.") };
        let scopes_json: &Vec<Json> = try!{
            jwt_token.get_payload(&Claim::Custom("scope"))
                .and_then(|json| json.as_array())
                .ok_or("Custom field 'realm' is missing or not an array.") };
        let scopes_res: Result<Vec<_>, _> = scopes_json.into_iter()
            .map(|elem| {
                elem.as_string()
                    .map(|x| String::from(x))
                    .ok_or("Element in scopes not a String")
            })
            .collect();

        let scopes = try!{scopes_res};

        let issuer: &str = try!{
            jwt_token.get_registered_payload(RegisteredClaim::Issuer).and_then(|json|
                json.as_string()).ok_or("Field 'Issuer' is missing or not a String.") };
        let expiration_date_unix_seconds: i64 = try!{
            jwt_token.get_registered_payload(RegisteredClaim::ExpirationTime).and_then(|json|
                json.as_i64()).ok_or("Field 'ExpirationTime' is missing or not a i64.") };
        let expiration_date =
            try!{NaiveDateTime::from_timestamp_opt(expiration_date_unix_seconds, 0).ok_or("Field 'ExpirationTime' is not a unix epoch.")};
        let issue_date_unix_seconds: i64 = try!{
            jwt_token.get_registered_payload(RegisteredClaim::IssuedAt).and_then(|json|
                json.as_i64()).ok_or("Field 'IssuedAt' is missing or not a i64.") };
        let issue_date =
            try!{NaiveDateTime::from_timestamp_opt(issue_date_unix_seconds, 0).ok_or("Field 'IssuedAt' is not a unix epoch.")};

        let payload = PlanbPayload {
            subject: String::from(subject),
            realm: String::from(realm),
            scopes: scopes,
            issuer: String::from(issuer),
            expiration_date_utc: expiration_date,
            issue_date_utc: issue_date,
        };

        Ok(PlanbToken {
            header: header,
            payload: payload,
        })
    }
}

impl FromStr for PlanbToken {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let jwt_token = try!{JsonWebToken::from_str(s)};
        PlanbToken::from_jwt_token(&jwt_token).map_err(|x| String::from(x))
    }
}

#[cfg(test)]
mod test {
    use super::{PlanbToken, PlanbHeader, PlanbPayload};
    use std::str::FromStr;
    use chrono::{NaiveDate, NaiveTime, NaiveDateTime};

    const SAMPLE_TOKEN: &'static str = "eyJraWQiOiJ0ZXN0a2V5LWVzMjU2IiwiYWxnIjoiRVMyNTYifQ.\
                                        eyJzdWIiOiJ0ZXN0MiIsInNjb3BlIjpbImNuIl0sImlzcyI6IkIiLCJyZWFsbSI6Ii9zZXJ2aWNlcyIsImV4cCI6MTQ1NzMxOTgxNCwiaWF0IjoxNDU3MjkxMDE0fQ.\
                                        KmDsVB09RAOYwT0Y6E9tdQpg0rAPd8SExYhcZ9tXEO6y9AWX4wBylnmNHVoetWu7MwoexWkaKdpKk09IodMVug";

    #[test]
    fn parse_the_token() {
        let sample = SAMPLE_TOKEN;
        let expected =
            PlanbToken::new(PlanbHeader {
                                key_id: String::from("testkey-es256"),
                                algorithm: String::from("ES256"),
                            },
                            PlanbPayload {
                                subject: String::from("test2"),
                                realm: String::from("/services"),
                                scopes: vec![String::from("cn")],
                                issuer: String::from("B"),
                                expiration_date_utc:
                                    NaiveDateTime::new(NaiveDate::from_ymd(2016, 3, 7),
                                                       NaiveTime::from_hms_milli(3, 3, 34, 0)),
                                issue_date_utc: NaiveDateTime::new(NaiveDate::from_ymd(2016, 3, 6),
                                                                   NaiveTime::from_hms_milli(19,
                                                                                             3,
                                                                                             34,
                                                                                             0)),
                            });

        let result = PlanbToken::from_str(sample).unwrap();

        assert_eq!(expected, result);
    }
}
