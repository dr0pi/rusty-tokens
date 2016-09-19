use std::str::FromStr;
use rustc_serialize::json::Json;
use chrono::*;
use super::*;

pub struct PlanbHeader {
    pub key_id: String,
    pub algorithm: String,
}

pub struct PlanbPayload {
    pub subject: String,
    pub realm: String,
    pub scopes: Vec<String>,
    pub issuer: String,
    pub expiration_date: NaiveDateTime,
    pub issue_date: NaiveDateTime,
}

pub struct PlanbToken {
    pub header: PlanbHeader,
    pub payload: PlanbPayload,
}

impl PlanbToken {
    fn from_jwt_token(jwt_token: &JsonWebToken) -> Result<PlanbToken, &'static str> {
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
            expiration_date: expiration_date,
            issue_date: issue_date,
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
