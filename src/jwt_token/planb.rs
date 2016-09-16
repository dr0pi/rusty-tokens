use std::str::FromStr;
use chrono::*;
use super::*;

pub struct PlanbHeader {
    pub kid: String,
    pub algorithms: String,
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
    fn from_jwt_token(jwt_token: &JsonWebToken) -> Result<PlanbToken, String> {
        panic!("")
    }
}

impl FromStr for PlanbToken {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let jwt_token = try!{JsonWebToken::from_str(s)};
        PlanbToken::from_jwt_token(&jwt_token)
    }
}
