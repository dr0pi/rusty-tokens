//! An `AuthorizationServer` implemented with hyper.
use std::convert::From;
use std::error::Error;
use std::io::Read;
use std::env;
use hyper::{Client, Error as HError};
use hyper::client::response::Response;
use ::InitializationError;
use hyper::status::StatusCode;
use Token;
use super::{AuthorizationServer, AuthenticatedUser, AuthorizationServerError};

/// A struct that implements an `AuthorizationServer`
pub struct AuthorizationHyperServer {
    /// The hyper client to use
    pub http_client: Client,
    /// The primary URL to authenticate Tokens
    pub token_info_url: String,
    /// An optional URL to authenticate Tokens. Used as a fallback when the first one fails.
    pub fallback_token_info_url: Option<String>,
    /// The query parameter that shall contain the Token.
    pub query_parameter: String,
}

impl AuthorizationHyperServer {
    /// Create a new instance
    pub fn new(http_client: Client,
               token_info_url: String,
               query_parameter: String,
               fallback_token_info_url: Option<String>)
               -> Result<AuthorizationHyperServer, InitializationError> {

        if token_info_url.is_empty() {
            return Err(InitializationError::new("token_info_url may ot be empty."));
        }

        if query_parameter.is_empty() {
            return Err(InitializationError::new("query_parameter may ot be empty."));
        }

        info!("token_info_url: {}", &token_info_url);
        info!("query_parameter: {}", &query_parameter);
        info!("fallback_token_info_url: {:?}", fallback_token_info_url);

        info!("The complete token_info_url is: \"{}?{}={{YOUR_TOKEN_HERE}}\"",
              &token_info_url,
              &query_parameter);

        for url in fallback_token_info_url.iter() {
            info!("The complete fallback_token_info_url is: \"{}?{}={{YOUR_TOKEN_HERE}}\"",
                  url,
                  &query_parameter);
        }

        Ok(AuthorizationHyperServer {
            http_client: http_client,
            token_info_url: token_info_url,
            fallback_token_info_url: fallback_token_info_url,
            query_parameter: query_parameter,
        })
    }

    /// Create a new instance from environment variables
    ///
    /// Used vars:
    ///
    /// * RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR(optional): Use this to override the default env var for the token info URL.
    /// If not set RUSTY_TOKENS_TOKEN_INFO_URL will be used as a default.
    /// * RUSTY_TOKENS_TOKEN_INFO_URL(special): Will be used to set the token info URL if not overriden by RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR.
    /// If RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR is not set, this var is mandatory.
    /// * RUSTY_TOKENS_TOKEN_INFO_URL_QUERY_PARAMETER(mandatory): The name of the query parameter used for the token info URL and the fallback URL if set.
    /// * RUSTY_TOKENS_FALLBACK_TOKEN_INFO_URL(optional): A fallback token info URL to be used if the primary one fails.
    pub fn from_env(http_client: Client) -> Result<AuthorizationHyperServer, InitializationError> {
        let token_info_url = match env::var("RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR") {
            Ok(value) => {
                info!("Reading token info url from env var \"{}\" as specified by \
                       \"RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR\".",
                      value);
                try!{env::var(value)}
            }
            Err(env::VarError::NotPresent) => {
                info!("Env var \"RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR\" not found. Reading from \
                       default env var \"RUSTY_TOKENS_TOKEN_INFO_URL\".");
                try!{env::var("RUSTY_TOKENS_TOKEN_INFO_URL")}
            }
            Err(err) => return Err(InitializationError { message: err.description().to_owned() }),
        };

        let fallback_token_info_url = match env::var("RUSTY_TOKENS_FALLBACK_TOKEN_INFO_URL") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => {
                warn!("Env var \"RUSTY_TOKENS_FALLBACK_TOKEN_INFO_URL\" not found. There will be \
                       no fallback URL.");
                None
            }
            Err(err) => return Err(InitializationError { message: err.description().to_owned() }),
        };

        let query_parameter = try!{env::var("RUSTY_TOKENS_TOKEN_INFO_URL_QUERY_PARAMETER")};

        AuthorizationHyperServer::new(http_client,
                                      token_info_url,
                                      query_parameter,
                                      fallback_token_info_url)
    }

    fn request_token_info(&self, token: &Token) -> Result<Response, AuthorizationServerError> {
        self.request_token_info_from_url_with_fallback(&self.create_url(token),
                                                       &self.create_fallback_url(token),
                                                       2)
    }


    fn request_token_info_from_url(&self,
                                   url: &str,
                                   attempts_left: usize)
                                   -> Result<Response, AuthorizationServerError> {
        if attempts_left == 0 {
            Err(AuthorizationServerError::Unknown {
                message: "No response after multiple retries.".to_owned(),
            })
        } else {
            match self.http_client.get(url).send() {
                Ok(rsp) => Ok(rsp),
                Err(HError::Io(io_err)) => {
                    error!("IO Error: {}", io_err.description());
                    self.request_token_info_from_url(url, attempts_left - 1)
                }
                Err(HError::Uri(parse_error)) => {
                    error!("URI not parsable: {}", parse_error.description());
                    return Err(AuthorizationServerError::NotAuthenticated {
                        message: "Token could not be validated.".to_owned(),
                    });
                }
                Err(err) => {
                    error!("Something bad happened: {}", err.description());
                    return Err(AuthorizationServerError::NotAuthenticated {
                        message: "Token could not be validated.".to_owned(),
                    });
                }
            }
        }

    }

    fn request_token_info_from_url_with_fallback(&self,
                                                 primary_url: &str,
                                                 fallback_url: &Option<String>,
                                                 attempts: usize)
                                                 -> Result<Response, AuthorizationServerError> {

        match self.request_token_info_from_url(primary_url, attempts) {
            Ok(rsp) => Ok(rsp),
            Err(err) => {
                match *fallback_url {
                    Some(ref url) => {
                        warn!("Falling back to fallback url.");
                        match self.request_token_info_from_url(url, attempts) {
                            Ok(rsp) => Ok(rsp),
                            Err(err) => Err(err),
                        }
                    }
                    None => Err(err),
                }
            }
        }
    }

    fn create_url(&self, token: &Token) -> String {
        format!("{}?{}={}",
                self.token_info_url,
                self.query_parameter,
                token.0)

    }

    fn create_fallback_url(&self, token: &Token) -> Option<String> {
        match self.fallback_token_info_url {
            Some(ref fb_url) => Some(format!("{}?{}={}", fb_url, self.query_parameter, token.0)),
            None => None,
        }
    }
}

impl AuthorizationServer for AuthorizationHyperServer {
    fn authenticate(&self, token: &Token) -> Result<AuthenticatedUser, AuthorizationServerError> {
        let mut response = try!{ self.request_token_info(&token) };
        match response.status {
            StatusCode::Ok => {
                let mut buf = String::new();
                let _ = try!{response.read_to_string(&mut buf)};
                let user = try!{AuthenticatedUser::from_json(buf.as_ref())};
                Ok(user)
            }
            StatusCode::BadRequest => {
                Err(AuthorizationServerError::NotAuthenticated {
                    message: "Token could not be validated.".to_owned(),
                })
            }
            status_code => {
                error!("The authorization server answered with status {}.",
                       status_code);
                Err(AuthorizationServerError::NotAuthenticated {
                    message: "Token could not be validated.".to_owned(),
                })
            }
        }
    }
}

impl From<HError> for AuthorizationServerError {
    fn from(err: HError) -> Self {
        AuthorizationServerError::Connection { message: err.description().to_owned() }
    }
}
