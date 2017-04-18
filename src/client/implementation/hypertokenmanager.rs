use std::thread::JoinHandle;
use std::io::Read;
use std::env;
use std::str::FromStr;
use std::convert::Into;
use std::thread;
use std::time::Duration;
use url::form_urlencoded;
use hyper;
use hyper::header::{Headers, Authorization, Basic, ContentType};
use hyper::client::response::Response;
use hyper::status::StatusCode;
use rustc_serialize::json;
use jwt::planb::PlanbToken;
use {InitializationError, Scope, Token};
use client::credentials::{CredentialsPair, CredentialsPairProvider, FileCredentialsProvider};
use client::ManagedToken;
use super::*;

pub struct HyperTokenManager;

/// A `TokenManager` that uses `hyper` to fetch `Tokens` remotely.
impl HyperTokenManager {
    /// Creates a new instance from scratch
    #[must_use]
    pub fn new<U>(config: SelfUpdatingTokenManagerConfig,
                  http_client: hyper::Client,
                  credentials_provider: U,
                  url: &str,
                  realm: &str)
                  -> Result<(SelfUpdatingTokenManager, JoinHandle<()>), InitializationError>
        where U: CredentialsPairProvider + Send + 'static
    {
        let acccess_token_provider =
            HyperAccessTokenProvider::new(http_client, format!("{}?realm={}", url, realm));
        SelfUpdatingTokenManager::new(config, credentials_provider, acccess_token_provider)
    }

    /// Creates a new instance from environment variables. The `CredentialsProvider` still has to be supplied manually.
    ///
    /// Used vars:
    ///
    /// * `RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR`(optional): Use this to override the default env var for the token provider URL.
    /// If not set `RUSTY_TOKENS_TOKEN_PROVIDER_URL` will be used as a default.
    /// * `RUSTY_TOKENS_TOKEN_PROVIDER_URL`(special): Will be used to set the token provider URL if not overriden by `RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR`.
    /// If `RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR` is not set, this var is mandatory.
    /// * `RUSTY_TOKENS_TOKEN_PROVIDER_REALM`(mandatory): The name realm for the `Token`.
    /// * `RUSTY_TOKENS_FALLBACK_TOKEN_PROVIDER_URL`(optional): A fallback provider info URL to be used if the primary one fails.
    /// * `RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR`(mandatory): The percentage of the lifetime of the `Token` after which a new one will be requested.
    /// * `RUSTY_TOKENS_TOKEN_MANAGER_WARNING_FACTOR`(mandatory): The percentage of the lifetime of the `Token` after a warning will be logged.
    /// Should be greater than `RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR`.
    #[must_use]
    pub fn new_from_env<U>
        (http_client: hyper::Client,
         credentials_provider: U,
         managed_tokens: Vec<ManagedToken>)
         -> Result<(SelfUpdatingTokenManager, JoinHandle<()>), InitializationError>
        where U: CredentialsPairProvider + Send + 'static
    {
        let config = try!{SelfUpdatingTokenManagerConfig::new_from_env(managed_tokens)};
        let url = try!{get_token_provider_url_from_env()};
        let realm = try!{env::var("RUSTY_TOKENS_TOKEN_PROVIDER_REALM")};
        HyperTokenManager::new(config, http_client, credentials_provider, &url, &realm)
    }

    /// Creates a new instance from environment variables. The used `CredentialsProvider` is
    /// a [`FileCredentialsProvider`](credentials.struct.FileCredentialsProvider.html) that will also be configured by environment variuables.
    ///
    /// Used vars:
    ///
    /// * `RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR`(optional): Use this to override the default env var for the token provider URL.
    /// If not set `RUSTY_TOKENS_TOKEN_PROVIDER_URL` will be used as a default.
    /// * `RUSTY_TOKENS_TOKEN_PROVIDER_URL`(special): Will be used to set the token provider URL if not overriden by `RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR`.
    /// If `RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR` is not set, this var is mandatory.
    /// * `RUSTY_TOKENS_TOKEN_PROVIDER_REALM`(mandatory): The name realm for the `Token`.
    /// * `RUSTY_TOKENS_FALLBACK_TOKEN_PROVIDER_URL`(optional): A fallback provider info URL to be used if the primary one fails.
    /// * `RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR`(mandatory): The percentage of the lifetime of the `Token` after which a new one will be requested.
    /// * `RUSTY_TOKENS_TOKEN_MANAGER_WARNING_FACTOR`(mandatory): The percentage of the lifetime of the `Token` after a warning will be logged.
    /// Should be greater than `RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR`.
    #[must_use]
    pub fn new_with_file_credentials_provider_from_env
        (http_client: hyper::Client,
         managed_tokens: Vec<ManagedToken>)
         -> Result<(SelfUpdatingTokenManager, JoinHandle<()>), InitializationError> {
        let config = try!{SelfUpdatingTokenManagerConfig::new_from_env(managed_tokens)};
        let url = try!{get_token_provider_url_from_env()};
        let realm = try!{env::var("RUSTY_TOKENS_TOKEN_PROVIDER_REALM")};
        let credentials_provider = try!{FileCredentialsProvider::new_from_env()};

        HyperTokenManager::new(config, http_client, credentials_provider, &url, &realm)
    }
}

struct HyperAccessTokenProvider {
    client: hyper::Client,
    full_url_with_realm: String,
}

#[derive(RustcDecodable, Debug)]
struct PlanBAccessTokenResponse {
    access_token: String,
    expires_in: u64,
}

impl HyperAccessTokenProvider {
    pub fn new<T: Into<String>>(client: hyper::Client,
                                full_url_with_realm: T)
                                -> HyperAccessTokenProvider {
        HyperAccessTokenProvider {
            client: client,
            full_url_with_realm: full_url_with_realm.into(),
        }
    }

    fn request_access_token(&self,
                            scopes: &[Scope],
                            credentials: &CredentialsPair)
                            -> RequestAccessTokenResult {
        let mut response =
            try!{self.execute_http_request_with_multiple_attempts(scopes, credentials, 3, None)};
        evaluate_response(&mut response)
    }

    fn execute_http_request_with_multiple_attempts(&self,
                                                   scopes: &[Scope],
                                                   credentials: &CredentialsPair,
                                                   attempts: u16,
                                                   last_error: Option<RequestAccessTokenError>)
                                                   -> Result<Response, RequestAccessTokenError> {
        if attempts == 0 {
            match last_error {
                Some(err) => Err(err),
                None => {
                    Err(RequestAccessTokenError::InternalError(String::from("No attempts were \
                                                                             made.")))
                }
            }
        } else {
            let result = self.execute_http_request(scopes, credentials);
            match result {
                Ok(res) => Ok(res),
                Err(err) => {
                    warn!("Failed to request access token(connection error): {}", err);
                    thread::sleep(Duration::from_millis(30));
                    self.execute_http_request_with_multiple_attempts(scopes,
                                                                     credentials,
                                                                     attempts - 1,
                                                                     Some(RequestAccessTokenError::ConnectionError(format!("{}", err))))
                }
            }
        }
    }

    fn execute_http_request(&self,
                            scopes: &[Scope],
                            credentials: &CredentialsPair)
                            -> hyper::error::Result<Response> {

        let mut headers = Headers::new();
        let mut scope_vec = Vec::new();
        for scope in scopes {
            scope_vec.push(scope.0.clone());
        }
        headers.set(Authorization(Basic {
            username: credentials.user_credentials.id.clone(),
            password: Some(credentials.user_credentials.secret.clone()),
//            username: credentials.client_credentials.id.clone(),
//            password: Some(credentials.client_credentials.secret.clone()),
        }));
        headers.set(ContentType::form_url_encoded());
        let form_encoded = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "password")
            .append_pair("username", &credentials.client_credentials.id)
            .append_pair("password", &credentials.client_credentials.secret)
//            .append_pair("username", &credentials.user_credentials.id)
//            .append_pair("password", &credentials.user_credentials.secret)
            .append_pair("scope", &scope_vec.join(" "))
            .finish();

        self.client
            .post(&self.full_url_with_realm)
            .headers(headers)
            .body(&form_encoded)
            .send()
    }
}

impl AccessTokenProvider for HyperAccessTokenProvider {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        credentials: &CredentialsPair)
                        -> RequestAccessTokenResult {
        self.request_access_token(scopes, credentials)
    }
}

fn evaluate_response(response: &mut Response) -> RequestAccessTokenResult {
    match response.status {
        StatusCode::Ok => {
            let mut buf = String::new();
            let _ = try!{response.read_to_string(&mut buf)};
            let decoded_response = try!{json::decode::<PlanBAccessTokenResponse>(&buf)};
            debug!("Received a token that expires in {} seconds",
                   decoded_response.expires_in);
            let planb_token = try!{PlanbToken::from_str(&decoded_response.access_token).map_err(|err|
                RequestAccessTokenError::ParsingError(format!("Failed to parse response as a Plan B token: {}", err)))};
            Ok(AccessToken {
                token: Token(decoded_response.access_token),
                issued_at_utc: planb_token.payload.issue_date_utc,
                valid_until_utc: planb_token.payload.expiration_date_utc,
            })
        }
        StatusCode::Unauthorized => {
            Err(RequestAccessTokenError::InvalidCredentials(format!("Token service said: \
                                                                     401-Unauthorized. Maybe I \
                                                                     have wrong credentials?")))
        }
        status => {
            let mut buf = String::new();
            let _ = try!{response.read_to_string(&mut buf)};
            Err(RequestAccessTokenError::RequestError {
                status: status.to_u16(),
                body: buf,
            })
        }
    }
}

fn get_token_provider_url_from_env() -> Result<String, InitializationError> {
    let env_var_name = match env::var("RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR") {
        Ok(env_var_name) => env_var_name,
        Err(env::VarError::NotPresent) => String::from("RUSTY_TOKENS_TOKEN_PROVIDER_URL"),
        Err(err) => {
            return Err(InitializationError {
                message: format!("Error reading RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR env var: \
                                  {}",
                                 err),
            })
        }
    };

    let mut url = String::new();
    match env::var(&env_var_name) {
        Ok(provider_url) => {
            info!("Token provider URL is {}.", &provider_url);
            url.push_str(&provider_url);
            Ok(url)
        }
        Err(err) => {
            Err(InitializationError {
                message: format!("Error reading Token Provider URL from env var {}: {}",
                                 &env_var_name,
                                 err),
            })
        }

    }
}
