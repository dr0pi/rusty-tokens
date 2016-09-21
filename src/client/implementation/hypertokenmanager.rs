use std::thread::JoinHandle;
use std::io::Read;
use url::form_urlencoded;
use hyper;
use hyper::header::{Headers, Authorization, Basic, ContentType};
use hyper::client::response::Response;
use hyper::status::StatusCode;
use {InitializationError, Scope};
use rustc_serialize::json;
use jwt::planb::PlanbToken;
use client::credentials::{CredentialsPair, CredentialsPairProvider};
use super::{SelfUpdatingTokenManager, SelfUpdatingTokenManagerConfig, AccessTokenProvider, AccessToken,
            RequestAccessTokenResult, RequestAccessTokenError};

pub struct HyperTokenManager;

impl HyperTokenManager {
    pub fn new<U>(config: SelfUpdatingTokenManagerConfig,
                  http_client: hyper::Client,
                  credentials_provider: U,
                  url: String,
                  realm: String)
                  -> Result<(SelfUpdatingTokenManager, JoinHandle<()>), InitializationError>
        where U: CredentialsPairProvider + Send + 'static
    {
        let acccess_token_provider = HyperAccessTokenProvider {
            client: http_client,
            full_url_with_realm: format!("{}?realm={}", url, realm),
        };
        SelfUpdatingTokenManager::new(config, credentials_provider, acccess_token_provider)
    }
}

struct HyperAccessTokenProvider {
    client: hyper::Client,
    full_url_with_realm: String,
}

#[derive(RustcDecodable, Debug)]
struct PlanBAccesTokenResponse {
    access_token: String,
}

impl HyperAccessTokenProvider {
    fn request_access_token(&self,
                            scopes: &[Scope],
                            credentials: &CredentialsPair)
                            -> RequestAccessTokenResult {
        // execute_http_request()
        // evaluate_response
        unimplemented!();
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
            username: credentials.client_credentials.id.clone(),
            password: Some(credentials.client_credentials.secret.clone()),
        }));
        headers.set(ContentType::form_url_encoded());
        let form_encoded = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "password")
            .append_pair("username", &credentials.user_credentials.id)
            .append_pair("password", &credentials.user_credentials.secret)
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
            let _ = response.read_to_string(&mut buf);

            match json::decode::<PlanBAccesTokenResponse>(buf) {
                Err(json_decode_error) => {
                    Err(RequestAccessTokenError::ParsingError(json_decode_error.description().to_owned()                    )
                }
                Ok(planb_response) => {
                    match PlanbToken::from_str(&planb_response) {
                        Ok(planbToken) => AccessToken{
                            token: Token,
                            issued_at_utc: NaiveDateTime,
                            valid_until_utc: NaiveDateTime,

                        },
                        Err(error) => Err(RequestAccessTokenError::ParsingError(format!("{}", error))
                    }

                }
            }

            unimplemented!();
        }
        status => {
            let mut buf = String::new();
            let _ = response.read_to_string(&mut buf);
            Err(RequestAccessTokenError::RequestError {
                status: status.to_u16(),
                body: buf,
            })
        }
    }
}
