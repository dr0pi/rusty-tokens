use hyper;
use hyper::header::{Headers, Authorization, Basic};
use hyper::client::response::Response;
use {InitializationError, Scope};
use client::credentials::{Credentials, UserCredentialsProvider, ClientCredentialsProvider};
use super::{SelfUpdatingTokenManager, SelfUpdatingTokenManagerConfig, AccessTokenProvider,
            RequestAccessTokenResult};

pub struct HyperTokenManager;

impl HyperTokenManager {
    pub fn new<U>(config: SelfUpdatingTokenManagerConfig,
                  http_client: hyper::Client,
                  credentials_provider: U,
                  url: String,
                  realm: String)
                  -> Result<SelfUpdatingTokenManager, InitializationError>
        where U: ClientCredentialsProvider + UserCredentialsProvider + Send + 'static
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

impl HyperAccessTokenProvider {
    fn request_access_token(&self,
                            scopes: &[Scope],
                            client_credentials: &Credentials,
                            user_credentials: &Credentials)
                            -> RequestAccessTokenResult {
        // execute_http_request()
        // evaluate_response
        panic!("")
    }

    fn execute_http_request(&self,
                            scopes: &[Scope],
                            client_credentials: &Credentials,
                            user_credentials: &Credentials)
                            -> hyper::error::Result<Response> {

        let grant = format!("grant_type=password&username={}&password={}",
                            user_credentials.id,
                            user_credentials.secret);
        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: client_credentials.id.clone(),
            password: Some(client_credentials.secret.clone()),
        }));
        self.client.post(&self.full_url_with_realm).headers(headers).send()
    }
}

impl AccessTokenProvider for HyperAccessTokenProvider {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        client_credentials: &Credentials,
                        user_credentials: &Credentials)
                        -> RequestAccessTokenResult {
        self.request_access_token(scopes, client_credentials, user_credentials)
    }
}

fn evaluate_response(response: Response) -> RequestAccessTokenResult {
    panic!("")
}
