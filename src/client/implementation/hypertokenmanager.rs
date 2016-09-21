use std::thread::JoinHandle;
use hyper;
use hyper::header::{Headers, Authorization, Basic};
use hyper::client::response::Response;
use {InitializationError, Scope};
use client::credentials::{CredentialsPair, CredentialsPairProvider};
use super::{SelfUpdatingTokenManager, SelfUpdatingTokenManagerConfig, AccessTokenProvider,
            RequestAccessTokenResult};

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

        let grant = format!("grant_type=password&username={}&password={}",
                            credentials.user_credentials.id,
                            credentials.user_credentials.secret);
        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: credentials.client_credentials.id.clone(),
            password: Some(credentials.client_credentials.secret.clone()),
        }));
        self.client.post(&self.full_url_with_realm).headers(headers).send()
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

fn evaluate_response(response: Response) -> RequestAccessTokenResult {
    unimplemented!();
}
