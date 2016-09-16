use hyper;
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
            full_url: format!("{}?realm={}", url, realm),
        };
        SelfUpdatingTokenManager::new(config, credentials_provider, acccess_token_provider)
    }
}

struct HyperAccessTokenProvider {
    client: hyper::Client,
    full_url: String,
}

impl AccessTokenProvider for HyperAccessTokenProvider {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        client_credentials: &Credentials,
                        user_credentials: &Credentials)
                        -> RequestAccessTokenResult {
        let grant = format!("grant_type=password&username={}&password={}",
                            user_credentials.id,
                            user_credentials.secret);
        panic!("")
    }
}
