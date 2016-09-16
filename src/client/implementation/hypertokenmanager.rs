use hyper;
use {InitializationError, Scope};
use client::credentials::{Credentials, UserCredentialsProvider, ClientCredentialsProvider};
use super::{SelfUpdatingTokenManager, SelfUpdatingTokenManagerConfig, AccessTokenProvider,
            RequestAccessTokenResult};

pub struct HyperTokenManager;

impl HyperTokenManager {
    fn new<U>(config: SelfUpdatingTokenManagerConfig,
              http_client: hyper::Client,
              credentials_provider: U,
              url: String)
              -> Result<SelfUpdatingTokenManager, InitializationError>
        where U: ClientCredentialsProvider + UserCredentialsProvider + Send + 'static
    {
        let acccess_token_provider = HyperAccessTokenProvider {
            client: http_client,
            url: url,
        };
        SelfUpdatingTokenManager::new(config, credentials_provider, acccess_token_provider)
    }
}

struct HyperAccessTokenProvider {
    client: hyper::Client,
    url: String,
}

impl AccessTokenProvider for HyperAccessTokenProvider {
    fn get_access_token(&self,
                        scopes: &[Scope],
                        client_credentials: &Credentials,
                        user_credentials: &Credentials)
                        -> RequestAccessTokenResult {
        panic!("")
    }
}
