use hyper;
use {InitializationError, Scope};
use client::credentials::Credentials;
use super::{SelfUpdatingTokenManager, SelfUpdatingTokenManagerConfig, AccessTokenProvider,
            RequestAccessTokenResult};

pub struct HyperTokenManager;

impl HyperTokenManager {
    fn new(config: SelfUpdatingTokenManagerConfig,
           http_client: hyper::Client,
           url: String)
           -> Result<SelfUpdatingTokenManager, InitializationError> {
        let provider = HyperAccessTokenProvider {
            client: http_client,
            url: url,
        };
        SelfUpdatingTokenManager::new(config, provider)
    }
}

struct HyperAccessTokenProvider {
    client: hyper::Client,
    url: String,
}

impl AccessTokenProvider for HyperAccessTokenProvider {
    fn request_access_token(&self,
                            scopes: &Vec<Scope>,
                            credentials: &Credentials)
                            -> RequestAccessTokenResult {
        panic!("")
    }
}
