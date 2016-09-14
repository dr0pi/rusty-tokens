use std::error::Error;
use {Token, InitializationError};
use super::{TokenError, TokenProvider, ManagedToken, CredentialsProvider};
use std::sync::{Arc, RwLock};
use hyper;

pub struct HyperTokenProviderConfig<T: CredentialsProvider> {
    url: String,
    credentials_provider: T,
}


#[derive(Clone)]
pub struct HyperTokenProvider {
    token_state: Arc<RwLock<Result<TokenData, TokenError>>>,
}

impl HyperTokenProvider {
    pub fn new<T: CredentialsProvider>(managed_token: ManagedToken,
                                       http_client: hyper::Client,
                                       conf: HyperTokenProviderConfig<T>)
                                       -> Result<HyperTokenProvider, InitializationError> {
        let provider =
            HyperTokenProvider { token_state: Arc::new(RwLock::new(Err(TokenError::NoToken))) };
        try!{start_manager(provider.clone(),
                      managed_token,
                      http_client,
                      conf)};
        Ok(provider)
    }
}

impl TokenProvider for HyperTokenProvider {
    fn get_token(&self) -> Result<Token, TokenError> {
        match self.token_state.read() {
            Err(err) => Err(TokenError::InternalProblem { message: err.description().to_string() }),
            Ok(lock) => (*lock).clone().map(|tokendata| tokendata.token),
        }
    }
}

fn start_manager<T: CredentialsProvider>(provider: HyperTokenProvider,
                                         managed_token: ManagedToken,
                                         http_client: hyper::Client,
                                         conf: HyperTokenProviderConfig<T>)
                                         -> Result<(), InitializationError> {
    panic!("")
}

fn update_token<T: CredentialsProvider>(provider: HyperTokenProvider,
                                        credentials_provider: T,
                                        managed_token: ManagedToken,
                                        http_client: hyper::Client,
                                        url: &str)
                                        -> Result<Token, TokenError> {
    panic!("")
}

fn query_token<T: CredentialsProvider>(provider: HyperTokenProvider,
                                       credentials_provider: T,
                                       managed_token: ManagedToken,
                                       http_client: hyper::Client,
                                       url: &str)
                                       -> Result<Token, TokenError> {
    panic!("")
}
