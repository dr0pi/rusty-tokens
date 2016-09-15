use hyper;
use InitializationError;
use super::{SelfUpdatingTokenManager, SelfUpdatingTokenManagerConfig};

pub struct HyperTokenManager;

impl HyperTokenManager {
    fn new(config: SelfUpdatingTokenManagerConfig,
           url: String)
           -> Result<SelfUpdatingTokenManager, InitializationError> {

        // SelfUpdatingTokenManager::new(config, Box::new(|scopes, credentials| panic!("")))
        panic!("")
    }
}
