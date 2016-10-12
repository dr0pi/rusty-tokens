//! Credentials provider that uses fixed credentials
use super::{Credentials, CredentialsError, UserCredentialsProvider, ClientCredentialsProvider,
            CredentialsPairProvider};

/// Uses fixed credentials
pub struct StaticCredentialsProvider {
    client_credentials: Credentials,
    user_credentials: Credentials,
}

impl StaticCredentialsProvider {
    pub fn new<S, T, U, V>(client_id: S,
                           client_secret: T,
                           user_id: U,
                           user_secret: V)
                           -> StaticCredentialsProvider
        where S: Into<String>,
              T: Into<String>,
              U: Into<String>,
              V: Into<String>
    {
        StaticCredentialsProvider {
            client_credentials: Credentials {
                id: client_id.into(),
                secret: client_secret.into(),
            },
            user_credentials: Credentials {
                id: user_id.into(),
                secret: user_secret.into(),
            },
        }
    }
}

impl UserCredentialsProvider for StaticCredentialsProvider {
    fn get_user_credentials(&self) -> Result<Credentials, CredentialsError> {
        Ok(self.user_credentials.clone())
    }
}

impl ClientCredentialsProvider for StaticCredentialsProvider {
    fn get_client_credentials(&self) -> Result<Credentials, CredentialsError> {
        Ok(self.client_credentials.clone())
    }
}

impl CredentialsPairProvider for StaticCredentialsProvider {}
