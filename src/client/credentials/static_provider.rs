use super::{Credentials, CredentialsError, UserCredentialsProvider, ClientCredentialsProvider};

pub struct StaticCredentialsProvider {
    client_credentials: Credentials,
    user_credentials: Credentials,
}

impl StaticCredentialsProvider {
    pub fn new(client_id: String,
               client_secret: String,
               user_id: String,
               user_secret: String)
               -> StaticCredentialsProvider {
        StaticCredentialsProvider {
            client_credentials: Credentials {
                id: client_id,
                secret: client_secret,
            },
            user_credentials: Credentials {
                id: user_id,
                secret: user_secret,
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
