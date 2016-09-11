use super::{Credentials, CredentialsError, CredentialsProvider};

pub struct StaticCredentialsProvider {
    credentials: Credentials,
}

impl StaticCredentialsProvider {
    pub fn new(id: String, secret: String) -> StaticCredentialsProvider {
        StaticCredentialsProvider {
            credentials: Credentials {
                id: id,
                secret: secret,
            },
        }
    }
}

impl CredentialsProvider for StaticCredentialsProvider {
    fn get_credentials(&self) -> Result<Credentials, CredentialsError> {
        Ok(self.credentials.clone())
    }
}
