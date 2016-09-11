
mod static_provider;

pub use self::static_provider::StaticCredentialsProvider;

#[derive(Clone, Debug)]
pub struct Credentials {
    id: String,
    secret: String,
}

pub trait CredentialsProvider {
    fn get_credentials(&self) -> Result<Credentials, CredentialsError>;
}

#[derive(Clone, Debug)]
pub enum CredentialsError {
    UnknownError { message: String },
}
