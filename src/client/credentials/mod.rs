
use std::io;
use std::convert::From;
use std::error::Error;
use std::fmt;

mod static_provider;
mod file_credentials_provider;

pub use self::static_provider::StaticCredentialsProvider;
pub use self::file_credentials_provider::ClientFileCredentialsProvider;

#[derive(Clone, Debug)]
pub struct Credentials {
    id: String,
    secret: String,
}

pub trait CredentialsProvider {
    fn get_credentials(&self) -> Result<Credentials, CredentialsError>;
}

#[derive(Debug)]
pub enum CredentialsError {
    IoError(io::Error),
    DecodingError { message: String },
}

impl From<io::Error> for CredentialsError {
    fn from(err: io::Error) -> Self {
        CredentialsError::IoError(err)
    }
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CredentialsError::IoError(ref err) => write!(f, "IO error: {}", err.description()),
            CredentialsError::DecodingError { ref message } => {
                write!(f, "Decoding error: {}", message)
            }
        }
    }
}

impl Error for CredentialsError {
    fn description(&self) -> &str {
        match *self {
            CredentialsError::IoError(ref err) => err.description(),
            CredentialsError::DecodingError { ref message } => message.as_ref(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CredentialsError::IoError(ref err) => Some(err),
            _ => None,
        }
    }
}
