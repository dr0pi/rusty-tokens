
use std::io;
use std::convert::From;
use std::error::Error;
use std::fmt;

mod static_provider;
mod file_credentials_provider;

pub use self::static_provider::StaticCredentialsProvider;
pub use self::file_credentials_provider::ClientFileCredentialsProvider;

pub type CredentialsResult = Result<Credentials, CredentialsError>;

#[derive(Clone, Debug, PartialEq)]
pub struct Credentials {
    id: String,
    secret: String,
}

pub trait CredentialsProvider: Send {
    fn get_credentials(&self) -> CredentialsResult;
}

#[derive(Debug, Clone)]
pub enum CredentialsError {
    IoError {
        message: String,
    },
    DecodingError {
        message: String,
    },
}

impl From<io::Error> for CredentialsError {
    fn from(err: io::Error) -> Self {
        CredentialsError::IoError { message: err.description().to_string() }
    }
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CredentialsError::IoError { ref message } => write!(f, "IO error: {}", message),
            CredentialsError::DecodingError { ref message } => {
                write!(f, "Decoding error: {}", message)
            }
        }
    }
}

impl Error for CredentialsError {
    fn description(&self) -> &str {
        match *self {
            CredentialsError::IoError { ref message } |
            CredentialsError::DecodingError { ref message } => message.as_ref(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}
