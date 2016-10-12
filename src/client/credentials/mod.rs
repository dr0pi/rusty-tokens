//! `Credentials` are needed to receive a token from the `TokenProvider`.
use std::io;
use std::convert::{Into, From};
use std::error::Error;
use std::fmt;

mod static_provider;
mod file_credentials_provider;

pub use self::static_provider::StaticCredentialsProvider;
pub use self::file_credentials_provider::{FileCredentialsProvider, UserFileCredentialsProvider,
                                          ClientFileCredentialsProvider};

/// The result of a credentials query.
pub type CredentialsResult = Result<Credentials, CredentialsError>;

/// Credentials contain an id which usually identifies a user and a secret to authenticate
/// against a server.
#[derive(Clone, Debug, PartialEq)]
pub struct Credentials {
    /// Identifies the user or client
    pub id: String,
    /// The secret to authenticate
    pub secret: String,
}

impl Credentials {
    pub fn new<T, U>(id: T, secret: U) -> Credentials
        where T: Into<String>,
              U: Into<String>
    {
        Credentials {
            id: id.into(),
            secret: secret.into(),
        }
    }
}

/// The token provider requires two credentials.
///
/// Theese are:
///
/// * One for the client
/// * One for the user
pub struct CredentialsPair {
    pub client_credentials: Credentials,
    pub user_credentials: Credentials,
}

/// A `CredentialsProvider` that provides client `Credentials`
pub trait ClientCredentialsProvider {
    fn get_client_credentials(&self) -> CredentialsResult;
}

/// A `CredentialsProvider` that provides user `Credentials`
pub trait UserCredentialsProvider {
    fn get_user_credentials(&self) -> CredentialsResult;
}

/// A `CredentialsProvider` that provides both user and client `Credentials`
pub trait CredentialsPairProvider
    : ClientCredentialsProvider + UserCredentialsProvider {
    fn get_credentials_pair(&self) -> Result<CredentialsPair, CredentialsError> {
        let client_credentials = try!{self.get_client_credentials()};
        let user_credentials = try!{self.get_user_credentials()};
        Ok(CredentialsPair {
            client_credentials: client_credentials,
            user_credentials: user_credentials,
        })
    }
}

/// The `CredentialsProvider` that provides both user and client `Credentials`
pub struct CredentialsProvider<C: ClientCredentialsProvider, U: UserCredentialsProvider> {
    client_credentials_provider: C,
    user_credentials_provider: U,
}

impl<C: ClientCredentialsProvider, U: UserCredentialsProvider> CredentialsProvider<C, U> {
    fn new(client_credentials_provider: C,
           user_credentials_provider: U)
           -> CredentialsProvider<C, U> {
        CredentialsProvider {
            client_credentials_provider: client_credentials_provider,
            user_credentials_provider: user_credentials_provider,
        }
    }
}

impl<C: ClientCredentialsProvider, U: UserCredentialsProvider> UserCredentialsProvider for CredentialsProvider<C, U> {
    fn get_user_credentials(&self) -> Result<Credentials, CredentialsError> {
        self.client_credentials_provider.get_client_credentials()
    }
}

impl<C: ClientCredentialsProvider, U: UserCredentialsProvider> ClientCredentialsProvider for CredentialsProvider<C, U> {
    fn get_client_credentials(&self) -> Result<Credentials, CredentialsError> {
        self.user_credentials_provider.get_user_credentials()
    }
}

impl<C: ClientCredentialsProvider, U: UserCredentialsProvider> CredentialsPairProvider for CredentialsProvider<C, U>{}


/// Errors that can occur when credentials could not be fetched.
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
        CredentialsError::IoError { message: err.description().to_owned() }
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
