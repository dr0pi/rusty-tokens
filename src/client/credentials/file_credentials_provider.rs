//! Credentials provider that fetches credentials from files whenever credentials are requested.
//!
//! The client credentials file must be of the following format:
//!
//! ```javascript
//! {
//!     "user_id": "id",
//!     "user_secret": "secret"
//! }
//! ```
//!
//! The user credentials file must be of the following format:
//!
//! ```javascript
//! {
//!     "application_username": "id",
//!     "application_password": "secret"
//! }
//! ```

use std::io;
use std::env;
use std::fs::File;
use std::io::Read;
use std::error::Error;
use std::path::{PathBuf, Path};
use rustc_serialize::json;

use InitializationError;
use super::{Credentials, CredentialsError, ClientCredentialsProvider, UserCredentialsProvider,
            CredentialsProvider};

/// Reads user credentials from a file.
///
/// The file must be of the following format:
///
/// ```javascript
/// {
///     "application_username": "id",
///     "application_password": "secret"
/// }
/// ```
pub struct UserFileCredentialsProvider {
    /// The complete path to the credentials file.
    pub path: PathBuf,
}

impl UserFileCredentialsProvider {
    /// Create a new instance given the complete path
    pub fn new(path: &Path) -> UserFileCredentialsProvider {
        UserFileCredentialsProvider { path: PathBuf::from(path) }
    }


    /// Create a new instance from environment variables
    ///
    /// Used vars:
    ///
    /// * `RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR`(optional): Use this to override the name of the env var for credentials file directory.
    /// If not set RUSTY_TOKENS_CREDENTIALS_DIR` will be used as a default.
    /// * `RUSTY_TOKENS_CREDENTIALS_DIR`(special): Will be used to set the credentials file directory if not overridden by `RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR`.
    /// * `RUSTY_TOKENS_USER_CREDENTIALS_FILE_NAME`(mandatory): The file name of the credentials file, e.g "user.json".
    pub fn new_from_env() -> Result<UserFileCredentialsProvider, InitializationError> {
        let mut path_buf = try!{get_credentials_dir_from_env()};

        match env::var("RUSTY_TOKENS_USER_CREDENTIALS_FILE_NAME") {
            Ok(user_filename) => path_buf.push(user_filename),
            Err(err) => {
                return Err(InitializationError {
                    message: format!("Error reading \
                                      RUSTY_TOKENS_USER_CREDENTIALS_FILE_NAME \
                                      var: {}",
                                     err),
                })
            }
        }

        Ok(UserFileCredentialsProvider { path: path_buf })
    }
}

impl UserCredentialsProvider for UserFileCredentialsProvider {
    fn get_user_credentials(&self) -> Result<Credentials, CredentialsError> {
        let file_content = try!{read_credentials_file(&self.path)};
        parse_user_json(&file_content)
    }
}


/// Reads client credentials from a file.
///
/// The file must be of the following format:
///
/// ```javascript
/// {
///     "user_id": "id",
///     "user_secret": "secret"
/// }
/// ```
pub struct ClientFileCredentialsProvider {
    path: PathBuf,
}

impl ClientFileCredentialsProvider {
    /// Create a new instance give the complete path the the client credentials file.
    pub fn new(path: &Path) -> ClientFileCredentialsProvider {
        ClientFileCredentialsProvider { path: PathBuf::from(path) }
    }

    /// Create a new instance from environment variables
    ///
    /// Used vars:
    ///
    /// * RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR(optional): Use this to override the name of the env var for credentials file directory.
    /// If not set RUSTY_TOKENS_CREDENTIALS_DIR will be used as a default.
    /// * RUSTY_TOKENS_CREDENTIALS_DIR(special): Will be used to set the credentials file directory if not overridden by RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR.
    /// * RUSTY_TOKENS_CLIENT_CREDENTIALS_FILE_NAME(mandatory): The file name of the credentials file, e.g "client.json".
    pub fn new_from_env() -> Result<ClientFileCredentialsProvider, InitializationError> {
        let mut path_buf = try!{get_credentials_dir_from_env()};

        match env::var("CREDENTIALS_DIR") {
            Ok(credentials_dir) => path_buf.push(credentials_dir),
            Err(err) => {
                return Err(InitializationError {
                    message: format!("Error reading CREDENTIALS_DIR var: {}", err),
                })
            }
        }

        match env::var("RUSTY_TOKENS_CLIENT_CREDENTIALS_FILE_NAME") {
            Ok(client_filename) => path_buf.push(client_filename),
            Err(err) => {
                return Err(InitializationError {
                    message: format!("Error reading \
                                      RUSTY_TOKENS_CLIENT_CREDENTIALS_FILE_NAME \
                                      var: {}",
                                     err),
                })
            }
        }

        Ok(ClientFileCredentialsProvider { path: path_buf })
    }
}

impl ClientCredentialsProvider for ClientFileCredentialsProvider {
    fn get_client_credentials(&self) -> Result<Credentials, CredentialsError> {
        let file_content = try!{read_credentials_file(&self.path)};
        parse_client_json(&file_content)
    }
}

pub struct FileCredentialsProvider {
    client_provider: ClientFileCredentialsProvider,
    user_provider: UserFileCredentialsProvider,
}

impl FileCredentialsProvider {
    /// Create a new instance given the credentials directory and both the filenames
    /// of the client and user credentials file
    pub fn new
        (credentials_dir: &str,
         client_filename: &str,
         user_filename: &str)
         -> CredentialsProvider<ClientFileCredentialsProvider, UserFileCredentialsProvider> {
        let mut client_path = PathBuf::from(credentials_dir);
        client_path.push(client_filename);
        let mut user_path = PathBuf::from(credentials_dir);
        user_path.push(user_filename);

        FileCredentialsProvider::create(ClientFileCredentialsProvider::new(client_path.as_path()),
                                        UserFileCredentialsProvider::new(user_path.as_path()))
    }

    /// Create a new instance from environment variables
    ///
    /// Used vars:
    ///
    /// * RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR(optional): Use this to override the name of the env var for credentials file directory.
    /// If not set RUSTY_TOKENS_CREDENTIALS_DIR will be used as a default.
    /// * RUSTY_TOKENS_CREDENTIALS_DIR(special): Will be used to set the credentials file directory if not overridden by RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR.
    /// * RUSTY_TOKENS_USER_CREDENTIALS_FILE_NAME(mandatory): The file name of the user credentials file, e.g "user.json".
    /// * RUSTY_TOKENS_CLIENT_CREDENTIALS_FILE_NAME(mandatory): The file name of the client credentials file, e.g "client.json".
    pub fn new_from_env()
        -> Result<CredentialsProvider<ClientFileCredentialsProvider, UserFileCredentialsProvider>,
                  InitializationError>
    {
        let client_provider = try!{ ClientFileCredentialsProvider::new_from_env() };
        let user_provider = try!{ UserFileCredentialsProvider::new_from_env() };

        Ok(FileCredentialsProvider::create(client_provider, user_provider))
    }

    pub fn create
        (client_provider: ClientFileCredentialsProvider,
         user_provider: UserFileCredentialsProvider)
         -> CredentialsProvider<ClientFileCredentialsProvider, UserFileCredentialsProvider> {
        CredentialsProvider::new(client_provider, user_provider)
    }
}

impl ClientCredentialsProvider for FileCredentialsProvider {
    fn get_client_credentials(&self) -> Result<Credentials, CredentialsError> {
        self.client_provider.get_client_credentials()
    }
}

impl UserCredentialsProvider for FileCredentialsProvider {
    fn get_user_credentials(&self) -> Result<Credentials, CredentialsError> {
        self.user_provider.get_user_credentials()
    }
}

fn read_credentials_file(path: &Path) -> io::Result<String> {
    let mut file = try!{File::open(path)};
    let mut buffer = String::new();
    try!(file.read_to_string(&mut buffer));
    Ok(buffer)
}

fn parse_client_json(to_parse: &str) -> Result<Credentials, CredentialsError> {
    match json::decode::<ClientCredentials>(to_parse) {
        Err(json_decode_error) => {
            Err(CredentialsError::DecodingError {
                message: json_decode_error.description().to_owned(),
            })
        }
        Ok(client_credentials) => {
            Ok(Credentials {
                id: client_credentials.client_id,
                secret: client_credentials.client_secret,
            })
        }
    }
}

fn parse_user_json(to_parse: &str) -> Result<Credentials, CredentialsError> {
    match json::decode::<UserCredentials>(to_parse) {
        Err(json_decode_error) => {
            Err(CredentialsError::DecodingError {
                message: json_decode_error.description().to_owned(),
            })
        }
        Ok(user_credentials) => {
            Ok(Credentials {
                id: user_credentials.application_username,
                secret: user_credentials.application_password,
            })
        }
    }
}

fn get_credentials_dir_from_env() -> Result<PathBuf, InitializationError> {
    let env_var_name = match env::var("RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR") {
        Ok(env_var_name) => env_var_name,
        Err(env::VarError::NotPresent) => String::from("RUSTY_TOKENS_CREDENTIALS_DIR"),
        Err(err) => {
            return Err(InitializationError {
                message: format!("Error reading RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR env var: {}",
                                 err),
            })
        }
    };

    let mut path = PathBuf::new();
    match env::var(&env_var_name) {
        Ok(credentials_dir) => {
            info!("Credentials directory is {}.", &credentials_dir);
            path.push(credentials_dir);
            Ok(path)
        }
        Err(err) => {
            Err(InitializationError {
                message: format!("Error reading credentials directory from env var {}: {}",
                                 &env_var_name,
                                 err),
            })
        }

    }
}



#[derive(RustcDecodable, PartialEq, Debug)]
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}

#[derive(RustcDecodable, PartialEq, Debug)]
struct UserCredentials {
    application_username: String,
    application_password: String,
}

#[test]
fn must_parse_client_credentials() {
    let expected = Credentials {
        id: String::from("id"),
        secret: String::from("secret"),
    };

    let sample = "{\"client_id\": \"id\", \"client_secret\": \"secret\"}";

    let parsed_sample = parse_client_json(sample).unwrap();

    assert_eq!(expected, parsed_sample);
}

#[test]
fn must_parse_user_credentials() {
    let expected = Credentials {
        id: String::from("id"),
        secret: String::from("secret"),
    };

    let sample = "{\"application_username\": \"id\", \"application_password\": \"secret\"}";

    let parsed_sample = parse_user_json(sample).unwrap();

    assert_eq!(expected, parsed_sample);
}
