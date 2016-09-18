use std::io;
use std::fs::File;
use std::io::Read;
use std::error::Error;
use std::path::{PathBuf, Path};
use rustc_serialize::json;

use super::{Credentials, CredentialsError, ClientCredentialsProvider, UserCredentialsProvider,
            CredentialsProvider};

pub struct UserFileCredentialsProvider {
    path: PathBuf,
}

impl UserFileCredentialsProvider {
    pub fn new(path: &Path) -> UserFileCredentialsProvider {
        UserFileCredentialsProvider { path: PathBuf::from(path) }
    }
}

impl UserCredentialsProvider for UserFileCredentialsProvider {
    fn get_user_credentials(&self) -> Result<Credentials, CredentialsError> {
        let file_content = try!{read_credentials_file(&self.path)};
        parse_user_json(&file_content)
    }
}


pub struct ClientFileCredentialsProvider {
    path: PathBuf,
}

impl ClientFileCredentialsProvider {
    pub fn new(path: &Path) -> ClientFileCredentialsProvider {
        ClientFileCredentialsProvider { path: PathBuf::from(path) }
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
    pub fn new
        (path: &str,
         client_filename: &str,
         user_filename: &str)
         -> CredentialsProvider<ClientFileCredentialsProvider, UserFileCredentialsProvider> {
        let mut client_path = PathBuf::from(path);
        client_path.push(client_filename);
        let mut user_path = PathBuf::from(path);
        user_path.push(user_filename);

        FileCredentialsProvider::create(ClientFileCredentialsProvider::new(client_path.as_path()),
                                        UserFileCredentialsProvider::new(user_path.as_path()))
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
