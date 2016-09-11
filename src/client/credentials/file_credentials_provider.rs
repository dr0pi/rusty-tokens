use std::io;
use std::fs::File;
use std::io::Read;
use std::error::Error;
use rustc_serialize::json;

use super::{Credentials, CredentialsError, CredentialsProvider};

pub struct ClientFileCredentialsProvider {
    path: String,
}

impl ClientFileCredentialsProvider {
    pub fn new(path: String) -> ClientFileCredentialsProvider {
        ClientFileCredentialsProvider { path: path }
    }
}

impl CredentialsProvider for ClientFileCredentialsProvider {
    fn get_credentials(&self) -> Result<Credentials, CredentialsError> {
        let file_content = try!{read_credentials_file(&self.path)};
        parse_client_json(&file_content)
    }
}

fn read_credentials_file(path: &str) -> io::Result<String> {
    let mut file = try!{File::open(path)};
    let mut buffer = String::new();
    try!(file.read_to_string(&mut buffer));
    Ok(buffer)
}


fn parse_client_json(to_parse: &str) -> Result<Credentials, CredentialsError> {
    match json::decode::<ClientCredentials>(to_parse) {
        Err(json_decode_error) => {
            Err(CredentialsError::DecodingError {
                message: json_decode_error.description().to_string(),
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


#[derive(RustcDecodable)]
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}
