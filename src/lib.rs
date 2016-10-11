//! A create for authentication and authorization.

#[macro_use]
extern crate log;
extern crate rustc_serialize;
#[cfg(feature = "hyper")]
extern crate hyper;
#[cfg(feature = "iron")]
extern crate iron;
#[cfg(feature = "iron")]
extern crate http_error_object;

extern crate chrono;

extern crate url;

use std::convert::{Into, From};
use std::error::Error;
use std::fmt;
use std::num::ParseFloatError;

use std::env::VarError;

pub mod jwt;
pub mod client;
pub mod resource_server;

/// This is a Scope used for authorization once the `AuthorizationServer` authenticated the user.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Scope(pub String);

impl Scope {
    /// Creates a new scope.
    pub fn new<T: Into<String>>(scope: T) -> Scope {
        Scope(scope.into())
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


/// This is a token that is sent by a client and which has to be validated by
/// an `AuthorizationServer`.
#[derive(PartialEq, Clone, Debug)]
pub struct Token(pub String);

impl Token {
    /// Creates a new Token. It allocates a String.
    pub fn new<T: Into<String>>(token: T) -> Token {
        Token(token.into())
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An error to be returned if the initialization of a component fails.
#[derive(Debug)]
pub struct InitializationError {
    pub message: String,
}

impl InitializationError {
    /// Creates a new InitializationError therby allocating a String.
    fn new<T: Into<String>>(message: T) -> InitializationError {
        InitializationError { message: message.into() }
    }
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unauthorized: {}", self.message)
    }
}

impl Error for InitializationError {
    fn description(&self) -> &str {
        self.message.as_ref()
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl From<VarError> for InitializationError {
    fn from(err: VarError) -> Self {
        InitializationError { message: format!{"{}", err} }
    }
}

impl From<ParseFloatError> for InitializationError {
    fn from(err: ParseFloatError) -> Self {
        InitializationError { message: format!{"{}", err} }
    }
}
