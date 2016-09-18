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

use std::convert::From;
use std::error::Error;
use std::fmt;

use std::env::VarError;

pub mod jwt;
pub mod client;
pub mod resource_server;

/// This is a Scope used for authorization once the `AuthorizationServer` authenticated the user.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Scope(pub String);

impl Scope {
    /// Creates a new scope. It allocates a String.
    pub fn from_str(scope: &str) -> Scope {
        Scope(scope.to_owned())
    }

    /// Creates a new scope and consumes the String.
    pub fn new(scope: String) -> Scope {
        Scope(scope)
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
    pub fn new(token: &str) -> Token {
        Token(token.to_owned())
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
    fn new(message: &str) -> InitializationError {
        InitializationError { message: message.to_owned() }
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
        InitializationError { message: err.description().to_owned() }
    }
}
