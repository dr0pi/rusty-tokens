//! This module is intended to be used if you are a resource server.
//!
//! It proxies an `AuthenticationServer` for you
//!
//! The basic concept is, that a client provides you with a Token and
//! that this Token is sent to an Authentication Server that will
//! authenticate the user and provide you with the assigned Scopes which
//! you can then use for authorization.
use std::error::Error;
use std::fmt;
use std::collections::HashSet;
use super::{Scope, Token};
use rustc_serialize::{Decoder, Decodable, json};

#[cfg(feature = "hyper")]
mod hyperserver;

#[cfg(feature = "hyper")]
pub use resource_server::hyperserver::AuthorizationHyperServer;

#[cfg(feature = "iron")]
pub mod ironmiddleware;

/// Authenticates a user by using a Token. In this proxies an external server.
pub trait AuthorizationServer {
    /// Authenticate a user by Token.
    fn authenticate(&self, token: &Token) -> Result<AuthenticatedUser, AuthorizationServerError>;
}

/// An id that uniquely identifies the owner of a resource
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Uid(String);

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Once a user has been authenticated this struct can be used for authorization.
#[derive(PartialEq, Debug)]
pub struct AuthenticatedUser {
    pub uid: Option<Uid>,
    pub scopes: HashSet<Scope>,
}

impl AuthenticatedUser {
    /// Convinience method for creating an AuthenticatedUser. Be aware, that the params are not "typesafe".
    pub fn from_strings(uid: &str, scopes: &[&str]) -> AuthenticatedUser {
        let mut hs = HashSet::new();
        for sc in scopes {
            hs.insert(Scope::from_str(sc));
        }
        AuthenticatedUser {
            uid: Some(Uid(uid.to_string())),
            scopes: hs,
        }
    }

    /// Parse the given JSON and create a new AuthenticatedUser
    pub fn from_json(json_response: &str) -> Result<AuthenticatedUser, AuthorizationServerError> {
        match json::decode::<AuthenticatedUser>(json_response) {
            Ok(authenticated_user) => Ok(authenticated_user),
            Err(err) => {
                Err(AuthorizationServerError::TokenInfoUnparsable {
                    message: err.description().to_string(),
                })
            }
        }
    }

    /// Use for authorization. Checks whether this user has the given Scope.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }

    /// Use for authorization. Checks whether this user has all of the given Scopes.
    pub fn has_scopes(&self, scopes: &[Scope]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// Authorize the user for an action defined by the given scope. If the user does not have the scope this method will fail.
    pub fn authorize(&self, scope: &Scope) -> Result<(), NotAuthorized> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            let uid_part = match self.uid {
                Some(Uid(ref uid)) => uid.clone(),
                None => "None".to_string(),
            };
            Err(NotAuthorized {
                message: format!("User with uid {} does not have the scope {}",
                                 uid_part,
                                 scope),
            })
        }
    }
}

impl Decodable for AuthenticatedUser {
    fn decode<D: Decoder>(d: &mut D) -> Result<AuthenticatedUser, D::Error> {
        d.read_struct("TokenInfo", 2, |d| {
            let uid: String = try!(d.read_struct_field("uid", 0, |d| d.read_str()));
            let scopes: HashSet<Scope> = try!(d.read_struct_field("scope", 1, |d| {
                d.read_seq(|d, len| {
                    let mut buf: HashSet<Scope> = HashSet::new();
                    for i in 0..len {
                        let element: String = try!(d.read_seq_elt(i, Decodable::decode));
                        buf.insert(Scope(element));
                    }
                    Ok(buf)
                })
            }));
            Ok(AuthenticatedUser {
                uid: Some(Uid(uid)),
                scopes: scopes,
            })
        })
    }
}

/// An Error signaling that an authorization failed.
#[derive(Debug)]
pub struct NotAuthorized {
    message: String,
}

impl fmt::Display for NotAuthorized {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Not authorized: {}", self.message)
    }
}

impl Error for NotAuthorized {
    fn description(&self) -> &str {
        self.message.as_ref()
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}


/// An error returned from an `AuthorizationServer` when it failed to authenticate a token.
#[derive(Debug)]
pub enum AuthorizationServerError {
    /// The Token was really unauthenticated
    NotAuthenticated { message: String },
    /// The token received from am AuthorizationServer was not parsable
    TokenInfoUnparsable { message: String },
    /// Failed to connect to a remote AuthorizationServer
    Connection { message: String },
    /// Something else happened
    Unknown { message: String },
}

impl fmt::Display for AuthorizationServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthorizationServerError::NotAuthenticated { ref message } => {
                write!(f, "NotAuthenticated: {}", message)
            }
            AuthorizationServerError::TokenInfoUnparsable { ref message } => {
                write!(f, "TokenInfoUnparsable: {}", message)
            }
            AuthorizationServerError::Connection { ref message } => {
                write!(f, "Connection: {}", message)
            }
            AuthorizationServerError::Unknown { ref message } => write!(f, "Unknown: {}", message),
        }
    }
}

impl Error for AuthorizationServerError {
    fn description(&self) -> &str {
        match *self {
            AuthorizationServerError::NotAuthenticated { ref message } => message.as_ref(),
            AuthorizationServerError::TokenInfoUnparsable { ref message } => message.as_ref(),
            AuthorizationServerError::Connection { ref message } => message.as_ref(),
            AuthorizationServerError::Unknown { ref message } => message.as_ref(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use rustc_serialize::json;
    use ::resource_server::{AuthenticatedUser, Uid};
    use ::Scope;
    #[test]
    fn an_authenticated_user_should_be_parsed_from_full_token_info_with_many_scopes() {
        let test_info = "{\"access_token\":\"*SNAP*\",\"cn\":true,\
        \"expires_in\":28653,\"grant_type\":\"password\",\
        \"realm\":\"/services\",\"scope\":[\"uid\",\"cn\"],\"token_type\":\"Bearer\",\
        \"uid\":\"my_app\"}";

        let mut scopes = HashSet::new();
        scopes.insert(Scope::from_str("uid"));
        scopes.insert(Scope::from_str("cn"));
        let expected = AuthenticatedUser {
            uid: Some(Uid("my_app".to_string())),
            scopes: scopes,
        };

        let parsed = json::decode(test_info).unwrap();

        assert_eq!(expected, parsed);
    }

    #[test]
    fn an_authenticated_user_should_be_parsed_from_full_token_info_with_one_scope() {
        let test_info = "{\"access_token\":\"*SNAP*\",\"cn\":true,\
        \"expires_in\":28653,\"grant_type\":\"password\",\
        \"realm\":\"/services\",\"scope\":[\"uid\"],\"token_type\":\"Bearer\",\
        \"uid\":\"my_app\"}";

        let mut scopes = HashSet::new();
        scopes.insert(Scope::from_str("uid"));
        let expected = AuthenticatedUser {
            uid: Some(Uid("my_app".to_string())),
            scopes: scopes,
        };

        let parsed = json::decode(test_info).unwrap();

        assert_eq!(expected, parsed);
    }

    #[test]
    fn an_authenticated_user_should_be_parsed_from_full_token_info_with_no_scopes() {
        let test_info = "{\"access_token\":\"*SNAP*\",\"cn\":true,\
        \"expires_in\":28653,\"grant_type\":\"password\",\
        \"realm\":\"/services\",\"scope\":[],\"token_type\":\"Bearer\",\
        \"uid\":\"my_app\"}";

        let expected = AuthenticatedUser {
            uid: Some(Uid("my_app".to_string())),
            scopes: HashSet::new(),
        };

        let parsed = json::decode(test_info).unwrap();

        assert_eq!(expected, parsed);
    }
}
