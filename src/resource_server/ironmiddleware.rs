//! Iron middleware to use an `AuthorizationServer` within hyper.
use std::error::Error;

use iron::prelude::*;
use iron::{BeforeMiddleware, AfterMiddleware};
use iron::headers::{Authorization, Bearer};
use iron::status::Status;
use iron::typemap::Key;

use Token;
use super::{AuthorizationServer, AuthenticatedUser, AuthorizationServerError};

use http_error_object::HttpErrorObject;

/// Used to store an `AuthenticatedUser` within the request extensions.
pub struct AuthenticatedUserKey;
impl Key for AuthenticatedUserKey {
    type Value = AuthenticatedUser;
}

/// A middleware that uses an `AuthorizationServer` to authenticate a user.
/// If the user was authenticated it will put the user into the request extensions.
/// Otherwise it will abort the request with Unauthorized.
/// If the call to the `AuthorizationServer` fails for any reason, the request will also
/// be aborted with Unauthorized.
pub struct AuthenticateTokenMiddleware<T: AuthorizationServer + Send + Sync> {
    pub authorization_server: T,
}

impl<T: AuthorizationServer + Send + Sync + 'static> BeforeMiddleware for AuthenticateTokenMiddleware<T> {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        let extensions = &mut req.extensions;
        let token: Option<Token> = req.headers
            .get::<Authorization<Bearer>>()
            .map(|t| Token::new(t.token.as_ref()));
        let user = try!{
         match token {
             Some(ref token) => {
                 match self.authorization_server.authenticate(token) {
                     Ok(user) => {
                         Ok(user)
                     }
                     Err(err) => {
                         error!("Failed to get token info from authorization server: {}", err.description());
                         Err(IronError::new(AuthorizationServerError::NotAuthenticated {
                                                message: "Could not validate token."
                                                    .to_owned(),
                                            },
                                            HttpErrorObject::new_iron(&Status::Unauthorized)
                                                .to_iron_response_triplet()))
                     }
                 }
             }
             None => {
                 warn!("No token.");
                 Err(IronError::new(AuthorizationServerError::NotAuthenticated {
                                        message: "Invalid token".to_owned(),
                                    },
                                    HttpErrorObject::new_iron(&Status::Unauthorized)
                                        .to_iron_response_triplet()))
             }
         }
        };
        extensions.insert::<AuthenticatedUserKey>(user);
        Ok(())
    }
}

/// Struct for creating `NotFoundToUnauthorizedWhenNotAuthorizedMiddleware`.
pub struct NotFoundToUnauthorizedWhenNotAuthorizedMiddleware;

/// A Middlware to post process authorization. This middleware will abort the request
/// with Unauthorized whenever there is no `AuthenticatedUser` AND the response does
/// not have a non success status.
/// This middleware is useful, when you do not want authenticate on all requests, e.g. a heartbeat, but
/// want to return Unauthorized whenever on all other requests.
impl AfterMiddleware for NotFoundToUnauthorizedWhenNotAuthorizedMiddleware {
    fn after(&self, req: &mut Request, response: Response) -> IronResult<Response> {
        match response.status {
            Some(Status::Unauthorized) => Ok(response),
            Some(status) => {
                if status.is_success() {
                    Ok(response)
                } else {
                    match req.extensions.get::<AuthenticatedUserKey>() {
                        Some(_) => Ok(response),
                        None => {
                            warn!("Modifiying unauthorized non success status {} to \
                                   Unauthorized.",
                                  status);
                            HttpErrorObject::new_iron(&Status::Unauthorized).to_iron_json_result()
                        }
                    }
                }
            }
            None => {
                match req.extensions.get::<AuthenticatedUserKey>() {
                    Some(_) => Ok(response),
                    None => {
                        warn!("Modifiying unauthorized response without status to \
                               Unauthorized.");
                        HttpErrorObject::new_iron(&Status::Unauthorized).to_iron_json_result()
                    }
                }
            }
        }
    }

    fn catch(&self, req: &mut Request, err: IronError) -> IronResult<Response> {
        match err.response.status {
            Some(Status::Unauthorized) => Err(err),
            Some(status) => {
                if status.is_success() {
                    Err(err)
                } else {
                    match req.extensions.get::<AuthenticatedUserKey>() {
                        Some(_) => Err(err),
                        None => {
                            warn!("Modifying catched unauthorized non success status {} to \
                                   Unauthorized.",
                                  status);
                            HttpErrorObject::new_iron(&Status::Unauthorized).to_iron_json_result()
                        }
                    }
                }
            }
            None => {
                match req.extensions.get::<AuthenticatedUserKey>() {
                    Some(_) => Err(err),
                    None => {
                        warn!("Modifying catched unauthorized response without status to \
                               Unauthorized.");
                        HttpErrorObject::new_iron(&Status::Unauthorized).to_iron_json_result()
                    }
                }
            }
        }
    }
}
