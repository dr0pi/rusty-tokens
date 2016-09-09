extern crate rusty_tokens;
extern crate iron;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::env;

use rusty_tokens::Token;
use rusty_tokens::resource_server::{AuthenticatedUser, AuthorizationServer,
                                    AuthorizationServerError};
use rusty_tokens::resource_server::ironmiddleware;

use iron::prelude::*;

fn handle(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with((iron::status::Ok, "Hello, you are authenticated!")))
}

struct FakeAuthorizationServer;

impl AuthorizationServer for FakeAuthorizationServer {
    fn authenticate(&self, token: &Token) -> Result<AuthenticatedUser, AuthorizationServerError> {
        info!("Received token: {}", token);
        Ok(AuthenticatedUser::from_strings("uid", &["a", "b"]))
    }
}

fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init().unwrap();

    let mut chain = Chain::new(handle);
    chain.link_before(ironmiddleware::AuthenticateTokenMiddleware {
        authorization_server: FakeAuthorizationServer,
    });
    chain.link_after(ironmiddleware::NotFoundToUnauthorizedWhenNotAuthorizedMiddleware);

    info!("Running 'iron middleware example' on localhost:9000");
    Iron::new(chain).http("localhost:9000").expect("Could not bind the service.");
}
