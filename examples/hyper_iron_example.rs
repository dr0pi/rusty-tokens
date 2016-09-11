extern crate rusty_tokens;
extern crate iron;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::env;

use rusty_tokens::resource_server;
use rusty_tokens::resource_server::ironmiddleware;

use iron::prelude::*;

fn handle(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with((iron::status::Ok, "Hello, you are authenticated!")))
}

fn main() {
    env::set_var("RUST_LOG", "info");
    env::set_var("RUSTY_TOKENS_TOKEN_INFO_URL", "http://localhost:9001");
    env::set_var("RUSTY_TOKENS_TOKEN_INFO_URL_QUERY_PARAMETER", "tokeninfo");
    env::set_var("RUST_LOG", "info");
    env_logger::init().unwrap();

    let hyper_client = hyper::Client::new();

    let authorization_server = resource_server::AuthorizationHyperServer::from_env(hyper_client)
        .unwrap();

    let mut chain = Chain::new(handle);
    chain.link_before(ironmiddleware::AuthenticateTokenMiddleware {
        authorization_server: authorization_server,
    });
    chain.link_after(ironmiddleware::NotFoundToUnauthorizedWhenNotAuthorizedMiddleware);

    info!("Running 'iron hyper middleware example' on localhost:9000");
    Iron::new(chain).http("localhost:9000").expect("Could not bind the service.");
}
