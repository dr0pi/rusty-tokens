#[macro_use]
extern crate log;
extern crate env_logger;
extern crate iron;

use std::env;
use iron::prelude::*;
use iron::mime::{Mime, TopLevel, SubLevel};
use iron::modifiers::Header;
use iron::headers::ContentType;

fn handle(_: &mut Request) -> IronResult<Response> {
    info!("Received token info request");
    let payload = "{\"scope\":[\"uid\",\"read\", \"write\"],\"uid\":\"test-user-id\"}";
    let header = Header(ContentType(Mime(TopLevel::Application, SubLevel::Json, vec![])));
    let status = iron::status::Ok;
    Ok(Response::with((status, payload, header)))
}

fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init().unwrap();

    info!("Running 'Token Info Server' localhost:9001");
    Iron::new(handle).http("localhost:9001").expect("Could not bind the service.");
}
