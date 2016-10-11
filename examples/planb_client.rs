extern crate rusty_tokens;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::env;
use std::time::Duration;
use std::thread;
use rusty_tokens::client::credentials::StaticCredentialsProvider;
use rusty_tokens::client::{ManagedToken, TokenManager, HyperTokenManager};
use rusty_tokens::Scope;

fn main() {
    env::set_var("RUST_LOG", "info");
    let _ = env_logger::init();

    env::set_var("RUSTY_TOKENS_TOKEN_PROVIDER_URL",
                 "http://localhost:8080/oauth2/access_token");
    env::set_var("RUSTY_TOKENS_TOKEN_PROVIDER_REALM", "/services");
    env::set_var("RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR", "0.8");
    env::set_var("RUSTY_TOKENS_TOKEN_MANAGER_WARNING_FACTOR", "0.9");

    let credentials_provider =
        StaticCredentialsProvider::new("client_id", "client_secret", "user_id", "user_secret");

    let hyper_client = hyper::Client::new();

    let managed_token1 = ManagedToken::new("my_token1").with_scope(Scope::new("my_scope"));
    let managed_token2 = ManagedToken::new("my_token2").with_scope(Scope::new("my_scope"));

    let managed_tokens = vec![managed_token1, managed_token2];

    let (manager, join_handle) =
        HyperTokenManager::new_from_env(hyper_client, credentials_provider, managed_tokens)
            .unwrap();


    let manager1 = manager.clone();
    thread::spawn(move || {
        loop {
            let result = manager1.get_token("my_token1");
            info!("===> my_token1: {:?}", result);
            thread::sleep(Duration::from_secs(1));
        }
    });

    let manager2 = manager.clone();
    thread::spawn(move || {
        loop {
            let result = manager2.get_token("my_token2");
            info!("===> my_token2: {:?}", result);
            thread::sleep(Duration::from_secs(2));
        }
    });

    thread::sleep(Duration::from_secs(300));

    info!("===> Stopping!");
    manager.stop();

    join_handle.join().unwrap();
    info!("=== >Stopped");
}
