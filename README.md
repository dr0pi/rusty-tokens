# Rusty Tokens

## Introduction

An authentication and authorization library for Rust.

This client part of library is(will be) basically a clone of https://github.com/zalando/go-tokens.

This library can be used if for resource servers or clients that need
authentication and authorization within the Zalando landscape.

**Rusty Tokens** uses semantic versioning. So unless 1.0.0 is reached expect many breaking changes.

## Project State

Currenty we are working on implementing the client side.

## Build

Clone this repository and run ```cargo build --features "all"```.

You will need to have the ```open-ssl dev``` package for your system to compile the sources.

## Test

You can run the tests with ```cargo test```.

## Documentation

Currently there is no online documentation so you have to build the documentation yourself.

To build a local documentation run ```cargo doc``` in the repository root. You will then find the documentation in the target directory.

## Using it in your project

Currently **rusty-tokens** is not published on **crates.io**.

To use it in your project add the following to your ```Cargo.toml```:

```
[dependencies.rusty-tokens]
git = "https://github.com/zalando-incubator/rusty-tokens.git"
tag = "v0.1.8"
features = ["hyper", "iron"]
```

## Configuration

**Rusty Tokens** uses [dotenv](https://github.com/slapresta/rust-dotenv) for configuration.

That means everything is configurable by using environment variables.

```
RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR=RUSTY_TOKENS_TOKEN_INFO_URL
RUSTY_TOKENS_TOKEN_INFO_URL="www.example.com"
RUSTY_TOKENS_TOKEN_INFO_URL_QUERY_PARAMETER=tokenInfo
RUSTY_TOKENS_FALLBACK_TOKEN_INFO_URL="www.example.com"

RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR=RUSTY_TOKENS_TOKEN_PROVIDER_URL
RUSTY_TOKENS_TOKEN_PROVIDER_URL="www.example.com"
RUSTY_TOKENS_TOKEN_PRIVIDER_URL_QUERY_PARAMETER=tokenInfo
RUSTY_TOKENS_FALLBACK_GENERATE_TOKEN_URL="www.example.com"
```

## Examples

There are basic examples in the ```examples``` directory

You can run an example with ```cargo run --example <example-name-here>```

## Task List

- [ ] Have on online documentation
- [x] Stabilize the configuration
- [x] Implement the client side


## Contributing(We need your help!)

We accept contributions from the open-source community. Please see the [issue tracker](https://example.com) for things to work on.

Before making a contribution, please let us know by posting a comment to the relevant issue. And if you would like to propose a new feature, do start a new issue explaining the feature you’d like to contribute.

## Coding Conventions

Nothing special but run ```rustfmt```(with default settings) before submitting code.

## License

Licensed under "The MIT License (MIT)"

Please see the enclosed LICENSE file.

Copyright (c) 2016 Zalando SE
