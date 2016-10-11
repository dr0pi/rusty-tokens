# Rusty Tokens

## Introduction

An OAUTH2 authentication and authorization library for Rust.

The client part of library is inspired by https://github.com/zalando/go-tokens.

This library can be used if for resource servers or clients that need
authentication and authorization.

**Rusty Tokens** uses semantic versioning. So unless 1.0.0 is reached expect many breaking changes.

## Project State

Client and resource server side are implemented. JWT lib has to be streamlined.

## Build

Clone this repository and run ```cargo build```.

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
tag = "v0.2.0"
features = ["hyper", "iron"]
```

## Configuration

**Rusty Tokens** is configured by environment variables.

You will find the exact descriptions of the environment vars within the documentation.

```
# When you are a resource server

RUSTY_TOKENS_TOKEN_INFO_URL_ENV_VAR=RUSTY_TOKENS_TOKEN_INFO_URL
RUSTY_TOKENS_TOKEN_INFO_URL=hallo
RUSTY_TOKENS_TOKEN_INFO_URL_QUERY_PARAMETER=tokenInfo
RUSTY_TOKENS_FALLBACK_TOKEN_INFO_URL=https://somewhere.else

# When you are a client

RUSTY_TOKENS_TOKEN_PROVIDER_URL_ENV_VAR=RUSTY_TOKENS_TOKEN_PROVIDER_URL
RUSTY_TOKENS_TOKEN_PROVIDER_URL=https:www.example.org
RUSTY_TOKENS_TOKEN_PROVIDER_REALM=/services
RUSTY_TOKENS_FALLBACK_TOKEN_PROVIDER_URL=http://somewhere.else

RUSTY_TOKENS_CREDENTIALS_DIR_ENV_VAR=RUSTY_TOKENS_CREDENTIALS_DIR
RUSTY_TOKENS_CREDENTIALS_DIR=/home/user/credentials
RUSTY_TOKENS_USER_CREDENTIALS_FILE_NAME=user.json
RUSTY_TOKENS_CLIENT_CREDENTIALS_FILE_NAME=client.json

RUSTY_TOKENS_TOKEN_MANAGER_REFRESH_FACTOR=0.8
RUSTY_TOKENS_TOKEN_MANAGER_WARNING_FACTOR=0.9
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
