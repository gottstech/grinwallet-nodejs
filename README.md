# grinwallet-nodejs

Grin Wallet Node.js APIs for Mac/Windows/Linux desktop App development.

# Contributing

## Requirements

* rust 1.35+ (use [rustup]((https://www.rustup.rs/))- i.e. `curl https://sh.rustup.rs -sSf | sh; source $HOME/.cargo/env`)
  * if rust is already installed, you can simply update version with `rustup update`
* npm 10. You can install it from [here](https://nodejs.org/en/).
* [neon](https://github.com/neon-bindings/neon). (install it by npm: `npm install --global neon-cli`)

For Debian-based distributions (Debian, Ubuntu, Mint, etc), to get the dependencies in a all-in-one line (except Rust and Npm):

```sh
apt install build-essential cmake git libgit2-dev clang libncurses5-dev libncursesw5-dev zlib1g-dev pkg-config libssl-dev llvm
```

For Mac:

```sh
xcode-select --install
brew install --with-toolchain llvm
brew install pkg-config
brew install openssl
```

## Build steps

```sh
    git clone https://github.com/gottstech/grinwallet-nodejs.git
    cd grinwallet-nodejs
    neon build --release
or  npm install
```

## Document

https://github.com/gottstech/grinwallet-nodejs/wiki

## License

Apache License v2.0.


