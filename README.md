# HDWallet
[![Crates.io](https://img.shields.io/crates/v/hdwallet.svg)](https://crates.io/crates/hdwallet)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/jjyr/hdwallet.svg?branch=master)](https://travis-ci.org/jjyr/hdwallet)
[Docs](https://docs.rs/hdwallet)

HD wallet BIP-32 related key derivation utilities.

This crate is build upon secp256k1 crate, only provide BIP-32 related features, for signatures
see the [secp256k1 documentation](https://docs.rs/secp256k1).

* [`ChainPath`] and [`KeyChain`] used to derivation child keys from string represented path.
* [`HDKey`] return value of `key_chain.fetch_key`, `HDKey` represent a derivated key which
include a `ExtendedPrivKey` and other derivation info.
* [`ExtendedPrivKey`] and [`ExtendedPubKey`] as BIP-32 described it is basic struct in `hdwallet`.
* [`KeyIndex`] is a simple enum indicate the index and type of child key(Normal key or Hardened
key).
* [`Error`] errors.

`hdwallet` crate itself is a key derivation framework.

Check `hdwallet-bitcoin` if you want derivation bitcoin keys, and you can find or submit other crypto
currencies supports on [hdwallet homepage](https://github.com/jjyr/hdwallet).

# Documentation

* [HDWallet](https://docs.rs/hdwallet)
* [HDWallet Bitcoin](https://docs.rs/hdwallet-bitcoin)

# License

MIT

