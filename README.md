# HDWallet
[![Crates.io](https://img.shields.io/crates/v/hdwallet.svg)](https://crates.io/crates/hdwallet)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/jjyr/hdwallet.svg?branch=master)](https://travis-ci.org/jjyr/hdwallet)
[Docs](https://docs.rs/hdwallet)

HD wallet(BIP-32) related key derivation utilities.

This crate is build upon secp256k1 crate, only provide BIP-32 related features, for signatures
see the [secp256k1 documentation](https://docs.rs/secp256k1).

* [`ChainPath`] and [`KeyChain`] used to derive HD wallet keys.
* [`Derivation`] contains key derivation info.
* [`ExtendedPrivKey`] and [`ExtendedPubKey`] according to BIP-32 described represents a key
that can derives child keys.
* [`KeyIndex`] indicate index and type in a child key derivation (Normal key or Hardened key).
* [`Error`] errors.

`hdwallet` crate itself is a key derivation framework.
Check `hdwallet-bitcoin` if you want to derive bitcoin keys, and you can find or submit other crypto
currencies support on [hdwallet homepage](https://github.com/jjyr/hdwallet).

# Documentation

* [HDWallet](https://docs.rs/hdwallet)
* [HDWallet Bitcoin](https://docs.rs/hdwallet-bitcoin)

# License

MIT

