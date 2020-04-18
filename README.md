# HDWallet

[![Crates.io](https://img.shields.io/crates/v/hdwallet.svg)](https://crates.io/crates/hdwallet)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/jjyr/hdwallet.svg?branch=master)](https://travis-ci.org/jjyr/hdwallet)
[Docs](https://docs.rs/hdwallet)

HD wallet([BIP-32]) key derivation utilities.

This crate is build upon [secp256k1] crate, this crate only provides [BIP-32] related features, for signature features see the [secp256k1 documentation](https://docs.rs/secp256k1).

* [`ChainPath`] and [`KeyChain`] are used to derive HD wallet keys.
* [`Derivation`] describes key derivation info.
* [`ExtendedPrivKey`] and [`ExtendedPubKey`] represent extended keys according to [BIP-32], which can derives child keys.
* [`KeyIndex`] indicates child key's index and type(Normal key or Hardened key).
* [`Error`] errors.

`hdwallet` itself is a key derivation framework.
Check `hdwallet-bitcoin` if you want to derive bitcoin keys; you can find or submit other crypto currencies on [hdwallet homepage](https://github.com/jjyr/hdwallet).

## Documentation

* [HDWallet](https://docs.rs/hdwallet)
* [HDWallet Bitcoin](https://docs.rs/hdwallet-bitcoin)

## License

MIT

[BIP-32]: https://github.com/bitcoin/bips/blob/0042dec548f8c819df7ea48fdeec78af21974384/bip-0032.mediawiki "BIP 32"
[secp256k1]: https://github.com/rust-bitcoin/rust-secp256k1/ "secp256k1"
