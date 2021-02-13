//! HD wallet(BIP-32) related key derivation utilities.
//!
//! This crate is build upon secp256k1 crate, only provide BIP-32 related features, for signatures
//! see the [secp256k1 documentation](https://docs.rs/secp256k1).
//!
//! * [`ChainPath`] and [`KeyChain`] used to derive HD wallet keys.
//! * [`Derivation`] contains key derivation info.
//! * [`ExtendedPrivKey`] and [`ExtendedPubKey`] according to BIP-32 described represents a key
//! that can derives child keys.
//! * [`KeyIndex`] indicate index and type in a child key derivation (Normal key or Hardened key).
//! * [`Error`] errors.
//!
//! `hdwallet` crate itself is a key derivation framework.
//! Check `hdwallet-bitcoin` if you want to derive bitcoin keys, and you can find or submit other crypto
//! currencies support on [hdwallet homepage](https://github.com/jjyr/hdwallet).
//!

#[macro_use]
extern crate lazy_static;

pub mod error;
pub mod extended_key;
pub mod key_chain;
pub mod traits;

pub use crate::extended_key::{key_index::KeyIndex, ExtendedPrivKey, ExtendedPubKey, KeySeed};
pub use crate::key_chain::{
    chain_path::{ChainPath, Error as ChainPathError, SubPath},
    DefaultKeyChain, Derivation, KeyChain,
};

// re-exports
pub use rand_core;
pub use ring;
pub use secp256k1;
