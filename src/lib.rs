//! HD wallet(BIP-32) related key derivation utilities.
//!
//! This crate is build upon secp256k1 crate, only provide BIP-32 related features, for signatures
//! see the original [secp256k1 documentation](https://docs.rs/secp256k1).
//!
//! * [`ChainPath`] and [`KeyChain`] used to derivation child keys from string represented path.
//! * [`HDKey`] return value of `key_chain.fetch_key`, `HDKey` represent a derivated key which
//! include a `ExtendedPrivKey` and other derivation info.
//! * [`ExtendedPrivKey`] and [`ExtendedPubKey`] as BIP-32 described it is basic struct in `hdwallet`.
//! * [`KeyIndex`] is a simple enum indicate the index and type of child key(Normal key or Hardened
//! key).
//! * [`Error`] errors.

#[macro_use]
extern crate lazy_static;

pub mod error;
pub mod extended_key;
pub mod key_chain;
pub mod traits;

pub use crate::extended_key::{
    key_index::KeyIndex, ChildPrivKey, ChildPubKey, ExtendedPrivKey, ExtendedPubKey, KeySeed,
};
pub use crate::key_chain::{
    chain_path::{ChainPath, Error as ChainPathError, SubPath},
    DefaultKeyChain, HDKey, KeyChain,
};

// re-exports
pub use rand;
pub use ring;
pub use secp256k1;
