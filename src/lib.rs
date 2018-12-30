//! HD wallet(BIP-32) related key derivation utilities.
//!
//! This crate is build upon secp256k1 crate, only provide BIP-32 related features, for signatures
//! see the original [secp256k1 documentation](https://docs.rs/secp256k1).
//!
//! * [`ExtendedPrivKey`] and [`ExtendedPubKey`] as BIP-32 described is used for key derivation
//! * [`KeyIndex`] is a simple enum indicate the index and type of child key.
//! * [`ChildPrivKey`] and [`ChildPubKey`] represent child key pair, note the field `extended_key`
//! inside structure, which means child keys can also as an extended key to derive new child keys.
//! * [`Error`] errors.

mod error;
mod key;
mod key_index;
mod util;

pub use crate::error::Error;
pub use crate::key::{ChildPrivKey, ChildPubKey, ExtendedPrivKey, ExtendedPubKey, KeySeed};
pub use crate::key_index::KeyIndex;
