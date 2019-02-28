pub mod key_index;

use crate::error::Error;
use key_index::KeyIndex;
use rand::Rng;
use ring::{
    digest,
    hmac::{SigningContext, SigningKey},
};
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};

lazy_static! {
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

/// Random entropy, part of extended key.
type ChainCode = Vec<u8>;

/// ExtendedPrivKey is used for child key derivation.
/// See [secp256k1 crate documentation](https://docs.rs/secp256k1) for SecretKey signatures usage.
///
/// # Examples
///
/// ```rust
/// # extern crate hdwallet;
/// use hdwallet::{ExtendedPrivKey, KeyIndex};
///
/// let master_key = ExtendedPrivKey::random().unwrap();
/// let hardened_key_index = KeyIndex::hardened_from_normalize_index(0).unwrap();
/// let hardended_child_priv_key = master_key.derive_private_key(hardened_key_index).unwrap();
/// let normal_key_index = KeyIndex::Normal(0);
/// let noamal_child_priv_key = master_key.derive_private_key(normal_key_index).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

/// Indicate size of random seed used to generate private key, 256 is recommended.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeySeed {
    S128 = 128,
    S256 = 256,
    S512 = 512,
}

impl ExtendedPrivKey {
    /// Generate an ExtendedPrivKey, use 256 size random seed.
    pub fn random() -> Result<ExtendedPrivKey, Error> {
        ExtendedPrivKey::random_with_seed_size(KeySeed::S256)
    }
    /// Generate an ExtendedPrivKey which use 128 or 256 or 512 size random seed.
    pub fn random_with_seed_size(seed_size: KeySeed) -> Result<ExtendedPrivKey, Error> {
        let seed = {
            let mut seed = vec![0; seed_size as usize];
            let mut rng = rand::thread_rng();
            rng.fill(seed.as_mut_slice());
            seed
        };
        Self::with_seed(&seed)
    }

    /// Generate an ExtendedPrivKey from seed
    pub fn with_seed(seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let signature = {
            let signing_key = SigningKey::new(&digest::SHA512, b"Bitcoin seed");
            let mut h = SigningContext::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(private_key) = SecretKey::from_slice(key) {
            return Ok(ExtendedPrivKey {
                private_key,
                chain_code: chain_code.to_vec(),
            });
        }
        Err(Error::InvalidResultKey)
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Signature {
        let signing_key = SigningKey::new(&digest::SHA512, &self.chain_code);
        let mut h = SigningContext::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        h.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Signature {
        let signing_key = SigningKey::new(&digest::SHA512, &self.chain_code);
        let mut h = SigningContext::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a ChildPrivKey from ExtendedPrivKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ChildPrivKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::InvalidKeyIndex);
        }
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardended_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(mut private_key) = SecretKey::from_slice(key) {
            private_key
                .add_assign(&self.private_key[..])
                .expect("add point");
            return Ok(ChildPrivKey {
                key_index,
                extended_key: ExtendedPrivKey {
                    private_key,
                    chain_code: chain_code.to_vec(),
                },
            });
        }
        Err(Error::InvalidResultKey)
    }
}

/// ExtendedPubKey is used for public child key derivation.
/// See [secp256k1 crate documentation](https://docs.rs/secp256k1) for PublicKey signatures usage.
///
/// # Examples
///
/// ```rust
/// # extern crate hdwallet;
/// use hdwallet::{ExtendedPrivKey, ExtendedPubKey, KeyIndex};
///
/// let priv_key = ExtendedPrivKey::random().unwrap();
/// let pub_key = ExtendedPubKey::from_private_key(&priv_key).unwrap();
///
/// // Public hardened child key derivation from parent public key is impossible
/// let hardened_key_index = KeyIndex::hardened_from_normalize_index(0).unwrap();
/// assert!(pub_key.derive_public_key(hardened_key_index).is_err());
///
/// // Derive public normal child key
/// let normal_key_index = KeyIndex::Normal(0);
/// assert!(pub_key.derive_public_key(normal_key_index).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
}

impl ExtendedPubKey {
    /// Derive public normal child key from ExtendedPubKey,
    /// will return error if key_index is a hardened key.
    pub fn derive_public_key(&self, key_index: KeyIndex) -> Result<ChildPubKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::InvalidKeyIndex);
        }

        let index = match key_index {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(_) => return Err(Error::InvalidKeyIndex),
        };

        let signature = {
            let signing_key = SigningKey::new(&digest::SHA512, &self.chain_code);
            let mut h = SigningContext::with_key(&signing_key);
            h.update(&self.public_key.serialize());
            h.update(&index.to_be_bytes());
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(private_key) = SecretKey::from_slice(key) {
            let mut public_key = self.public_key;
            if public_key
                .add_exp_assign(&*SECP256K1_VERIFY_ONLY, &private_key[..])
                .is_ok()
            {
                return Ok(ChildPubKey {
                    key_index: KeyIndex::Normal(index),
                    extended_key: ExtendedPubKey {
                        public_key,
                        chain_code: chain_code.to_vec(),
                    },
                });
            }
        }
        Err(Error::InvalidResultKey)
    }

    /// ExtendedPubKey from ExtendedPrivKey
    pub fn from_private_key(extended_key: &ExtendedPrivKey) -> Result<Self, Error> {
        let public_key =
            PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &extended_key.private_key);
        Ok(ExtendedPubKey {
            public_key,
            chain_code: extended_key.chain_code.clone(),
        })
    }
}

/// ChildKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedKey {
    PrivKey(ExtendedPrivKey),
    PubKey(ExtendedPubKey),
}

/// ChildPrivKey, derive from ExtendedPrivKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPrivKey {
    pub key_index: KeyIndex,
    pub extended_key: ExtendedPrivKey,
}

/// ChildPubKey derive from ExtendedPubKey, or from ChildPrivKey
///
/// # Examples
///
/// ```rust
/// # extern crate hdwallet;
/// use hdwallet::{ExtendedPrivKey, ExtendedPubKey, ChildPubKey, KeyIndex};
///
/// let priv_key = ExtendedPrivKey::random().unwrap();
/// let pub_key = ExtendedPubKey::from_private_key(&priv_key).unwrap();
///
/// // Derive public normal child key
/// let normal_key_index = KeyIndex::Normal(0);
/// let child_pub_key = pub_key.derive_public_key(normal_key_index).unwrap();
///
/// // Generate public child key from private child key
/// let child_priv_key = priv_key.derive_private_key(KeyIndex::Normal(0)).unwrap();
/// assert_eq!(child_pub_key, ChildPubKey::from_private_key(&child_priv_key).unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPubKey {
    pub key_index: KeyIndex,
    pub extended_key: ExtendedPubKey,
}

impl ChildPubKey {
    pub fn from_private_key(child_key: &ChildPrivKey) -> Result<Self, Error> {
        let extended_key = ExtendedPubKey::from_private_key(&child_key.extended_key)?;
        Ok(ChildPubKey {
            key_index: child_key.key_index,
            extended_key,
        })
    }
}

/// ChildKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildKey {
    PrivKey(ChildPrivKey),
    PubKey(ChildPubKey),
}

#[cfg(test)]
mod tests {
    use super::{ChildPubKey, ExtendedPrivKey, ExtendedPubKey, KeyIndex};

    fn fetch_random_key() -> ExtendedPrivKey {
        loop {
            if let Ok(key) = ExtendedPrivKey::random() {
                return key;
            }
        }
    }

    #[test]
    fn random_extended_priv_key() {
        for _ in 0..10 {
            if ExtendedPrivKey::random().is_ok() {
                return;
            }
        }
        panic!("can't generate valid ExtendedPrivKey");
    }

    #[test]
    fn random_seed_not_empty() {
        assert_ne!(
            fetch_random_key(),
            ExtendedPrivKey::with_seed(&[]).expect("privkey")
        );
    }

    #[test]
    fn extended_priv_key_derive_child_priv_key() {
        let master_key = fetch_random_key();
        master_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap())
            .expect("hardended_key");
        master_key
            .derive_private_key(KeyIndex::Normal(0))
            .expect("normal_key");
    }

    #[test]
    fn extended_pub_key_derive_child_pub_key() {
        let parent_priv_key = fetch_random_key();
        let child_pub_key_from_child_priv_key = {
            let child_priv_key = parent_priv_key
                .derive_private_key(KeyIndex::Normal(0))
                .expect("hardended_key");
            ChildPubKey::from_private_key(&child_priv_key).expect("public key")
        };
        let child_pub_key_from_parent_pub_key = {
            let parent_pub_key =
                ExtendedPubKey::from_private_key(&parent_priv_key).expect("public key");
            parent_pub_key
                .derive_public_key(KeyIndex::Normal(0))
                .expect("public key")
        };
        assert_eq!(
            child_pub_key_from_child_priv_key,
            child_pub_key_from_parent_pub_key
        )
    }
}
