pub mod key_index;

use crate::{
    error::Error,
    traits::{Deserialize, Serialize},
};
use key_index::KeyIndex;
use rand_core::{CryptoRng, RngCore};
use ring::hmac::{Context, Key, HMAC_SHA512};
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
/// use rand;
///
/// let mut rng = rand::thread_rng();
/// let master_key = ExtendedPrivKey::random(&mut rng).unwrap();
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

/// Indicate bits of random seed used to generate private key, 256 is recommended.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeySeed {
    S128 = 128,
    S256 = 256,
    S512 = 512,
}

impl ExtendedPrivKey {
    /// Generate an ExtendedPrivKey, use 256 size random seed.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<ExtendedPrivKey, Error> {
        ExtendedPrivKey::random_with_seed_size(rng, KeySeed::S256)
    }

    /// Generate an ExtendedPrivKey which use 128 or 256 or 512 bits random seed.
    pub fn random_with_seed_size<R: RngCore + CryptoRng>(
        rng: &mut R,
        seed_size: KeySeed,
    ) -> Result<ExtendedPrivKey, Error> {
        let seed = {
            let mut seed = vec![0u8; seed_size as usize / 8];
            rng.try_fill_bytes(seed.as_mut_slice())?;
            seed
        };
        Self::with_seed(&seed)
    }

    /// Generate an ExtendedPrivKey from seed
    pub fn with_seed(seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let signature = {
            let signing_key = Key::new(HMAC_SHA512, b"Bitcoin seed");
            let mut h = Context::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        h.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a child key from ExtendedPrivKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ExtendedPrivKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfRange);
        }
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardended_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let mut private_key = SecretKey::from_slice(key)?;
        private_key.add_assign(&self.private_key[..])?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
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
/// use rand;
///
/// let mut rng = rand::thread_rng();
/// let priv_key = ExtendedPrivKey::random(&mut rng).unwrap();
/// let pub_key = ExtendedPubKey::from_private_key(&priv_key);
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
    pub fn derive_public_key(&self, key_index: KeyIndex) -> Result<ExtendedPubKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfRange);
        }

        let index = match key_index {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(_) => return Err(Error::KeyIndexOutOfRange),
        };

        let signature = {
            let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
            let mut h = Context::with_key(&signing_key);
            h.update(&self.public_key.serialize());
            h.update(&index.to_be_bytes());
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        let mut public_key = self.public_key;
        public_key.add_exp_assign(&*SECP256K1_VERIFY_ONLY, &private_key[..])?;
        Ok(ExtendedPubKey {
            public_key,
            chain_code: chain_code.to_vec(),
        })
    }

    /// ExtendedPubKey from ExtendedPrivKey
    pub fn from_private_key(extended_key: &ExtendedPrivKey) -> Self {
        let public_key =
            PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &extended_key.private_key);
        ExtendedPubKey {
            public_key,
            chain_code: extended_key.chain_code.clone(),
        }
    }
}

impl Serialize<Vec<u8>> for ExtendedPrivKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = self.private_key[..].to_vec();
        buf.extend(&self.chain_code);
        buf
    }
}
impl Deserialize<&[u8], Error> for ExtendedPrivKey {
    fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let private_key = SecretKey::from_slice(&data[..32])?;
        let chain_code = data[32..].to_vec();
        Ok(ExtendedPrivKey {
            private_key,
            chain_code,
        })
    }
}

impl Serialize<Vec<u8>> for ExtendedPubKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = self.public_key.serialize().to_vec();
        buf.extend(&self.chain_code);
        buf
    }
}
impl Deserialize<&[u8], Error> for ExtendedPubKey {
    fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let public_key = PublicKey::from_slice(&data[..33])?;
        let chain_code = data[33..].to_vec();
        Ok(ExtendedPubKey {
            public_key,
            chain_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ExtendedPrivKey, ExtendedPubKey, KeyIndex};
    use crate::traits::{Deserialize, Serialize};
    use rand;

    fn fetch_random_key() -> ExtendedPrivKey {
        let mut rng = rand::thread_rng();
        loop {
            if let Ok(key) = ExtendedPrivKey::random(&mut rng) {
                return key;
            }
        }
    }

    #[test]
    fn random_extended_priv_key() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            if ExtendedPrivKey::random(&mut rng).is_ok() {
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
            ExtendedPubKey::from_private_key(&child_priv_key)
        };
        let child_pub_key_from_parent_pub_key = {
            let parent_pub_key = ExtendedPubKey::from_private_key(&parent_priv_key);
            parent_pub_key
                .derive_public_key(KeyIndex::Normal(0))
                .expect("public key")
        };
        assert_eq!(
            child_pub_key_from_child_priv_key,
            child_pub_key_from_parent_pub_key
        )
    }

    #[test]
    fn priv_key_serialize_deserialize() {
        let key = fetch_random_key();
        let buf = key.serialize();
        assert_eq!(ExtendedPrivKey::deserialize(&buf).expect("de"), key);
    }

    #[test]
    fn pub_key_serialize_deserialize() {
        let key = ExtendedPubKey::from_private_key(&fetch_random_key());
        let buf = key.serialize();
        assert_eq!(ExtendedPubKey::deserialize(&buf).expect("de"), key);
    }
}
