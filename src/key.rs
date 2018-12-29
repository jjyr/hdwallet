use crate::error::Error;
use crate::key_index::KeyIndex;
use crate::util::hmac_sha512;
use numext_fixed_uint::U256;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

type ChainCode = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

pub enum KeySeed {
    S128 = 128,
    S256 = 256,
    S512 = 512,
}

impl ExtendedPrivKey {
    pub fn random() -> Result<ExtendedPrivKey, Error> {
        ExtendedPrivKey::random_with_seed_size(KeySeed::S256)
    }
    pub fn random_with_seed_size(seed_size: KeySeed) -> Result<ExtendedPrivKey, Error> {
        let seed = {
            let mut seed = Vec::with_capacity(seed_size as usize);
            let mut rng = rand::thread_rng();
            rng.fill(seed.as_mut_slice());
            seed
        };
        let signature = hmac_sha512(b"Bitcoin seed", &seed);
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

    fn derive_hardended_key(&self, index: u64) -> Result<ChildPrivKey, Error> {
        let data = {
            let mut data = Vec::with_capacity(33);
            data.extend_from_slice(&[0x00]);
            data.extend_from_slice(&self.private_key[..]);
            let mut ser_index = [0u8; 32];
            U256::from(index)
                .into_big_endian(&mut ser_index)
                .expect("big_endian encode");
            data.extend_from_slice(&ser_index);
            data
        };
        assert_eq!(data.len(), 65);
        let signature = hmac_sha512(&self.chain_code, &data);
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(private_key) = SecretKey::from_slice(key) {
            return Ok(ChildPrivKey {
                key_index: KeyIndex::Hardened(index),
                extended_key: ExtendedPrivKey {
                    private_key,
                    chain_code: chain_code.to_vec(),
                },
            });
        }
        Err(Error::InvalidResultKey)
    }

    fn derive_normal_key(&self, index: u64) -> Result<ChildPrivKey, Error> {
        let data = {
            let mut data = Vec::with_capacity(33);
            let secp = Secp256k1::new();
            let ser_public_key = PublicKey::from_secret_key(&secp, &self.private_key).serialize();
            data.extend_from_slice(&ser_public_key[..]);
            let mut ser_index = [0u8; 32];
            U256::from(index)
                .into_big_endian(&mut ser_index)
                .expect("big_endian encode");
            data.extend_from_slice(&ser_index);
            data
        };
        assert_eq!(data.len(), 65);
        let signature = hmac_sha512(&self.chain_code, &data);
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(mut private_key) = SecretKey::from_slice(key) {
            private_key
                .add_assign(&self.private_key[..])
                .expect("add point");
            return Ok(ChildPrivKey {
                key_index: KeyIndex::Normal(index),
                extended_key: ExtendedPrivKey {
                    private_key,
                    chain_code: chain_code.to_vec(),
                },
            });
        }
        Err(Error::InvalidResultKey)
    }

    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ChildPrivKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::InvalidKeyIndex);
        }
        match key_index {
            KeyIndex::Hardened(index) => self.derive_hardended_key(index),
            KeyIndex::Normal(index) => self.derive_normal_key(index),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
}

impl ExtendedPubKey {
    pub fn derive_public_key(&self, key_index: KeyIndex) -> Result<ChildPubKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::InvalidKeyIndex);
        }

        let index = match key_index {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(_) => return Err(Error::InvalidKeyIndex),
        };

        let data = {
            let mut data = Vec::new();
            data.extend_from_slice(&self.public_key.serialize());
            let mut ser_index = [0u8; 32];
            U256::from(index)
                .into_big_endian(&mut ser_index)
                .expect("big_endian encode");
            data.extend_from_slice(&ser_index);
            data
        };
        assert_eq!(data.len(), 65);
        let signature = hmac_sha512(&self.chain_code, &data);
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(private_key) = SecretKey::from_slice(key) {
            let secp = Secp256k1::new();
            let mut public_key = self.public_key;
            if public_key.add_exp_assign(&secp, &private_key[..]).is_ok() {
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

    pub fn from_private_key(extended_key: &ExtendedPrivKey) -> Result<Self, Error> {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &extended_key.private_key);
        Ok(ExtendedPubKey {
            public_key,
            chain_code: extended_key.chain_code.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPrivKey {
    pub key_index: KeyIndex,
    pub extended_key: ExtendedPrivKey,
}

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
