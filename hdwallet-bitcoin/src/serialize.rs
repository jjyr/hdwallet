use crate::{Error, Network, PrivKey, PubKey};
use base58::{FromBase58, ToBase58};
use hdwallet::ring::digest;
use hdwallet::{
    secp256k1::{PublicKey, SecretKey},
    traits::{Deserialize, Serialize},
    Derivation, ExtendedPrivKey, ExtendedPubKey, KeyIndex,
};
use ripemd160::{Digest, Ripemd160};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyType {
    PrivKey,
    PubKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Version {
    network: Network,
    key_type: KeyType,
}

impl Version {
    #[allow(dead_code)]
    fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let version = match hex::encode(data).to_uppercase().as_ref() {
            "0488ADE4" => Version {
                network: Network::MainNet,
                key_type: KeyType::PrivKey,
            },
            "0488B21E" => Version {
                network: Network::MainNet,
                key_type: KeyType::PubKey,
            },
            "04358394" => Version {
                network: Network::TestNet,
                key_type: KeyType::PrivKey,
            },
            "043587CF" => Version {
                network: Network::TestNet,
                key_type: KeyType::PubKey,
            },
            _ => {
                return Err(Error::UnknownVersion);
            }
        };
        Ok(version)
    }

    fn to_bytes(self) -> Vec<u8> {
        let hex_str = match self.network {
            Network::MainNet => match self.key_type {
                KeyType::PrivKey => "0488ADE4",
                KeyType::PubKey => "0488B21E",
            },
            Network::TestNet => match self.key_type {
                KeyType::PrivKey => "04358394",
                KeyType::PubKey => "043587CF",
            },
        };
        hex::decode(hex_str).expect("bitcoin network")
    }
}

trait DerivationExt {
    fn parent_fingerprint(&self) -> Vec<u8>;
}

impl DerivationExt for Derivation {
    fn parent_fingerprint(&self) -> Vec<u8> {
        match self.parent_key {
            Some(ref key) => {
                let pubkey = ExtendedPubKey::from_private_key(key);
                let buf = digest::digest(&digest::SHA256, &pubkey.public_key.serialize());
                let mut hasher = Ripemd160::new();
                hasher.input(&buf.as_ref());
                hasher.result()[0..4].to_vec()
            }
            None => vec![0; 4],
        }
    }
}

fn encode_derivation(buf: &mut Vec<u8>, version: Version, derivation: &Derivation) {
    buf.extend_from_slice(&version.to_bytes());
    buf.extend_from_slice(&derivation.depth.to_be_bytes());
    buf.extend_from_slice(&derivation.parent_fingerprint());
    match derivation.key_index {
        Some(key_index) => {
            buf.extend_from_slice(&key_index.raw_index().to_be_bytes());
        }
        None => buf.extend_from_slice(&[0; 4]),
    }
}

fn decode_derivation(buf: &[u8]) -> Result<(Version, Derivation), Error> {
    let version = Version::from_bytes(&buf[0..4])?;
    let depth = u8::from_be_bytes([buf[4]; 1]);
    let parent_fingerprint = &buf[5..=8];
    let key_index = {
        // is master key
        if parent_fingerprint == [0; 4] {
            None
        } else {
            let mut key_index_buf = [0u8; 4];
            key_index_buf.copy_from_slice(&buf[9..=12]);
            let raw_index = u32::from_be_bytes(key_index_buf);
            Some(KeyIndex::from(raw_index))
        }
    };
    Ok((
        version,
        Derivation {
            depth,
            parent_key: None,
            key_index,
        },
    ))
}

fn encode_checksum(buf: &mut Vec<u8>) {
    let check_sum = {
        let buf = digest::digest(&digest::SHA256, &buf);
        digest::digest(&digest::SHA256, &buf.as_ref())
    };

    buf.extend_from_slice(&check_sum.as_ref()[0..4]);
}

fn verify_checksum(buf: &[u8]) -> Result<(), Error> {
    let check_sum = {
        let buf = digest::digest(&digest::SHA256, &buf[0..78]);
        digest::digest(&digest::SHA256, &buf.as_ref())
    };
    if check_sum.as_ref()[0..4] == buf[78..82] {
        Ok(())
    } else {
        Err(Error::MisChecksum)
    }
}

impl Serialize<Vec<u8>> for PrivKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(112);
        encode_derivation(
            &mut buf,
            Version {
                network: self.network,
                key_type: KeyType::PrivKey,
            },
            &self.derivation,
        );
        buf.extend_from_slice(&self.extended_key.chain_code);
        buf.extend_from_slice(&[0]);
        buf.extend_from_slice(&self.extended_key.private_key[..]);
        assert_eq!(buf.len(), 78);
        encode_checksum(&mut buf);
        buf
    }
}

impl Serialize<String> for PrivKey {
    fn serialize(&self) -> String {
        Serialize::<Vec<u8>>::serialize(self).to_base58()
    }
}

impl Serialize<Vec<u8>> for PubKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(112);
        encode_derivation(
            &mut buf,
            Version {
                network: self.network,
                key_type: KeyType::PubKey,
            },
            &self.derivation,
        );
        buf.extend_from_slice(&self.extended_key.chain_code);
        buf.extend_from_slice(&self.extended_key.public_key.serialize());
        assert_eq!(buf.len(), 78);
        encode_checksum(&mut buf);
        buf
    }
}

impl Serialize<String> for PubKey {
    fn serialize(&self) -> String {
        Serialize::<Vec<u8>>::serialize(self).to_base58()
    }
}

impl Deserialize<Vec<u8>, Error> for PrivKey {
    fn deserialize(data: Vec<u8>) -> Result<PrivKey, Error> {
        verify_checksum(&data)?;
        let (version, derivation) = decode_derivation(&data)?;
        let chain_code = data[13..45].to_vec();
        let private_key = SecretKey::from_slice(&data[46..78])?;
        Ok(PrivKey {
            network: version.network,
            derivation,
            extended_key: ExtendedPrivKey {
                chain_code,
                private_key,
            },
        })
    }
}

impl Deserialize<String, Error> for PrivKey {
    fn deserialize(data: String) -> Result<PrivKey, Error> {
        let data = data.from_base58().map_err(|_| Error::InvalidBase58)?;
        PrivKey::deserialize(data)
    }
}

impl Deserialize<Vec<u8>, Error> for PubKey {
    fn deserialize(data: Vec<u8>) -> Result<PubKey, Error> {
        verify_checksum(&data)?;
        let (version, derivation) = decode_derivation(&data)?;
        let chain_code = data[13..45].to_vec();
        let public_key = PublicKey::from_slice(&data[45..78])?;
        Ok(PubKey {
            network: version.network,
            derivation,
            extended_key: ExtendedPubKey {
                chain_code,
                public_key,
            },
        })
    }
}

impl Deserialize<String, Error> for PubKey {
    fn deserialize(data: String) -> Result<PubKey, Error> {
        let data = data.from_base58().map_err(|_| Error::InvalidBase58)?;
        PubKey::deserialize(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdwallet::{DefaultKeyChain, KeyChain};

    #[test]
    fn test_deserialize_priv_key() {
        let mut rng = rand::thread_rng();
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::random(&mut rng).expect("master key"));
        let (extended_key, derivation) =
            key_chain.derive_private_key("m".into()).expect("fetch key");
        let key = PrivKey {
            network: Network::MainNet,
            derivation,
            extended_key,
        };
        let serialized_key: String = key.serialize();
        let key2 = PrivKey::deserialize(serialized_key).expect("deserialize");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_deserialize_pub_key() {
        let mut rng = rand::thread_rng();
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::random(&mut rng).expect("master key"));
        let (extended_key, derivation) =
            key_chain.derive_private_key("m".into()).expect("fetch key");
        let key = PrivKey {
            network: Network::MainNet,
            derivation,
            extended_key,
        };
        let key = PubKey::from_private_key(&key);
        let serialized_key: String = key.serialize();
        let key2 = PubKey::deserialize(serialized_key).expect("deserialize");
        assert_eq!(key, key2);
    }
}
