use crate::{Network, PrivKey, PubKey};
use base58::ToBase58;
use hdwallet::ring::digest;
use hdwallet::{
    traits::{Deserialize, Serialize},
    Derivation, ExtendedPubKey,
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
    fn from_bytes(data: &[u8]) -> Result<Self, ()> {
        let version = match hex::encode(data).as_ref() {
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
                return Err(());
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

fn encode_checksum(buf: &mut Vec<u8>) {
    let check_sum = {
        let buf = digest::digest(&digest::SHA256, &buf);
        digest::digest(&digest::SHA256, &buf.as_ref())
    };

    buf.extend_from_slice(&check_sum.as_ref()[0..4]);
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
        buf.extend_from_slice(&self.key.chain_code);
        buf.extend_from_slice(&[0]);
        buf.extend_from_slice(&self.key.private_key[..]);
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
        buf.extend_from_slice(&self.key.chain_code);
        buf.extend_from_slice(&self.key.public_key.serialize());
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

impl Deserialize<Vec<u8>, ()> for PrivKey {
    fn deserialize(_data: Vec<u8>) -> Result<PrivKey, ()> {
        unreachable!()
        // verify buf
        // 4 version bytes
        // 1 depth bytes
        // parent fingerprint
        // 1 index
        // chain_code
        // key
    }
}
