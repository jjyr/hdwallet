use crate::{ChainPath, ChainPathError, Error, ExtendedPrivKey, SubPath};

pub trait KeyChain {
    fn fetch_key(&self, chain_path: ChainPath) -> Result<ExtendedPrivKey, Error>;
}

pub struct DefaultKeyChain {
    master_key: ExtendedPrivKey,
}

impl DefaultKeyChain {
    pub fn new(master_key: ExtendedPrivKey) -> Self {
        DefaultKeyChain { master_key }
    }
}

impl KeyChain for DefaultKeyChain {
    fn fetch_key(&self, chain_path: ChainPath) -> Result<ExtendedPrivKey, Error> {
        let mut iter = chain_path.iter();
        // chain_path must start with root
        if iter.next() != Some(Ok(SubPath::Root)) {
            return Err(ChainPathError::Invalid.into());
        }
        let mut key = self.master_key.clone();
        for sub_path in iter {
            match sub_path? {
                SubPath::Child(key_index) => {
                    key = key.derive_private_key(key_index)?.extended_key;
                }
                _ => return Err(ChainPathError::Invalid.into()),
            }
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExtendedPubKey;

    fn from_hex(hex_string: &str) -> Vec<u8> {
        hex::decode(hex_string).expect("decode")
    }

    fn to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    fn test_bip32_vector_1() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f");
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::with_seed(&seed).expect("master key"));
        for (chain_path, hex_priv_key, hex_pub_key) in &[
            ("m", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        ] {
            let ext_priv_key = key_chain.fetch_key(ChainPath::from(chain_path.to_string())).expect("fetch key");
            assert_eq!(&to_hex(&ext_priv_key.private_key[..]), hex_priv_key);
            let ext_pub_key = ExtendedPubKey::from_private_key(&ext_priv_key).expect("pubkey");
            assert_eq!(&to_hex(&ext_pub_key.public_key.serialize()), hex_pub_key);
        }
    }

    fn test_bip32_vector_2() {}
}
