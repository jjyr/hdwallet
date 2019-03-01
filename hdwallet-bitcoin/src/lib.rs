use base58::ToBase58;
use hdwallet::ring::digest;
use hdwallet::{ExtendedKey, ExtendedPrivKey, ExtendedPubKey, KeyIndex, Serialize};
use ripemd160::{Digest, Ripemd160};

#[derive(Clone, Copy, Debug)]
pub enum Network {
    MainNet,
    TestNet,
}

#[derive(Clone, Debug)]
pub struct Key {
    pub network: Network,
    pub depth: u8,
    pub parent_key: Option<ExtendedPrivKey>,
    pub key_index: Option<KeyIndex>,
    pub key: ExtendedKey,
}

impl Key {
    fn version_bytes(&self) -> Vec<u8> {
        let hex_str = match self.network {
            Network::MainNet => match self.key {
                ExtendedKey::PrivKey(..) => "0488ADE4",
                ExtendedKey::PubKey(..) => "0488B21E",
            },
            Network::TestNet => match self.key {
                ExtendedKey::PrivKey(..) => "04358394",
                ExtendedKey::PubKey(..) => "043587CF",
            },
        };
        hex::decode(hex_str).expect("bitcoin network")
    }

    fn parent_fingerprint(&self) -> Vec<u8> {
        match self.parent_key {
            Some(ref key) => {
                let pubkey = ExtendedPubKey::from_private_key(key).expect("get public_key");
                let buf = digest::digest(&digest::SHA256, &pubkey.public_key.serialize());
                let mut hasher = Ripemd160::new();
                hasher.input(&buf.as_ref());
                hasher.result()[0..4].to_vec()
            }
            None => vec![0; 4],
        }
    }

    #[inline]
    pub fn is_private_key(&self) -> bool {
        self.private_key().is_some()
    }
    #[inline]
    pub fn is_public_key(&self) -> bool {
        !self.is_private_key()
    }

    pub fn private_key(&self) -> Option<&Key> {
        match self.key {
            ExtendedKey::PrivKey(..) => Some(&self),
            ExtendedKey::PubKey(..) => None,
        }
    }

    pub fn to_public_key(&self) -> Key {
        match self.key {
            ExtendedKey::PrivKey(ref key) => {
                let pubkey = ExtendedPubKey::from_private_key(key).expect("get public_key");
                let mut bitcoin_key = self.clone();
                bitcoin_key.key = ExtendedKey::PubKey(pubkey);
                bitcoin_key
            }
            ExtendedKey::PubKey(..) => self.clone(),
        }
    }
}

impl Serialize<Vec<u8>> for Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(112);
        buf.extend_from_slice(&self.version_bytes());
        buf.extend_from_slice(&self.depth.to_be_bytes());
        buf.extend_from_slice(&self.parent_fingerprint());
        match self.key_index {
            Some(key_index) => {
                buf.extend_from_slice(&key_index.raw_index().to_be_bytes());
            }
            None => buf.extend_from_slice(&[0; 4]),
        }
        match self.key {
            ExtendedKey::PrivKey(ref key) => {
                buf.extend_from_slice(&key.chain_code);
                buf.extend_from_slice(&[0]);
                buf.extend_from_slice(&key.private_key[..]);
            }
            ExtendedKey::PubKey(ref key) => {
                buf.extend_from_slice(&key.chain_code);
                buf.extend_from_slice(&key.public_key.serialize());
            }
        }
        assert_eq!(buf.len(), 78);

        let check_sum = {
            let buf = digest::digest(&digest::SHA256, &buf);
            digest::digest(&digest::SHA256, &buf.as_ref())
        };

        buf.extend_from_slice(&check_sum.as_ref()[0..4]);
        buf
    }
}

impl Serialize<String> for Key {
    fn serialize(&self) -> String {
        Serialize::<Vec<u8>>::serialize(self).to_base58()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdwallet::{ChainPath, DefaultKeyChain, KeyChain};

    #[test]
    fn test_bip32_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").expect("decode");
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::with_seed(&seed).expect("master key"));
        for (chain_path, hex_priv_key, hex_pub_key) in &[
            ("m", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
            ("m/0H", "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
            ("m/0H/1", "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
            ("m/0H/1/2H", "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"),
            ("m/0H/1/2H/2", "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"),
            ("m/0H/1/2H/2/1000000000", "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
        ] {
            let key_info = key_chain.fetch_key(ChainPath::from(chain_path.to_string())).expect("fetch key");
            let priv_key = Key{
                network: Network::MainNet,
                depth: key_info.depth,
                parent_key: key_info.parent_key,
                key_index: key_info.key_index,
                key: ExtendedKey::PrivKey(key_info.key),
            };
            assert_eq!(&Serialize::<String>::serialize(&priv_key), hex_priv_key);
            assert_eq!(&Serialize::<String>::serialize(&priv_key.to_public_key()), hex_pub_key);
        }
    }

    #[test]
    fn test_bip32_vector_2() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").expect("decode");
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::with_seed(&seed).expect("master key"));
        for (chain_path, hex_priv_key, hex_pub_key) in &[
            ("m", "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"),
            ("m/0", "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"),
            ("m/0/2147483647H", "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"),
            ("m/0/2147483647H/1", "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"),
            ("m/0/2147483647H/1/2147483646H", "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"),
            ("m/0/2147483647H/1/2147483646H/2", "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
        ] {
            let key_info = key_chain.fetch_key(ChainPath::from(chain_path.to_string())).expect("fetch key");
            let priv_key = Key{
                network: Network::MainNet,
                depth: key_info.depth,
                parent_key: key_info.parent_key,
                key_index: key_info.key_index,
                key: ExtendedKey::PrivKey(key_info.key),
            };
            assert_eq!(&Serialize::<String>::serialize(&priv_key), hex_priv_key);
            assert_eq!(&Serialize::<String>::serialize(&priv_key.to_public_key()), hex_pub_key);
        }
    }

    #[test]
    fn test_bip32_vector_3() {
        let seed = hex::decode("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").expect("decode");
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::with_seed(&seed).expect("master key"));
        for (chain_path, hex_priv_key, hex_pub_key) in &[
            ("m", "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"),
            ("m/0H", "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")
        ] {
            let key_info = key_chain.fetch_key(ChainPath::from(chain_path.to_string())).expect("fetch key");
            let priv_key = Key{
                network: Network::MainNet,
                depth: key_info.depth,
                parent_key: key_info.parent_key,
                key_index: key_info.key_index,
                key: ExtendedKey::PrivKey(key_info.key),
            };
            assert_eq!(&Serialize::<String>::serialize(&priv_key), hex_priv_key);
            assert_eq!(&Serialize::<String>::serialize(&priv_key.to_public_key()), hex_pub_key);
        }
    }
}
