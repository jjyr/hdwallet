#[cfg(test)]
mod tests {
    use numext_fixed_uint::U256;
    use rand::Rng;
    use ring::{digest, hmac};
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    type ChainCode = Vec<u8>;
    const HARDENDED_KEY_START_INDEX: u64 = 2_147_483_648; // 2 ** 31
    const HARDENDED_KEY_END_INDEX: u64 = 4_294_967_295; // 2 ** 32 - 1

    #[derive(Debug, Clone)]
    struct ExtendedPrivateKey {
        private_key: SecretKey,
        chain_code: ChainCode,
    }

    #[derive(Debug, Clone)]
    struct ExtendedPublicKey {
        public_key: PublicKey,
        chain_code: ChainCode,
    }

    #[derive(Debug)]
    enum Error {
        IndexOutOfRange,
        InvalidIndex,
    }

    #[derive(Debug, Copy, Clone)]
    enum KeyMode {
        Normal,
        Hardened,
    }

    #[derive(Debug, Clone)]
    struct ChildPrivateKey {
        index: u64,
        key_mode: KeyMode,
        extended_key: ExtendedPrivateKey,
    }

    #[derive(Debug, Clone)]
    struct ChildPublicKey {
        index: u64,
        key_mode: KeyMode,
        extended_key: ExtendedPublicKey,
    }

    fn random_secret_key() -> SecretKey {
        let mut rng = rand::thread_rng();
        let mut seed = [0x00; 32];
        rng.fill(&mut seed);
        SecretKey::from_slice(&seed).expect("secret key")
    }

    fn hmac_sha512(key: &[u8], data: &[u8]) -> hmac::Signature {
        let s_key = hmac::SigningKey::new(&digest::SHA512, key);
        hmac::sign(&s_key, data)
    }

    fn generate_master_key(seed_length: usize) -> Result<ExtendedPrivateKey, Error> {
        let seed = {
            let mut seed = Vec::with_capacity(seed_length);
            let mut rng = rand::thread_rng();
            rng.fill(seed.as_mut_slice());
            seed
        };
        let signature = hmac_sha512(b"Bitcoin seed", &seed);
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(private_key) = SecretKey::from_slice(key) {
            return Ok(ExtendedPrivateKey {
                private_key,
                chain_code: chain_code.to_vec(),
            });
        }
        Err(Error::InvalidIndex)
    }

    fn to_hardened_key_index(index: u64) -> u64 {
        if index < HARDENDED_KEY_START_INDEX {
            HARDENDED_KEY_START_INDEX + index
        } else {
            index
        }
    }

    impl ExtendedPrivateKey {
        fn derive_hardended_key(&self, index: u64) -> Result<ChildPrivateKey, Error> {
            let index = to_hardened_key_index(index);
            if index > HARDENDED_KEY_END_INDEX {
                return Err(Error::IndexOutOfRange);
            }
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
                return Ok(ChildPrivateKey {
                    index,
                    key_mode: KeyMode::Hardened,
                    extended_key: ExtendedPrivateKey {
                        private_key,
                        chain_code: chain_code.to_vec(),
                    },
                });
            }
            Err(Error::InvalidIndex)
        }

        fn derive_normal_key(&self, index: u64) -> Result<ChildPrivateKey, Error> {
            if index >= HARDENDED_KEY_START_INDEX {
                return Err(Error::IndexOutOfRange);
            }
            let data = {
                let mut data = Vec::with_capacity(33);
                let secp = Secp256k1::new();
                let ser_public_key =
                    PublicKey::from_secret_key(&secp, &self.private_key).serialize();
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
                return Ok(ChildPrivateKey {
                    index,
                    key_mode: KeyMode::Normal,
                    extended_key: ExtendedPrivateKey {
                        private_key,
                        chain_code: chain_code.to_vec(),
                    },
                });
            }
            Err(Error::InvalidIndex)
        }

        pub fn derive_child_private_key(
            &self,
            key_mode: KeyMode,
            index: u64,
        ) -> Result<ChildPrivateKey, Error> {
            match key_mode {
                KeyMode::Hardened => self.derive_hardended_key(index),
                KeyMode::Normal => self.derive_normal_key(index),
            }
        }
    }

    fn fetch_random_key(seed_size: usize) -> ExtendedPrivateKey {
        loop {
            if let Ok(ex_key) = generate_master_key(seed_size) {
                return ex_key;
            }
        }
    }

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn secp256k1_random_key() {
        let secp = Secp256k1::new();
        let secret_key = random_secret_key();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let message = Message::from_slice(&[0xab; 32]).expect("message");
        let sig = secp.sign(&message, &secret_key);
        assert!(secp.verify(&message, &sig, &public_key).is_ok());
    }

    #[test]
    fn generate_bip32_seed_and_entropy() {
        for _ in 0..10 {
            if let Ok(ex_key) = generate_master_key(256) {
                println!(
                    "secret_key: {:?}\nchain_code: {:?}",
                    ex_key.private_key, ex_key.chain_code
                );
                return;
            }
        }
        panic!("can't generate valid secret_key");
    }

    #[test]
    fn derivation_private_child_key_from_private_parent_key() {
        let master_key = fetch_random_key(256);
        master_key
            .derive_child_private_key(KeyMode::Hardened, 0)
            .expect("hardended_key");
        master_key
            .derive_child_private_key(KeyMode::Normal, 0)
            .expect("normal_key");
    }

    #[test]
    fn derivation_public_child_key_from_public_parent_key() {}

    #[test]
    fn derivation_public_child_key_from_private_parent_key() {}
}
