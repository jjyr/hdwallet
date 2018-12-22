#[cfg(test)]
mod tests {
    use numext_fixed_uint::U256;
    use rand::Rng;
    use ring::{digest, hmac};
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    type ChainCode = Vec<u8>;
    const HARDENDED_KEY_START_INDEX: u64 = 2_147_483_648; // 2 ** 31

    struct ExtendedPrivateKey {
        private_key: SecretKey,
        chain_code: ChainCode,
    }
    //struct ExtendedPublicKey {
    //    public_key: PublicKey,
    //    chain_code: ChainCode,
    //}

    #[derive(Debug)]
    enum Error {
        InvalidKey,
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
        let mut seed = Vec::with_capacity(seed_length);
        let mut rng = rand::thread_rng();
        rng.fill(seed.as_mut_slice());
        let signature = hmac_sha512(b"Bitcoin seed", &seed);
        extract_private_key_from_signature(signature)
    }

    fn extract_private_key_from_signature(
        sig: hmac::Signature,
    ) -> Result<ExtendedPrivateKey, Error> {
        let sig_bytes = sig.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        if let Ok(private_key) = SecretKey::from_slice(key) {
            return Ok(ExtendedPrivateKey {
                private_key,
                chain_code: chain_code.to_vec(),
            });
        }
        Err(Error::InvalidKey)
    }

    impl ExtendedPrivateKey {
        pub fn derive_child_private_key(&self, index: u64) -> Result<ExtendedPrivateKey, Error> {
            let signature = if index >= HARDENDED_KEY_START_INDEX {
                let mut ser_index = Vec::new();
                U256::from(index)
                    .into_big_endian(&mut ser_index)
                    .expect("big_endian encode");
                let mut data = Vec::with_capacity(33);
                data.extend_from_slice(&[0x00]);
                data.extend_from_slice(&self.private_key[..]);
                data.extend_from_slice(&ser_index);
                hmac_sha512(&self.chain_code, &data)
            } else {
                //// normal child
                //let data = &[point(self.private_key.serialize()?), index];
                //hmac_sha512(&self.chain_code, data)
                hmac_sha512(&self.chain_code, &Vec::new())
            };
            extract_private_key_from_signature(signature)
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
            .derive_child_private_key(HARDENDED_KEY_START_INDEX + 1)
            .expect("hardended_key");
    }

    #[test]
    fn derivation_public_child_key_from_public_parent_key() {}

    #[test]
    fn derivation_public_child_key_from_private_parent_key() {}
}
