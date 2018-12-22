#[cfg(test)]
mod tests {
    use rand::Rng;
    use ring::{digest, hmac};
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

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

    fn generate_master_key(seed_length: usize) -> (Vec<u8>, Vec<u8>) {
        let mut seed = Vec::with_capacity(seed_length);
        let mut rng = rand::thread_rng();
        rng.fill(seed.as_mut_slice());
        let signature = hmac_sha512(b"Bitcoin seed", &seed);
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        (key.to_vec(), chain_code.to_vec())
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
            let (key, chain_code) = generate_master_key(256);
            if let Ok(secret_key) = SecretKey::from_slice(&key) {
                println!("secret_key: {:?}\nchain_code: {:?}", secret_key, chain_code);
                return;
            }
        }
        panic!("can't generate valid secret_key");
    }

    #[test]
    fn derivation_private_child_key_from_private_parent_key() {}

    #[test]
    fn derivation_public_child_key_from_public_parent_key() {}

    #[test]
    fn derivation_public_child_key_from_private_parent_key() {}
}
