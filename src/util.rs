use ring::{digest, hmac};

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> hmac::Signature {
    let s_key = hmac::SigningKey::new(&digest::SHA512, key);
    hmac::sign(&s_key, data)
}
