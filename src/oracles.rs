use std::collections::HashMap;

use anyhow::{ensure, Context, Result};
use lazy_static::lazy_static;
use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};

use crate::aes::AesKey;
use crate::padding::Padding;

pub struct Challenge11Oracle();

impl Challenge11Oracle {
    pub fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, bool)> {
        lazy_static! {
            static ref EXTRA_RANGE: Uniform<usize> = Uniform::new_inclusive(5, 10);
            static ref KEY: AesKey = {
                let mut raw_key = [0u8; 16];
                OsRng.fill_bytes(&mut raw_key);
                AesKey::new(&raw_key).unwrap()
            };
            static ref IV: [u8; 16] = [0; 16];
        }
        let mut rng = OsRng::default();

        let mut extra = vec![];
        extra.resize(EXTRA_RANGE.sample(&mut rng), 0u8);
        rng.fill_bytes(&mut extra);

        let mut result: Vec<u8> = vec![];
        result.extend(extra.iter());
        result.extend(plaintext.iter());

        extra.resize(EXTRA_RANGE.sample(&mut rng), 0u8);
        rng.fill_bytes(&mut extra);
        result.extend(extra.iter());

        let result = Padding::Pkcs7Padding(16).pad(&result)?;

        let use_cbc: bool = rng.gen();
        let result = if use_cbc {
            KEY.encrypt_cbc(&IV[..], &result)?
        } else {
            KEY.encrypt_ecb(&result)?
        };
        Ok((result, use_cbc))
    }
}

pub struct Set2Oracle {
    key: AesKey,
    pub prefix: Vec<u8>,
}

impl Set2Oracle {
    pub fn new() -> Set2Oracle {
        let mut raw_key = [0u8; 16];
        OsRng.fill_bytes(&mut raw_key);
        let key = AesKey::new(&raw_key).unwrap();

        let prefix_range = Uniform::new_inclusive(5, 10);
        let mut prefix = vec![];
        prefix.resize_with(prefix_range.sample(&mut OsRng), || OsRng.gen());

        Set2Oracle { key, prefix }
    }

    pub fn encrypt12(&self, prefix: &[u8]) -> Result<Vec<u8>> {
        lazy_static! {
            static ref HIDDEN_PT: Vec<u8> = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        }

        let mut plaintext = Vec::from(prefix);
        plaintext.extend(HIDDEN_PT.iter());

        let padded = Padding::Pkcs7Padding(16).pad(&plaintext)?;
        Ok(self.key.encrypt_ecb(&padded)?)
    }

    pub fn encrypt14(&self, attacker_controlled: &[u8]) -> Result<Vec<u8>> {
        lazy_static! {
            static ref HIDDEN_PT: Vec<u8> = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        }

        let mut plaintext = self.prefix.clone();
        plaintext.extend(attacker_controlled);
        plaintext.extend(HIDDEN_PT.iter());

        let padded = Padding::Pkcs7Padding(16).pad(&plaintext)?;
        Ok(self.key.encrypt_ecb(&padded)?)
    }

    pub fn is_admin_13(&self, ciphertext: &[u8]) -> bool {
        let invalid_str = String::from("invalid");
        self.key
            .decrypt_ecb(ciphertext)
            .and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt))
            .and_then(|pt| String::from_utf8(pt).context("Bad UTF8"))
            .and_then(|pt| Set2Oracle::parse_kv(&pt))
            .map(|m| m.get("role").unwrap_or(&invalid_str) == "admin")
            .unwrap_or(false)
    }

    pub fn get_role_13(&self, ciphertext: &[u8]) -> Result<String> {
        let invalid_str = String::from("invalid");
        self.key
            .decrypt_ecb(ciphertext)
            .and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt))
            .and_then(|pt| String::from_utf8(pt).context("Bad UTF8"))
            .and_then(|pt| Set2Oracle::parse_kv(&pt))
            .map(|m| m.get("role").unwrap_or(&invalid_str).to_owned())
    }

    pub fn profile_for_13(&self, email: &str) -> Result<Vec<u8>> {
        ensure!(!email.contains('&'), "Email contains invalid character");
        ensure!(!email.contains('='), "Email contains invalid character");

        let mut pt: Vec<u8> = Vec::from(&b"email="[..]);
        pt.extend(email.as_bytes().iter());
        pt.extend_from_slice(b"&uid=10&role=user");

        self.key.encrypt_ecb(&Padding::Pkcs7Padding(16).pad(&pt)?)
    }

    
    fn parse_kv(s: &str) -> Result<HashMap<String, String>> {
        let mut result = HashMap::new();
        for pairs in s.split('&') {
            let mut parts = pairs.splitn(2, '=');
            let key = parts.next().context("Missing key")?;
            let value = parts.next().context("Missing value")?;

            result.insert(key.to_owned(), value.to_owned());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::Set2Oracle;
    use anyhow::Result;

    #[test]
    fn chall13_smoke() -> Result<()> {
        let oracle = Set2Oracle::new();
        let ct = oracle.profile_for_13("salusa@salusa.dev")?;
        assert_eq!(false, oracle.is_admin_13(&ct));
        assert_eq!("user", oracle.get_role_13(&ct)?);

        Ok(())
    }
}
