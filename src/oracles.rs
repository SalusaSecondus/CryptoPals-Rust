use anyhow::Result;
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
            result
                .chunks_exact(16)
                .flat_map(|block| KEY.encrypt_block(block))
                .collect()
        };
        Ok((result, use_cbc))
    }
}
