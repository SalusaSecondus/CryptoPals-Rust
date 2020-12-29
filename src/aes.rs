use crate::xor;
use anyhow::{bail, ensure, Result};
use core::fmt::Display;
use lazy_static::lazy_static;
use std::str::FromStr;

const BLOCK_SIZE: usize = 16;
type RoundKeys = [[u8; BLOCK_SIZE]; 15];
type AesBlock = [u8; BLOCK_SIZE];

// This is a horribly insecure implementation of AES. Don't use it for anything!

lazy_static! {
    static ref SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16
    ];
    static ref SBOX_INV: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d
    ];
    static ref RC: [u8; 11] = [0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
}

pub struct AesKey {
    round_keys: RoundKeys,
    rounds: usize,
}

impl AesKey {
    #[allow(non_snake_case)]
    pub fn new(bin: &[u8]) -> Result<AesKey> {
        ensure!(bin.len() == 16, "Only AES-128 is currently supported");
        let N = bin.len() / 4;
        let rounds = match bin.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => bail!("Invalid key length"),
        };

        let mut round_keys = [[0; BLOCK_SIZE]; 15];

        for i in 0..4 * (rounds + 1) {
            if i < N {
                set_word(&mut round_keys, i, get_word(bin, i));
            } else if i >= N && i % N == 0 {
                let word = get_round_word(&round_keys, i - 1);
                let word = rot_word(word)?;
                let mut word = sub_word(&word)?;
                word[0] ^= RC[(i / N) as usize];
                let word = xor(&word, get_round_word(&round_keys, i - N));
                set_word(&mut round_keys, i, &word);
            } else if i >= N && N > 6 && i % N == 4 {
                let word = get_round_word(&round_keys, i - 1);
                let word = sub_word(&word)?;
                let word = xor(&word, get_round_word(&round_keys, i - N));
                set_word(&mut round_keys, i, &word);
            } else {
                let word = get_round_word(&round_keys, i - 1);
                let word = xor(&word, get_round_word(&round_keys, i - N));
                set_word(&mut round_keys, i, &word);
            }
        }

        Ok(AesKey { round_keys, rounds })
    }

    pub fn encrypt_cbc(&self, iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() % BLOCK_SIZE == 0,
            "Not a multiple of the block size"
        );
        ensure!(iv.len() >= BLOCK_SIZE, "IV is not long enough");

        let mut previous_block = Vec::from(&iv[iv.len() - 16..]);
        Ok(plaintext
            .chunks_exact(BLOCK_SIZE)
            .flat_map(|pt_block| {
                let ct_block = self.encrypt_block(&xor(&previous_block, pt_block));
                previous_block.copy_from_slice(&ct_block);
                ct_block
            })
            .collect())
    }

    pub fn decrypt_cbc(&self, iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() % BLOCK_SIZE == 0,
            "Not a multiple of the block size"
        );
        ensure!(iv.len() >= BLOCK_SIZE, "IV is not long enough");

        let mut previous_block = Vec::from(&iv[iv.len() - 16..]);
        Ok(plaintext
            .chunks_exact(BLOCK_SIZE)
            .flat_map(|ct_block| {
                let pt_block = xor(&self.decrypt_block(ct_block), &previous_block);
                previous_block.copy_from_slice(&ct_block);
                pt_block
            })
            .collect())
    }

    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() % BLOCK_SIZE == 0,
            "Not a multiple of the block size"
        );
        Ok(plaintext
            .chunks_exact(16)
            .flat_map(|block| self.encrypt_block(block))
            .collect())
    }

    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            ciphertext.len() % BLOCK_SIZE == 0,
            "Not a multiple of the block size"
        );
        Ok(ciphertext
            .chunks_exact(16)
            .flat_map(|block| self.decrypt_block(block))
            .collect())
    }

    pub fn encrypt_block(&self, block: &[u8]) -> Vec<u8> {
        let mut result = Vec::from(block);

        let round_keys = self.round_keys;

        // Initial round key addition
        for (b, k) in result.iter_mut().zip(round_keys[0].iter()) {
            *b ^= k;
        }
        // Internal rounds
        for round_key in &self.round_keys[1..self.rounds] {
            // SubBytes
            for b in result.iter_mut() {
                *b = SBOX[*b as usize];
            }
            // ShiftRows
            shift_rows(&mut result);

            // MixColumns
            for column in 0..4 {
                let offset = column * 4;
                mix_column(&mut result[offset..offset + 4]);
            }

            // AddRoundKey
            for (b, k) in result.iter_mut().zip(round_key.iter()) {
                *b ^= k;
            }
        }

        // Final Round
        // SubBytes
        for b in result.iter_mut() {
            *b = SBOX[*b as usize];
        }
        // ShiftRows
        shift_rows(&mut result);

        // AddRoundKey
        for (b, k) in result.iter_mut().zip(round_keys[self.rounds].iter()) {
            *b ^= k;
        }
        result
    }

    pub fn decrypt_block(&self, block: &[u8]) -> Vec<u8> {
        let mut result = Vec::from(block);

        let round_keys = self.round_keys;

        // Final round
        // AddRoundKey
        for (b, k) in result.iter_mut().zip(round_keys[self.rounds].iter()) {
            *b ^= k;
        }

        // ShiftRows
        inv_shift_rows(&mut result);

        // SubBytes
        for b in result.iter_mut() {
            *b = SBOX_INV[*b as usize];
        }

        // Internal rounds
        for round_key in self.round_keys[1..self.rounds].iter().rev() {
            // AddRoundKey
            for (b, k) in result.iter_mut().zip(round_key.iter()) {
                *b ^= k;
            }

            // MixColumns
            for column in 0..4 {
                let offset = column * 4;
                inv_mix_column(&mut result[offset..offset + 4]);
            }

            // ShiftRows
            inv_shift_rows(&mut result);

            // SubBytes
            for b in result.iter_mut() {
                *b = SBOX_INV[*b as usize];
            }
        }

        // Initial round key addition
        for (b, k) in result.iter_mut().zip(round_keys[0].iter()) {
            *b ^= k;
        }
        result
    }
}

fn get_round_word(round_keys: &RoundKeys, w_index: usize) -> &[u8] {
    let b_index = w_index * 4;
    let round = b_index / 16;
    let offset = b_index % 16;

    &round_keys[round][offset..offset + 4]
}

fn get_word(key: &[u8], w_index: usize) -> &[u8] {
    let offset = w_index * 4;
    &key[offset..offset + 4]
}

fn set_word(round_keys: &mut RoundKeys, w_index: usize, word: &[u8]) {
    let b_index = w_index * 4;
    let round = b_index / 16;
    let offset = b_index % 16;

    for (idx, b) in word.iter().enumerate() {
        round_keys[round][offset + idx] = *b;
    }
}

fn w_to_round_idx(w: usize) -> (usize, usize) {
    (w / 16, w % 16)
}

fn rot_word(word: &[u8]) -> Result<[u8; 4]> {
    ensure!(word.len() == 4, "Invalid word length");
    let result = [word[1], word[2], word[3], word[0]];

    Ok(result)
}

fn sub_word(word: &[u8]) -> Result<[u8; 4]> {
    ensure!(word.len() == 4, "Invalid word length");
    let result = [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ];

    Ok(result)
}

fn shift_rows(r: &mut [u8]) {
    let tmp = [
        r[0], r[5], r[10], r[15], r[4], r[9], r[14], r[3], r[8], r[13], r[2], r[7], r[12], r[1],
        r[6], r[11],
    ];
    r.copy_from_slice(&tmp);
}

fn inv_shift_rows(r: &mut [u8]) {
    let tmp = [
        r[0], r[13], r[10], r[7], r[4], r[1], r[14], r[11], r[8], r[5], r[2], r[15], r[12], r[9],
        r[6], r[3],
    ];
    r.copy_from_slice(&tmp);
}

fn gmul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;

    for _ in 0..8 {
        if b & 1 == 1 {
            p ^= a;
        }
        let c = a & 0x80;
        a <<= 1;
        if c != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }

    p
}

fn inv_mix_column(r: &mut [u8]) {
    let mut a = [0u8; 4];
    a.copy_from_slice(r);

    r[0] = gmul(0x0e, a[0]) ^ gmul(0x0b, a[1]) ^ gmul(0x0d, a[2]) ^ gmul(0x09, a[3]);
    r[1] = gmul(0x09, a[0]) ^ gmul(0x0e, a[1]) ^ gmul(0x0b, a[2]) ^ gmul(0x0d, a[3]);
    r[2] = gmul(0x0d, a[0]) ^ gmul(0x09, a[1]) ^ gmul(0x0e, a[2]) ^ gmul(0x0b, a[3]);
    r[3] = gmul(0x0b, a[0]) ^ gmul(0x0d, a[1]) ^ gmul(0x09, a[2]) ^ gmul(0x0e, a[3]);
}

fn mix_column(r: &mut [u8]) {
    let mut a = [0u8; 4];
    a.copy_from_slice(r);

    r[0] = gmul(0x02, a[0]) ^ gmul(0x03, a[1]) ^ a[2] ^ a[3];
    r[1] = a[0] ^ gmul(0x02, a[1]) ^ gmul(0x03, a[2]) ^ a[3];
    r[2] = a[0] ^ a[1] ^ gmul(0x02, a[2]) ^ gmul(0x03, a[3]);
    r[3] = gmul(0x03, a[0]) ^ a[1] ^ a[2] ^ gmul(0x02, a[3]);
}

impl FromStr for AesKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, <Self as std::str::FromStr>::Err> {
        AesKey::new(&hex::decode(s)?)
    }
}

impl Display for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for (num, key) in self.round_keys.iter().take(self.rounds + 1).enumerate() {
            writeln!(f, "Round {}:\t{}", num, hex::encode(key))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_schedule() -> Result<()> {
        let key = AesKey::from_str("00000000000000000000000000000000")?;
        // println!("{}", key);

        assert_eq!(10, key.rounds);
        assert_eq!(
            hex::decode("00000000000000000000000000000000")?,
            key.round_keys[0]
        );
        assert_eq!(
            hex::decode("62636363626363636263636362636363")?,
            key.round_keys[1]
        );
        assert_eq!(
            hex::decode("9b9898c9f9fbfbaa9b9898c9f9fbfbaa")?,
            key.round_keys[2]
        );
        assert_eq!(
            hex::decode("90973450696ccffaf2f457330b0fac99")?,
            key.round_keys[3]
        );
        assert_eq!(
            hex::decode("ee06da7b876a1581759e42b27e91ee2b")?,
            key.round_keys[4]
        );
        assert_eq!(
            hex::decode("7f2e2b88f8443e098dda7cbbf34b9290")?,
            key.round_keys[5]
        );
        assert_eq!(
            hex::decode("ec614b851425758c99ff09376ab49ba7")?,
            key.round_keys[6]
        );
        assert_eq!(
            hex::decode("217517873550620bacaf6b3cc61bf09b")?,
            key.round_keys[7]
        );
        assert_eq!(
            hex::decode("0ef903333ba9613897060a04511dfa9f")?,
            key.round_keys[8]
        );
        assert_eq!(
            hex::decode("b1d4d8e28a7db9da1d7bb3de4c664941")?,
            key.round_keys[9]
        );
        assert_eq!(
            hex::decode("b4ef5bcb3e92e21123e951cf6f8f188e")?,
            key.round_keys[10]
        );

        let key = AesKey::from_str("ffffffffffffffffffffffffffffffff")?;
        // println!("{}", key);
        assert_eq!(10, key.rounds);
        assert_eq!(
            hex::decode("ffffffffffffffffffffffffffffffff")?,
            key.round_keys[0]
        );
        assert_eq!(
            hex::decode("e8e9e9e917161616e8e9e9e917161616")?,
            key.round_keys[1]
        );
        assert_eq!(
            hex::decode("adaeae19bab8b80f525151e6454747f0")?,
            key.round_keys[2]
        );
        assert_eq!(
            hex::decode("090e2277b3b69a78e1e7cb9ea4a08c6e")?,
            key.round_keys[3]
        );
        assert_eq!(
            hex::decode("e16abd3e52dc2746b33becd8179b60b6")?,
            key.round_keys[4]
        );
        assert_eq!(
            hex::decode("e5baf3ceb766d488045d385013c658e6")?,
            key.round_keys[5]
        );
        assert_eq!(
            hex::decode("71d07db3c6b6a93bc2eb916bd12dc98d")?,
            key.round_keys[6]
        );
        assert_eq!(
            hex::decode("e90d208d2fbb89b6ed5018dd3c7dd150")?,
            key.round_keys[7]
        );
        assert_eq!(
            hex::decode("96337366b988fad054d8e20d68a5335d")?,
            key.round_keys[8]
        );
        assert_eq!(
            hex::decode("8bf03f233278c5f366a027fe0e0514a3")?,
            key.round_keys[9]
        );
        assert_eq!(
            hex::decode("d60a3588e472f07b82d2d7858cd7c326")?,
            key.round_keys[10]
        );

        let key = AesKey::from_str("000102030405060708090a0b0c0d0e0f")?;
        // println!("{}", key);
        assert_eq!(10, key.rounds);
        assert_eq!(
            hex::decode("000102030405060708090a0b0c0d0e0f")?,
            key.round_keys[0]
        );
        assert_eq!(
            hex::decode("d6aa74fdd2af72fadaa678f1d6ab76fe")?,
            key.round_keys[1]
        );
        assert_eq!(
            hex::decode("b692cf0b643dbdf1be9bc5006830b3fe")?,
            key.round_keys[2]
        );
        assert_eq!(
            hex::decode("b6ff744ed2c2c9bf6c590cbf0469bf41")?,
            key.round_keys[3]
        );
        assert_eq!(
            hex::decode("47f7f7bc95353e03f96c32bcfd058dfd")?,
            key.round_keys[4]
        );
        assert_eq!(
            hex::decode("3caaa3e8a99f9deb50f3af57adf622aa")?,
            key.round_keys[5]
        );
        assert_eq!(
            hex::decode("5e390f7df7a69296a7553dc10aa31f6b")?,
            key.round_keys[6]
        );
        assert_eq!(
            hex::decode("14f9701ae35fe28c440adf4d4ea9c026")?,
            key.round_keys[7]
        );
        assert_eq!(
            hex::decode("47438735a41c65b9e016baf4aebf7ad2")?,
            key.round_keys[8]
        );
        assert_eq!(
            hex::decode("549932d1f08557681093ed9cbe2c974e")?,
            key.round_keys[9]
        );
        assert_eq!(
            hex::decode("13111d7fe3944a17f307a78b4d2b30c5")?,
            key.round_keys[10]
        );

        let key = AesKey::from_str("4920e299a520526164696f476174756e")?;
        // println!("{}", key);
        assert_eq!(10, key.rounds);
        assert_eq!(
            hex::decode("4920e299a520526164696f476174756e")?,
            key.round_keys[0]
        );
        assert_eq!(
            hex::decode("dabd7d767f9d2f171bf440507a80353e")?,
            key.round_keys[1]
        );
        assert_eq!(
            hex::decode("152bcfac6ab6e0bb7142a0eb0bc295d5")?,
            key.round_keys[2]
        );
        assert_eq!(
            hex::decode("3401cc875eb72c3c2ff58cd724371902")?,
            key.round_keys[3]
        );
        assert_eq!(
            hex::decode("a6d5bbb1f862978dd7971b5af3a00258")?,
            key.round_keys[4]
        );
        assert_eq!(
            hex::decode("56a2d1bcaec0463179575d6b8af75f33")?,
            key.round_keys[5]
        );
        assert_eq!(
            hex::decode("1e6d12c2b0ad54f3c9fa0998430d56ab")?,
            key.round_keys[6]
        );
        assert_eq!(
            hex::decode("89dc70d83971242bf08b2db3b3867b18")?,
            key.round_keys[7]
        );
        assert_eq!(
            hex::decode("4dfdddb5748cf99e8407d42d3781af35")?,
            key.round_keys[8]
        );
        assert_eq!(
            hex::decode("5a844b2f2e08b2b1aa0f669c9d8ec9a9")?,
            key.round_keys[9]
        );
        assert_eq!(
            hex::decode("755998715b512ac0f15e4c5c6cd085f5")?,
            key.round_keys[10]
        );

        Ok(())
    }

    #[test]
    fn mix_column_kats() {
        let kats = [
            [[0xdbu8, 0x13, 0x53, 0x45], [0x8e, 0x4d, 0xa1, 0xbc]],
            [[0xf2u8, 0x0a, 0x22, 0x5c], [0x9f, 0xdc, 0x58, 0x9d]],
            [[0x01u8, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x01]],
            [[0xc6u8, 0xc6, 0xc6, 0xc6], [0xc6, 0xc6, 0xc6, 0xc6]],
            [[0xd4u8, 0xd4, 0xd4, 0xd5], [0xd5, 0xd5, 0xd7, 0xd6]],
            [[0x2du8, 0x26, 0x31, 0x4c], [0x4d, 0x7e, 0xbd, 0xf8]],
        ];

        for pair in &kats {
            let input = pair[0];
            let expected = pair[1];
            let mut result = input;

            mix_column(&mut result);
            assert_eq!(expected, result);
            inv_mix_column(&mut result);
            assert_eq!(input, result);
        }
    }

    #[test]
    fn encrypt_kats() -> Result<()> {
        let key: AesKey = "00000000000000000000000000000000".parse()?;
        let kats = [
            [
                "f34481ec3cc627bacd5dc3fb08f273e6",
                "0336763e966d92595a567cc9ce537f5e",
            ],
            [
                "9798c4640bad75c7c3227db910174e72",
                "a9a1631bf4996954ebc093957b234589",
            ],
            [
                "96ab5c2ff612d9dfaae8c31f30c42168",
                "ff4f8391a6a40ca5b25d23bedd44a597",
            ],
            [
                "6a118a874519e64e9963798a503f1d35",
                "dc43be40be0e53712f7e2bf5ca707209",
            ],
            [
                "cb9fceec81286ca3e989bd979b0cb284",
                "92beedab1895a94faa69b632e5cc47ce",
            ],
            [
                "b26aeb1874e47ca8358ff22378f09144",
                "459264f4798f6a78bacb89c15ed3d601",
            ],
            [
                "58c8e00b2631686d54eab84b91f0aca1",
                "08a4e2efec8a8e3312ca7460b9040bbf",
            ],
        ];

        for pair in &kats {
            let input = hex::decode(pair[0])?;
            let expected = pair[1];

            let result = key.encrypt_block(&input);
            assert_eq!(expected, hex::encode(&result));
            let decrypted = key.decrypt_block(&result);
            assert_eq!(pair[0], hex::encode(decrypted));
        }

        let plaintext = hex::decode("00000000000000000000000000000000")?;
        let kats = [
            [
                "10a58869d74be5a374cf867cfb473859",
                "6d251e6944b051e04eaa6fb4dbf78465",
            ],
            [
                "caea65cdbb75e9169ecd22ebe6e54675",
                "6e29201190152df4ee058139def610bb",
            ],
            [
                "a2e2fa9baf7d20822ca9f0542f764a41",
                "c3b44b95d9d2f25670eee9a0de099fa3",
            ],
            [
                "b6364ac4e1de1e285eaf144a2415f7a0",
                "5d9b05578fc944b3cf1ccf0e746cd581",
            ],
            [
                "64cf9c7abc50b888af65f49d521944b2",
                "f7efc89d5dba578104016ce5ad659c05",
            ],
            [
                "47d6742eefcc0465dc96355e851b64d9",
                "0306194f666d183624aa230a8b264ae7",
            ],
            [
                "3eb39790678c56bee34bbcdeccf6cdb5",
                "858075d536d79ccee571f7d7204b1f67",
            ],
            [
                "64110a924f0743d500ccadae72c13427",
                "35870c6a57e9e92314bcb8087cde72ce",
            ],
            [
                "18d8126516f8a12ab1a36d9f04d68e51",
                "6c68e9be5ec41e22c825b7c7affb4363",
            ],
            [
                "f530357968578480b398a3c251cd1093",
                "f5df39990fc688f1b07224cc03e86cea",
            ],
            [
                "da84367f325d42d601b4326964802e8e",
                "bba071bcb470f8f6586e5d3add18bc66",
            ],
            [
                "e37b1c6aa2846f6fdb413f238b089f23",
                "43c9f7e62f5d288bb27aa40ef8fe1ea8",
            ],
            [
                "6c002b682483e0cabcc731c253be5674",
                "3580d19cff44f1014a7c966a69059de5",
            ],
            [
                "143ae8ed6555aba96110ab58893a8ae1",
                "806da864dd29d48deafbe764f8202aef",
            ],
            [
                "b69418a85332240dc82492353956ae0c",
                "a303d940ded8f0baff6f75414cac5243",
            ],
            [
                "71b5c08a1993e1362e4d0ce9b22b78d5",
                "c2dabd117f8a3ecabfbb11d12194d9d0",
            ],
            [
                "e234cdca2606b81f29408d5f6da21206",
                "fff60a4740086b3b9c56195b98d91a7b",
            ],
            [
                "13237c49074a3da078dc1d828bb78c6f",
                "8146a08e2357f0caa30ca8c94d1a0544",
            ],
            [
                "3071a2a48fe6cbd04f1a129098e308f8",
                "4b98e06d356deb07ebb824e5713f7be3",
            ],
            [
                "90f42ec0f68385f2ffc5dfc03a654dce",
                "7a20a53d460fc9ce0423a7a0764c6cf2",
            ],
            [
                "febd9a24d8b65c1c787d50a4ed3619a9",
                "f4a70d8af877f9b02b4c40df57d45b17",
            ],
        ];

        for pair in &kats {
            let key: AesKey = pair[0].parse()?;
            let expected = pair[1];

            let result = key.encrypt_block(&plaintext);
            assert_eq!(expected, hex::encode(&result));

            let decrypted = key.decrypt_block(&result);
            assert_eq!("00000000000000000000000000000000", hex::encode(decrypted));
        }
        Ok(())
    }

    #[test]
    fn shift_unshift() {
        let start = [0, 10, 20, 30, 1, 11, 21, 31, 2, 12, 22, 32, 3, 13, 23, 33];
        let mut result = start;
        shift_rows(&mut result);
        println!("Mix: {:?}", result);
        inv_shift_rows(&mut result);
        println!("Mix: {:?}", result);

        assert_eq!(start, result);
    }
}
