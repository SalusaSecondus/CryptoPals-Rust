#![allow(dead_code)]

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
    vec,
};

mod aes;
mod padding;
mod oracles;

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter().cycle()).map(|(a, b)| a ^ b).collect()
}

const FILE_BASE: &str = r"res\";

pub fn read_file(file_name: &str) -> Result<Lines<BufReader<File>>> {
    let input = File::open(FILE_BASE.to_owned() + file_name).context("Could not open file")?;
    let reader = BufReader::new(input);

    Ok(reader.lines())
}

pub fn file_to_string(file_name: &str) -> Result<String> {
    let mut input = String::new();
    for l in read_file(file_name)? {
        input += &l?;
    }
    Ok(input)
}

fn find_best_single_xor(bin: &[u8]) -> Result<(Vec<u8>, u8, f64)> {
    let mut best_byte = 0;
    let mut best_score = f64::MAX;
    let mut best_guess = Option::None;

    for twiddle in 0..=255u8 {
        let guess = crate::xor(&bin, &[twiddle]);
        let score = crate::monogram_score(&guess);
        if score < best_score {
            best_score = score;
            best_byte = twiddle;
            best_guess = Option::Some(guess);
        }
    }

    Ok((best_guess.context("Nothing found")?, best_byte, best_score))
}

fn find_best_multi_xor(bin: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut best_weight = f64::MAX;
    let mut key_length: usize = 0;

    for possible_length in 1..=40 {
        let offset = &bin[possible_length..];
        let (_, weight) = hamming_weight(bin, &offset);
        if weight < best_weight {
            best_weight = weight;
            key_length = possible_length;
        }
    }
    let key_length = key_length;
    let chunks = parallel_chunk(bin, key_length);

    let mut key = vec![];
    for c in chunks {
        key.push(find_best_single_xor(&c)?.1);
    }

    let plaintext = xor(bin, &key);

    Ok((plaintext, key))
}

fn parallel_chunk(input: &[u8], width: usize) -> Vec<Vec<u8>> {
    let mut result = vec![];
    for _ in 0..width {
        result.push(vec![]);
    }

    for (idx, b) in input.iter().enumerate() {
        result[idx % width].push(*b);
    }
    result
}

fn hamming_weight(a: &[u8], b: &[u8]) -> (u32, f64) {
    lazy_static! {
        static ref WEIGHTS: [u8; 256] = {
            let mut weights = [0u8; 256];
            #[allow(clippy::clippy::needless_range_loop)]
            for i in 0..256 {
                let mut tmp = 0;
                if i & 1 != 0 {
                    tmp += 1;
                }
                if i & 2 != 0 {
                    tmp += 1;
                }
                if i & 4 != 0 {
                    tmp += 1;
                }
                if i & 8 != 0 {
                    tmp += 1;
                }
                if i & 16 != 0 {
                    tmp += 1;
                }
                if i & 32 != 0 {
                    tmp += 1;
                }
                if i & 64 != 0 {
                    tmp += 1;
                }
                if i & 128 != 0 {
                    tmp += 1;
                }
                weights[i] = tmp;
            }
            weights
        };
    };
    let sum: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| WEIGHTS[(a ^ b) as usize] as u32)
        .sum();
    let normalized = sum as f64;
    (sum, normalized / (std::cmp::min(a.len(), b.len()) as f64))
}

pub fn monogram_score(bin: &[u8]) -> f64 {
    lazy_static! {
        static ref FREQ: HashMap<u8, f64> = {
            let mut m: HashMap<u8, f64> = HashMap::new();
            m.insert(b' ', 0.1217);
            m.insert(b'a', 0.0609);
            m.insert(b'b', 0.0105);
            m.insert(b'c', 0.0284);
            m.insert(b'd', 0.0292);
            m.insert(b'e', 0.1136);
            m.insert(b'f', 0.0179);
            m.insert(b'g', 0.0138);
            m.insert(b'h', 0.0341);
            m.insert(b'i', 0.0544);
            m.insert(b'j', 0.0024);
            m.insert(b'k', 0.0041);
            m.insert(b'l', 0.0292);
            m.insert(b'm', 0.0276);
            m.insert(b'n', 0.0544);
            m.insert(b'o', 0.0600);
            m.insert(b'p', 0.0195);
            m.insert(b'q', 0.0024);
            m.insert(b'r', 0.0495);
            m.insert(b's', 0.0568);
            m.insert(b't', 0.0803);
            m.insert(b'u', 0.0243);
            m.insert(b'v', 0.0097);
            m.insert(b'w', 0.0138);
            m.insert(b'x', 0.0024);
            m.insert(b'y', 0.0130);
            m.insert(b'z', 0.0003);
            m
        };
    };
    let mut counts: HashMap<u8, f64> = HashMap::new();
    let total = bin.len() as f64;
    for b in bin {
        if b > &127 {
            return 100.0;
        }
        if b <= &8 || (b >= &11 && b <= &31) {
            return 100.0;
        }
        if !b.is_ascii() {
            return 100.0;
        }
        let mut b = b.to_ascii_lowercase();
        if !FREQ.contains_key(&b) {
            b = 0;
        }
        *counts.entry(b).or_insert(0.0) += &1.0;
    }

    let mut result = 0.0;
    for k in FREQ.keys() {
        let found = counts.get(&k).unwrap_or(&0.0) / total;
        let expected = FREQ.get(&k).unwrap();
        let diff = found - expected;
        let sq_diff = diff * diff;
        result += sq_diff;
    }

    // Other characters
    {
        let found = counts.get(&0).unwrap_or(&0.0) / total;
        let expected = 0.0657;
        let diff = found - expected;
        let sq_diff = diff * diff;
        result += sq_diff;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming() {
        let val1 = b"this is a test";
        let val2 = b"wokka wokka!!!";
        let (weight, _) = hamming_weight(val1, val2);
        assert_eq!(37, weight);
    }

    mod set1 {
        use std::collections::HashSet;

        use crate::*;
        use aes::AesKey;
        use anyhow::{bail, Result};
        use hex::decode as hex_decode;
        use hex::encode as hex_encode;
    
        #[test]
        fn challenge_1() -> Result<()> {
            let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            assert_eq!(
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
                base64::encode(&hex::decode(hex)?)
            );
    
            Ok(())
        }
    
        #[test]
        fn challenge_2() -> Result<()> {
            let val1 = hex_decode("1c0111001f010100061a024b53535009181c")?;
            let val2 = hex_decode("686974207468652062756c6c277320657965")?;
    
            let result = crate::xor(&val1, &val2);
            assert_eq!("746865206b696420646f6e277420706c6179", hex_encode(result));
    
            Ok(())
        }
    
        #[test]
        fn challenge_3() -> Result<()> {
            let input =
                hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
            let (best_guess, _, _) = find_best_single_xor(&input)?;
    
            println!("1.3: Hex: {}", hex_encode(&best_guess));
            println!("1.3: Answer: {}", String::from_utf8_lossy(&best_guess));
            assert_eq!(
                "436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e",
                hex_encode(&best_guess)
            );
            Ok(())
        }
    
        #[test]
        fn challenge_4() -> Result<()> {
            let mut best_score = f64::MAX;
            let mut best_guess = Option::None;
    
            for line in crate::read_file("1_4.txt")? {
                let line = hex_decode(line?)?;
                let (guess, _, score) = find_best_single_xor(&line)?;
                if score < best_score {
                    best_score = score;
                    best_guess = Option::Some(guess);
                }
            }
    
            let best_guess = best_guess.unwrap();
            println!("1.4: Hex: {}", hex_encode(&best_guess));
            println!("1.4: Answer: {}", String::from_utf8_lossy(&best_guess));
            assert_eq!(
                "4e6f77207468617420746865207061727479206973206a756d70696e670a",
                hex_encode(&best_guess)
            );
    
            Ok(())
        }
    
        #[test]
        fn challenge_5() -> Result<()> {
            let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            let plaintext =
                b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            // let plaintext = text.as_bytes();
            let key = b"ICE";
            let ciphertext = crate::xor(plaintext, key);
    
            println!("Challenge 1.5: {}", hex_encode(&ciphertext));
            assert_eq!(expected_hex, hex_encode(&ciphertext));
    
            Ok(())
        }
    
        #[test]
        #[ignore = "large_output"]
        fn challenge_6() -> Result<()> {
            let input = file_to_string("6.txt")?;
            let input = base64::decode(&input)?;
            let pieces = find_best_multi_xor(&input)?;
            println!(
                "Challenge 6: {}\n\n{}",
                hex_encode(&pieces.1),
                String::from_utf8_lossy(&pieces.0)
            );
            Ok(())
        }
    
        #[test]
        fn challenge_7() -> Result<()> {
            let key: AesKey = AesKey::new(b"YELLOW SUBMARINE")?;
            let input = file_to_string("7.txt")?;
            let input = base64::decode(&input)?;
    
            let plaintext: Vec<u8> = input
                .chunks_exact(16)
                .flat_map(|block| key.decrypt_block(block))
                .collect();
            let plaintext = String::from_utf8(plaintext)?;
            println!("Challenge 7: {}", plaintext);
            Ok(())
        }
    
        #[test]
        fn challenge_8() -> Result<()> {
            let mut ciphertexts = vec![];
            for l in crate::read_file("8.txt")? {
                ciphertexts.push(hex_decode(l?)?);
            }
    
            for (idx, c) in ciphertexts.iter().enumerate() {
                let mut seen = HashSet::new();
                for chunk in c.chunks_exact(16) {
                    if !seen.insert(chunk) {
                        println!(
                            "Ciphertext {} has duplicate block {}",
                            idx,
                            hex_encode(chunk)
                        );
                        return Ok(());
                    }
                }
            }
            bail!("No duplicates found");
        }
    }

    mod set2 {
        use std::collections::HashSet;

        use crate::{aes::AesKey, oracles, padding::Padding};
        use anyhow::Result;

        #[test]
        #[ignore]
        fn challenge_10() -> Result<()> {
            let key = AesKey::new(b"YELLOW SUBMARINE")?;
            let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

            let ciphertext = base64::decode(&crate::file_to_string("10.txt")?)?;

            let plaintext = Padding::Pkcs7Padding(16).unpad(&key.decrypt_cbc(&iv, &ciphertext)?)?;

            let plaintext = String::from_utf8(plaintext)?;

            println!("Challenge 10: {}", plaintext);

            Ok(())
        }

        #[test]
        fn challenge_11() -> Result<()> {
            let plaintext = [0u8; 128];
            for _ in 0 .. 100 {
                let (ciphertext, cbc) = oracles::Challenge11Oracle::encrypt(&plaintext)?;

                let mut seen = HashSet::new();
                let mut guess = true;
                for chunk in ciphertext.chunks_exact(16) {
                    if !seen.insert(chunk) {
                        guess = false;
                        break;
                    }
                }

                assert_eq!(cbc, guess);
            }
            Ok(())
        }

        #[test]
        fn challenge_12() -> Result<()> {
            let oracle = oracles::Challenge12Oracle::new();
            // Determine block size
            let mut block_size = 0;
            {
                let mut prev_size = Option::None;
                let mut pt = vec![];
                for _len in 0 .. 40 {
                    let ct_len = oracle.encrypt(&pt)?.len();
                    if let Some(prev) = prev_size {
                        if prev != ct_len {
                            block_size = ct_len - prev;
                            break;
                        }
                    } else {
                        prev_size = Option::Some(ct_len);
                    }
                    
                    pt.push(0);
                }
            }
            let block_size = block_size;
            // Skipping ECB detection because I've done it so many times.
            println!("12: {}", block_size);
            Ok(())
        }
    }
}
