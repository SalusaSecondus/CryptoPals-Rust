#![allow(dead_code)]

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
    vec,
};

mod set1;

fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    Ok(a.iter().zip(b.iter().cycle()).map(|(a, b)| a ^ b).collect())
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
        let guess = crate::xor(&bin, &[twiddle])?;
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

    let plaintext = xor(bin, &key)?;

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
}
