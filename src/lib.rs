#![allow(dead_code)]

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
    usize, vec,
};

mod aes;
mod digest;
mod oracles;
mod padding;
mod prng;

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
    let chunks = parallel_chunk(bin, key_length);
    let key = find_best_multi_xor_with_chunks(&chunks)?;
    let plaintext = xor(bin, &key);
    Ok((plaintext, key))
}

fn find_best_multi_xor_with_chunks(chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut key = vec![];
    for c in chunks {
        key.push(find_best_single_xor(&c)?.1);
    }
    Ok(key)
}

fn transpose(input: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let width = input.iter().map(|ct| ct.len()).max().unwrap();
    let mut result = vec![];
    for _ in 0..width {
        result.push(vec![]);
    }

    for entry in input {
        for (idx, b) in entry.iter().enumerate() {
            result[idx % width].push(*b);
        }
    }
    result
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
    let mut result = 0.0;
    for b in bin {
        if b > &127 {
            result += 100.0;
        }
        if b <= &8 || (b >= &11 && b <= &31) {
            result += 100.0;
        }
        if !b.is_ascii() {
            result += 100.0;
        }
        let mut b = b.to_ascii_lowercase();
        if !FREQ.contains_key(&b) {
            b = 0;
        }
        *counts.entry(b).or_insert(0.0) += &1.0;
    }

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

fn find_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b.iter())
        .enumerate()
        .find_map(|(idx, (ai, bi))| {
            if ai != bi {
                Option::Some(idx)
            } else {
                Option::None
            }
        })
}

fn decrypt_with_pkcs7_padding_oracle<F>(oracle: F, old_iv: &[u8], block: &[u8]) -> Vec<u8>
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    let mut iv = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut result = iv.clone();

    for pad_len in 1..=16 {
        for idx in 1..pad_len {
            iv[16 - idx] = result[16 - idx] ^ (pad_len as u8);
        }
        // println!("Result: {}\nIV: {}", hex::encode(&result), hex::encode(&iv));

        for guess in 0u8..=255 {
            iv[16 - pad_len] = guess ^ (pad_len as u8);
            if oracle(&iv, block) {
                // println!("Guessed: {}", guess);
                result[16 - pad_len] = guess;
                break;
            }
        }
    }
    xor(&result, old_iv)
    // println!("Result: {}\nIV: {}", hex::encode(&result), hex::encode(&iv));
    // // todo!();
    // result
}

#[cfg(test)]
mod tests {
    use oracles::Set2Oracle;

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
        use oracles::Set2Oracle;

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
            for _ in 0..100 {
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
        #[ignore]
        fn challenge_12() -> Result<()> {
            let oracle = oracles::Set2Oracle::new();
            // Determine block size
            let ct_len = oracle.encrypt12(&[])?.len();
            let mut block_size = 0;
            {
                let mut pt = vec![];
                for _len in 0..40 {
                    let new_len = oracle.encrypt12(&pt)?.len();
                    if new_len != ct_len {
                        block_size = new_len - ct_len;
                        break;
                    }
                    pt.push(0);
                }
            }
            let block_size = block_size;
            // Skipping ECB detection because I've done it so many times.

            // Start guessing and decrypting
            let mut a_block = vec![];
            a_block.extend(std::iter::repeat(b'A').take(block_size));
            let a_block = a_block;

            // We start with a dummy value just to make things easier and will remove it at the end.
            let mut decrypted = a_block.clone();

            let mut offset = 0;
            while offset < ct_len {
                for byte_to_guess in 1..=block_size {
                    // println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
                    let mut challenge =
                        Vec::from(&decrypted[decrypted.len() - block_size + 1..decrypted.len()]);

                    challenge.extend(&a_block[..(block_size - byte_to_guess + 1)]);
                    for guess in 0..=255 {
                        // println!("Guess: {} {} {}", offset, byte_to_guess, guess);
                        challenge[15] = guess;
                        // println!("Challenge: {}", hex::encode(&challenge));

                        let ct = oracle.encrypt12(&challenge)?;
                        let guess_block = &ct[0..block_size];
                        let target_block =
                            &ct[offset + block_size..offset + block_size + block_size];
                        // println!("\tBlocks: {} {}", hex::encode(guess_block), hex::encode(target_block));

                        if guess_block == target_block {
                            decrypted.push(guess);
                            // println!("Found! {}", guess);
                            break;
                        }
                    }
                }
                offset += block_size;
            }

            println!(
                "Challenge 12:\n{}",
                String::from_utf8_lossy(&decrypted[block_size..decrypted.len()])
            );
            Ok(())
        }

        #[test]
        fn challenge_13() -> Result<()> {
            let oracle = Set2Oracle::new();
            let role_block = oracle.profile_for_13(&"__________admin")?;

            let role_block = role_block.chunks_exact(16).nth(1).unwrap();

            let padding_block = oracle.profile_for_13(&"f")?;
            let padding_block = padding_block.chunks_exact(16).last().unwrap();

            let victim = oracle.profile_for_13(&"gr@sample.com")?;

            let mut attack = vec![];
            attack.extend_from_slice(&victim[0..32]);
            attack.extend_from_slice(role_block);
            attack.extend_from_slice(padding_block);

            assert_eq!("admin", oracle.get_role_13(&attack)?);
            assert!(oracle.is_admin_13(&attack));

            Ok(())
        }

        #[test]
        #[ignore]
        fn challenge_14() -> Result<()> {
            let oracle = oracles::Set2Oracle::new();
            // Determine block size
            let bare_ct = oracle.encrypt14(&[])?;
            let ct_len = bare_ct.len();
            let mut block_size = 0;
            {
                let mut pt = vec![];
                for _len in 0..40 {
                    let new_len = oracle.encrypt14(&pt)?.len();
                    if new_len != ct_len {
                        block_size = new_len - ct_len;
                        break;
                    }
                    pt.push(0);
                }
            }
            let block_size = block_size;
            // Skipping ECB detection because I've done it so many times.

            // Figure out prefix length.
            // We know that the first block has a random length prefix.
            // Pad until the second and third blocks are equal, then remove the last two blocks for our constant prefix.
            let mut constant_prefix = vec![];
            constant_prefix.extend(std::iter::repeat(b'A').take(block_size * 2));
            {
                let mut sample_ct = oracle.encrypt14(&constant_prefix)?;
                loop {
                    // println!("{} {}", hex::encode(sample_ct[16..32]), hex::encode(sample_ct[32..48]));
                    if sample_ct[block_size..block_size * 2]
                        == sample_ct[block_size * 2..block_size * 3]
                    {
                        break;
                    } else {
                        constant_prefix.push(b'A');
                        sample_ct = oracle.encrypt14(&constant_prefix)?;
                    }
                }
            }
            constant_prefix.resize(constant_prefix.len() - block_size * 2, 0);
            let constant_prefix = constant_prefix;

            // Start guessing and decrypting
            let mut a_block = vec![];
            a_block.extend(std::iter::repeat(b'A').take(block_size));
            let a_block = a_block;

            // We start with a dummy value just to make things easier and will remove it at the end.
            let mut decrypted = a_block.clone();

            let mut offset = block_size;
            while offset < ct_len {
                for byte_to_guess in 1..=block_size {
                    // println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
                    let mut challenge = constant_prefix.clone();
                    challenge.extend_from_slice(
                        &decrypted[decrypted.len() - block_size + 1..decrypted.len()],
                    );

                    challenge.extend(&a_block[..(block_size - byte_to_guess + 1)]);
                    for guess in 0..=255 {
                        // println!("Guess: {} {} {}", offset, byte_to_guess, guess);
                        challenge[constant_prefix.len() + block_size - 1] = guess;
                        // println!("Challenge: {}", hex::encode(&challenge));

                        let ct = oracle.encrypt14(&challenge)?;
                        let guess_block = &ct[block_size..block_size * 2];
                        let target_block =
                            &ct[offset + block_size..offset + block_size + block_size];
                        // println!("\tBlocks: {} {}", hex::encode(guess_block), hex::encode(target_block));

                        if guess_block == target_block {
                            decrypted.push(guess);
                            // println!("Found! {}", guess);
                            break;
                        }
                    }
                }
                offset += block_size;
            }

            println!(
                "Challenge 14:\n{}",
                String::from_utf8_lossy(&decrypted[block_size..decrypted.len()])
            );
            Ok(())
        }

        #[test]
        fn challenge_15() -> Result<()> {
            let padding = Padding::Pkcs7Padding(16);
            assert_eq!(
                &b"ICE ICE BABY"[..],
                padding
                    .unpad(&b"ICE ICE BABY\x04\x04\x04\x04"[..])?
                    .as_slice()
            );

            assert!(padding.unpad(&b"ICE ICE BABY\x05\x05\x05\x05"[..]).is_err());
            assert!(padding.unpad(&b"ICE ICE BABY\x01\x02\x03\x04"[..]).is_err());
            Ok(())
        }
    }

    #[test]
    fn challenge_16() -> Result<()> {
        let oracle = Set2Oracle::new();
        let target = b"A;admin=true;a=b";
        let mut ciphertext = oracle.encrypt_16("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
        for (b, m) in ciphertext[48..64].iter_mut().zip(target.iter()) {
            *b ^= m ^ b'A';
        }
        let parsed = oracle.get_fields_16(&ciphertext)?;
        assert_eq!("true", parsed.get("admin").unwrap());

        Ok(())
    }

    mod set3 {
        use std::time::{SystemTime, UNIX_EPOCH};

        use crate::{
            decrypt_with_pkcs7_padding_oracle, find_best_multi_xor_with_chunks,
            oracles::{Challenge17Oracle, Challenge19Oracle, Challenge22Oracle},
            padding::Padding,
            prng::MT19937,
            transpose,
        };
        use anyhow::Result;
        use rand::RngCore;
        use rand_core::OsRng;

        #[test]
        fn challenge_17() -> Result<()> {
            let oracle = Challenge17Oracle::new();

            let shim = |iv: &[u8], block: &[u8]| -> bool {
                let mut merged = Vec::from(iv);
                merged.extend_from_slice(block);
                oracle.is_valid(&merged)
            };

            let mut result: Vec<u8> = vec![];
            let mut last_chunk: Option<Vec<u8>> = Option::None;
            for chunk in oracle.ciphertext.chunks_exact(16) {
                if let Some(old_iv) = last_chunk {
                    let block = decrypt_with_pkcs7_padding_oracle(shim, &old_iv, chunk);

                    result.extend(block.iter());
                }
                last_chunk = Option::Some(chunk.to_owned());
            }
            println!("Challenge 17: {}", String::from_utf8_lossy(&result));
            let result = Padding::Pkcs7Padding(16).unpad(&result)?;
            oracle.assert_success(&String::from_utf8(result)?);
            Ok(())
        }

        #[test]
        fn challenge_19() -> Result<()> {
            let oracle = Challenge19Oracle::new();

            let merged = transpose(&oracle.ciphertexts);

            let key = find_best_multi_xor_with_chunks(&merged)?;
            for ct in oracle.ciphertexts {
                let pt = crate::xor(&ct, &key);
                println!("Challenge 19: {}", String::from_utf8_lossy(&pt));
            }
            Ok(())
        }

        #[test]
        fn challenge_20() -> Result<()> {
            let mut ciphertexts = vec![];
            for line in crate::read_file("20.txt")? {
                let line = line?;
                ciphertexts.push(base64::decode(&line)?);
            }
            let ciphertexts = ciphertexts;
            let transposed = transpose(&ciphertexts);
            let key = find_best_multi_xor_with_chunks(&transposed)?;

            for ct in ciphertexts {
                let pt = crate::xor(&ct, &key);
                println!("Challenge 20: {}", String::from_utf8_lossy(&pt));
            }

            Ok(())
        }

        #[test]
        #[ignore = "slow"]
        fn challenge_22() -> Result<()> {
            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            let oracle = Challenge22Oracle::new();
            let end_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            println!("Challenge 22. Starting guess");

            for seed in start_time..end_time {
                let mut rng = MT19937::new(seed);
                if rng.next_u32() == oracle.clue {
                    oracle.assert_success(seed);
                    println!("Challenge 22. Guessed seed: {}", seed);
                    return Ok(());
                }
            }
            panic!("No seed found");
        }

        #[test]
        fn challenge_23() -> Result<()> {
            let mut target = MT19937::new(OsRng.next_u32());

            let mut state = vec![];
            for _ in 0..624 {
                state.push(MT19937::untemper(target.next_u32()));
            }

            let mut cloned = MT19937::from_state(&state, 624)?;

            for _ in 0..10 {
                assert_eq!(target.next_u32(), cloned.next_u32());
            }

            Ok(())
        }

        // Yes, I know it's lazy, but I'm just skipping #24. I've done it before in other languages and don't think it adds enough to my rust practice
    }

    mod set4 {
        use anyhow::Result;

        use crate::{file_to_string, oracles};
        use oracles::{challenge31, Challenge25Oracle, Challenge26Oracle, Set2Oracle};

        #[test]
        fn challenge_25() -> Result<()> {
            // It turns out that I'm not doing this with the exact requested input, but the technique still works, and I'm tired so it doesn't matter.
            let plaintext = file_to_string("25.txt")?;
            let plaintext = base64::decode(&plaintext)?;
            let mut oracle = Challenge25Oracle::new(plaintext);

            // Let's do this the boring way
            let ciphertext = oracle.ciphertext.clone();
            let zero_plaintext = vec![0u8; ciphertext.len()];
            oracle.edit(0, &zero_plaintext);

            let guess = crate::xor(&ciphertext, &oracle.ciphertext);
            oracle.assert_success(&guess);

            Ok(())
        }

        #[test]
        fn challenge_26() -> Result<()> {
            let oracle = Challenge26Oracle::new();
            let target = b"A;admin=true;a=b";
            let mut ciphertext = oracle.encrypt_26("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
            for (b, m) in ciphertext[48..64].iter_mut().zip(target.iter()) {
                *b ^= m ^ b'A';
            }
            let parsed = oracle.get_fields_26(&ciphertext)?;
            assert_eq!("true", parsed.get("admin").unwrap());

            Ok(())
        }

        #[test]
        fn challenge_27() -> Result<()> {
            let oracle = Set2Oracle::new();
            let ciphertext =
                oracle.encrypt_27("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
            let mut tampered = vec![];
            tampered.extend_from_slice(&ciphertext[0..16]);
            tampered.resize(32, 0);
            tampered.extend_from_slice(&ciphertext[0..16]);
            // Finally, make sure we have proper padding
            tampered.extend_from_slice(&ciphertext[ciphertext.len() - 32..]);

            let plaintext = oracle.decrypt_27(&tampered);
            let plaintext = match plaintext {
                Err(vec) => vec,
                Ok(text) => text.as_bytes().to_owned(),
            };
            let key = crate::xor(&plaintext[0..16], &plaintext[32..48]);
            oracle.assert_27(&key);
            Ok(())
        }

        #[test]
        fn challenge_31() -> Result<()> {
            let mut oracle = challenge31();
            let address = oracle.get_server_addr();
            println!("Address: {:?}", address);
            let base_url = oracle.get_base_url();
            println!("Base address: {}", base_url);
            let client = reqwest::blocking::Client::new();
            let request = client
                .get(base_url)
                .query(&[("file", "bar"), ("signature", "0a0b0c0d0e")]);
            let result = request.send()?;
            println!("Result {:?}", result);
            println!("Result {:?}", result.text());
            oracle.stop();

            Ok(())
        }
    }
}
