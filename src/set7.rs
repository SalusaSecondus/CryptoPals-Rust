use std::{collections::HashMap, fmt::Display, sync::mpsc::channel};

use hex::ToHex;
use num_traits::ToPrimitive;

use crate::{
    aes::AesKey,
    digest::Digest,
    padding::Padding,
};
use anyhow::{ensure, Result};
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use workerpool::{
    thunk::{Thunk, ThunkWorker},
    Pool,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RD0 {
    initial: [u8; 2],
    state: [u8; 2],
    length: usize,
    buffer: Option<Vec<u8>>,
}

impl RD0 {
    fn compress(old_state: &[u8], block: &[u8]) -> Vec<u8> {
        let mut key = vec![];
        key.extend_from_slice(old_state);
        key.resize(16, 0);
        let aes = AesKey::new(&key).unwrap();
        let mut long_state = aes.encrypt_block(block);
        long_state.resize(Self::digest_size(), 0);
        long_state
        // vec![0u8; 2]
    }
}

impl Digest for RD0 {
    fn reset(&mut self) {
        self.state = self.initial;
        self.length = 0;
    }

    fn update(&mut self, input: &[u8]) {
        let mut merged = self.buffer.take().unwrap_or_default();
        merged.extend(input);
        for block in merged.chunks(Self::block_size()) {
            if block.len() != Self::block_size() {
                self.buffer = Some(block.to_owned());
            } else {
                let new_state = Self::compress(&self.state, block);
                self.state.copy_from_slice(&new_state);
            }
        }
        self.length += input.len();
    }

    fn digest(&mut self) -> Vec<u8> {
        let encoded_length = self.length.to_u64().unwrap().to_be_bytes();
        self.update(&encoded_length);
        let remaining = self.buffer.take().unwrap_or_default();
        let padded = Padding::Pkcs7Padding(Self::block_size())
            .pad(&remaining)
            .unwrap();
        let result = Self::compress(&self.state, &padded);
        self.reset();
        result
    }

    fn digest_size() -> usize {
        2
    }

    fn block_size() -> usize {
        16
    }

    fn oid() -> Option<&'static asn1::ObjectIdentifier<'static>> {
        None
    }
}

impl Display for RD0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.state.encode_hex::<String>())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RD1 {
    initial: [u8; 4],
    state: [u8; 4],
    length: usize,
    buffer: Option<Vec<u8>>,
}

impl RD1 {
    fn compress(old_state: &[u8], block: &[u8]) -> Vec<u8> {
        let mut key = vec![];
        key.extend_from_slice(old_state);
        key.resize(16, 0);
        let aes = AesKey::new(&key).unwrap();
        let mut long_state = aes.encrypt_block(block);
        long_state.resize(Self::digest_size(), 0);
        long_state
        // vec![0u8; 2]
    }
}

impl Digest for RD1 {
    fn reset(&mut self) {
        self.state = self.initial;
        self.length = 0;
    }

    fn update(&mut self, input: &[u8]) {
        let mut merged = self.buffer.take().unwrap_or_default();
        merged.extend(input);
        for block in merged.chunks(Self::block_size()) {
            if block.len() != Self::block_size() {
                self.buffer = Some(block.to_owned());
            } else {
                let new_state = Self::compress(&self.state, block);
                self.state.copy_from_slice(&new_state);
            }
        }
        self.length += input.len();
    }

    fn digest(&mut self) -> Vec<u8> {
        let encoded_length = self.length.to_u64().unwrap().to_be_bytes();
        self.update(&encoded_length);
        let remaining = self.buffer.take().unwrap_or_default();
        let padded = Padding::Pkcs7Padding(Self::block_size())
            .pad(&remaining)
            .unwrap();
        let result = Self::compress(&self.state, &padded);
        self.reset();
        result
    }

    fn digest_size() -> usize {
        4
    }

    fn block_size() -> usize {
        16
    }

    fn oid() -> Option<&'static asn1::ObjectIdentifier<'static>> {
        None
    }
}

impl Display for RD1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.state.encode_hex::<String>())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RD2 {
    rd0: RD0,
    rd1: RD1,
}

impl Digest for RD2 {
    fn reset(&mut self) {
        self.rd0.reset();
        self.rd1.reset();
    }

    fn update(&mut self, input: &[u8]) {
        self.rd0.update(input);
        self.rd1.update(input);
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut result = self.rd0.digest();
        result.extend(self.rd1.digest());
        result
    }

    fn digest_size() -> usize {
        RD0::digest_size() + RD1::digest_size()
    }

    fn block_size() -> usize {
        16
    }

    fn oid() -> Option<&'static asn1::ObjectIdentifier<'static>> {
        None
    }
}

fn find_collision<D>(
    block_size: usize,
    start: &[u8],
    compress: D,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, usize)>
where
    D: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let pool_size = 4;

    let pool: Pool<ThunkWorker<(Vec<u8>, Vec<u8>)>> = Pool::new(pool_size);
    let (tx, rx) = channel();
    let mut rnd = OsRng;
    let mut results: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut count = 0;
    loop {
        for _ in 0..(pool_size * 2) {
            let mut input = vec![0u8; block_size];
            rnd.fill_bytes(&mut input);
            let tmp = start.to_owned();
            pool.execute_to(
                tx.clone(),
                Thunk::of(move || (compress(&tmp, &input), input)),
            );
        }
        for r in rx.iter().take(pool_size * 2) {
            count += 1;
            let output = r.0;
            let input = r.1;
            // println!("Compress({}) = {}", input.encode_hex::<String>(), output.encode_hex::<String>());
            if let Some(collision) = results.get(&output) {
                return Ok((collision.to_owned(), input, output, count));
            } else {
                results.insert(output, input);
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ExpandCollision {
    short: Vec<u8>,
    long: Vec<u8>,
    h_in: Vec<u8>,
    h_out: Vec<u8>,
    compressions: usize,
}

fn find_collision_expand<C>(
    alpha: usize,
    h_in: &[u8],
    block_size: usize,
    compress: C,
) -> Result<ExpandCollision>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let q = vec![0u8; block_size];
    let mut long = vec![0u8; (alpha - 1) * RD1::block_size()];
    let mut h_tmp = h_in.to_owned();
    let mut compressions = 0;
    for _ in 0..(alpha - 1) {
        compressions += 1;
        h_tmp = compress(&h_tmp, &q);
    }

    let mut rng = OsRng;

    let mut a_short: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut b_long: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut block = vec![0u8; block_size];
    loop {
        rng.fill_bytes(&mut block);
        // println!("Trying block: {:?}", block);
        let a_i = compress(h_in, &block);
        compressions += 1;
        let b_i = compress(&h_tmp, &block);
        compressions += 1;

        // println!("a_i = {:?}", a_i);
        // println!("b_i = {:?}", b_i);

        if let Some(old_short) = a_short.get(&b_i) {
            long.extend(&block);
            return Ok(ExpandCollision {
                short: old_short.to_owned(),
                long,
                h_in: h_in.to_owned(),
                h_out: b_i,
                compressions,
            });
        }
        if let Some(old_long) = b_long.get(&a_i) {
            long.extend(old_long);
            return Ok(ExpandCollision {
                short: block,
                long,
                h_in: h_in.to_owned(),
                h_out: a_i,
                compressions,
            });
        }
        if a_i == b_i {
            long.extend(&block);
            return Ok(ExpandCollision {
                short: block,
                long,
                h_in: h_in.to_owned(),
                h_out: b_i,
                compressions,
            });
        }
        a_short.insert(a_i, block.clone());
        b_long.insert(b_i, block.clone());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExpandableMessage {
    h_out: Vec<u8>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    compressions: usize
}

fn make_expandable_message<C>(
    h_in: &[u8],
    k: usize,
    block_size: usize,
    compress: C,
) -> Result<ExpandableMessage>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut h_tmp = h_in.to_owned();
    let mut pairs = vec![(vec![], vec![]); k];

    let mut compressions = 0;
    for i in (0..=(k - 1)).rev() {
        let alpha = (1 << i) + 1;
        let step = find_collision_expand(alpha, &h_tmp, block_size, compress)?;
        pairs[k - i - 1].0 = step.short;
        pairs[k - i - 1].1 = step.long;
        h_tmp = step.h_out;
        compressions += step.compressions;
    }

    Ok(ExpandableMessage {
        h_out: h_tmp.to_owned(),
        pairs,
        compressions
    })
}

fn expand_message(expandable_message: &ExpandableMessage, l: usize) -> Result<Vec<u8>> {
    let k = expandable_message.pairs.len();
    ensure!(l >= k);
    ensure!(l <= (1 << k) + k - 1);

    let mut m = vec![];
    let mut t = l - k;

    for (i, pair) in expandable_message.pairs.iter().enumerate()  {
        let edge = 1 << (k - 1 - i);
        if t >= edge {
            m.extend(&pair.1);
            t -= edge;
        } else {
            m.extend(&pair.0);
        }
    }
    Ok(m)
}
fn find_2n_collisions<D>(
    n: usize,
    block_size: usize,
    start: &[u8],
    compress: D,
) -> Result<(Vec<Vec<Vec<u8>>>, usize)>
where
    D: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut pairs: Vec<Vec<Vec<u8>>> = vec![];
    let mut count = 0;

    let mut current_state = start.to_owned();
    for _ in 0..n {
        let collision = find_collision(block_size, &current_state, compress)?;
        count += collision.3;
        current_state.copy_from_slice(&collision.2);
        pairs.push(vec![collision.0, collision.1]);
    }
    Ok((pairs, count))
}

fn pairs_to_product(pairs: &[Vec<Vec<u8>>]) -> impl Iterator<Item = Vec<u8>> + '_ {
    pairs
        .iter()
        .map(|v| v.iter())
        .multi_cartesian_product()
        .map(|i| i.into_iter().cloned().concat())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        aes::AesKey,
        oracles::{Challenge49Oracle, Challenge51Oracle},
        padding::Padding,
        xor,
    };
    use anyhow::{Context, Result};
    use itertools::Itertools;

    use super::*;

    #[test]
    fn challenge49_1() -> Result<()> {
        let oracle: Challenge49Oracle = Default::default();

        let iv = [0u8; 16];
        println!("Creating");
        let tag1 = oracle.sign1(&iv, "7", "7", 1000000)?;
        println!("Verifying");
        assert!(oracle.verify1(&iv, &tag1, "7", "7", 1000000).is_ok());
        println!("Bad verif");
        assert!(oracle.verify1(&iv, &tag1, "5", "7", 1000000).is_err());

        let diff = b'7' ^ b'9';
        let mut iv2 = iv;
        iv2[5] = diff;
        println!("Hacked");
        assert!(oracle.verify1(&iv2, &tag1, "9", "7", 1000000).is_ok());
        Ok(())
    }

    #[test]
    fn challenge49_2() -> Result<()> {
        let oracle: Challenge49Oracle = Default::default();
        let pkcs7 = Padding::Pkcs7Padding(16);

        let txns1 = vec![("0", 1), ("15", 32), ("2", 45)];
        let good_mac = oracle.sign2("1", &txns1)?;
        println!("Good mac: {}", hex::encode(&good_mac));
        let good_signed = pkcs7.pad(Challenge49Oracle::sts2("1", &txns1).as_bytes())?;

        let txns2 = vec![("99", 1000000), ("99", 10), ("99", 1000000)];
        println!("{}", Challenge49Oracle::sts2("99", &txns2));
        let evil_mac = oracle.sign2("99", &txns2)?;
        let evil_base = pkcs7.pad(Challenge49Oracle::sts2("99", &txns2).as_bytes())?;

        let mut forged = good_signed.clone();
        let mut evil_chunks = evil_base.chunks_exact(16);
        let first_evil = evil_chunks.next().context("Too few chunks")?; // Drop first chunk
                                                                        // let glue_chunk = evil_chunks.next().context("Too few chunks")?;
                                                                        // let xored = glue_chunk.to_owned();
        let xored = xor(first_evil, &good_mac);
        forged.extend_from_slice(&xored);
        evil_chunks.for_each(|c| forged.extend_from_slice(c));
        println!("{}", hex::encode(&forged));
        let forged = pkcs7.unpad(&forged)?;
        assert!(oracle.verify_mac(&[0u8; 16], &forged, &evil_mac));
        Ok(())
    }

    #[test]
    fn challenge50() -> Result<()> {
        let iv = &[0u8; 16];
        let pkcs7 = Padding::Pkcs7Padding(16);
        let key = AesKey::new(b"YELLOW SUBMARINE")?;
        let good_js = "alert('MZA who was that?');\n";
        let good_hash = "296b8d7cb78a243dda4d0a61d33bbdd1";
        assert_eq!(good_hash, hex::encode(key.cbc_mac(iv, good_js.as_bytes())?));
        let padded_good_js = pkcs7.pad(good_js.as_bytes())?;
        println!("{}", hex::encode(&padded_good_js));
        let encrypted_good = key.encrypt_cbc(&[0u8; 16], &padded_good_js)?;
        println!("Encrypted good: {}", hex::encode(&encrypted_good));

        let decrypted_tag =
            key.decrypt_block(encrypted_good.chunks_exact(16).last().context("To few")?);
        let expected_end_pt = xor(
            encrypted_good
                .chunks_exact(16)
                .tail(2)
                .next()
                .context("too few")?,
            &decrypted_tag,
        );
        println!("{}", hex::encode(expected_end_pt));

        let target_pt = "alert('Ayo, the Wu is back!');\n <!--                            -->";
        let padded_target = pkcs7.pad(target_pt.as_bytes())?;
        println!("Padded target: {}", hex::encode(&padded_target));
        let final_target = padded_target.chunks_exact(16).last().unwrap();
        let encrypted_target = key.encrypt_cbc(iv, &padded_target)?;

        let mut replaced_end = vec![];
        replaced_end.extend_from_slice(&encrypted_target[..encrypted_target.len() - 16]);
        replaced_end.extend_from_slice(&hex::decode(good_hash)?);
        println!("encrypted_target: {}", hex::encode(&encrypted_target));
        println!("replaced_end:     {}", hex::encode(&replaced_end));
        let tmp_len = replaced_end.len();

        for idx in 0..16 {
            replaced_end[tmp_len - 32 + idx] = 0;
        }
        let decrypted_replaced_end = key.decrypt_cbc(iv, &replaced_end)?;
        println!("decrypted_target: {}", hex::encode(&decrypted_replaced_end));
        let final_diff = xor(
            final_target,
            decrypted_replaced_end.chunks_exact(16).last().unwrap(),
        );
        println!("final_diff: {}", hex::encode(&final_diff));
        for (idx, val) in final_diff.iter().enumerate() {
            replaced_end[tmp_len - 32 + idx] = *val;
        }
        println!("replaced_end:     {}", hex::encode(&replaced_end));
        let decrypted_replaced_end = key.decrypt_cbc(iv, &replaced_end)?;
        let decrypted_replaced_end = pkcs7.unpad(&decrypted_replaced_end)?;
        println!("decrypted_target: {}", hex::encode(&decrypted_replaced_end));

        assert_eq!(
            good_hash,
            hex::encode(key.cbc_mac(iv, &decrypted_replaced_end)?)
        );
        Ok(())
    }

    #[test]
    fn challenge51_1() -> Result<()> {
        let base64_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=";
        let oracle = Challenge51Oracle::new();
        let junk: &str = "#!?:@&[]^";
        println!("Length: {}", oracle.oracle1("sessionid=A")?);
        println!("Length: {}", oracle.oracle1("sessionid=T")?);

        let mut guess: Vec<char> = vec![];

        while guess.last().unwrap_or(&'A') != &'=' {
            let mut best_guess = '?';
            let mut best_guess_value: usize;
            for first_guess in base64_chars.chars() {
                for second_guess in base64_chars.chars() {
                    let full_guess = format!(
                        "Cookie: sessionid={}{}{}{}",
                        guess.iter().join(""),
                        junk,
                        first_guess,
                        second_guess
                    );
                    let len2 = oracle.oracle1(&full_guess)?;
                    let full_guess = format!(
                        "Cookie: sessionid={}{}{}{}",
                        guess.iter().join(""),
                        first_guess,
                        second_guess,
                        junk
                    );
                    let len1 = oracle.oracle1(&full_guess)?;
                    // println!("{}{}? {} <> {}", first_guess, second_guess, len1, len2);
                    if len1 < len2 {
                        best_guess = first_guess;
                        best_guess_value = len1;
                        println!(
                            "{} -> {}: (Best: {} = {})",
                            full_guess, len1, best_guess, best_guess_value
                        );
                    }
                }
            }
            guess.push(best_guess);
            println!("Guessing {}", best_guess);
            // todo!();
        }
        let final_guess = guess.iter().join("");
        println!("Final guess: {}", final_guess);
        oracle.check(&final_guess)
    }

    #[test]
    fn challenge51_2() -> Result<()> {
        let base64_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=";
        let oracle = Challenge51Oracle::new();
        let pad_src = "#!?{}:/@&[}*],^-$\"_';|,/.#-?]@[^*_!\\}{";
        let junk: &str = "#!?:@&[]^-$\"';|,.";

        // Find initial padding
        let mut initial_padding = "".to_string();
        let no_padded_guess_len =
            oracle.oracle2(&format!("{}Cookie: sessionid={}", &initial_padding, junk))?;
        println!("No padding length {}", no_padded_guess_len);
        for j in pad_src.chars() {
            initial_padding += &j.to_string();
            let padded_guess_len =
                oracle.oracle2(&format!("{}Cookie: sessionid={}", &initial_padding, junk))?;
            println!(
                "Trying padding {} with length {}",
                &initial_padding, padded_guess_len
            );
            if padded_guess_len > no_padded_guess_len {
                initial_padding.pop();
                initial_padding.pop();
                println!("Using padding {}", &initial_padding);
                break;
            }
        }

        let mut guess: Vec<char> = vec![];

        while guess.last().unwrap_or(&'A') != &'=' {
            let mut best_guess = '?';
            let mut best_guess_value: usize;
            for first_guess in base64_chars.chars() {
                for second_guess in base64_chars.chars() {
                    let full_guess = format!(
                        "{}Cookie: sessionid={}{}{}{}",
                        initial_padding,
                        guess.iter().join(""),
                        junk,
                        first_guess,
                        second_guess
                    );
                    let len2 = oracle.oracle2(&full_guess)?;
                    let full_guess = format!(
                        "{}Cookie: sessionid={}{}{}{}",
                        initial_padding,
                        guess.iter().join(""),
                        first_guess,
                        second_guess,
                        junk
                    );
                    let len1 = oracle.oracle2(&full_guess)?;
                    // println!("{}{}? {} <> {}", first_guess, second_guess, len1, len2);
                    if len1 < len2 {
                        best_guess = first_guess;
                        best_guess_value = len1;
                        println!(
                            "{} -> {}: (Best: {} = {})",
                            full_guess, len1, best_guess, best_guess_value
                        );
                    }
                }
            }
            if best_guess == '?' {
                initial_padding.pop();
                println!("New prefix: {}", initial_padding);
            } else {
                guess.push(best_guess);
                println!("Guessing {}", best_guess);
            }
            // todo!();
        }
        let final_guess = guess.iter().join("");
        println!("Final guess: {}", final_guess);
        oracle.check(&final_guess)
    }

    #[test]
    fn challenge52_smoke() -> Result<()> {
        let mut dgst = RD0::default();

        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());

        let collisions = find_collision(RD0::block_size(), &[0u8; 2], RD0::compress)?;

        dgst.update(&collisions.0);
        println!(
            "rd0({}) = {}",
            &collisions.0.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        dgst.update(&collisions.1);
        println!(
            "rd0({}) = {}",
            &collisions.1.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        println!("Took {} compressions!", collisions.3);
        Ok(())
    }

    #[test]
    fn challenge52_smoke2() -> Result<()> {
        let mut dgst = RD1::default();

        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());

        let collisions = find_collision(RD1::block_size(), &[0u8; 4], RD1::compress)?;

        dgst.update(&collisions.0);
        println!(
            "rd1({}) = {}",
            &collisions.0.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        dgst.update(&collisions.1);
        println!(
            "rd1({}) = {}",
            &collisions.1.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        println!("Took {} compressions!", collisions.3);
        Ok(())
    }

    #[test]
    fn challenge52_smoke3() -> Result<()> {
        let mut dgst = RD2::default();

        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());

        Ok(())
    }

    #[test]
    fn challenge52_1() -> Result<()> {
        let mut dgst = RD0::default();
        let collisions = find_2n_collisions(10, RD0::block_size(), &[0u8; 2], RD0::compress)?;
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for c in pairs_to_product(&collisions.0) {
            dgst.update(&c);
            println!(
                "rd0({}) = {}",
                &c.encode_hex::<String>(),
                dgst.digest().encode_hex::<String>()
            );
            assert!(seen.insert(c));
        }
        println!("Took {} compressions!", collisions.1);
        Ok(())
    }

    #[test]
    fn challenge52_2() -> Result<()> {
        let collisions = find_2n_collisions(20, RD0::block_size(), &[0u8; 2], RD0::compress)?;
        let mut seen: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        println!("Took {} compressions!", collisions.1);
        let mut compressions = collisions.1;

        let mut rd1 = RD1::default();
        for c in pairs_to_product(&collisions.0) {
            rd1.update(&c);
            let dgst = rd1.digest();
            compressions += 1;
            if let Some(other) = seen.get(&dgst) {
                let mut rd2 = RD2::default();
                rd2.update(other);
                let dgst1 = rd2.digest();
                rd2.update(&c);
                let dgst2 = rd2.digest();
                println!(
                    "rd2({}) -> {}",
                    other.encode_hex::<String>(),
                    dgst1.encode_hex::<String>()
                );
                println!(
                    "rd2({}) -> {}",
                    c.encode_hex::<String>(),
                    dgst2.encode_hex::<String>()
                );
                println!("Took {} compressions!", compressions);
                assert_ne!(other, &c);
                assert_eq!(dgst1, dgst2);
                break;
            } else {
                seen.insert(dgst, c);
            }
        }
        Ok(())
    }

    #[test]
    fn challenge53_smoke() -> Result<()> {
        let result = find_collision_expand(3, &[0u8; 16], 16, RD1::compress)?;
        let mut digest = RD1::default();
        digest.update(&result.short);
        println!("{:?}", digest);
        digest.reset();
        digest.update(&result.long);
        println!("{:?}", digest);
        println!("{:?}", result);

        let k = 10;
        let expandable_message = make_expandable_message(&[0u8; 16], k, 16, RD1::compress)?;
        // println!("{:?}", expandable_message);
        digest.reset();
        for c in expandable_message.pairs.iter() {
            digest.update(&c.0);
        }
        println!("{:?}", digest);
        digest.reset();
        for c in expandable_message.pairs.iter() {
            digest.update(&c.1);
        }
        println!("{:?}", digest);


        let limit = (1<<k) + k - 1;
        println!("Actually expanding");
        let mut expected = None;
        for len in k..=limit {
            let m = expand_message(&expandable_message, len)?;
            // println!("m = {}", m.encode_hex::<String>());
            assert_eq!(len * RD1::block_size(), m.len());
            digest.reset();
            digest.update(&m);
            // println!("{:?}", digest);
            if let Some(expected) = expected {
                assert_eq!(expected, digest.state);
            } else {
                expected = Some(digest.state);
            }
        }
        Ok(())
    }
}
