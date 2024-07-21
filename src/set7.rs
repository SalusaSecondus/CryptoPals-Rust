use std::{collections::HashMap, fmt::Display, sync::mpsc::channel, vec};

use hex::ToHex;
use lazy_static::lazy_static;
use num_traits::ToPrimitive;

use crate::{
    aes::AesKey,
    digest::{to_w32_be, Digest, DigestOneShot, MD4},
    padding::Padding,
    BitArray,
};
use anyhow::{ensure, Context, Result};
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
    compressions: usize,
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
        compressions,
    })
}

fn expand_message(expandable_message: &ExpandableMessage, l: usize) -> Result<Vec<u8>> {
    let k = expandable_message.pairs.len();
    ensure!(l >= k);
    ensure!(l <= (1 << k) + k - 1);

    let mut m = vec![];
    let mut t = l - k;

    for (i, pair) in expandable_message.pairs.iter().enumerate() {
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

fn second_preimage<C>(
    m: &[u8],
    h_in: &[u8],
    block_size: usize,
    compress: C,
) -> Result<(Vec<u8>, usize)>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    ensure!(m.len() % block_size == 0);
    let mut compression_count = 0;
    // Step 1: Figure out minimum k such that len(m) / block_size \in [k, k + 2^k - 1]
    let m_block_count = m.len() / block_size;
    let mut k = 1;
    while m_block_count > k + (1 << k) - 1 {
        println!("K? = {}", k);
        k += 1;
    }
    let k = k;
    println!("Step 1: k = {}", k);

    // Step 2: Create expandable message
    let expandable_message = make_expandable_message(h_in, k, block_size, compress)?;
    compression_count += expandable_message.compressions;
    println!(
        "Step 2: Expandable message out = {}",
        expandable_message.h_out.encode_hex::<String>()
    );

    // Step 3: Intermediate hash states
    let mut intermediate_hash_states: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut intermediate_state = h_in.to_vec();
    for (i, block) in m.chunks_exact(block_size).enumerate() {
        intermediate_state = compress(&intermediate_state, block);
        compression_count += 1;
        if i > k {
            intermediate_hash_states.insert(intermediate_state.clone(), i + 1);
        }
    }
    println!(
        "Step 3: intermediate hash states {}",
        intermediate_hash_states.len()
    );

    // Step 4: Find bridge block
    let mut bridge = vec![0u8; block_size];
    let mut rng = OsRng;
    compression_count += 1;
    while !intermediate_hash_states.contains_key(&compress(&expandable_message.h_out, &bridge)) {
        compression_count += 1;
        rng.fill_bytes(&mut bridge);
    }
    compression_count += 1;
    let i = *intermediate_hash_states
        .get(&compress(&expandable_message.h_out, &bridge))
        .unwrap();
    println!("Step 4: Bridge block {}", bridge.encode_hex::<String>());

    // Step 5: Build expanded message of length 1
    let mut result = expand_message(&expandable_message, i - 1)?;

    // (Check we're good but don't count these compressions against our total
    {
        let mut h_check = h_in.to_vec();
        for block in result.chunks_exact(block_size) {
            h_check = compress(&h_check, block);
        }
        ensure!(
            h_check == expandable_message.h_out,
            "Intermediate state check failed"
        );
        ensure!(result.len() == (i - 1) * block_size);
    }

    // Add bridge block
    result.extend_from_slice(&bridge);

    // Add the rest!
    result.extend_from_slice(&m[(block_size * i)..]);

    ensure!(result.len() == m.len());

    Ok((result, compression_count))
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct NostradamusElement {
    h_in: Vec<u8>,
    bridge: Vec<u8>,
}
fn build_nostradamus_tail_parts<C>(
    k: usize,
    block_size: usize,
    compress_size: usize,
    compress: C,
) -> Result<(Vec<NostradamusElement>, usize)>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut result = vec![];
    let targets = 1 << k;
    result.resize(
        1 << (k + 1),
        NostradamusElement {
            h_in: vec![0u8; compress_size],
            bridge: vec![0u8; block_size],
        },
    );
    let mut compressions = 0;

    // Step 1: Generate random initial states
    let mut rng = OsRng;
    for (idx, element) in result.iter_mut().enumerate().skip(targets) {
        println!("Filling {}", idx);
        rng.fill_bytes(&mut element.h_in);
    }

    // Step 2: Collide them down
    for idx in (3..result.len()).rev().step_by(2) {
        let dest_idx = (idx - 1) / 2;

        println!("Mapping ({}, {}) -> {}", idx, idx - 1, dest_idx);
        let mut a_outs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut b_outs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut block = vec![0u8; block_size];
        let a_in = &result[idx].h_in;
        let b_in = &result[idx - 1].h_in;

        loop {
            rng.fill_bytes(&mut block);
            // println!("Trying block: {:?}", block);
            let a_i = compress(a_in, &block);
            compressions += 1;
            let b_i = compress(b_in, &block);
            compressions += 1;

            // println!("a_i = {:?}", a_i);
            // println!("b_i = {:?}", b_i);

            if let Some(old_a) = a_outs.get(&b_i) {
                result[idx].bridge.copy_from_slice(old_a);
                result[idx - 1].bridge.copy_from_slice(&block);
                result[dest_idx].h_in.copy_from_slice(&b_i);
                break;
            } else if let Some(old_b) = b_outs.get(&a_i) {
                result[idx - 1].bridge.copy_from_slice(old_b);
                result[idx].bridge.copy_from_slice(&block);
                result[dest_idx].h_in.copy_from_slice(&a_i);
                break;
            } else if a_i == b_i {
                result[idx].bridge.copy_from_slice(&block);
                result[idx - 1].bridge.copy_from_slice(&block);
                result[dest_idx].h_in.copy_from_slice(&a_i);
                break;
            }
            a_outs.insert(a_i, block.clone());
            b_outs.insert(b_i, block.clone());
        }
    }
    Ok((result, compressions))
}

fn build_nostradamus_result<C>(
    parts: &[NostradamusElement],
    msg: &[u8],
    h_initial: &[u8],
    compress: C,
) -> Result<(Vec<u8>, usize)>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut compressions = 0;
    let mut result = vec![];
    let target_cnt = parts.len() / 2;
    let block_size = parts[0].bridge.len();

    // Step 0: Build table of known ends
    let mut targets: HashMap<Vec<u8>, usize> = HashMap::new();
    for (idx, h_end) in parts.iter().enumerate().skip(target_cnt) {
        targets.insert(h_end.h_in.clone(), idx);
    }
    let targets = targets;

    // Step 0.5: Hash message so far
    let mut h_in = h_initial.to_vec();
    for block in msg.chunks_exact(block_size) {
        result.extend(block);
        h_in = compress(&h_in, block);
        compressions += 1;
    }

    // Step 1: Find bridge
    let mut bridge = vec![0u8; block_size];
    let mut rng = OsRng;
    let target_idx;
    loop {
        rng.fill_bytes(&mut bridge);
        let h_out = compress(&h_in, &bridge);
        compressions += 1;

        if let Some(tmp) = targets.get(&h_out) {
            target_idx = *tmp;
            break;
        }
    }
    result.extend(bridge);
    result.extend(build_nostradamus_tail(parts, target_idx));

    Ok((result, compressions))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NostradamusCommitment<C>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    tail_parts: Vec<NostradamusElement>,
    pre_hash: Vec<u8>,
    total_length: usize,
    compressions: usize,
    compression: C,
}

fn build_nostradamus_commitment<C>(
    base_message_length: usize,
    tail_length: usize,
    compression: C,
    block_size: usize,
    state_size: usize,
) -> Result<NostradamusCommitment<C>>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let tail = build_nostradamus_tail_parts(tail_length, block_size, state_size, compression)?;

    let pre_hash = tail.0[1].h_in.clone();
    Ok(NostradamusCommitment {
        tail_parts: tail.0,
        pre_hash,
        total_length: base_message_length + tail_length + 1,
        compressions: tail.1,
        compression,
    })
}

fn build_nostradamus_tail(parts: &[NostradamusElement], start: usize) -> Vec<u8> {
    let mut result = vec![];
    let mut idx = start;
    while idx > 1 {
        result.extend(&parts[idx].bridge);
        idx /= 2;
    }
    result
}

fn massage_md4_block(block: &mut [u8]) {
    assert_eq!(block.len(), MD4::block_size());

    let md4 = MD4::default();
    let a0 = md4.h[0];
    let b0 = md4.h[1];
    let c0 = md4.h[2];
    let d0 = md4.h[3];
    let mut X: Vec<u32> = to_w32_be(block).iter().map(|w| u32::from_be(*w)).collect();
    // First condition
    {
        let mut a1 = MD4::ff(a0, b0, c0, d0, 0, 3, &X);
        // Fix the bad bit
        a1 ^= (a1.bit(6) ^ b0.bit(6)) << 6;
        X[0] = a1
            .rotate_right(3)
            .wrapping_sub(a0)
            .wrapping_sub(MD4::f(b0, c0, d0));
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum MD4Constraint {
    Equal(usize),
    One(usize),
    Zero(usize),
    Neg(usize),
    EqOffset(usize, usize),
}

impl MD4Constraint {
    fn apply(&self, new_word: u32, state: [u32; 4], word_idxs: [usize; 4]) -> u32 {
        let old_word_idx = match self {
            MD4Constraint::Equal(_) => word_idxs[1],
            MD4Constraint::EqOffset(_, old_idx) => word_idxs[*old_idx],
            _ => 0,
        };
        let old_word = state[old_word_idx];

        if self == &MD4Constraint::Equal(19) {
            println!(
                "Foo: new_word = {}[{}] = {}, old_word = {}[{}] = {}",
                new_word.to_le_hex(),
                self.i(),
                new_word.bit(self.i()),
                old_word.to_le_hex(),
                self.i(),
                old_word.bit(self.i())
            );
        }
        match self {
            MD4Constraint::Equal(idx) | MD4Constraint::EqOffset(idx, _) => {
                new_word.set_bit(*idx, old_word.bit(*idx))
            }
            MD4Constraint::Neg(idx) => new_word.set_bit(*idx, 1 - old_word.bit(*idx)),
            MD4Constraint::One(idx) => new_word.set_bit(*idx, 1),
            MD4Constraint::Zero(idx) => new_word.set_bit(*idx, 0),
            // MD4Constraint::EqOffset(index, ) => new_word.set_bit(*idx, val)
        }
    }

    fn require(&self, new_word: u32, state: [u32; 4], word_idxs: [usize; 4]) -> Result<()> {
        ensure!(
            new_word == self.apply(new_word, state, word_idxs),
            "{:#04x} != {:#04x}, idxs = {:?}, {:#04x}[{}] = {}",
            new_word.to_be(),
            self.apply(new_word, state, word_idxs).to_be(),
            word_idxs,
            state[word_idxs[1]].to_be(),
            self.i(),
            state[word_idxs[1]].bit(self.i())
        );
        Ok(())
    }

    fn i(&self) -> usize {
        match self {
            MD4Constraint::Equal(i)
            | MD4Constraint::One(i)
            | MD4Constraint::Zero(i)
            | MD4Constraint::Neg(i)
            | MD4Constraint::EqOffset(i, _) => *i,
        }
    }
}

impl Display for MD4Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

lazy_static! {
    static ref MD4CollisionConstraints: Vec<Vec<MD4Constraint>> =
        vec![
            // a1
            vec![MD4Constraint::Equal(6)],
            // d1
            vec![MD4Constraint::Zero(6), MD4Constraint::Equal(7), MD4Constraint::Equal(10)],
            // c1
            vec![MD4Constraint::One(6), MD4Constraint::One(7), MD4Constraint::Zero(10), MD4Constraint::Equal(25)],
            // b1
            vec![MD4Constraint::One(6), MD4Constraint::Zero(7), MD4Constraint::Zero(10), MD4Constraint::Zero(25)],
            // a2
            vec![MD4Constraint::One(7), MD4Constraint::One(10), MD4Constraint::Zero(25), MD4Constraint::Equal(13),
                MD4Constraint::Equal(16), MD4Constraint::Equal(17), MD4Constraint::Equal(19), MD4Constraint::Equal(22)
            ],
            // d2
            vec![MD4Constraint::Zero(13), MD4Constraint::Equal(18), MD4Constraint::Equal(19), MD4Constraint::Equal(20), MD4Constraint::Equal(21), MD4Constraint::One(25),
                MD4Constraint::Zero(16), MD4Constraint::Zero(17), MD4Constraint::Zero(19), MD4Constraint::Zero(22)
            ],
            // c2
            vec![MD4Constraint::Equal(12), MD4Constraint::Zero(13), MD4Constraint::Equal(14), MD4Constraint::Zero(18), MD4Constraint::Zero(19), MD4Constraint::One(20), MD4Constraint::Zero(21),
                MD4Constraint::Zero(16), MD4Constraint::Zero(17), MD4Constraint::Zero(19), MD4Constraint::Zero(22)
            ],
            // b2
            vec![MD4Constraint::One(12), MD4Constraint::One(13), MD4Constraint::Zero(14), MD4Constraint::Equal(16), MD4Constraint::Zero(18), MD4Constraint::Zero(19), MD4Constraint::Zero(20), MD4Constraint::Zero(21),
                MD4Constraint::Zero(16), MD4Constraint::Zero(17), MD4Constraint::Zero(19), MD4Constraint::Zero(22)
            ],
            // a3
            vec![MD4Constraint::One(12), MD4Constraint::One(13), MD4Constraint::One(14), MD4Constraint::Zero(16), MD4Constraint::Zero(18), MD4Constraint::Zero(19), MD4Constraint::Zero(20), MD4Constraint::Equal(22), MD4Constraint::One(21), MD4Constraint::Equal(25)],
            // d3
            vec![MD4Constraint::One(12), MD4Constraint::One(13), MD4Constraint::One(14), MD4Constraint::Zero(16), MD4Constraint::Zero(19), MD4Constraint::One(20), MD4Constraint::One(21), MD4Constraint::Zero(22), MD4Constraint::One(25), MD4Constraint::Equal(29)],
            // c3
            vec![MD4Constraint::One(16), MD4Constraint::Zero(19), MD4Constraint::Zero(20), MD4Constraint::Zero(21), MD4Constraint::Zero(22), MD4Constraint::Zero(25), MD4Constraint::One(29), MD4Constraint::Equal(31)],
            // b3
            vec![MD4Constraint::Zero(19), MD4Constraint::One(20), MD4Constraint::One(21), MD4Constraint::Equal(22), MD4Constraint::One(25), MD4Constraint::Zero(29), MD4Constraint::Zero(31)],
            // a4
            vec![MD4Constraint::Zero(22), MD4Constraint::Zero(25), MD4Constraint::Equal(26), MD4Constraint::Equal(28), MD4Constraint::One(29), MD4Constraint::Zero(31)],
            // d4
            vec![MD4Constraint::Zero(22), MD4Constraint::Zero(25), MD4Constraint::One(26), MD4Constraint::One(28), MD4Constraint::Zero(29), MD4Constraint::One(31)],
            // c4
            vec![MD4Constraint::Equal(18), MD4Constraint::One(22), MD4Constraint::One(25), MD4Constraint::Zero(26), MD4Constraint::Zero(28), MD4Constraint::Zero(29)],
            // b4
            vec![MD4Constraint::Zero(18), MD4Constraint::Equal(25), MD4Constraint::One(26), MD4Constraint::One(28), MD4Constraint::Zero(29), MD4Constraint::Equal(31)],
            // // a5
            vec![MD4Constraint::EqOffset(18, 2), MD4Constraint::One(25), MD4Constraint::Zero(26), MD4Constraint::One(28), MD4Constraint::One(31)],
            // // d5
            vec![MD4Constraint::Equal(18), MD4Constraint::EqOffset(25, 2), MD4Constraint::EqOffset(26, 2), MD4Constraint::EqOffset(28, 2), MD4Constraint::EqOffset(31, 2)],
            // // c5
            vec![MD4Constraint::Equal(25), MD4Constraint::Equal(26), MD4Constraint::Equal(28), MD4Constraint::Equal(29), MD4Constraint::Equal(31)],
            // // b5
            // vec![MD4Constraint::Equal(28), MD4Constraint::One(29), MD4Constraint::Zero(31)],
            // // a6
            // vec![MD4Constraint::One(28), MD4Constraint::One(31)],
            // // d6
            // vec![MD4Constraint::Equal(28)],
            // // c6
            // vec![MD4Constraint::Equal(28), MD4Constraint::Neg(29), MD4Constraint::Neg(31)],
            // // b6
            // vec![],
            // // a7
            // vec![],
            // // d7
            // vec![],
            // // c7
            // vec![],
            // // b7
            // vec![],
            // // a8
            // vec![],
            // // d8
            // vec![],
            // // c8
            // vec![],
            // // b8
            // vec![],
            // // a9
            // vec![],
            // // d9
            // vec![],
            // // c9
            // vec![],
            // // b9
            // vec![MD4Constraint::One(31)],
            // // a10
            // vec![MD4Constraint::One(31)],
            ];
}

fn apply_md4_constraints(blocks: &mut [u32], constraints: &[Vec<MD4Constraint>]) -> [u32; 4] {
    // println!("Len {}", constraints.len());
    assert!(constraints.len() == 16);
    let mut state = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];
    for (step, step_constraints) in constraints.iter().enumerate() {
        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a_idx: usize = offset;
        let a_prev = state[a_idx];
        let b_idx = (offset + 1) % 4;
        let c_idx = (b_idx + 1) % 4;
        let d_idx = (c_idx + 1) % 4;
        let word_idxs = [a_idx, b_idx, c_idx, d_idx];

        let mut x = blocks[MD4::WORD_ORDER[step]];
        for constraint in step_constraints {
            MD4::ff1(&mut state, step, x);
            let a_next = state[a_idx];
            let fixed_a1 = constraint.apply(a_next, state, word_idxs);
            if step == 5 {
                println!(
                    "Candidate next: {} => {} by {:?}",
                    a_next, fixed_a1, constraint
                );
            }
            x = MD4::ff2word(
                fixed_a1,
                a_prev,
                state[b_idx],
                state[c_idx],
                state[d_idx],
                MD4::SHIFTS[step % 4],
            );
            state[a_idx] = a_prev; // Restore to previous state because we always advance outside the constraint
        }
        // if blocks[MD4::WORD_ORDER[step]] != x {
        //     println!("\t{}: Updating word {:#04x} to {:#04x}", step, blocks[MD4::WORD_ORDER[step]].to_le(), x.to_le());
        // }
        blocks[MD4::WORD_ORDER[step]] = x;
        MD4::ff1(&mut state, step, x);
        print_md4_state(step, state);
    }
    state
}

fn print_md4_state(step: usize, state: [u32; 4]) {
    println!(
        "{}:\ta = {:#04x}\tb = {:#04x}\tc = {:#04x}\td = {:#04x}",
        step, state[0], state[1], state[2], state[3]
    );
}

fn get_hist_state(history: &[[u32; 4]], element: usize, idx: usize) -> u32 {
    let version = if idx == 0 { 0 } else { (idx * 4) - 1 };
    history[version][element]
}

fn set_hist_state(history: &mut [[u32; 4]], element: usize, idx: usize, value: u32) {
    let version = (idx * 4) - 1;
    history[version][element] = value;
}

fn apply_md4_round2_contraints(
    blocks: &mut [u32],
    state: [u32; 4],
    constraints: &[Vec<MD4Constraint>],
) -> [u32; 4] {
    let mut state = state;
    assert_ne!(state[0], 0);
    // let a0 = MD4::I0;
    // let b0 = MD4::I1;
    // let c0 = MD4::I2;
    // let d0 = MD4::I3;
    let initial_state = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];

    for (step, word_idx) in MD4::WORD_ORDER.iter().enumerate().skip(16).take(16) {
        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a_idx: usize = offset;
        let b_idx = (offset + 1) % 4;
        let c_idx = (b_idx + 1) % 4;
        let d_idx = (c_idx + 1) % 4;

        // let a4 = state[a_idx];
        let prev_state = state;
        MD4::gg1(&mut state, step, blocks[*word_idx]);
        print_md4_state(step, state);

        // a_5,{18,25,26,28,31}=c_4,i
        if step == 16 {
            //} || step == 17 { // a5, d5
            let a0 = initial_state[0];
            let b0 = initial_state[1];
            let c0 = initial_state[2];
            let d0 = initial_state[3];
            for constraint in &constraints[step] {
                let old_element = prev_state[a_idx];
                let mut new_element = state[a_idx];
                let word_idxs = [a_idx, b_idx, c_idx, d_idx];
                println!(
                    "{}: {:?} says {:?}",
                    step,
                    constraint,
                    constraint.require(new_element, state, word_idxs)
                );
                if constraint.require(new_element, state, word_idxs).is_ok() {
                    continue;
                }
                // println!("{:?}", state_history);
                let unmodifed = MD4::gg2word(
                    new_element,
                    old_element,
                    state[b_idx],
                    state[c_idx],
                    state[d_idx],
                    MD4::SHIFTS[4 + step % 4],
                );
                println!("{:#04x} =? {:#04x}", unmodifed.to_be(), blocks[0].to_be());

                new_element = constraint.apply(new_element, state, word_idxs);
                println!(
                    "{}: {:?} says {:?}",
                    step,
                    constraint,
                    constraint.require(new_element, state, word_idxs)
                );
                assert_ne!(new_element, old_element);

                let m0 = MD4::gg2word(
                    new_element,
                    old_element,
                    state[b_idx],
                    state[c_idx],
                    state[d_idx],
                    MD4::SHIFTS[4 + step % 4],
                );
                println!("{:#04x} =? {:#04x}", new_element.to_be(), blocks[0].to_be());

                println!(
                    "Updating word 0 {:#04x} to {:#04x}",
                    blocks[0].to_be(),
                    m0.to_be()
                );
                assert_ne!(blocks[0].to_be(), m0.to_be());
                let a1 = MD4::ff(a0, b0, c0, d0, MD4::WORD_ORDER[0], MD4::SHIFTS[0], blocks);
                let d1 = MD4::ff(d0, a1, b0, c0, MD4::WORD_ORDER[1], MD4::SHIFTS[1], blocks);
                let c1 = MD4::ff(c0, d1, a1, b0, MD4::WORD_ORDER[2], MD4::SHIFTS[2], blocks);
                let b1 = MD4::ff(b0, c1, d1, a1, MD4::WORD_ORDER[3], MD4::SHIFTS[3], blocks);
                let a2 = MD4::ff(a1, b1, c1, d1, MD4::WORD_ORDER[4], MD4::SHIFTS[0], blocks);

                println!("a1 = {:#04x}", a1.to_be());
                println!("d1 = {:#04x}", d1.to_be());

                blocks[0] = m0;

                let a1_prime = MD4::ff(a0, b0, c0, d0, MD4::WORD_ORDER[0], MD4::SHIFTS[0], blocks);

                let m1 = d1
                    .rotate_right(7)
                    .wrapping_sub(d0)
                    .wrapping_sub(MD4::f(a1_prime, b0, c0));
                blocks[1] = m1;

                let m2 = c1
                    .rotate_right(11)
                    .wrapping_sub(c0)
                    .wrapping_sub(MD4::f(d1, a1_prime, b0));
                blocks[2] = m2;

                let m3 = b1
                    .rotate_right(19)
                    .wrapping_sub(b0)
                    .wrapping_sub(MD4::f(c1, d1, a1_prime));
                blocks[3] = m3;

                let m4 = a2
                    .rotate_right(3)
                    .wrapping_sub(a1_prime)
                    .wrapping_sub(MD4::f(b1, c1, d1));
                blocks[4] = m4;

                state = prev_state;
                MD4::gg1(&mut state, step, blocks[*word_idx]);
            }
        } else if step == 18 { // c5
             // // assert_eq!(*word_idx, 5);
             // for constraint in &constraints[step] {
             //     let c5 = state[2];
             //     let word_idxs = [a_idx, b_idx, c_idx, d_idx];
             //     // println!("{}: {:?} says {:?}", step, constraint, constraint.require(c5, state, word_idxs));
             //     if constraint.require(c5, state, word_idxs).is_ok() {
             //         continue;
             //     }
             //     let i = constraint.i();
             //     // c5 = constraint.apply(c5, state, word_idxs);
             //     // let m5 = MD4::gg2word(c5, c4, state[b_idx], state[c_idx], state[d_idx], MD4::SHIFTS[4 + step % 4]);
             //     let m5 = blocks[5].overflowing_add(1 << (i - 17)).0;
             //     // println!("Updating word 5 {:#04x} to {:#04x}", blocks[5].to_be(), m5.to_be());
             //     blocks[5] = m5;
             //     let m8 = blocks[8].overflowing_sub(1 << (i - 10)).0;
             //     // println!("Updating word 8 {:#04x} to {:#04x}", blocks[8].to_be(), m8.to_be());
             //     blocks[8] = m8;
             //     let m9 = blocks[9].overflowing_sub(1 << (i - 10)).0;
             //     // println!("Updating word 9 {:#04x} to {:#04x}", blocks[9].to_be(), m9.to_be());
             //     blocks[9] = m9;
             // }
        }
    }

    state
}

fn verify_md4_constraints(blocks: &[u32], constraints: &[Vec<MD4Constraint>]) -> Result<()> {
    // assert!(constraints.len() <= 16);
    let mut state = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];
    let ops = [MD4::ff1, MD4::gg1, MD4::hh1];
    println!();
    for (step, step_constraints) in constraints.iter().enumerate() {
        let round = step / 16;
        let op = ops[step / 16];
        let mut offset: usize = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a_idx: usize = offset;
        let b_idx = (offset + 1) % 4;
        let c_idx = (b_idx + 1) % 4;
        let d_idx = (c_idx + 1) % 4;
        let word_idxs = [a_idx, b_idx, c_idx, d_idx];

        let x = blocks[MD4::WORD_ORDER[step]];
        op(&mut state, step, x);
        print_md4_state(step, state);
        for constraint in step_constraints {
            let a1 = state[a_idx];
            let error_msg = format!("Step {}: {:?}", step, constraint);
            constraint
                .require(a1, state, word_idxs)
                .context(error_msg)?;
            // ensure!(constraint.require(a1, state, word_idxs).is_ok(), error_msg);
        }
        // println!("Step {}\t: {:#04x}{:#04x}{:#04x}{:#04x}", step, state[0].to_le(), state[1].to_le(), state[2].to_le(), state[3].to_le());
        // let mut md4 = MD4::default();
        // MD4::ff1(&mut state, step, MD4::SHIFTS[step % 4], x);
    }
    Ok(())
}

fn create_md4_collision_candidate() -> Result<Vec<u8>> {
    let mut rng = OsRng;
    // loop {
    let mut msg1 = vec![0u8; MD4::block_size()];
    rng.fill_bytes(&mut msg1);
    let mut block: Vec<u32> = to_w32_be(&msg1).iter().map(|w| u32::from_be(*w)).collect();
    let state = apply_md4_constraints(&mut block, &MD4CollisionConstraints[0..16]);
    // apply_md4_round2_contraints(&mut block, state, &MD4CollisionConstraints);
    let tmp = verify_md4_constraints(&block, &MD4CollisionConstraints[0..16]);
    if tmp.is_err() {
        panic!("{:?}", tmp);
        // println!("Trying again: {:?}", tmp);
        // continue;
    }
    // if verify_md4_constraints(&block, &MD4CollisionConstraints).is_ok() {
    let msg1 = block
        .iter()
        .flat_map(|b| b.to_le_bytes())
        .collect::<Vec<u8>>();
    Ok(msg1)
    // }
    // println!("Trying again...");
    // }
}

fn create_md4_collision(msg2_limit: usize) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    let pool_size = 4;

    let pool: Pool<ThunkWorker<(Vec<u8>, Vec<u8>, usize)>> = Pool::new(pool_size);
    let (tx, rx) = channel();
    // let mut results: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    // loop {
    for _ in 0..(pool_size * 2) {
        pool.execute_to(
            tx.clone(),
            Thunk::of(move || create_md4_collision_inner(msg2_limit).unwrap()),
        );
    }
    Ok(rx.recv()?)
    // }
    // for r in rx.iter().take(pool_size * 2) {
    //     count += 1;
    //     let output = r.0;
    //     let input = r.1;
    //     // println!("Compress({}) = {}", input.encode_hex::<String>(), output.encode_hex::<String>());
    //     if let Some(collision) = results.get(&output) {
    //         return Ok((collision.to_owned(), input, output, count));
    //     } else {
    //         results.insert(output, input);
    //     }
    // }
}

fn create_md4_collision_inner(msg2_limit: usize) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    let mut count = 0;
    // let mut rng = OsRng;
    loop {
        let msg1 = create_md4_collision_candidate()?;

        for _ in 0..msg2_limit {
            if count % 10000 == 0 {
                println!("Trial {}", count);
            }
            let mut msg2 = msg1.clone();
            // let byte1 = rng.gen_range(0..msg2.len());
            // let byte2= rng.gen_range(0..msg2.len());
            // let byte3 = rng.gen_range(0..msg2.len());
            msg2[1] ^= 1;
            msg2[4] ^= 1;
            msg2[28] ^= 1;
            count += 1;

            if MD4::oneshot_digest(&msg1) == MD4::oneshot_digest(&msg2) {
                return Ok((msg1, msg2, count));
            }
        }
    }
}

// n = counts, r = position, p = distribution
pub fn rc4_single_byte_attack(n: [usize; 256], r: usize, p: &[[f64; 256]]) -> Result<u8> {
    ensure!(r >= 0);
    ensure!(r < p.len());
    let mut l = [0f64; 256];

    for u in 0..=255u8 {
        let mut n_u = [0usize; 256];
        for k in 0..=255u8 {
            n_u[k as usize] = n[(u ^ k) as usize];
        }
        for k in 0..=255u8 {
            l[u as usize] += (n_u[k as usize] as f64) * p[r][k as usize].log2();
        }
    }
    let mut best_val = f64::MIN;
    let mut best = 0u8;
    for u in 10..=126 {
        if l[u] > best_val {
            best_val = l[u];
            best = u as u8;
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        aes::AesKey,
        oracles::{Challenge49Oracle, Challenge51Oracle, Challenge56Oracle},
        padding::Padding,
        rc4::Rc4Key,
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
    #[ignore = "smoke"]
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

        let limit = (1 << k) + k - 1;
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

    #[test]
    fn challenge53() -> Result<()> {
        let mut rd1 = RD1::default();
        let mut rng = OsRng;
        let mut msg = vec![0u8; RD1::block_size() * (1 << 20)];
        rng.fill_bytes(&mut msg);
        rd1.update(&msg);
        let expected_hash = rd1.digest();

        let preimage = second_preimage(&msg, &rd1.initial, RD1::block_size(), RD1::compress)?;
        rd1.update(&preimage.0);
        let actual_hash = rd1.digest();

        assert_eq!(expected_hash, actual_hash);
        assert_ne!(msg, preimage.0);

        rd1.reset();
        rd1.update(&msg);
        println!("rd1(..) -> {}", rd1.digest().encode_hex::<String>());

        rd1.reset();
        rd1.update(&preimage.0);
        println!("rd1(..) -> {}", rd1.digest().encode_hex::<String>());

        println!("compressions executed: {}", preimage.1);
        Ok(())
    }

    #[test]
    #[ignore = "smoke"]
    fn challenge54_smoke() -> Result<()> {
        let k = 3;
        let tail =
            build_nostradamus_tail_parts(k, RD1::block_size(), RD1::digest_size(), RD1::compress)?;

        println!("{:?}", tail);

        let mut rd1 = RD1::default();
        for (idx, elem) in tail.0.iter().enumerate().skip(1).rev() {
            println!("{}: {:?}", idx, elem);
            rd1.reset();
            rd1.state.copy_from_slice(&elem.h_in);
            rd1.update(&elem.bridge);
            println!("\t{:?}", rd1.state);
        }

        println!();
        let targets = 1 << k;
        for idx in targets..(2 * targets) {
            rd1.reset();
            rd1.state.copy_from_slice(&tail.0[idx].h_in);
            let tmp = build_nostradamus_tail(&tail.0, idx);
            println!("{}, {:?}", idx, tmp);
            rd1.update(&tmp);
            println!("\t{:?}", rd1.state);
            assert_eq!(rd1.state.to_vec(), tail.0[1].h_in);
        }
        Ok(())
    }

    #[test]
    #[ignore = "slow"]
    fn challenge54() -> Result<()> {
        let commitment = build_nostradamus_commitment(
            2,
            10,
            RD1::compress,
            RD1::block_size(),
            RD1::digest_size(),
        )?;

        let mut rd1 = RD1::default();
        rd1.state.copy_from_slice(&commitment.pre_hash);
        rd1.length = commitment.total_length * RD1::block_size();
        let committed_hash = rd1.digest();
        println!("Committed hash = {}", committed_hash.encode_hex::<String>());

        // Messages!
        let msgs = vec![
            //123456789abcdef0123456789abcdef
            "Star wars is the best!",
            "Star trek is the best!",
            "I prefer Battlestar Galactica",
            "Babylon 5 is underloved.",
        ];
        for m in msgs {
            println!("{}", m);
            let mut padded_base = m.as_bytes().to_vec();
            padded_base.resize(2 * RD1::block_size(), 0);
            let forged_msg = build_nostradamus_result(
                &commitment.tail_parts,
                &padded_base,
                &[0u8; 16],
                RD1::compress,
            )?;
            rd1.reset();
            rd1.update(&forged_msg.0);
            let forged_commitment = rd1.digest();
            println!(
                "\t{}\n{} with {}+{}={} compressions",
                forged_msg.0.encode_hex::<String>(),
                forged_commitment.encode_hex::<String>(),
                commitment.compressions,
                forged_msg.1,
                commitment.compressions + forged_msg.1
            );
            assert_eq!(committed_hash, forged_commitment);
        }
        Ok(())
    }

    #[test]
    #[ignore = "Not working"]
    fn challenge55_smoke() -> Result<()> {
        // let mut msg = vec![0u8; MD4::block_size()];
        // let mut rng = OsRng;
        // let used_constraints = &MD4CollisionConstraints;
        for _ in 0..10 {
            let msg = create_md4_collision_candidate()?;
            // rng.fill_bytes(&mut msg);
            // println!("Old msg: {}", msg.encode_hex::<String>());
            let block: Vec<u32> = to_w32_be(&msg).iter().map(|w| u32::from_be(*w)).collect();
            // let state = apply_md4_constraints(&mut block, &MD4CollisionConstraints[0..16]);
            // let msg = block
            //     .iter()
            //     .flat_map(|b| b.to_le_bytes())
            //     .collect::<Vec<u8>>();

            // apply_md4_round2_contraints(&mut block, state, &MD4CollisionConstraints);
            // println!("New msg: {}", msg.encode_hex::<String>());

            verify_md4_constraints(&block, &MD4CollisionConstraints[0..17])?;

            // MD4::oneshot_digest(&msg);
            println!();
        }

        // let sample = hex::decode("a6af943ce36f0cf4adcb12bef7f0dc1f526dd914bd3da3cafde14467ab129e640b4c41819915cb43db752155ae4b895fc71b9b0d384d06ef3118bbc643ae6384")?;
        // let block: Vec<u32> = to_w32_be(&sample)
        //     .iter()
        //     .map(|w| u32::from_be(*w))
        //     .collect();
        // verify_md4_constraints(&block, &MD4CollisionConstraints)?;

        Ok(())
    }

    #[test]
    #[ignore = "Not working"]
    fn challenge55() -> Result<()> {
        let collision = create_md4_collision(1)?;
        println!("After {} attempts", collision.2);
        assert_ne!(collision.0, collision.1);
        let hash1: String = MD4::oneshot_digest(&collision.0).encode_hex();
        let hash2: String = MD4::oneshot_digest(&collision.1).encode_hex();
        assert_eq!(hash1, hash2);

        Ok(())
    }

    #[test]
    // #[ignore = "slow"]
    fn challenge56_detect_bias() -> Result<()> {
        // Second byte should be zero 1/128 of the time
        let trials = 4096000;
        let mut zero_count = 0;
        let zeros = [0u8; 32];

        let mut length_bias_count = 0;
        for _ in 0..trials {
            let mut key = Rc4Key::random();
            let ciphertext = key.crypt(&zeros);
            // key.next_byte();
            if ciphertext[1] == 0 {
                zero_count += 1;
            }

            if ciphertext[31] == 224 {
                length_bias_count += 1;
            }
        }
        let expected = trials / 256;
        println!("Expected = {}, actual = {}", expected, zero_count);
        assert!(zero_count as f32 >= (expected as f32 * 1.5));

        println!("Expected = {}, actual = {}", expected, length_bias_count);
        assert!(length_bias_count as f32 >= (expected as f32 * 1.002));
        Ok(())
    }

    // #[test]
    fn challenge56_generate_table() -> Result<()> {
        let pool_size = 12;
        let trials = 1usize << 32;
        let f_trials = trials as f64;

        let pool: Pool<ThunkWorker<Vec<u8>>> = Pool::new(pool_size);
        let (tx, rx) = channel();
        let mut counts = [[0f64; 256]; 32];

        let mut i = 0;
        println!("Active count: {}", pool.active_count());
        for _ in 0..=pool_size {
            println!("Enqueed");
            pool.execute_to(
                tx.clone(),
                Thunk::of(|| {
                    let zeros = [0u8; 32];
                    Rc4Key::random().crypt(&zeros)
                }),
            );
        }
        println!("Active count: {}", pool.active_count());

        while i < trials {
            // println!("Fod");
            if i % (1025 * 1025) == 0 {
                println!("Trial {} ({})", i, (i as f64 / f_trials));
            }
            let tmp = rx.recv()?;
            for (idx, val) in tmp.iter().enumerate() {
                counts[idx][*val as usize] += 1f64;
            }
            i += 1;

            pool.execute_to(
                tx.clone(),
                Thunk::of(|| {
                    let zeros = [0u8; 32];
                    Rc4Key::random().crypt(&zeros)
                }),
            );
        }
        // for _i in 0..(trials / pool_size) {
        //     for _ in 0..pool_size {
        //     pool.execute_to(tx.clone(), Thunk::of(|| {
        //         let zeros = [0u8; 32];
        //         Rc4Key::random().crypt(&zeros) }));
        //     }

        //     let mut key = Rc4Key::random();
        //     for r_count in counts.iter_mut() {
        //         r_count[key.next_byte() as usize] += 1f64;
        //     }
        // }

        for r_count in counts.iter_mut() {
            for elem in r_count.iter_mut() {
                *elem /= f_trials;
            }
        }

        println!("{:?}", counts);
        Ok(())
    }

    #[test]
    fn challenge56_recovery_smoke() -> Result<()> {
        let target = [0u8, b'A'];
        let mut counts = [0usize; 256];
        for _i in 0..10240 {
            let mut key = Rc4Key::random();
            let ct = key.crypt(&target);
            counts[ct[1] as usize] += 1;
        }
        println!("Counts = {:?}", counts);
        let recovered = rc4_single_byte_attack(counts, 1, &crate::rc4::distribution::DISTRIBUTION)?;
        assert_eq!(recovered, target[1]);
        Ok(())
    }

    #[test]
    fn challenge56() -> Result<()> {
        let oracle = Challenge56Oracle::new();
        let length = oracle.encrypt(&[]).len();
        let mut counts = vec![[1044110, 1042276, 1042647, 1043123, 1042652, 1041706, 1041802, 1044128, 1044039, 1043422, 1043598, 1045822, 1042988, 1044184, 1044946, 1044518, 1043393, 1045522, 1042700, 1045160, 1045297, 1042686, 1046337, 1043882, 1043564, 1042274, 1045584, 1045027, 1043440, 1043985, 1044305, 1044459, 1044353, 1043853, 1043078, 1044041, 1044955, 1043658, 1043296, 1044679, 1042135, 1042162, 1043217, 1043842, 1043181, 1043478, 1042895, 1045718, 1044359, 1045207, 1042500, 1045482, 1045984, 1042709, 1044271, 1043782, 1042313, 1044678, 1044710, 1043898, 1044515, 1044651, 1044290, 1044169, 1034242, 1041961, 2100059, 1037998, 1042223, 1042431, 1043049, 1040549, 1041851, 1040970, 1040872, 1041121, 1042196, 1041371, 1040936, 1043158, 1041780, 1043690, 1042507, 1042072, 1045549, 1042821, 1043001, 1042613, 1040576, 1042544, 1042670, 1042558, 1042866, 1043885, 1044636, 1042863, 1041332, 1044393, 1043300, 1041704, 1043234, 1042767, 1043288, 1041344, 1042245, 1044515, 1043045, 1043334, 1044249, 1043977, 1042234, 1042772, 1043127, 1045669, 1043202, 1043640, 1044053, 1044580, 1043846, 1042968, 1043462, 1043062, 1042220, 1043396, 1044713, 1043135, 1041621, 1044193, 1045421, 1047314, 1045471, 1045982, 1045379, 1045498, 1045774, 1046295, 1045949, 1046136, 1045748, 1043885, 1045539, 1045904, 1046914, 1043961, 1046707, 1045942, 1045799, 1046977, 1046003, 1046813, 1045634, 1046588, 1045725, 1046179, 1045027, 1044508, 1046933, 1046286, 1047502, 1044680, 1045750, 1047064, 1046163, 1045932, 1045949, 1047517, 1046188, 1045504, 1045960, 1047418, 1043901, 1044843, 1045999, 1047876, 1046545, 1047551, 1047251, 1044654, 1045768, 1047489, 1044375, 1044423, 1045050, 1046121, 1045074, 1047269, 1045991, 1046281, 1047792, 1046631, 1047533, 1046093, 1044187, 1045328, 1044572, 1041586, 1043729, 1044510, 1044292, 1043891, 1045374, 1045309, 1044866, 1045253, 1044320, 1044314, 1044393, 1045352, 1043983, 1045806, 1045170, 1045908, 1045477, 1043036, 1045458, 1043667, 1046459, 1045380, 1045747, 1045286, 1045232, 1045486, 1045049, 1044770, 1045002, 1045263, 1046488, 1044522, 1044724, 1045950, 1044951, 1044328, 1044777, 1045586, 1046069, 1046241, 1045989, 1045096, 1047405, 1046347, 1046860, 1044112, 1046253, 1044942, 1045616, 1045636, 1046134, 1045971, 1043318, 1047145, 1046824, 1043805, 1044407, 1047341, 1045867, 1046996], [1047165, 1046948, 1048028, 1048438, 1049635, 1048993, 1047305, 1048460, 1046535, 1048355, 1045774, 1047395, 1048620, 1047378, 1048840, 1047925, 1049709, 1047708, 1047922, 1049472, 1047317, 1049560, 1047639, 1049644, 1048201, 1048049, 1047356, 1049646, 1048651, 1047555, 1047991, 1049033, 1049377, 1049889, 1049330, 1048546, 1046527, 1049243, 1048163, 1047511, 1047323, 1049403, 1049042, 1048298, 1048528, 1047864, 1047539, 1047713, 1049666, 1048748, 1046825, 1047969, 1047694, 1049589, 1046721, 1049530, 1048023, 1048816, 1049560, 1047703, 1049504, 1050108, 1046860, 1046563, 1049103, 1046656, 1047419, 1046485, 1048393, 1049302, 1050363, 1048913, 1048528, 1046968, 1048250, 1047531, 1047168, 1046406, 1046502, 1046849, 1048359, 1048048, 1048147, 1047006, 1047885, 1046581, 1047069, 1046863, 1047395, 1048714, 1047597, 1046634, 1048203, 1048064, 1046903, 1048936, 1049936, 1048597, 1047336, 1047401, 1047737, 1048414, 1047452, 1047600, 1047748, 1045495, 1049555, 1048925, 1049890, 1044647, 1045573, 1046577, 1049929, 1048534, 1046901, 1047080, 1046456, 1048692, 1046240, 1047955, 1047086, 1048223, 1047757, 1046347, 1046524, 1048276, 1046353, 1047875, 1047614, 1048621, 1049174, 1050863, 1050197, 1049528, 1049500, 1048442, 1048799, 1049762, 1049382, 1048849, 1049155, 1049056, 1050503, 1049059, 1048869, 1049587, 1049062, 1048834, 1047899, 1051549, 1048815, 1050123, 1050010, 1048772, 1050611, 1049034, 1048697, 1051144, 1051034, 1050145, 1051091, 1049599, 1050537, 1050253, 1052641, 1049049, 1048487, 1050474, 1048875, 1050837, 1049177, 1050229, 1049355, 1049549, 1051064, 1050062, 1051528, 1049150, 1050399, 1050401, 1048989, 1047992, 1050318, 1050186, 1050698, 1050580, 1048825, 1050757, 1051478, 1048628, 1049495, 1050130, 1047758, 1047381, 1048827, 1048826, 1047104, 1047917, 1051253, 1049138, 1050191, 1047986, 1047113, 1048632, 1047651, 1048238, 1049343, 1048353, 1048213, 1049055, 1050924, 1048518, 1049258, 1048711, 1048151, 1048271, 1049797, 1048569, 1047980, 1049088, 1048386, 1048600, 1047902, 1048082, 1047873, 1048731, 1048057, 1048624, 1045911, 1049183, 1048160, 1048012, 1047222, 1048802, 1050359, 1047427, 1049251, 1049323, 1047665, 1047194, 1048229, 1049642, 1050127, 1049459, 1047571, 1048516, 1049468, 1050429, 1049033, 1049352, 1049807, 1047875, 1049267, 1047295, 1050698, 1048383], [1048408, 1047887, 1049075, 1047059, 1046321, 1047873, 1046908, 1048834, 1049506, 1047837, 1047791, 1049804, 1046351, 1045907, 1048379, 1048216, 1048507, 1046834, 1046151, 1047031, 1047355, 1048016, 1048337, 1047396, 1047667, 1048859, 1047028, 1050630, 1048207, 1048520, 1047613, 1046449, 1052981, 1049440, 1051148, 1047652, 1053744, 1047320, 1048857, 1047156, 1047915, 1048138, 1046923, 1046689, 1048049, 1047502, 1049794, 1047956, 1049208, 1048890, 1046792, 1046661, 1048044, 1047898, 1049183, 1048196, 1049225, 1049103, 1047411, 1045919, 1046986, 1048311, 1046828, 1048190, 1047195, 1048586, 1048861, 1048296, 1049363, 1047100, 1047697, 1048507, 1047847, 1048421, 1048807, 1049495, 1049130, 1047371, 1049078, 1046969, 1047772, 1048128, 1049341, 1049071, 1047806, 1049690, 1049194, 1048668, 1048317, 1047749, 1049477, 1048694, 1047648, 1047799, 1049649, 1047300, 1047255, 1047509, 1046402, 1046457, 1047969, 1047122, 1048330, 1047607, 1046486, 1049298, 1047927, 1046049, 1048648, 1047259, 1051548, 1049581, 1047624, 1048025, 1048796, 1047711, 1046193, 1048539, 1048914, 1046348, 1048095, 1047134, 1047671, 1048093, 1047097, 1047983, 1048938, 1049497, 1049808, 1047820, 1049809, 1048091, 1047613, 1050035, 1046766, 1049198, 1049332, 1049643, 1049061, 1048065, 1049737, 1049803, 1049377, 1048301, 1047253, 1049003, 1048638, 1050174, 1049219, 1050454, 1048540, 1048834, 1048238, 1048934, 1049731, 1049228, 1049738, 1047769, 1050170, 1048698, 1046364, 1047835, 1048305, 1047696, 1050828, 1049122, 1045637, 1048013, 1048731, 1049739, 1047131, 1048545, 1047773, 1046506, 1048417, 1047579, 1048319, 1047635, 1047785, 1048989, 1049132, 1048581, 1049343, 1048755, 1048364, 1049272, 1047675, 1047822, 1048947, 1048464, 1049202, 1046841, 1050626, 1049244, 1050141, 1049475, 1049060, 1050793, 1048045, 1049683, 1049220, 1048316, 1049053, 1049990, 1049666, 1051879, 1049686, 1049159, 1048162, 1050406, 1051335, 1049067, 1050107, 1050148, 1051376, 1049708, 1051383, 1049095, 1047994, 1049159, 1050667, 1048881, 1050743, 1049865, 1048456, 1049584, 1050197, 1048962, 1048126, 1050351, 1050394, 1048505, 1048544, 1048917, 1048518, 1049400, 1050798, 1050596, 1048114, 1048085, 1050203, 1049682, 1047546, 1049308, 1049987, 1047475, 1049531, 1048470, 1049034, 1049179, 1048955, 1049861, 1048468, 1050248, 1049575, 1047832], [1048088, 1048359, 1048071, 1048808, 1047687, 1049672, 1048022, 1045606, 1048828, 1049114, 1047423, 1049606, 1046604, 1047725, 1047580, 1049171, 1048591, 1049056, 1047884, 1048875, 1046713, 1047259, 1046881, 1049947, 1048692, 1046349, 1046651, 1046293, 1049010, 1046623, 1048335, 1047249, 1046939, 1050021, 1048602, 1046477, 1048463, 1046394, 1050540, 1048237, 1047084, 1045949, 1048783, 1048343, 1047745, 1047698, 1047665, 1048880, 1048174, 1047997, 1048655, 1049211, 1050229, 1048967, 1045824, 1047633, 1047967, 1050720, 1049161, 1048076, 1046593, 1048887, 1046908, 1046649, 1047716, 1046131, 1046753, 1049225, 1048286, 1047211, 1047153, 1049245, 1047782, 1046557, 1047688, 1048986, 1046401, 1047908, 1047550, 1048070, 1049404, 1048232, 1047821, 1053216, 1048149, 1046396, 1054135, 1048684, 1046944, 1049187, 1047488, 1044490, 1045206, 1047117, 1049803, 1047428, 1048510, 1048518, 1047420, 1046624, 1046387, 1048438, 1048999, 1048646, 1048093, 1046994, 1047097, 1047138, 1049436, 1048494, 1047755, 1047002, 1047243, 1046392, 1049166, 1048970, 1048167, 1047885, 1046683, 1048376, 1045015, 1046904, 1048091, 1048355, 1048821, 1047554, 1048544, 1045441, 1049590, 1050335, 1051089, 1048382, 1049420, 1050212, 1049182, 1050102, 1049499, 1049571, 1047242, 1049483, 1049402, 1050080, 1046308, 1047424, 1048839, 1049739, 1048269, 1050311, 1049175, 1049264, 1049445, 1051579, 1048561, 1049692, 1049770, 1049741, 1049940, 1048151, 1049343, 1048377, 1050035, 1048947, 1049425, 1050469, 1050077, 1049499, 1049818, 1050362, 1050252, 1050058, 1049518, 1051086, 1050558, 1050525, 1048820, 1051106, 1049998, 1050856, 1051282, 1048958, 1050395, 1049079, 1052038, 1049273, 1050808, 1048581, 1051827, 1049820, 1049187, 1050689, 1049323, 1049394, 1048516, 1046581, 1047283, 1049196, 1048221, 1050043, 1048700, 1047577, 1048773, 1048911, 1049273, 1049093, 1048950, 1048379, 1047184, 1047529, 1048442, 1047761, 1049935, 1048412, 1048823, 1048503, 1048476, 1049249, 1048263, 1049777, 1048941, 1048277, 1048605, 1049675, 1048527, 1049410, 1048517, 1048625, 1049209, 1049176, 1048156, 1047620, 1048833, 1048322, 1048771, 1049547, 1049624, 1049471, 1047996, 1050991, 1051983, 1051122, 1048216, 1048235, 1047975, 1049731, 1048643, 1048384, 1049590, 1049957, 1048312, 1048660, 1047834, 1046856, 1047909, 1048576, 1048038, 1047949], [1048358, 1048064, 1046964, 1047907, 1047076, 1048927, 1048745, 1048602, 1047119, 1047458, 1048664, 1047305, 1047455, 1048993, 1048742, 1047429, 1047550, 1049015, 1048426, 1047267, 1047710, 1047408, 1048255, 1049095, 1047540, 1048445, 1048386, 1047054, 1049477, 1048529, 1047193, 1048606, 1048465, 1047844, 1049167, 1047689, 1047615, 1046817, 1048633, 1047934, 1049440, 1048332, 1049044, 1047589, 1047162, 1047725, 1047838, 1048381, 1049266, 1048391, 1047598, 1048384, 1048833, 1048121, 1046347, 1047888, 1048905, 1047693, 1048260, 1049701, 1048865, 1049181, 1048012, 1048383, 1046748, 1047295, 1047805, 1047237, 1048179, 1046418, 1047061, 1046515, 1045922, 1049995, 1049776, 1047349, 1048633, 1045830, 1046835, 1048328, 1047691, 1050190, 1045977, 1055918, 1048277, 1054243, 1047385, 1048245, 1047731, 1047183, 1046958, 1047846, 1047709, 1045279, 1047766, 1047564, 1046166, 1048390, 1047564, 1049002, 1047617, 1047034, 1045602, 1046071, 1047904, 1048981, 1046415, 1049892, 1047331, 1048451, 1046666, 1048235, 1047520, 1048106, 1047139, 1047944, 1049755, 1047324, 1048346, 1046533, 1047634, 1048765, 1047890, 1047662, 1047544, 1047360, 1047165, 1047241, 1050691, 1050664, 1048358, 1048012, 1050408, 1049906, 1047375, 1049466, 1048827, 1051827, 1048122, 1049327, 1048789, 1050471, 1049157, 1049748, 1048840, 1048372, 1049576, 1048358, 1049912, 1048198, 1050133, 1050271, 1049390, 1050345, 1046972, 1048403, 1049525, 1051133, 1048990, 1048631, 1051197, 1050441, 1048997, 1050291, 1051849, 1050518, 1049409, 1048907, 1050094, 1049109, 1050750, 1050690, 1050737, 1049475, 1051705, 1049462, 1049055, 1048800, 1048469, 1052054, 1049107, 1049403, 1049602, 1047965, 1050719, 1050793, 1050668, 1050639, 1049455, 1050692, 1048361, 1048530, 1049801, 1048963, 1050473, 1051207, 1047701, 1047573, 1049752, 1048354, 1048184, 1049554, 1048718, 1047759, 1047726, 1049515, 1047544, 1049164, 1047285, 1048196, 1047539, 1047893, 1047651, 1048479, 1047583, 1048007, 1048957, 1049735, 1048858, 1049836, 1047847, 1049242, 1048869, 1048516, 1050998, 1047967, 1049039, 1048984, 1049337, 1048689, 1046918, 1049365, 1049993, 1048983, 1048475, 1049185, 1048784, 1048846, 1048136, 1048249, 1049297, 1048251, 1048785, 1047723, 1049030, 1048678, 1048779, 1047613, 1047813, 1049235, 1048723, 1048676, 1049481, 1048085, 1049242, 1049072], [1046555, 1048426, 1048165, 1049103, 1048014, 1050621, 1047685, 1049494, 1046910, 1047169, 1049420, 1051372, 1048053, 1046607, 1046705, 1046473, 1048562, 1047125, 1049539, 1048588, 1046810, 1049725, 1047432, 1047784, 1047736, 1047643, 1048433, 1047444, 1049084, 1048440, 1048579, 1047953, 1047408, 1048488, 1048892, 1047180, 1046559, 1048403, 1048098, 1048214, 1049368, 1048127, 1048369, 1049041, 1046796, 1048182, 1048514, 1048969, 1049082, 1048358, 1047280, 1049707, 1049763, 1048736, 1048105, 1048271, 1047807, 1047224, 1048915, 1048246, 1047734, 1047944, 1048146, 1049304, 1047480, 1046658, 1047856, 1049798, 1048555, 1047147, 1045676, 1048426, 1047668, 1049395, 1048414, 1047066, 1046968, 1047171, 1049643, 1046202, 1046745, 1049743, 1054352, 1046763, 1046926, 1053229, 1048035, 1046736, 1047731, 1049373, 1047827, 1048363, 1047757, 1046061, 1047998, 1047399, 1047058, 1048786, 1047693, 1048572, 1047084, 1046433, 1047997, 1048405, 1047085, 1045634, 1049075, 1045650, 1048071, 1048086, 1046997, 1048423, 1047914, 1048100, 1046245, 1047007, 1048582, 1048228, 1048772, 1048286, 1048342, 1046324, 1047874, 1048994, 1049242, 1046137, 1047376, 1050133, 1047573, 1049453, 1049065, 1050598, 1047840, 1046586, 1049340, 1050909, 1049562, 1048345, 1049586, 1049270, 1049333, 1050115, 1049258, 1049978, 1047899, 1051182, 1048738, 1047647, 1050929, 1049067, 1048146, 1048454, 1048975, 1047796, 1045837, 1048837, 1047746, 1049855, 1050448, 1050816, 1049505, 1048911, 1050016, 1050017, 1050993, 1049170, 1051397, 1049298, 1052104, 1051654, 1050665, 1049863, 1050966, 1050112, 1050015, 1050009, 1049777, 1049749, 1048074, 1048796, 1048641, 1048710, 1048326, 1047592, 1049206, 1047990, 1049135, 1049902, 1051132, 1049253, 1050306, 1048863, 1048539, 1048747, 1048814, 1048538, 1051657, 1047470, 1047836, 1048780, 1051195, 1048188, 1049493, 1047815, 1047480, 1048219, 1048021, 1047704, 1047846, 1047103, 1049488, 1047429, 1049271, 1047878, 1047127, 1049300, 1049422, 1048535, 1046594, 1049280, 1049641, 1048403, 1049095, 1047069, 1049251, 1048862, 1047677, 1048001, 1050017, 1048830, 1051598, 1050304, 1048517, 1049520, 1050256, 1049519, 1049851, 1048799, 1050261, 1049415, 1049633, 1049823, 1046312, 1050031, 1049186, 1048637, 1049288, 1048935, 1048323, 1048925, 1046302, 1046536, 1049283, 1049271, 1049414, 1048927], [1047224, 1047088, 1048023, 1046945, 1049376, 1047787, 1046387, 1048305, 1046522, 1048226, 1047103, 1047600, 1047828, 1048416, 1046873, 1047045, 1048626, 1048139, 1047382, 1050543, 1048785, 1048331, 1048268, 1049684, 1046912, 1047225, 1047530, 1050415, 1048565, 1047277, 1047257, 1049247, 1049323, 1047090, 1048698, 1047777, 1048959, 1047933, 1047503, 1045241, 1047373, 1048094, 1048342, 1046782, 1049628, 1047464, 1049391, 1048082, 1048290, 1049545, 1046539, 1048462, 1047383, 1048370, 1047530, 1047391, 1048475, 1049692, 1047463, 1048409, 1047698, 1048490, 1049625, 1048506, 1049145, 1048547, 1047731, 1048165, 1046672, 1053530, 1047254, 1048753, 1046896, 1046007, 1047430, 1047069, 1048416, 1054820, 1046722, 1045869, 1047771, 1048975, 1047047, 1047762, 1046857, 1047982, 1045923, 1047981, 1049282, 1048876, 1047349, 1048814, 1047775, 1046549, 1049297, 1046588, 1047722, 1046945, 1047555, 1047019, 1048263, 1047267, 1049045, 1048308, 1048477, 1048969, 1046647, 1048058, 1048973, 1048333, 1047616, 1045665, 1048304, 1048080, 1048068, 1048007, 1049509, 1047251, 1048457, 1048884, 1048625, 1046525, 1048807, 1048920, 1048410, 1049148, 1047580, 1046820, 1048235, 1048365, 1049249, 1049259, 1050206, 1046978, 1049040, 1049369, 1049326, 1048681, 1049112, 1049746, 1049450, 1048619, 1049143, 1049081, 1049443, 1049773, 1047712, 1049898, 1048864, 1050126, 1049139, 1050149, 1048728, 1050308, 1049683, 1049665, 1050695, 1048388, 1048712, 1047586, 1050814, 1050717, 1050352, 1049111, 1048510, 1048241, 1050777, 1050715, 1049282, 1050179, 1049007, 1050598, 1052036, 1048446, 1050583, 1050671, 1049374, 1049583, 1050769, 1052018, 1049863, 1051230, 1050805, 1048524, 1048876, 1049105, 1050833, 1047749, 1050646, 1047640, 1048519, 1050648, 1046743, 1047991, 1048282, 1047071, 1048495, 1047878, 1047579, 1049226, 1047927, 1049858, 1048940, 1048126, 1048311, 1049113, 1047560, 1049234, 1047329, 1048703, 1048593, 1050074, 1048514, 1049290, 1051149, 1047569, 1049045, 1049404, 1048576, 1049011, 1049321, 1048772, 1049039, 1047683, 1046542, 1049097, 1048302, 1048120, 1049534, 1048080, 1048237, 1046736, 1047765, 1049933, 1048510, 1050439, 1049960, 1048535, 1049583, 1048573, 1048994, 1049353, 1049654, 1049416, 1050990, 1048181, 1047507, 1048553, 1048525, 1049638, 1048166, 1049785, 1051632, 1047776, 1050859, 1046533], [1047048, 1047035, 1047371, 1047190, 1048671, 1048070, 1047967, 1047589, 1046713, 1047601, 1048392, 1047343, 1047155, 1047277, 1046383, 1047629, 1049537, 1046640, 1049180, 1047800, 1048059, 1047428, 1047129, 1049554, 1049113, 1046660, 1048114, 1049151, 1049104, 1048938, 1044258, 1047300, 1052261, 1048229, 1046441, 1048349, 1048311, 1048470, 1047494, 1050149, 1049216, 1054551, 1048165, 1048433, 1048771, 1045348, 1046987, 1047881, 1049608, 1048310, 1047483, 1048463, 1046499, 1045206, 1048917, 1046989, 1047648, 1048114, 1047468, 1047560, 1048650, 1047932, 1047777, 1047854, 1047978, 1047566, 1047479, 1048845, 1049523, 1049221, 1047515, 1047179, 1048085, 1048251, 1048943, 1048579, 1048781, 1046945, 1047843, 1048918, 1048075, 1049720, 1047096, 1047336, 1047867, 1048090, 1047021, 1049232, 1048722, 1046218, 1048205, 1047194, 1048410, 1048114, 1048566, 1049429, 1048390, 1047331, 1046923, 1048720, 1049035, 1047617, 1047137, 1046716, 1048263, 1049174, 1049467, 1048434, 1048828, 1049521, 1047807, 1048955, 1049525, 1047135, 1046482, 1048162, 1046770, 1047239, 1046258, 1048325, 1045816, 1047661, 1046926, 1048725, 1047271, 1046302, 1046903, 1048159, 1048093, 1047111, 1049227, 1048458, 1049380, 1049132, 1048659, 1049720, 1048198, 1050583, 1047825, 1049444, 1048539, 1047894, 1048524, 1049541, 1048953, 1049561, 1048826, 1050061, 1047963, 1047820, 1048752, 1049986, 1049045, 1047842, 1049387, 1047289, 1049855, 1047602, 1049296, 1050219, 1046937, 1049049, 1046988, 1048136, 1048166, 1049310, 1048079, 1047992, 1049156, 1048387, 1048977, 1048589, 1048915, 1048961, 1050382, 1047686, 1049330, 1047330, 1047974, 1049134, 1049265, 1050634, 1047722, 1047235, 1047131, 1050172, 1047780, 1049596, 1050215, 1049667, 1048731, 1050580, 1052224, 1049241, 1046525, 1049549, 1050119, 1051619, 1050040, 1050609, 1051374, 1049016, 1050010, 1049693, 1048984, 1051825, 1051078, 1049969, 1050670, 1048233, 1049581, 1049612, 1050259, 1050095, 1049807, 1050828, 1049222, 1051986, 1048904, 1050597, 1049790, 1051109, 1048559, 1049443, 1048735, 1048221, 1048836, 1047954, 1048733, 1048354, 1048081, 1050859, 1049745, 1049079, 1049291, 1048622, 1047337, 1050416, 1048579, 1047312, 1049331, 1050747, 1050508, 1047515, 1050165, 1049604, 1049712, 1049735, 1048904, 1051635, 1049841, 1049475, 1049218, 1048989, 1048335, 1048171], [1046350, 1049134, 1046556, 1048703, 1045901, 1047559, 1048184, 1048096, 1049851, 1046572, 1049187, 1049008, 1047007, 1050151, 1046165, 1047107, 1046952, 1046720, 1049695, 1048730, 1048143, 1046826, 1046441, 1046625, 1047031, 1047517, 1049525, 1046659, 1045691, 1048009, 1047094, 1048698, 1048817, 1048889, 1048197, 1047397, 1049599, 1049032, 1048331, 1047906, 1048108, 1047325, 1047526, 1047328, 1048741, 1049416, 1048218, 1048385, 1048876, 1046746, 1047055, 1048205, 1047925, 1048315, 1048565, 1047992, 1048832, 1046981, 1047028, 1049506, 1047777, 1048967, 1049576, 1047196, 1049078, 1049170, 1048127, 1047998, 1047440, 1045688, 1047405, 1049051, 1046476, 1047789, 1048429, 1046048, 1047802, 1047799, 1045506, 1049973, 1048413, 1047656, 1048340, 1048811, 1053882, 1049429, 1048509, 1046956, 1048805, 1047397, 1046067, 1048717, 1048703, 1047969, 1055331, 1047652, 1048123, 1047924, 1046452, 1047546, 1051140, 1047478, 1046820, 1046098, 1049832, 1048972, 1047346, 1047918, 1048462, 1047854, 1047203, 1048012, 1048232, 1047851, 1046133, 1048267, 1047981, 1047002, 1047386, 1048003, 1047823, 1047649, 1048827, 1046611, 1046140, 1049255, 1048403, 1046120, 1049111, 1050953, 1051076, 1049879, 1048959, 1049475, 1048071, 1049630, 1047917, 1047536, 1048768, 1050375, 1051214, 1050047, 1050696, 1048894, 1049214, 1049486, 1047976, 1050683, 1051069, 1050049, 1049584, 1048919, 1049593, 1049513, 1048288, 1049568, 1049013, 1051101, 1049851, 1048666, 1048750, 1050361, 1049601, 1050301, 1049402, 1048871, 1052104, 1049583, 1048160, 1051165, 1049645, 1050735, 1049697, 1049008, 1049760, 1049517, 1050143, 1048020, 1050342, 1049452, 1048938, 1050078, 1049180, 1049757, 1050689, 1050237, 1051349, 1049953, 1048816, 1050883, 1050012, 1049888, 1048311, 1049220, 1047651, 1047813, 1049590, 1047654, 1048498, 1049178, 1046707, 1048181, 1049021, 1047945, 1048752, 1048632, 1048703, 1048052, 1048507, 1048293, 1047733, 1049371, 1049711, 1047702, 1049541, 1050161, 1048452, 1049745, 1049567, 1048881, 1048106, 1050102, 1049441, 1047867, 1048503, 1047774, 1048943, 1048494, 1047669, 1048343, 1047459, 1046871, 1049042, 1047975, 1049143, 1049962, 1048051, 1048177, 1048752, 1047818, 1049509, 1048131, 1048697, 1050433, 1051503, 1049525, 1048534, 1049636, 1048839, 1047976, 1046527, 1047774, 1047636, 1048339, 1049361, 1049478], [1046622, 1048500, 1049155, 1046352, 1047158, 1047402, 1050047, 1047215, 1048535, 1048176, 1047611, 1048874, 1048064, 1047786, 1047505, 1047290, 1048169, 1047747, 1046481, 1049124, 1048732, 1048115, 1045932, 1047697, 1048471, 1048810, 1048221, 1047184, 1047992, 1047189, 1046626, 1049395, 1049187, 1047680, 1048482, 1048274, 1049111, 1048677, 1047406, 1046422, 1048024, 1049876, 1050089, 1048361, 1047857, 1048929, 1047901, 1050020, 1049420, 1047653, 1046965, 1048544, 1049428, 1047342, 1049545, 1048981, 1048280, 1049319, 1047059, 1049032, 1047989, 1046230, 1049312, 1048718, 1047494, 1047911, 1047380, 1047174, 1054060, 1048862, 1047571, 1049467, 1047809, 1046833, 1046360, 1049023, 1050327, 1048514, 1048490, 1053320, 1048067, 1046975, 1047193, 1045990, 1048105, 1046132, 1047154, 1047677, 1049198, 1047793, 1048665, 1048462, 1045915, 1046898, 1048760, 1046730, 1047963, 1046873, 1048112, 1046180, 1048460, 1047285, 1046089, 1046787, 1048260, 1047435, 1049321, 1047700, 1048263, 1047416, 1048023, 1049163, 1048667, 1046375, 1048393, 1047215, 1046700, 1047804, 1048387, 1048008, 1048136, 1048485, 1045370, 1047687, 1048955, 1046775, 1048776, 1049332, 1049575, 1050182, 1050515, 1047075, 1047454, 1049138, 1048914, 1047681, 1049059, 1048724, 1049867, 1048559, 1050283, 1049698, 1051041, 1048835, 1049363, 1048772, 1051053, 1049674, 1048451, 1051048, 1047381, 1048360, 1050799, 1050052, 1047670, 1048820, 1049998, 1049544, 1050088, 1049235, 1048928, 1049616, 1050384, 1050701, 1048585, 1049685, 1049100, 1049597, 1051963, 1050271, 1051332, 1050578, 1047449, 1050235, 1050285, 1048127, 1047377, 1050640, 1049235, 1050154, 1049138, 1050948, 1049601, 1047602, 1050480, 1050712, 1050225, 1049572, 1049181, 1048864, 1049987, 1049722, 1049927, 1046710, 1049985, 1047399, 1048419, 1047786, 1048891, 1048243, 1048483, 1049711, 1046974, 1047722, 1047018, 1046670, 1048073, 1048273, 1047790, 1048545, 1050174, 1048220, 1048318, 1046737, 1049166, 1047498, 1046765, 1049789, 1048829, 1048409, 1049270, 1048114, 1047860, 1050081, 1048863, 1049755, 1049277, 1049707, 1050731, 1048285, 1048702, 1048742, 1049275, 1050417, 1047386, 1048925, 1049281, 1047804, 1049789, 1048860, 1048738, 1048745, 1048049, 1048602, 1051098, 1049035, 1048671, 1049396, 1050519, 1048216, 1051679, 1048898, 1050181, 1048683, 1048012, 1047110], [1046921, 1051092, 1048582, 1048380, 1047337, 1047997, 1049068, 1044394, 1047079, 1048499, 1048347, 1047241, 1046519, 1046573, 1046675, 1047938, 1047246, 1050932, 1047798, 1046227, 1047477, 1048735, 1046706, 1048460, 1048499, 1049259, 1046297, 1049266, 1049116, 1047309, 1046960, 1047881, 1053327, 1048578, 1049377, 1047602, 1047203, 1048565, 1048630, 1048808, 1048006, 1047462, 1048597, 1048506, 1054310, 1044805, 1048353, 1048004, 1048860, 1048733, 1046626, 1048152, 1048044, 1048591, 1046489, 1045186, 1047427, 1048243, 1048304, 1048293, 1048267, 1047768, 1044749, 1046653, 1048077, 1049701, 1048715, 1048003, 1047645, 1048192, 1048040, 1047074, 1048048, 1050559, 1047012, 1049220, 1047349, 1048003, 1047104, 1048490, 1048292, 1047627, 1049485, 1048561, 1048327, 1050628, 1048281, 1048098, 1049397, 1046327, 1047789, 1048037, 1049835, 1046930, 1047562, 1049030, 1047882, 1046762, 1047964, 1046433, 1048447, 1046585, 1044766, 1047152, 1047674, 1047711, 1047932, 1046907, 1048270, 1048415, 1048536, 1047197, 1049128, 1047545, 1047449, 1048074, 1048094, 1048714, 1049060, 1047149, 1047673, 1047880, 1047768, 1047754, 1046852, 1048719, 1047679, 1049104, 1047756, 1049072, 1048579, 1046812, 1048336, 1050330, 1048512, 1048538, 1049680, 1048921, 1048181, 1049319, 1048405, 1048765, 1050630, 1046874, 1050286, 1049545, 1048521, 1049357, 1048579, 1048791, 1050000, 1049424, 1048140, 1049419, 1047063, 1048999, 1047688, 1050490, 1050845, 1047695, 1049591, 1047816, 1047852, 1047146, 1047453, 1048499, 1047512, 1047826, 1047792, 1049381, 1048025, 1048511, 1048222, 1047973, 1048971, 1049558, 1047278, 1047989, 1047302, 1046641, 1048653, 1050392, 1049271, 1047464, 1049499, 1051419, 1048799, 1048194, 1048532, 1048342, 1049208, 1048676, 1049808, 1049646, 1048840, 1047443, 1049446, 1049631, 1048079, 1050471, 1050926, 1051539, 1050853, 1049951, 1050440, 1049850, 1049903, 1049683, 1048364, 1049945, 1049632, 1049893, 1050890, 1050557, 1048866, 1048819, 1052349, 1050286, 1050183, 1051965, 1052267, 1050582, 1051892, 1050397, 1047509, 1047612, 1049979, 1050461, 1047491, 1048837, 1049033, 1049038, 1050897, 1047826, 1049103, 1048343, 1048518, 1049404, 1047471, 1050598, 1050498, 1049336, 1049975, 1049646, 1049397, 1050157, 1050716, 1048149, 1049611, 1048872, 1049652, 1049594, 1048458, 1048956, 1049500, 1050043], [1047175, 1048939, 1047743, 1049164, 1047555, 1047480, 1050764, 1047990, 1048912, 1048430, 1046596, 1046286, 1048659, 1046948, 1048633, 1048670, 1047480, 1048336, 1049250, 1048945, 1050478, 1048072, 1047519, 1049097, 1046869, 1048222, 1047050, 1048376, 1049151, 1048112, 1048914, 1049282, 1049804, 1047090, 1046836, 1047537, 1049549, 1047322, 1046982, 1050367, 1048107, 1047254, 1047655, 1048661, 1047359, 1048688, 1048925, 1049132, 1048378, 1049187, 1046773, 1049114, 1047394, 1048564, 1046917, 1048106, 1048051, 1047318, 1046441, 1050325, 1048741, 1048897, 1046271, 1047881, 1048425, 1049768, 1049402, 1049875, 1054950, 1049542, 1045626, 1048623, 1046411, 1054823, 1048410, 1046801, 1048153, 1047761, 1048004, 1048273, 1047633, 1047385, 1044614, 1047173, 1047779, 1045911, 1045641, 1046573, 1048571, 1045574, 1048295, 1048570, 1048388, 1048825, 1048504, 1047735, 1047345, 1047323, 1049144, 1047446, 1046950, 1047768, 1047154, 1049276, 1047815, 1048192, 1046826, 1048071, 1046699, 1047392, 1047466, 1048369, 1049596, 1048490, 1046596, 1048645, 1049295, 1048467, 1046962, 1047007, 1046463, 1049582, 1048158, 1047658, 1046815, 1047635, 1047590, 1047937, 1048980, 1049904, 1050600, 1050855, 1048895, 1047973, 1049272, 1048794, 1048173, 1049986, 1049105, 1049280, 1047866, 1049609, 1047769, 1048487, 1048257, 1049652, 1046857, 1050062, 1048074, 1049839, 1049078, 1049522, 1049582, 1050061, 1050489, 1048521, 1049176, 1049543, 1050260, 1048867, 1050490, 1050173, 1051969, 1048408, 1050256, 1048867, 1048540, 1050506, 1049115, 1048977, 1050464, 1049410, 1049788, 1049508, 1048578, 1049143, 1048624, 1051217, 1050587, 1050868, 1049963, 1049922, 1048194, 1050568, 1049059, 1050697, 1048045, 1050519, 1047438, 1049785, 1049751, 1050992, 1049581, 1048649, 1049198, 1047653, 1047076, 1047701, 1048116, 1048851, 1050235, 1047141, 1047864, 1048471, 1048270, 1046797, 1048372, 1050053, 1048471, 1048735, 1049945, 1047939, 1049060, 1047375, 1049042, 1048574, 1048734, 1048844, 1049266, 1048053, 1048048, 1048215, 1048604, 1046290, 1047022, 1048360, 1049457, 1048020, 1049595, 1048872, 1048427, 1049428, 1049201, 1048317, 1049282, 1046858, 1049765, 1049457, 1048371, 1047444, 1049807, 1050699, 1048431, 1050844, 1050012, 1049114, 1050185, 1048868, 1048815, 1047251, 1047511, 1050315, 1050132, 1048808, 1048211, 1048672], [1048183, 1048348, 1046773, 1047989, 1048126, 1048254, 1048726, 1047205, 1047809, 1048466, 1047575, 1049005, 1047087, 1048077, 1048742, 1047764, 1047661, 1047757, 1047323, 1046961, 1047688, 1048172, 1047773, 1047400, 1047914, 1047085, 1048656, 1047320, 1047056, 1046009, 1047154, 1049065, 1048111, 1048158, 1047568, 1049894, 1048757, 1048573, 1048059, 1045959, 1049629, 1049038, 1047351, 1047164, 1049244, 1047443, 1048215, 1048077, 1048969, 1049737, 1046207, 1046433, 1049411, 1049211, 1048256, 1048226, 1049209, 1047630, 1047056, 1049146, 1049380, 1048442, 1048688, 1047884, 1047507, 1048694, 1048179, 1047772, 1047705, 1046474, 1045133, 1048613, 1046988, 1047693, 1048164, 1048243, 1047710, 1048477, 1048612, 1047818, 1045771, 1049642, 1054408, 1046882, 1050225, 1048279, 1048249, 1049502, 1047184, 1047489, 1048029, 1050362, 1054224, 1045101, 1048603, 1046518, 1047425, 1046091, 1048399, 1049035, 1048377, 1046942, 1048390, 1047826, 1049570, 1047865, 1048200, 1048419, 1047729, 1047470, 1048382, 1047725, 1046841, 1048238, 1048995, 1046819, 1046784, 1046287, 1049504, 1048525, 1049756, 1047969, 1049295, 1047028, 1049548, 1047183, 1046492, 1048138, 1049256, 1049463, 1048959, 1048165, 1047176, 1050902, 1049315, 1047534, 1048864, 1049132, 1048993, 1048305, 1049589, 1048536, 1047866, 1048600, 1049135, 1049284, 1049220, 1048222, 1049270, 1051906, 1048158, 1047087, 1046993, 1050433, 1048276, 1049510, 1048455, 1052210, 1048468, 1049188, 1047870, 1050980, 1049240, 1051693, 1050715, 1049148, 1050781, 1049925, 1050640, 1048765, 1050021, 1049520, 1049743, 1049324, 1050431, 1048888, 1048363, 1049446, 1049664, 1049016, 1049551, 1050087, 1051837, 1051697, 1049583, 1051482, 1050129, 1050499, 1050439, 1048430, 1050154, 1049257, 1048350, 1050272, 1048410, 1049018, 1050236, 1047208, 1048583, 1048281, 1047603, 1048580, 1048801, 1047209, 1048971, 1047905, 1048078, 1049222, 1050352, 1046725, 1047711, 1049773, 1048920, 1048649, 1048063, 1049778, 1048087, 1046255, 1048443, 1049074, 1047002, 1048744, 1047433, 1049128, 1049746, 1048558, 1048943, 1050208, 1049717, 1047782, 1050086, 1049418, 1051132, 1049122, 1049004, 1047066, 1047990, 1050360, 1050145, 1049437, 1046026, 1048931, 1050107, 1047523, 1047002, 1048914, 1048799, 1047519, 1048502, 1048458, 1050981, 1048167, 1049102, 1049014, 1049374, 1049926], [1048952, 1046977, 1046488, 1048012, 1047439, 1048407, 1047975, 1048220, 1048940, 1046858, 1048820, 1048708, 1049296, 1048070, 1047808, 1048338, 1048344, 1047774, 1047725, 1047877, 1047440, 1049049, 1047497, 1049798, 1047171, 1046343, 1048171, 1048769, 1046819, 1048027, 1049145, 1047604, 1048215, 1048494, 1048076, 1047312, 1047635, 1049329, 1048350, 1046683, 1047315, 1047447, 1045796, 1048666, 1049893, 1047319, 1047338, 1049844, 1048045, 1046958, 1047537, 1048072, 1048142, 1048064, 1047848, 1047525, 1049828, 1047023, 1048401, 1046815, 1049235, 1048450, 1047102, 1048068, 1048249, 1049144, 1048795, 1047871, 1048013, 1047953, 1053325, 1048755, 1047615, 1051415, 1048228, 1049263, 1046060, 1050174, 1046689, 1046839, 1047256, 1049117, 1046893, 1048448, 1047373, 1047318, 1047255, 1048691, 1046018, 1047884, 1046807, 1049525, 1046429, 1047089, 1048627, 1046610, 1046573, 1046139, 1048169, 1048376, 1046924, 1047369, 1047304, 1046307, 1046488, 1048205, 1046324, 1045910, 1047592, 1049035, 1046414, 1045981, 1047920, 1046494, 1048113, 1047921, 1049878, 1046686, 1045304, 1047962, 1047488, 1048066, 1046824, 1048146, 1049395, 1046861, 1047362, 1047528, 1050256, 1048636, 1048687, 1050731, 1049033, 1049361, 1050007, 1049916, 1049233, 1050693, 1048811, 1049923, 1051460, 1048366, 1049237, 1050136, 1051024, 1049525, 1049707, 1048928, 1050131, 1048480, 1050069, 1049158, 1050667, 1048656, 1051392, 1049126, 1048267, 1050220, 1049864, 1048737, 1049548, 1049261, 1050485, 1047798, 1050573, 1050306, 1049165, 1051117, 1049146, 1050028, 1047969, 1050224, 1050332, 1051514, 1050544, 1051498, 1049651, 1051286, 1049240, 1048923, 1048509, 1050979, 1051629, 1051766, 1050678, 1049504, 1050289, 1051025, 1050421, 1051023, 1050063, 1048878, 1050073, 1046999, 1048039, 1049172, 1048308, 1048075, 1049117, 1048789, 1046351, 1046857, 1047507, 1048643, 1048300, 1049427, 1047621, 1048955, 1048765, 1048864, 1048499, 1047948, 1048187, 1049378, 1049946, 1048849, 1048775, 1049541, 1049446, 1048800, 1048819, 1049741, 1048897, 1047159, 1048840, 1048759, 1048591, 1050266, 1047221, 1047850, 1049067, 1049253, 1048937, 1048872, 1049136, 1050317, 1048427, 1048546, 1047170, 1049318, 1048565, 1050188, 1049908, 1049013, 1048263, 1048730, 1048416, 1050618, 1048608, 1049273, 1048351, 1047908, 1048532, 1047193, 1049029, 1050163], [1047269, 1048584, 1048223, 1048077, 1047448, 1048289, 1048212, 1048214, 1050214, 1047287, 1046157, 1048942, 1048187, 1047438, 1046916, 1048180, 1046614, 1047826, 1047451, 1050208, 1047429, 1048875, 1049009, 1048038, 1048500, 1048093, 1048018, 1047203, 1048876, 1046104, 1047488, 1047328, 1048029, 1048583, 1049379, 1049162, 1048364, 1046085, 1047184, 1048962, 1046934, 1048052, 1046949, 1048045, 1047543, 1047412, 1047611, 1045895, 1048598, 1047755, 1049653, 1047877, 1049666, 1047658, 1048986, 1047440, 1047662, 1046865, 1048558, 1050199, 1047669, 1049592, 1048600, 1047097, 1047528, 1049337, 1046328, 1048859, 1047435, 1048915, 1049102, 1050514, 1047992, 1048166, 1047874, 1049938, 1047539, 1047080, 1054089, 1048270, 1047954, 1048540, 1045030, 1049408, 1046909, 1047456, 1047521, 1047326, 1047658, 1047075, 1048753, 1047980, 1045514, 1047682, 1052183, 1046309, 1048156, 1047584, 1048820, 1045661, 1047257, 1047687, 1048797, 1048231, 1048290, 1047204, 1047219, 1047146, 1047293, 1047522, 1048477, 1046107, 1046619, 1048629, 1050340, 1047571, 1047327, 1048954, 1047258, 1047040, 1047592, 1047689, 1048910, 1047823, 1047501, 1048245, 1045739, 1047531, 1049694, 1049881, 1048862, 1047913, 1050158, 1050512, 1048209, 1046174, 1048900, 1048486, 1049160, 1049939, 1048475, 1049930, 1049308, 1047969, 1049540, 1050191, 1051309, 1048422, 1048572, 1049535, 1049120, 1049179, 1048668, 1050137, 1048723, 1048323, 1049019, 1047598, 1048321, 1047723, 1049341, 1049413, 1047521, 1051685, 1048434, 1048912, 1050310, 1049555, 1048491, 1050121, 1050206, 1048615, 1048768, 1049595, 1048703, 1049034, 1050414, 1049492, 1051745, 1048846, 1050076, 1050157, 1051073, 1050522, 1050766, 1049458, 1048010, 1048986, 1049892, 1049426, 1086358, 1048928, 1048831, 1046731, 1046562, 1049208, 1049157, 1048375, 1047831, 1047270, 1045925, 1048000, 1047417, 1048719, 1048980, 1047466, 1047145, 1046037, 1046819, 1047649, 1048433, 1048864, 1047045, 1048149, 1049217, 1047801, 1048251, 1050327, 1049103, 1049857, 1049275, 1047838, 1048829, 1048366, 1049266, 1048040, 1049075, 1048705, 1049649, 1049862, 1049399, 1046186, 1047840, 1049595, 1048372, 1047436, 1047860, 1049784, 1047790, 1048400, 1048744, 1048940, 1050055, 1048767, 1047915, 1050590, 1049558, 1049471, 1049075, 1049325, 1047741, 1048619, 1048842, 1051597, 1048236, 1049198], [1048720, 1047795, 1048500, 1046862, 1047789, 1049013, 1048951, 1047037, 1048036, 1047515, 1049291, 1047593, 1047033, 1046975, 1048668, 1048369, 1047656, 1050127, 1046368, 1049133, 1048027, 1048149, 1048173, 1047795, 1048640, 1047215, 1049117, 1048794, 1047986, 1048225, 1048728, 1047895, 1046974, 1047799, 1046573, 1050287, 1047282, 1048223, 1045542, 1047262, 1048020, 1047093, 1048785, 1048462, 1048598, 1048965, 1049785, 1047760, 1048397, 1047280, 1047337, 1048962, 1050487, 1047951, 1046766, 1048056, 1049264, 1047328, 1048838, 1047046, 1047906, 1048568, 1047489, 1047572, 1047878, 1047473, 1049762, 1048211, 1046463, 1048645, 1047503, 1047950, 1046983, 1048406, 1048813, 1053602, 1046507, 1047683, 1046177, 1048196, 1048431, 1047191, 1049326, 1049710, 1049521, 1045845, 1047647, 1047605, 1049623, 1047143, 1055434, 1046698, 1048951, 1048458, 1047282, 1046892, 1047558, 1047841, 1046559, 1046903, 1049419, 1047453, 1046276, 1045914, 1047805, 1048924, 1046674, 1048554, 1047307, 1046895, 1048858, 1047895, 1047008, 1047018, 1046651, 1047818, 1046487, 1051080, 1047239, 1048553, 1047795, 1047252, 1049902, 1047540, 1047876, 1047875, 1048261, 1046307, 1049016, 1049712, 1050098, 1049008, 1049147, 1049950, 1049055, 1050658, 1047806, 1049672, 1050858, 1047918, 1049463, 1047419, 1050365, 1048848, 1050785, 1048240, 1048657, 1048755, 1049742, 1048361, 1050997, 1049685, 1047936, 1048950, 1049717, 1048908, 1050454, 1049602, 1049427, 1047152, 1050820, 1049368, 1049915, 1050024, 1049578, 1049892, 1052385, 1048507, 1049387, 1049140, 1049247, 1049161, 1049807, 1049631, 1049615, 1050464, 1051367, 1050076, 1050607, 1050286, 1050037, 1050308, 1051119, 1049984, 1048888, 1049898, 1049804, 1049966, 1050181, 1048871, 1049641, 1050094, 1048849, 1048689, 1048261, 1049420, 1048939, 1048423, 1048848, 1048737, 1048374, 1051029, 1047855, 1048370, 1047305, 1047982, 1047758, 1048835, 1048704, 1051223, 1047590, 1049247, 1047713, 1049294, 1050215, 1048145, 1046673, 1048825, 1049497, 1047389, 1047718, 1048292, 1048151, 1049166, 1048101, 1048849, 1050574, 1047006, 1047847, 1050250, 1048233, 1049373, 1049371, 1048663, 1048123, 1048950, 1047861, 1048222, 1048040, 1046659, 1047585, 1050202, 1049216, 1049411, 1050665, 1050241, 1047470, 1050186, 1048310, 1046827, 1048979, 1048848, 1047828, 1048932, 1047672, 1048679], [1049673, 1047443, 1048519, 1048805, 1046230, 1048076, 1046969, 1048457, 1047514, 1048231, 1047453, 1046638, 1046519, 1048652, 1048377, 1046243, 1048488, 1048484, 1047973, 1046432, 1046415, 1047993, 1048719, 1047553, 1048311, 1047459, 1047669, 1047601, 1048845, 1046270, 1046981, 1047151, 1054416, 1046993, 1049551, 1048765, 1048103, 1046738, 1048950, 1049568, 1049244, 1045655, 1047891, 1048862, 1049373, 1048863, 1047664, 1047362, 1048523, 1047872, 1054604, 1047554, 1048565, 1048197, 1047737, 1048588, 1048713, 1045349, 1047056, 1047452, 1048209, 1047093, 1048166, 1047250, 1047412, 1048924, 1048156, 1047333, 1048559, 1046858, 1049056, 1047232, 1050043, 1047737, 1049041, 1048420, 1048304, 1047762, 1048096, 1046359, 1047642, 1048031, 1048619, 1046295, 1047594, 1047487, 1046983, 1047997, 1045037, 1047026, 1047857, 1048592, 1048327, 1048338, 1049502, 1049156, 1047268, 1047670, 1046569, 1047431, 1049566, 1048012, 1047750, 1046938, 1048198, 1049008, 1047678, 1048942, 1047038, 1047819, 1049823, 1048158, 1049873, 1049034, 1048970, 1049341, 1049550, 1047121, 1047948, 1048354, 1048862, 1048049, 1047713, 1049371, 1049839, 1049264, 1048206, 1047694, 1049059, 1050139, 1050510, 1050173, 1048264, 1049250, 1046971, 1047816, 1049180, 1047620, 1049257, 1048975, 1047552, 1048876, 1049139, 1048138, 1048788, 1049112, 1049640, 1049549, 1049748, 1049880, 1047913, 1049565, 1048475, 1050407, 1048274, 1048190, 1051016, 1049429, 1050080, 1048613, 1047296, 1048655, 1047329, 1050043, 1047608, 1048205, 1048121, 1045748, 1048363, 1049052, 1048832, 1047973, 1048115, 1047541, 1046628, 1047341, 1049034, 1048864, 1048051, 1048199, 1048348, 1046848, 1047289, 1049141, 1046888, 1047371, 1046564, 1049191, 1050552, 1048753, 1049839, 1048650, 1050790, 1050859, 1050302, 1050137, 1047419, 1050242, 1047533, 1049666, 1050428, 1049789, 1050307, 1047663, 1049342, 1049972, 1049022, 1050423, 1050628, 1051430, 1050520, 1050791, 1049611, 1050167, 1049968, 1050567, 1050228, 1048471, 1050175, 1049992, 1052134, 1050691, 1051642, 1049339, 1049596, 1048288, 1050261, 1047417, 1048294, 1048700, 1051306, 1048208, 1048566, 1048679, 1049131, 1047898, 1049872, 1047624, 1048184, 1048777, 1050284, 1047825, 1050511, 1048074, 1048707, 1051154, 1048401, 1049487, 1049188, 1051286, 1049742, 1049030, 1048310, 1047380, 1049531, 1049566], [1048050, 1048521, 1049361, 1049692, 1048175, 1049744, 1047829, 1048012, 1050070, 1047088, 1048229, 1047863, 1045319, 1048428, 1046292, 1048270, 1047229, 1048032, 1047875, 1049315, 1048547, 1047971, 1045788, 1048607, 1046664, 1047569, 1045727, 1049786, 1048233, 1048627, 1048447, 1047055, 1046703, 1048931, 1048155, 1048761, 1045024, 1049003, 1047178, 1048115, 1046835, 1047917, 1048805, 1047699, 1048359, 1048178, 1046331, 1049511, 1047616, 1049623, 1049417, 1048809, 1046817, 1047608, 1048061, 1048098, 1046718, 1046996, 1048772, 1049006, 1048024, 1047555, 1048767, 1047604, 1047373, 1048713, 1046828, 1045827, 1047565, 1047522, 1048589, 1049522, 1049057, 1047473, 1052801, 1047961, 1048667, 1046642, 1046846, 1048373, 1049910, 1048092, 1046844, 1048205, 1048437, 1047113, 1047265, 1047741, 1047797, 1053056, 1048219, 1047208, 1048029, 1048327, 1047863, 1048097, 1046108, 1045876, 1046939, 1045799, 1046878, 1048206, 1048807, 1049277, 1047442, 1047898, 1048218, 1046749, 1047123, 1046951, 1048506, 1045575, 1047761, 1048130, 1048518, 1046184, 1046567, 1048605, 1048380, 1047259, 1048079, 1048423, 1048632, 1047091, 1047524, 1047955, 1048636, 1047019, 1049073, 1047834, 1049607, 1049561, 1049999, 1049150, 1048851, 1050053, 1047572, 1050059, 1049847, 1049265, 1047680, 1048414, 1050020, 1049760, 1047833, 1049030, 1050144, 1050312, 1050118, 1051677, 1048953, 1051005, 1048738, 1050468, 1047691, 1048185, 1051050, 1047859, 1049582, 1048877, 1050597, 1052470, 1049711, 1051221, 1051234, 1048165, 1051828, 1049633, 1051237, 1050647, 1049760, 1049490, 1050161, 1050938, 1050511, 1049419, 1049051, 1050302, 1051284, 1049910, 1051206, 1049089, 1050219, 1049941, 1050614, 1049379, 1050534, 1049743, 1048885, 1049941, 1048873, 1050946, 1049439, 1049847, 1048205, 1049233, 1049004, 1050039, 1046885, 1050012, 1050833, 1048318, 1048260, 1049063, 1047122, 1048558, 1047802, 1048984, 1049107, 1048003, 1050058, 1047744, 1048286, 1047900, 1048392, 1048977, 1049026, 1048396, 1046977, 1047574, 1047636, 1047832, 1047776, 1048901, 1048524, 1049255, 1049562, 1048813, 1050458, 1048148, 1050562, 1047859, 1049940, 1047626, 1047417, 1048519, 1047627, 1048488, 1047609, 1050154, 1049475, 1049844, 1048044, 1048059, 1047454, 1045633, 1048422, 1049875, 1047672, 1050959, 1048650, 1049841, 1048428, 1048140, 1049234, 1051282], [1047645, 1046757, 1048093, 1047669, 1046411, 1048942, 1049452, 1047369, 1048255, 1046058, 1048434, 1046344, 1047195, 1046482, 1046438, 1047084, 1049104, 1048367, 1047929, 1048985, 1049159, 1048362, 1045827, 1048952, 1047597, 1049064, 1049867, 1048848, 1046094, 1049218, 1047898, 1048691, 1048243, 1047800, 1050399, 1048980, 1047610, 1047119, 1047646, 1048239, 1048780, 1048228, 1049050, 1048030, 1047350, 1049113, 1047161, 1049890, 1046383, 1046708, 1049158, 1047934, 1048496, 1049586, 1047850, 1048299, 1048285, 1049523, 1048475, 1048318, 1046784, 1049425, 1049009, 1047295, 1048625, 1048559, 1048944, 1048700, 1046784, 1048283, 1047250, 1048725, 1047397, 1048435, 1047476, 1048558, 1047266, 1047294, 1047529, 1054494, 1047302, 1048306, 1047317, 1048245, 1046893, 1048870, 1046399, 1047641, 1047436, 1048984, 1048395, 1053700, 1048236, 1048791, 1049203, 1047872, 1046997, 1046324, 1046862, 1047763, 1047579, 1046783, 1047647, 1048009, 1047724, 1047532, 1047535, 1048118, 1046314, 1047349, 1048340, 1048631, 1047854, 1046784, 1047353, 1048690, 1047478, 1046206, 1046257, 1047487, 1048562, 1049013, 1045795, 1047865, 1044546, 1048878, 1046842, 1048713, 1049772, 1047424, 1049343, 1048094, 1048450, 1048914, 1048575, 1049398, 1049771, 1050368, 1049228, 1048445, 1049097, 1047807, 1050012, 1047705, 1050185, 1049074, 1049426, 1050641, 1048692, 1049158, 1048720, 1047327, 1050067, 1050994, 1049313, 1048215, 1049473, 1048395, 1049818, 1049261, 1048934, 1049538, 1051442, 1049825, 1049597, 1050517, 1050076, 1050124, 1050064, 1049350, 1050494, 1049220, 1049260, 1049691, 1050480, 1047821, 1049703, 1050970, 1051142, 1051113, 1048480, 1050165, 1050414, 1049251, 1050414, 1049157, 1051296, 1051716, 1049459, 1050219, 1050523, 1050823, 1048232, 1049078, 1048204, 1048273, 1047744, 1049239, 1048958, 1049033, 1047391, 1047819, 1048605, 1047547, 1048556, 1048225, 1048892, 1049275, 1049632, 1046761, 1048600, 1048217, 1047697, 1050405, 1048720, 1048945, 1048585, 1050056, 1047045, 1049174, 1049985, 1047146, 1050212, 1049458, 1047777, 1048066, 1048857, 1049100, 1050407, 1049162, 1049730, 1048392, 1048448, 1048823, 1048433, 1048093, 1049335, 1048586, 1049563, 1049485, 1049328, 1048089, 1049451, 1048976, 1049128, 1047984, 1047829, 1049251, 1047876, 1049749, 1048061, 1048753, 1050665, 1048533, 1048212, 1049670], [1049412, 1047936, 1046415, 1047631, 1048265, 1047633, 1047939, 1048251, 1047297, 1048994, 1049568, 1048415, 1047223, 1048410, 1048710, 1047704, 1050330, 1049670, 1048580, 1048236, 1048731, 1048453, 1047990, 1047351, 1046946, 1048139, 1048523, 1047903, 1049307, 1047418, 1047798, 1047390, 1047148, 1049884, 1047994, 1047559, 1048391, 1049846, 1047270, 1048720, 1047158, 1049602, 1047289, 1048522, 1049658, 1049918, 1046834, 1047000, 1048884, 1047095, 1047745, 1047746, 1046970, 1046599, 1048055, 1046986, 1048937, 1048570, 1048323, 1045519, 1045725, 1047817, 1047276, 1047524, 1054183, 1048588, 1047550, 1046063, 1047813, 1048800, 1048280, 1047366, 1049377, 1046924, 1049251, 1048591, 1048074, 1047785, 1047089, 1048115, 1048395, 1049982, 1047612, 1049454, 1048247, 1053387, 1048875, 1047724, 1049406, 1050991, 1047584, 1048108, 1048909, 1048750, 1047746, 1047038, 1047492, 1048322, 1048896, 1047357, 1048041, 1047965, 1046991, 1047784, 1046256, 1048466, 1046562, 1048104, 1045756, 1047874, 1048568, 1047619, 1047202, 1047400, 1047550, 1047048, 1046980, 1045874, 1047755, 1047426, 1046003, 1047620, 1048241, 1046890, 1047948, 1047743, 1047991, 1048044, 1049836, 1049648, 1048666, 1049465, 1049900, 1050000, 1051380, 1048265, 1049856, 1049726, 1049769, 1050741, 1048064, 1049653, 1048677, 1051323, 1046803, 1048297, 1048542, 1048556, 1051101, 1050304, 1049058, 1049367, 1048857, 1050900, 1049237, 1048726, 1050137, 1047546, 1047655, 1051207, 1048929, 1051177, 1050631, 1049966, 1048193, 1050607, 1050779, 1049656, 1050505, 1049814, 1049059, 1049346, 1049407, 1050387, 1048837, 1050436, 1049160, 1051080, 1050440, 1049445, 1049928, 1049030, 1048871, 1048449, 1049086, 1049833, 1049772, 1047842, 1050741, 1050014, 1050002, 1050585, 1047301, 1048679, 1047909, 1049354, 1049291, 1047277, 1049436, 1047033, 1048987, 1049402, 1048524, 1046618, 1047449, 1050035, 1048940, 1048671, 1047513, 1048758, 1046982, 1048272, 1048582, 1048934, 1048501, 1046727, 1049722, 1049287, 1048407, 1047659, 1048757, 1047263, 1047732, 1047673, 1050140, 1048271, 1047699, 1048598, 1049277, 1047451, 1048179, 1047739, 1049121, 1048793, 1049700, 1049194, 1049124, 1049268, 1050157, 1050360, 1048716, 1047586, 1048345, 1048794, 1049342, 1049271, 1047783, 1048651, 1048506, 1048273, 1049491, 1050091, 1050188, 1048922, 1048270, 1050255], [1048926, 1046192, 1048474, 1047963, 1046699, 1048506, 1047227, 1048380, 1047761, 1048571, 1049006, 1047672, 1046684, 1047346, 1048937, 1047765, 1047379, 1050454, 1046640, 1047476, 1048348, 1046193, 1048242, 1048652, 1047619, 1046456, 1045409, 1047565, 1048530, 1047539, 1050377, 1046066, 1047587, 1048403, 1049142, 1047901, 1047892, 1051085, 1047601, 1046919, 1048707, 1049356, 1049372, 1048175, 1047632, 1049305, 1049623, 1047772, 1047430, 1048261, 1049003, 1047594, 1047704, 1048978, 1049604, 1049922, 1047665, 1049043, 1045703, 1048434, 1048572, 1046944, 1049837, 1047505, 1048079, 1047201, 1048912, 1046612, 1054645, 1048201, 1046832, 1046419, 1047306, 1048698, 1047070, 1046297, 1046816, 1048351, 1046860, 1047649, 1047626, 1050450, 1053064, 1047038, 1046799, 1046897, 1048386, 1047781, 1047827, 1047037, 1049470, 1048100, 1048479, 1048181, 1049151, 1049341, 1048133, 1046019, 1047410, 1046561, 1047348, 1048346, 1049691, 1048275, 1047028, 1046167, 1047463, 1047742, 1047215, 1048070, 1047688, 1046993, 1047211, 1047302, 1046887, 1047257, 1048221, 1047927, 1048130, 1047282, 1047436, 1047214, 1046984, 1047064, 1048621, 1048043, 1046905, 1047836, 1048383, 1049321, 1051154, 1047301, 1049624, 1050846, 1048947, 1050398, 1051188, 1049163, 1048315, 1048992, 1048147, 1048610, 1049024, 1050333, 1048986, 1050156, 1049129, 1048828, 1048839, 1048275, 1048644, 1050348, 1050142, 1049382, 1049038, 1050016, 1050244, 1050673, 1048020, 1048588, 1050206, 1050095, 1048036, 1051065, 1051399, 1051079, 1048047, 1048889, 1051255, 1048896, 1050989, 1050268, 1050432, 1051715, 1048577, 1049697, 1050458, 1049748, 1046465, 1050076, 1049328, 1050457, 1048516, 1049352, 1048264, 1049455, 1050365, 1049868, 1050383, 1049322, 1052400, 1050459, 1048320, 1048760, 1047607, 1047929, 1049633, 1048556, 1048057, 1047060, 1048049, 1047405, 1047833, 1048510, 1049578, 1048772, 1048552, 1048929, 1047060, 1047718, 1048889, 1049423, 1049552, 1048691, 1049908, 1050869, 1049279, 1048244, 1048409, 1049339, 1047997, 1048259, 1047284, 1048397, 1048931, 1049433, 1047474, 1048212, 1049545, 1049444, 1047607, 1049564, 1048257, 1050241, 1048659, 1048718, 1048264, 1048468, 1048102, 1048577, 1048889, 1049117, 1049657, 1050745, 1049309, 1049065, 1048549, 1049425, 1049350, 1048810, 1048601, 1049157, 1048362, 1048173, 1050345, 1051154], [1048509, 1047701, 1048009, 1047671, 1047052, 1047385, 1045321, 1047870, 1047350, 1047904, 1046828, 1049573, 1048157, 1048682, 1046342, 1047541, 1049296, 1046800, 1049160, 1045979, 1046727, 1046717, 1047908, 1048867, 1047042, 1049366, 1047045, 1047910, 1046781, 1048030, 1047365, 1046198, 1054989, 1049676, 1049130, 1049405, 1050967, 1048648, 1046535, 1048416, 1046406, 1047138, 1046101, 1048845, 1048065, 1049575, 1048207, 1048906, 1047446, 1048585, 1048693, 1047095, 1048728, 1047891, 1048658, 1055150, 1047046, 1048597, 1048167, 1048820, 1047182, 1048733, 1046929, 1048459, 1048846, 1047117, 1047816, 1047799, 1048330, 1048335, 1048515, 1047887, 1047147, 1049933, 1047424, 1048453, 1048708, 1047429, 1046562, 1048298, 1048917, 1048496, 1049044, 1048783, 1046503, 1049245, 1046950, 1048390, 1047805, 1050480, 1046903, 1047707, 1047884, 1046821, 1048193, 1047455, 1047876, 1048767, 1046846, 1048827, 1046853, 1048506, 1048706, 1045694, 1049313, 1048545, 1049373, 1047619, 1046817, 1047830, 1047551, 1047718, 1047263, 1048362, 1048470, 1047960, 1047390, 1046644, 1047622, 1047194, 1047380, 1048554, 1047224, 1049114, 1047508, 1048032, 1046719, 1047501, 1050143, 1048207, 1047973, 1048427, 1049928, 1049232, 1050095, 1047865, 1049532, 1047730, 1050137, 1048811, 1049103, 1049046, 1047879, 1048801, 1046604, 1049115, 1049196, 1049343, 1048802, 1046373, 1049592, 1046965, 1046189, 1049029, 1048982, 1047981, 1050719, 1050073, 1050656, 1048313, 1050982, 1047933, 1049306, 1047620, 1047564, 1048768, 1048011, 1049046, 1048938, 1049441, 1047790, 1047947, 1047384, 1048873, 1050176, 1048247, 1049022, 1047948, 1050869, 1047632, 1049840, 1047706, 1049063, 1049090, 1049451, 1048614, 1049667, 1048979, 1048661, 1047907, 1048680, 1049662, 1047652, 1048101, 1049308, 1050269, 1049468, 1049614, 1049630, 1049128, 1048952, 1049649, 1049191, 1048683, 1050963, 1050372, 1048660, 1051683, 1050370, 1048979, 1049587, 1049155, 1051110, 1047990, 1048627, 1050989, 1049458, 1048908, 1051413, 1049842, 1050793, 1050054, 1047908, 1049745, 1048932, 1048942, 1049260, 1049733, 1048607, 1048564, 1050063, 1048290, 1050038, 1051343, 1049333, 1051904, 1049706, 1047151, 1047538, 1047483, 1047816, 1050044, 1049018, 1048759, 1049141, 1050010, 1050674, 1048038, 1051213, 1050608, 1049211, 1049809, 1049589, 1049199, 1049575, 1049729], [1049244, 1047513, 1048490, 1048215, 1046870, 1048546, 1048641, 1049733, 1046813, 1047909, 1048644, 1047829, 1048678, 1048950, 1047000, 1048397, 1047295, 1047074, 1047852, 1047441, 1047821, 1048241, 1047765, 1047218, 1047891, 1049135, 1048558, 1048494, 1047093, 1047100, 1048522, 1048094, 1049767, 1046279, 1049481, 1048091, 1050348, 1048689, 1048030, 1046895, 1049309, 1047228, 1047373, 1047691, 1049656, 1049402, 1047834, 1047321, 1046987, 1048504, 1049315, 1047862, 1047658, 1046802, 1047923, 1048016, 1047082, 1049459, 1047890, 1045837, 1048024, 1047080, 1048516, 1049365, 1048366, 1050635, 1047518, 1049087, 1046526, 1047759, 1048946, 1048095, 1048131, 1048295, 1048128, 1047468, 1047286, 1047655, 1048347, 1054316, 1048968, 1047094, 1048663, 1046712, 1046077, 1047537, 1044664, 1054051, 1048181, 1048974, 1048094, 1048620, 1049159, 1049557, 1048735, 1047528, 1045799, 1046189, 1047891, 1047767, 1049944, 1046933, 1048516, 1048117, 1047069, 1048909, 1049478, 1047526, 1048133, 1046644, 1047148, 1047092, 1046600, 1048525, 1048883, 1048733, 1049463, 1046551, 1048513, 1046252, 1047893, 1046378, 1047713, 1047802, 1046562, 1045237, 1047914, 1048239, 1047695, 1049874, 1050757, 1050722, 1048515, 1048892, 1049093, 1049381, 1049822, 1049342, 1049712, 1048330, 1050571, 1048936, 1048071, 1049256, 1049925, 1047744, 1049340, 1048627, 1048125, 1047903, 1049526, 1049949, 1049748, 1049646, 1048645, 1050740, 1047754, 1050095, 1049668, 1048807, 1050756, 1048706, 1050745, 1052777, 1050891, 1048989, 1050374, 1050157, 1051169, 1048843, 1049351, 1049399, 1048404, 1049614, 1047134, 1049043, 1049981, 1050078, 1050104, 1048738, 1050919, 1051273, 1046837, 1049434, 1049856, 1049291, 1048264, 1049889, 1051355, 1050927, 1049422, 1048849, 1048897, 1048876, 1049728, 1048320, 1047795, 1048283, 1048689, 1047537, 1047842, 1049896, 1049583, 1047367, 1048482, 1047543, 1048846, 1049107, 1048394, 1048658, 1048004, 1048195, 1048227, 1048558, 1049845, 1048432, 1046355, 1045813, 1048267, 1049955, 1048300, 1048129, 1047298, 1048784, 1048249, 1048043, 1048625, 1050614, 1049256, 1049659, 1048155, 1049472, 1047072, 1048788, 1049157, 1047635, 1048274, 1046771, 1050365, 1048482, 1048404, 1049116, 1050412, 1051215, 1049357, 1048446, 1046989, 1050760, 1051102, 1048548, 1049325, 1049659, 1049640, 1050426, 1050600, 1047690], [1045714, 1048259, 1045941, 1047640, 1046451, 1047170, 1046641, 1047220, 1049056, 1047257, 1047210, 1046401, 1049224, 1049731, 1050044, 1048818, 1048066, 1046836, 1047678, 1047969, 1046620, 1047747, 1051338, 1046581, 1047218, 1047908, 1046473, 1049431, 1048835, 1047845, 1044963, 1047327, 1047953, 1047183, 1048640, 1046649, 1047463, 1048575, 1047885, 1048679, 1050396, 1048597, 1048769, 1048386, 1048689, 1048709, 1047894, 1047597, 1049187, 1049231, 1047654, 1046851, 1048803, 1048632, 1046823, 1048314, 1046574, 1047015, 1049804, 1049202, 1048422, 1047934, 1049704, 1047555, 1047697, 1048232, 1050678, 1047253, 1049237, 1047277, 1047204, 1048492, 1047251, 1049078, 1046441, 1048611, 1049549, 1047785, 1048990, 1053963, 1047636, 1047733, 1048719, 1047854, 1047784, 1048752, 1054327, 1047742, 1050405, 1047034, 1047056, 1047974, 1045988, 1048676, 1048375, 1049620, 1048509, 1047472, 1048067, 1048120, 1046952, 1048583, 1046953, 1045692, 1048805, 1047933, 1048940, 1048849, 1047713, 1045961, 1047292, 1047675, 1049339, 1048791, 1047281, 1048264, 1048473, 1047259, 1045569, 1047791, 1047719, 1045584, 1046721, 1047415, 1047286, 1048244, 1048659, 1047819, 1049392, 1050055, 1048470, 1048424, 1049054, 1048132, 1049521, 1049917, 1050953, 1049611, 1049301, 1048706, 1049433, 1047245, 1049071, 1049751, 1050290, 1048261, 1051310, 1049799, 1050188, 1049255, 1049125, 1049256, 1049080, 1048428, 1050496, 1049617, 1049475, 1049200, 1049319, 1050339, 1048569, 1051493, 1050142, 1050226, 1048451, 1051035, 1050351, 1050995, 1049845, 1049306, 1049451, 1050225, 1050001, 1049663, 1049665, 1050433, 1048757, 1049436, 1048826, 1052553, 1049121, 1051650, 1050517, 1048067, 1051856, 1050088, 1049904, 1048356, 1050083, 1050610, 1049311, 1050738, 1048584, 1047037, 1049119, 1047265, 1048152, 1048310, 1048560, 1048153, 1046937, 1047217, 1048227, 1052125, 1048766, 1047950, 1048554, 1048043, 1048294, 1049257, 1048318, 1046402, 1049173, 1047641, 1047138, 1047725, 1048159, 1047367, 1047995, 1047672, 1048009, 1047929, 1046033, 1047907, 1048047, 1048913, 1049984, 1048676, 1047219, 1048687, 1048707, 1050844, 1049276, 1050450, 1049454, 1047353, 1050550, 1050660, 1048467, 1049107, 1049129, 1048420, 1048975, 1048880, 1049237, 1049264, 1047425, 1048441, 1049511, 1048314, 1048401, 1050151, 1049522, 1047933, 1048869, 1049850], [1047272, 1047481, 1045933, 1048336, 1047378, 1046069, 1048100, 1047533, 1047147, 1047540, 1047847, 1049834, 1047916, 1047931, 1047684, 1048129, 1048005, 1048705, 1048294, 1047827, 1047520, 1048655, 1048740, 1048556, 1047297, 1048393, 1048049, 1046593, 1049057, 1047451, 1047684, 1046371, 1048331, 1048025, 1046435, 1047713, 1048727, 1046928, 1048520, 1046418, 1048621, 1047637, 1046610, 1049593, 1047533, 1049517, 1049238, 1048766, 1049324, 1047954, 1047503, 1047491, 1048053, 1049898, 1049372, 1048182, 1047596, 1046859, 1048405, 1049666, 1049371, 1048964, 1048524, 1048941, 1046913, 1052919, 1050465, 1048063, 1046913, 1049027, 1047990, 1048931, 1046624, 1047139, 1047190, 1046638, 1049253, 1048838, 1048572, 1049057, 1047007, 1047080, 1048403, 1048107, 1047343, 1048611, 1048412, 1048169, 1047650, 1048471, 1046597, 1054315, 1049097, 1047023, 1046365, 1047848, 1048115, 1046779, 1046776, 1048234, 1048044, 1049227, 1046633, 1047069, 1048986, 1049712, 1047073, 1049309, 1047613, 1046356, 1048350, 1048215, 1047118, 1047955, 1048193, 1046744, 1048920, 1048424, 1049138, 1048094, 1049170, 1049839, 1047136, 1049143, 1047483, 1047902, 1049319, 1047011, 1048119, 1048340, 1051892, 1049601, 1047831, 1049495, 1051779, 1047388, 1051524, 1049434, 1049439, 1048972, 1050277, 1050000, 1049143, 1050741, 1049098, 1050752, 1048675, 1049236, 1048349, 1048282, 1049565, 1050948, 1049519, 1048736, 1051294, 1047521, 1050958, 1049124, 1052043, 1048903, 1050317, 1048672, 1047797, 1050806, 1048745, 1049588, 1048050, 1047695, 1050311, 1049460, 1049773, 1048290, 1047220, 1050047, 1049543, 1049286, 1047924, 1049949, 1050755, 1049166, 1049224, 1049544, 1049381, 1049236, 1049928, 1051116, 1048531, 1050508, 1049201, 1050721, 1050482, 1049847, 1047959, 1047925, 1049702, 1048587, 1049081, 1049421, 1048618, 1047400, 1049552, 1047328, 1048650, 1049220, 1046399, 1047417, 1048129, 1047968, 1049505, 1050536, 1047962, 1046622, 1049232, 1049507, 1049402, 1046838, 1047267, 1047404, 1048832, 1049027, 1048118, 1049495, 1047237, 1050087, 1047670, 1047079, 1048419, 1049890, 1047320, 1048557, 1048070, 1049601, 1048179, 1050046, 1047933, 1048112, 1047152, 1048291, 1047659, 1047314, 1049274, 1049491, 1049689, 1049314, 1049438, 1049558, 1049685, 1046960, 1049134, 1050922, 1048240, 1050948, 1049630, 1049129, 1048520, 1048562], [1046024, 1048784, 1048202, 1047962, 1047094, 1048080, 1048587, 1049141, 1045368, 1048199, 1048908, 1046848, 1045623, 1046341, 1047873, 1047019, 1047439, 1048012, 1046369, 1048273, 1047789, 1049586, 1048761, 1046849, 1048578, 1047934, 1046815, 1046713, 1047752, 1047709, 1048886, 1046740, 1046580, 1047236, 1047626, 1049672, 1048777, 1048689, 1048423, 1046980, 1047043, 1049020, 1047366, 1046418, 1047513, 1047107, 1048648, 1048537, 1047181, 1047734, 1046831, 1048579, 1047019, 1046858, 1048703, 1047798, 1049809, 1048978, 1047658, 1047663, 1049121, 1048497, 1047949, 1049625, 1049190, 1047430, 1048553, 1048017, 1047985, 1046894, 1048483, 1049201, 1045986, 1047718, 1047470, 1048232, 1053727, 1048060, 1046644, 1047855, 1046931, 1045876, 1047858, 1048007, 1047570, 1046925, 1049581, 1054379, 1049612, 1047750, 1049108, 1046358, 1047495, 1046352, 1047037, 1047447, 1047177, 1048100, 1047684, 1047627, 1048023, 1046354, 1049299, 1048682, 1047524, 1048698, 1049054, 1049217, 1046908, 1047684, 1047293, 1047641, 1048345, 1048130, 1046844, 1048593, 1049296, 1049975, 1047783, 1047184, 1047156, 1049348, 1048179, 1048395, 1046509, 1048596, 1046698, 1047627, 1047463, 1049247, 1047889, 1048544, 1049536, 1049321, 1050989, 1050107, 1049348, 1049842, 1050521, 1048539, 1048091, 1048205, 1048164, 1049218, 1049933, 1049196, 1050003, 1050158, 1048884, 1047727, 1049580, 1047731, 1048976, 1050581, 1048455, 1051766, 1049684, 1050021, 1049577, 1048838, 1048063, 1051458, 1050773, 1048481, 1050041, 1049231, 1048993, 1048953, 1048520, 1049408, 1048302, 1049893, 1050617, 1049840, 1049629, 1050885, 1048327, 1050565, 1048796, 1051930, 1050063, 1050383, 1051142, 1051252, 1051924, 1048960, 1049731, 1049404, 1051454, 1048582, 1051092, 1050601, 1049949, 1046499, 1049716, 1047346, 1049570, 1047675, 1048585, 1048053, 1050883, 1049377, 1047590, 1048187, 1048079, 1049021, 1046654, 1048395, 1050408, 1048292, 1047229, 1050351, 1049007, 1048370, 1049604, 1048647, 1049511, 1050265, 1048432, 1048454, 1048664, 1049860, 1047780, 1046976, 1049197, 1050979, 1048806, 1048930, 1047813, 1049351, 1050229, 1049456, 1049038, 1049959, 1049297, 1048148, 1048762, 1048526, 1048891, 1050208, 1048268, 1051039, 1050006, 1048399, 1047400, 1048206, 1048413, 1048369, 1048641, 1049208, 1049233, 1051847, 1049271, 1047250, 1048356, 1047854], [1047962, 1048510, 1046399, 1048541, 1045845, 1047562, 1047918, 1046811, 1047233, 1049269, 1048925, 1049430, 1048494, 1046975, 1049617, 1047542, 1049668, 1047860, 1045775, 1049628, 1046445, 1047422, 1047413, 1046111, 1047899, 1048298, 1048420, 1048180, 1047691, 1049055, 1049042, 1048036, 1048432, 1049817, 1045936, 1047681, 1048676, 1046555, 1048709, 1049847, 1048849, 1048606, 1048008, 1049325, 1047604, 1048806, 1049791, 1049989, 1047935, 1046848, 1048749, 1046805, 1048650, 1048392, 1047346, 1047310, 1048027, 1049327, 1048977, 1048084, 1046336, 1047248, 1047262, 1048258, 1047422, 1046282, 1047104, 1050352, 1049806, 1048083, 1048299, 1048586, 1053429, 1046941, 1047429, 1048036, 1048631, 1049892, 1048618, 1048584, 1047704, 1048724, 1046501, 1046920, 1054645, 1049171, 1047898, 1048639, 1048147, 1049481, 1048499, 1048723, 1048815, 1048499, 1048842, 1048524, 1047710, 1047675, 1047044, 1048026, 1048383, 1046438, 1048398, 1046567, 1046746, 1046818, 1048865, 1046879, 1048526, 1046677, 1047998, 1048987, 1047390, 1047662, 1046166, 1047997, 1050003, 1048233, 1047108, 1046525, 1046413, 1049292, 1046580, 1046927, 1045763, 1047781, 1047778, 1046575, 1048225, 1050429, 1050015, 1050038, 1050516, 1049678, 1047807, 1048392, 1048551, 1049752, 1047719, 1049358, 1050360, 1048223, 1051427, 1049811, 1049562, 1048912, 1050694, 1049173, 1048653, 1048607, 1049148, 1049615, 1048371, 1050171, 1048633, 1050027, 1050211, 1050351, 1048573, 1048120, 1048830, 1051460, 1050099, 1049934, 1050868, 1050151, 1049647, 1048719, 1049697, 1049818, 1046798, 1051430, 1050511, 1049529, 1049513, 1050582, 1049126, 1049651, 1051494, 1050775, 1050511, 1048767, 1048756, 1049101, 1050740, 1049305, 1050118, 1051219, 1050414, 1050260, 1048998, 1049424, 1048166, 1048777, 1049299, 1048894, 1048105, 1050201, 1047239, 1045370, 1047387, 1049614, 1049666, 1047416, 1050572, 1049189, 1048342, 1048770, 1047788, 1049532, 1048926, 1049076, 1048402, 1048958, 1047839, 1048703, 1048034, 1047899, 1048717, 1047194, 1048727, 1048412, 1047839, 1048720, 1050793, 1047448, 1048300, 1048449, 1048807, 1049550, 1047038, 1046715, 1047718, 1048511, 1047259, 1049489, 1050753, 1051378, 1048006, 1050478, 1048549, 1046170, 1046498, 1049679, 1048545, 1049865, 1048423, 1049257, 1048149, 1049019, 1049754, 1047821, 1047574, 1048471, 1048558, 1047975], [1048173, 1047716, 1047512, 1046548, 1046839, 1048586, 1047509, 1047530, 1048133, 1048547, 1047574, 1047771, 1048426, 1048016, 1047579, 1047255, 1048640, 1048600, 1048081, 1047422, 1050265, 1047119, 1047383, 1047762, 1050184, 1046704, 1048759, 1048440, 1048347, 1048113, 1049332, 1049436, 1045314, 1048903, 1048537, 1047355, 1048206, 1048446, 1048223, 1046571, 1050043, 1048360, 1047635, 1047191, 1048730, 1048333, 1047296, 1046170, 1048442, 1049985, 1048280, 1047949, 1048448, 1047921, 1046917, 1046405, 1049542, 1047386, 1047058, 1048761, 1047447, 1049468, 1047236, 1047260, 1047549, 1048567, 1048249, 1048708, 1048223, 1048053, 1049537, 1048475, 1046882, 1052553, 1049247, 1048805, 1048760, 1048994, 1048664, 1047845, 1048226, 1047850, 1048342, 1047996, 1052225, 1048092, 1047851, 1046367, 1047684, 1047358, 1049140, 1047228, 1050476, 1048524, 1047393, 1048871, 1047923, 1046532, 1048753, 1048055, 1047188, 1047108, 1048874, 1047547, 1048764, 1047191, 1048111, 1047077, 1047677, 1048902, 1049210, 1047664, 1046341, 1049218, 1047027, 1046176, 1047281, 1048024, 1047350, 1047669, 1048678, 1047087, 1048300, 1049247, 1046693, 1047824, 1047774, 1045256, 1049863, 1050147, 1050679, 1049499, 1049119, 1048291, 1049131, 1047164, 1048812, 1048733, 1046491, 1047300, 1047613, 1048015, 1048538, 1051240, 1048984, 1050269, 1048859, 1051011, 1050074, 1048630, 1048796, 1050995, 1049997, 1048839, 1049440, 1052162, 1050405, 1048579, 1047759, 1050157, 1050096, 1047641, 1048719, 1050918, 1049413, 1049948, 1050001, 1050658, 1049598, 1048336, 1049098, 1048211, 1050102, 1050587, 1050386, 1049710, 1051123, 1050961, 1050165, 1050263, 1050507, 1051212, 1050827, 1051389, 1050387, 1050983, 1049294, 1050768, 1049997, 1049356, 1050809, 1050225, 1047608, 1049290, 1047279, 1049786, 1049557, 1048154, 1049234, 1048175, 1048186, 1050076, 1047600, 1048417, 1048598, 1048569, 1048802, 1048058, 1048621, 1049033, 1050193, 1047621, 1048183, 1046560, 1050988, 1048846, 1048795, 1047866, 1046864, 1047862, 1047159, 1049987, 1047579, 1048786, 1049477, 1048628, 1047421, 1048363, 1047511, 1048899, 1048113, 1049530, 1048915, 1048944, 1048416, 1049347, 1046876, 1048433, 1049504, 1048984, 1048377, 1047296, 1046605, 1049675, 1048223, 1049663, 1048004, 1049311, 1048553, 1049578, 1048491, 1048455, 1047556, 1048542, 1050974, 1047807], [1047915, 1046556, 1046420, 1048742, 1048403, 1046487, 1049346, 1047717, 1047107, 1046095, 1048600, 1048458, 1047318, 1046234, 1047786, 1046440, 1047586, 1047996, 1047400, 1047125, 1047626, 1047838, 1048008, 1049138, 1047161, 1050031, 1047238, 1049618, 1047180, 1049275, 1048584, 1049751, 1048430, 1049007, 1049658, 1047446, 1045914, 1048864, 1048258, 1048355, 1050015, 1047065, 1048311, 1047281, 1049100, 1047391, 1048679, 1046952, 1047713, 1046625, 1047839, 1048128, 1047724, 1048881, 1047653, 1048361, 1048253, 1046883, 1047381, 1049048, 1046784, 1047906, 1048487, 1047005, 1046353, 1048434, 1046083, 1047046, 1047238, 1047815, 1047964, 1046629, 1048918, 1048108, 1047149, 1047054, 1047595, 1048143, 1054215, 1047779, 1053355, 1046727, 1048386, 1048066, 1047780, 1049116, 1046989, 1048903, 1049500, 1046479, 1046748, 1049823, 1048901, 1048014, 1048958, 1048709, 1048545, 1048749, 1046898, 1046872, 1047008, 1047835, 1049944, 1047945, 1047398, 1046159, 1048414, 1045586, 1046772, 1046220, 1048037, 1048943, 1046606, 1047479, 1048759, 1047939, 1047501, 1047541, 1048346, 1048175, 1048014, 1046308, 1047617, 1047678, 1049275, 1047287, 1048324, 1047107, 1049802, 1049330, 1047836, 1049223, 1047492, 1049428, 1049107, 1047989, 1049483, 1048636, 1047588, 1049162, 1048412, 1048753, 1048715, 1048653, 1050364, 1048505, 1051343, 1050874, 1051852, 1048732, 1049897, 1050624, 1050532, 1049340, 1048227, 1048975, 1048408, 1049603, 1049958, 1048251, 1049145, 1050095, 1051771, 1049475, 1050425, 1048926, 1049115, 1050565, 1049969, 1049277, 1047479, 1050461, 1050722, 1049338, 1049997, 1048436, 1051273, 1049196, 1049922, 1050424, 1049443, 1051222, 1050958, 1050282, 1051802, 1051283, 1048841, 1048345, 1050945, 1049734, 1049309, 1050709, 1048054, 1047434, 1049529, 1048958, 1048252, 1049184, 1049071, 1048877, 1050227, 1047548, 1049628, 1049298, 1048351, 1047723, 1048546, 1048253, 1047475, 1050309, 1049843, 1050149, 1048987, 1048939, 1048348, 1050426, 1047231, 1048200, 1048661, 1047622, 1048475, 1050435, 1049091, 1048874, 1047879, 1048666, 1048414, 1050073, 1047344, 1048206, 1049446, 1049956, 1047089, 1048102, 1048429, 1046376, 1049640, 1050536, 1046967, 1049417, 1049910, 1050070, 1050326, 1049545, 1048640, 1048521, 1048292, 1048410, 1050750, 1049014, 1047504, 1050104, 1048916, 1049126, 1049825, 1049153], [1049256, 1046831, 1047634, 1046607, 1048718, 1046531, 1047143, 1047241, 1048674, 1048600, 1048934, 1047758, 1047060, 1048830, 1048885, 1045752, 1048792, 1048354, 1049010, 1049197, 1047745, 1046172, 1048637, 1048703, 1048036, 1046651, 1049992, 1047386, 1047647, 1046890, 1050609, 1047245, 1048701, 1049531, 1047921, 1049240, 1050344, 1047312, 1049160, 1048029, 1049504, 1046176, 1047961, 1047931, 1047510, 1049934, 1047301, 1047369, 1050397, 1047938, 1047656, 1047242, 1050570, 1048279, 1047973, 1048120, 1049856, 1049456, 1047585, 1046345, 1049406, 1047122, 1050274, 1048277, 1047949, 1048929, 1047533, 1049188, 1047390, 1051610, 1048890, 1049166, 1047854, 1049502, 1049271, 1047698, 1046147, 1049489, 1047527, 1047256, 1047899, 1049876, 1048226, 1048652, 1049081, 1048030, 1049027, 1048028, 1048346, 1048278, 1054467, 1047829, 1047972, 1048218, 1047439, 1047695, 1047728, 1048395, 1047958, 1045221, 1046913, 1046242, 1046768, 1047423, 1046979, 1048742, 1047785, 1046683, 1048353, 1047350, 1045989, 1047167, 1048200, 1047204, 1048576, 1046727, 1047357, 1047561, 1048647, 1046479, 1047683, 1047690, 1047971, 1045334, 1048141, 1047843, 1048251, 1047488, 1048545, 1047950, 1049708, 1049681, 1050116, 1049462, 1048273, 1050522, 1052921, 1048396, 1050679, 1049714, 1049359, 1048427, 1050189, 1048845, 1049675, 1049102, 1049263, 1048802, 1050558, 1048557, 1049926, 1050384, 1047996, 1050014, 1049420, 1051906, 1049389, 1047470, 1047909, 1050340, 1048623, 1048373, 1050327, 1048750, 1049878, 1048840, 1049910, 1049162, 1047357, 1049715, 1049157, 1050606, 1049871, 1049595, 1048835, 1050208, 1049459, 1049592, 1049237, 1048669, 1049571, 1049913, 1050102, 1049144, 1050845, 1049513, 1051350, 1048407, 1049973, 1049122, 1051478, 1047509, 1047720, 1048560, 1048410, 1048449, 1049923, 1048616, 1048085, 1047861, 1048910, 1048705, 1048285, 1049313, 1046339, 1048899, 1047672, 1048305, 1048786, 1046786, 1049030, 1048693, 1048506, 1050005, 1048011, 1047042, 1049498, 1047701, 1049998, 1047904, 1048140, 1048182, 1049672, 1049446, 1048541, 1048805, 1048542, 1049530, 1048512, 1049192, 1048031, 1048129, 1048866, 1048561, 1048000, 1048550, 1049497, 1048646, 1048734, 1047534, 1048283, 1048934, 1047191, 1048184, 1049359, 1047873, 1048370, 1049289, 1050075, 1049753, 1048380, 1047725, 1049862, 1049520, 1049737, 1049960]];

        let pool_size = 12;
        let trials = 1usize << 28;
        let f_trials = trials as f64;

        let pool: Pool<ThunkWorker<Vec<u8>>> = Pool::new(pool_size);
        let (tx, rx) = channel();

        let mut i = 0;
        println!("Active count: {}", pool.active_count());
        for _ in 0..=pool_size {
            println!("Enqueed");
            let tmp = oracle.clone();
            pool.execute_to(
                tx.clone(),
                Thunk::of(move || {
                    tmp.encrypt(&[0])
                }),
            );
        }
        println!("Active count: {}", pool.active_count());

        while i < trials {
            // println!("Fod");
            if i % (1025 * 1025) == 0 {
                println!("Trial {} ({})", i, (i as f64 / f_trials));
            }
            let tmp = rx.recv()?;
            for (idx, val) in tmp.iter().enumerate().skip(1) {
                counts[idx - 1][*val as usize] += 1;
            }
            i += 1;
            let tmp = oracle.clone();

            pool.execute_to(
                tx.clone(),
                Thunk::of(move || {
                    tmp.encrypt(&[0])
                }),
            );
        }

        let mut result = vec![0u8; length];
        for (r, val) in result.iter_mut().enumerate() {
            *val = rc4_single_byte_attack(counts[r], r, &crate::rc4::distribution::DISTRIBUTION)?;
        }
        println!("Saved state: {:?}", counts);
        println!("Hex: {}", result.encode_hex::<String>());
        println!("Result: {}", String::from_utf8_lossy(&result));

        assert!(oracle.check(&result));
        Ok(())
    }
}
